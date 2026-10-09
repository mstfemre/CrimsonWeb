import asyncio

import pytest
from ai_helpers import MockProvider, seeded_repository
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import text

from crimsonweb.api.ai.models import AnalysisRequest
from crimsonweb.api.ai.provider import AIError, AISettings
from crimsonweb.api.ai.service import AIService
from crimsonweb.api.database import Base, Repository, migration_config


async def finish(service, request):
    initial = await service.start(request)
    task = service.tasks.get(initial.id)
    if task:
        await task
    return service.repository.get_analysis(initial.id)


@pytest.mark.parametrize("language", ["tr", "en"])
def test_analysis_stores_separate_opinion_usage_and_priorities(language):
    repo, report = seeded_repository()
    before = repo.get(report.id).model_dump_json()
    provider = MockProvider()
    service = AIService(repo, provider, AISettings(enabled=True))
    record = asyncio.run(
        finish(service, AnalysisRequest(scan_id=report.id, language=language))
    )
    assert record.status == "completed" and record.output.language == language
    assert record.priorities[0].technical_severity == "medium"
    assert record.usage.input_tokens == 120 and record.duration_ms is not None
    assert record.finished_at and record.model_claims_verified is False
    assert repo.get(report.id).model_dump_json() == before
    assert len(provider.calls) == 1
    repo.close()


@pytest.mark.parametrize("kind", ["findings", "waf"])
def test_finding_and_waf_selection_binds_only_existing_evidence(kind):
    repo, report = seeded_repository()
    request = AnalysisRequest(
        kind=kind,
        finding_ids=[report.findings[0].id] if kind == "findings" else [],
        waf_event_ids=[report.waf_events[0].id] if kind == "waf" else [],
    )
    service = AIService(repo, MockProvider(), AISettings(enabled=True))
    record = asyncio.run(finish(service, request))
    assert record.status == "completed" and record.scan_id == report.id
    assert len(record.output.technical_findings) == (1 if kind == "findings" else 0)
    assert len(record.output.waf_assessment) == (1 if kind == "waf" else 0)
    repo.close()


@pytest.mark.parametrize(
    "error",
    [
        AIError("provider_unavailable"),
        AIError("provider_timeout"),
        RuntimeError("api-key=secret-value"),
    ],
)
def test_failure_stored_without_raw_messages_or_technical_changes(error):
    repo, report = seeded_repository()
    before = repo.get(report.id).model_dump_json()
    service = AIService(repo, MockProvider(error=error), AISettings(enabled=True))
    record = asyncio.run(finish(service, AnalysisRequest(scan_id=report.id)))
    assert record.status == "failed" and record.output is None and record.error_code
    assert "secret-value" not in record.model_dump_json()
    assert repo.get(report.id).model_dump_json() == before
    repo.close()


def test_total_timeout_without_provider_cooperation():
    repo, report = seeded_repository()
    service = AIService(
        repo, MockProvider(delay=10), AISettings(enabled=True, timeout_seconds=0.01)
    )
    record = asyncio.run(finish(service, AnalysisRequest(scan_id=report.id)))
    assert record.error_code == "provider_timeout" and record.status == "failed"
    repo.close()


def test_bad_json_not_persisted_as_valid_analysis():
    repo, report = seeded_repository()
    service = AIService(
        repo,
        MockProvider(transform=lambda output: "secret malformed JSON"),
        AISettings(enabled=True),
    )
    record = asyncio.run(finish(service, AnalysisRequest(scan_id=report.id)))
    assert record.error_code == "invalid_model_output" and record.output is None
    assert "malformed" not in record.model_dump_json()
    repo.close()


def test_capacity_and_shutdown_persist_stopped_jobs():
    repo, report = seeded_repository()
    provider = MockProvider(delay=60)
    service = AIService(repo, provider, AISettings(enabled=True, max_concurrency=1))

    async def run():
        record = await service.start(AnalysisRequest(scan_id=report.id))
        with pytest.raises(AIError, match="provider_capacity"):
            await service.start(AnalysisRequest(scan_id=report.id))
        await service.shutdown()
        return repo.get_analysis(record.id)

    record = asyncio.run(run())
    assert record.status == "stopped" and record.error_code == "server_shutdown"
    assert len(provider.calls) <= 1
    repo.close()


def test_ai_persistence_restart_and_interrupted_recovery(tmp_path):
    url = f"sqlite:///{(tmp_path / 'ai.sqlite').as_posix()}"
    repo, report = seeded_repository(url)
    service = AIService(repo, MockProvider(), AISettings(enabled=True))
    completed = asyncio.run(finish(service, AnalysisRequest(scan_id=report.id)))
    queued = completed.model_copy(deep=True)
    queued.id = "interrupted"
    queued.status, queued.output, queued.finished_at = "running", None, None
    repo.save_analysis(queued)
    repo.close()
    reopened = Repository(url)
    reopened.initialize()
    assert reopened.get_analysis(completed.id).model_dump() == completed.model_dump()
    assert reopened.get_analysis(queued.id).status == "stopped"
    assert reopened.get_analysis(queued.id).error_code == "process_interrupted"
    assert reopened.analysis_history(50, 0).total == 2
    reopened.close()


def test_phase2_to_phase3_migration_preserves_technical_data(tmp_path):
    url = f"sqlite:///{(tmp_path / 'upgrade.sqlite').as_posix()}"
    repo, report = seeded_repository(url)
    before = repo.get(report.id).model_dump_json()
    with repo.engine.begin() as connection:
        config = migration_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "0001_phase2")
        assert (
            connection.scalar(text("SELECT version_num FROM alembic_version"))
            == "0001_phase2"
        )
        command.upgrade(config, "head")
        assert (
            compare_metadata(MigrationContext.configure(connection), Base.metadata)
            == []
        )
    assert repo.get(report.id).model_dump_json() == before
    repo.close()


def test_failed_provider_health_keeps_diagnostics_safe():
    repo, _report = seeded_repository()
    service = AIService(
        repo,
        MockProvider(error=RuntimeError("password=secret")),
        AISettings(enabled=True),
    )
    status = asyncio.run(service.status())
    assert (
        status.error_code == "provider_error"
        and "secret" not in status.model_dump_json()
    )
    repo.close()


def test_stale_analysis_after_defense_event_added():
    repo, report = seeded_repository()
    service = AIService(repo, MockProvider(), AISettings(enabled=True))
    asyncio.run(finish(service, AnalysisRequest(scan_id=report.id)))
    assert service.report_annotation(report.id).stale is False
    event = report.waf_events[0].model_copy(deep=True)
    event.id = "new-defense-event"
    event.evidence = "Additional defense evidence"
    repo.import_events([event])
    assert service.report_annotation(report.id).stale is True
    repo.close()
