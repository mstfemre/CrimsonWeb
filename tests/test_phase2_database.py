from datetime import UTC, datetime
from uuid import uuid4

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from crimsonweb.api.database import (
    Base,
    FindingRow,
    Repository,
    ScanRow,
    TargetRow,
    migration_config,
)
from crimsonweb.api.models import Finding, ScanReport, WAFEvent


def report(status="completed"):
    return ScanReport(
        id=str(uuid4()),
        engagement_id="lab",
        target="http://127.0.0.1/",
        scope={"hosts": ["127.0.0.1"], "networks": ["127.0.0.0/8"]},
        status=status,
        finished_at=datetime.now(UTC),
        findings=[
            Finding(
                code="test",
                severity="low",
                evidence="observed",
                recommendation="review",
            )
        ],
    )


def test_persistence_relationships_and_idempotent_save(tmp_path):
    url = f"sqlite:///{(tmp_path / 'persistent.sqlite').as_posix()}"
    repo = Repository(url)
    repo.initialize()
    item = report()
    item.waf_events.append(
        WAFEvent(
            source="http",
            scan_id=item.id,
            event_type="access_denied",
            status_code=403,
            evidence="HTTP 403",
        )
    )
    repo.save(item)
    repo.save(item)
    with Session(repo.engine) as session:
        assert session.scalar(select(func.count()).select_from(FindingRow)) == 1
        assert session.scalar(select(func.count()).select_from(TargetRow)) == 1
        row = session.get(ScanRow, item.id)
        assert row.target.url == item.target and row.findings[0].scan.id == item.id
        assert row.events[0].scan.id == item.id
    repo.close()
    reopened = Repository(url)
    reopened.initialize()
    assert reopened.get(item.id).model_dump() == item.model_dump()
    reopened.close()


@pytest.mark.parametrize("status", ["queued", "running"])
def test_interrupted_scans_stopped_without_network_retry(tmp_path, status):
    url = f"sqlite:///{(tmp_path / 'restart.sqlite').as_posix()}"
    repo = Repository(url)
    repo.initialize()
    item = report(status)
    repo.save(item)
    repo.close()
    reopened = Repository(url)
    reopened.initialize()
    recovered = reopened.get(item.id)
    assert (
        recovered.status == "stopped" and recovered.stop_reason == "process_interrupted"
    )
    assert recovered.finished_at is not None
    reopened.close()


def test_migration_upgrade_downgrade_and_model_consistency(tmp_path):
    repo = Repository(f"sqlite:///{(tmp_path / 'migrate.sqlite').as_posix()}")
    repo.initialize()
    with repo.engine.begin() as connection:
        assert (
            connection.scalar(text("SELECT version_num FROM alembic_version"))
            == "0006_phase4c"
        )
        assert (
            compare_metadata(MigrationContext.configure(connection), Base.metadata)
            == []
        )
        config = migration_config()
        config.attributes["connection"] = connection
        command.downgrade(config, "base")
        command.upgrade(config, "head")
        assert (
            compare_metadata(MigrationContext.configure(connection), Base.metadata)
            == []
        )
    repo.close()


def test_import_atomicity_and_foreign_keys():
    repo = Repository("sqlite://")
    repo.initialize()
    good = WAFEvent(source="normalized_json", event_type="rule_match", evidence="rule")
    invalid = WAFEvent(
        source="normalized_json",
        event_type="ip_block",
        evidence="block",
        scan_id="absent",
    )
    with pytest.raises(LookupError):
        repo.import_events([good, invalid])
    assert repo.events(100, 0).total == 0
    with repo.engine.begin() as connection, pytest.raises(IntegrityError):
        connection.execute(
            text(
                "INSERT INTO findings(id, scan_id, severity, data) "
                "VALUES ('test', 'missing', 'low', '{}')"
            )
        )
    repo.close()


def test_history_filters_and_pages():
    repo = Repository("sqlite://")
    repo.initialize()
    for status in ["completed", "failed", "blocked", "stopped"]:
        repo.save(report(status))
    assert repo.history(2, 0).total == 4
    assert len(repo.history(2, 2).items) == 2
    assert repo.history(50, 0, status="blocked").total == 1
    assert repo.findings(1, 0, severity="low").total == 4
    assert repo.findings(50, 0, severity="high").total == 0
    target_id = repo.targets(10, 0).items[0].id
    assert repo.history(50, 0, target_id=target_id).total == 4
    repo.close()
