"""AI jobs operate on immutable evidence snapshots and never receive scanner capabilities."""

import asyncio
from datetime import UTC, datetime
from time import perf_counter

from .contract import output_schema
from .models import AnalysisRecord, AnalysisRequest, ProviderStatus
from .provider import AIError, AISettings, LLMProvider, OllamaProvider, ProviderGate
from .security import (
    EvidenceBundle,
    build_bundle,
    system_prompt,
    validate_provider_output,
)


class AIService:
    def __init__(
        self,
        repository,
        provider: LLMProvider | None = None,
        settings: AISettings | None = None,
    ) -> None:
        self.repository = repository
        self.configuration_error: str | None = None
        try:
            self.settings = settings or AISettings.from_env()
            self.provider = provider or (
                OllamaProvider(self.settings) if self.settings.enabled else None
            )
        except (ValueError, AIError):
            self.settings = AISettings()
            self.provider = None
            self.configuration_error = "invalid_configuration"
        self.gate = ProviderGate(self.settings)
        self.tasks: dict[str, asyncio.Task] = {}
        self.records: dict[str, AnalysisRecord] = {}
        self._submission_lock = asyncio.Lock()

    def descriptor(self) -> ProviderStatus:
        return ProviderStatus(
            provider=self.provider.name if self.provider else "ollama",
            model=self.provider.model if self.provider else self.settings.model,
            enabled=self.settings.enabled and self.provider is not None,
            error_code=self.configuration_error
            or (None if self.settings.enabled else "ai_disabled"),
        )

    async def status(self) -> ProviderStatus:
        status = self.descriptor()
        if not status.enabled:
            return status
        try:
            return await self.gate.call(self.provider.health)
        except AIError as exc:
            status.error_code = exc.code
            return status
        except Exception:  # noqa: BLE001 -- Provider diagnostic errors must never disclose raw messages.
            status.error_code = "provider_error"
            return status

    async def start(self, request: AnalysisRequest) -> AnalysisRecord:
        if not self.descriptor().enabled:
            raise AIError(self.configuration_error or "ai_disabled")
        bundle = await asyncio.to_thread(
            build_bundle, self.repository, request, self.settings.max_input_bytes
        )
        async with self._submission_lock:
            if len(self.tasks) >= self.settings.max_concurrency:
                raise AIError("provider_capacity")
            record = AnalysisRecord(
                scan_id=bundle.scan_id,
                kind=request.kind,
                language=request.language,
                provider=self.provider.name,
                model=self.provider.model,
                evidence_refs=bundle.refs,
                input_digest=bundle.digest,
                safety_notes=bundle.notes,
                priorities=bundle.priorities,
            )
            await asyncio.to_thread(self.repository.save_analysis, record)
            self.records[record.id] = record
            task = asyncio.create_task(self._run(record, bundle))
            self.tasks[record.id] = task
            task.add_done_callback(lambda t: self._finished(t, record.id))
            return record.model_copy(deep=True)

    def _finished(self, task: asyncio.Task, analysis_id: str) -> None:
        self.tasks.pop(analysis_id, None)
        record = self.records.get(analysis_id)
        if record and record.status not in {"queued", "running"}:
            self.records.pop(analysis_id, None)
        # Retrieve task exceptions without logging provider messages or evidence.
        if not task.cancelled():
            task.exception()

    async def _run(self, record: AnalysisRecord, bundle: EvidenceBundle) -> None:
        started = perf_counter()
        record.started_at = datetime.now(UTC)
        record.status = "running"
        try:
            await asyncio.to_thread(
                self.repository.save_analysis, record.model_copy(deep=True)
            )
            reply = await self.gate.call(
                lambda: self.provider.generate(
                    system_prompt(record.language),
                    bundle.data,
                    output_schema(bundle.refs, record.language),
                )
            )
            if len(reply.content.encode()) > self.settings.max_response_bytes:
                raise AIError("response_too_large")
            record.usage = reply.usage
            record.output = validate_provider_output(
                reply.content, bundle, record.language
            )
            record.status = "completed"
        except AIError as exc:
            record.status, record.error_code = "failed", exc.code
        except asyncio.CancelledError:
            record.status, record.error_code = "stopped", "server_shutdown"
            raise
        except Exception:  # noqa: BLE001 -- Boundary stores a safe code, never raw provider output/errors.
            record.status, record.error_code = "failed", "analysis_error"
        finally:
            record.duration_ms = int((perf_counter() - started) * 1000)
            record.finished_at = datetime.now(UTC)
            await asyncio.to_thread(
                self.repository.save_analysis, record.model_copy(deep=True)
            )

    async def shutdown(self) -> None:
        pending = list(self.tasks.values())
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for record in list(self.records.values()):
            if record.status in {"queued", "running"}:
                record.status, record.error_code = "stopped", "server_shutdown"
                record.finished_at = datetime.now(UTC)
                await asyncio.to_thread(self.repository.save_analysis, record)
        self.records.clear()

    def report_annotation(self, scan_id: str) -> AnalysisRecord | None:
        record = self.repository.latest_scan_analysis(scan_id)
        if record:
            request = AnalysisRequest(scan_id=scan_id, language=record.language)
            try:
                bundle = build_bundle(
                    self.repository, request, self.settings.max_input_bytes
                )
                record.stale = record.input_digest != bundle.digest
            except AIError:
                record.stale = True
        return record
