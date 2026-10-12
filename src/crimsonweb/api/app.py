import asyncio
import ipaddress
import os
import secrets
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.exc import SQLAlchemyError

from .ai.provider import AISettings, LLMProvider
from .ai.routes import add_ai_routes
from .ai.service import AIService
from .database import Repository
from .discovery.routes import add_discovery_routes
from .discovery.service import DiscoveryJobManager
from .engine import ScanEngine
from .engine import logger as scan_logger
from .hosts import HostAllowlist, HostAllowlistMiddleware
from .models import ScanReport, ScanRequest
from .privacy.routes import add_privacy_routes
from .privacy.service import PrivacyService
from .routes import add_query_routes
from .scope import Scope, ScopeError
from .verification.routes import add_verification_routes
from .verification.service import VerificationService
from .workspaces.routes import add_workspace_routes
from .workspaces.service import WorkspaceService
from .workspaces.store import Conflict, NotFound


def create_app(
    scope: Scope | None = None,
    engine: ScanEngine | None = None,
    repository: Repository | None = None,
    ai_provider: LLMProvider | None = None,
    ai_settings: AISettings | None = None,
    discovery_transport=None,
    privacy_transport=None,
    verification_transport=None,
) -> FastAPI:
    if not scan_logger.handlers:
        import logging

        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        scan_logger.addHandler(handler)
        scan_logger.setLevel(logging.INFO)
        scan_logger.propagate = False
    policy = scope or Scope.from_env()
    scanner = engine or ScanEngine(policy)
    tasks: dict[str, asyncio.Task] = {}
    active: dict[str, ScanReport] = {}
    repo: Repository | None = repository
    ai_service: AIService | None = None
    discovery_manager: DiscoveryJobManager | None = None
    privacy_service: PrivacyService | None = None
    verification_service: VerificationService | None = None
    submission_lock = asyncio.Lock()
    token = os.getenv("CRIMSON_API_TOKEN", "").strip()
    # Tokenless operation is a local development mode and must be requested explicitly.
    allow_no_token = os.getenv("CRIMSON_API_DEV_ALLOW_NO_TOKEN", "").strip() == "1"
    allowed_hosts = HostAllowlist.from_env()
    bearer = HTTPBearer(auto_error=False)
    bearer_dependency = Depends(bearer)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal repo, ai_service, discovery_manager, privacy_service
        nonlocal verification_service
        if not token and not allow_no_token:
            raise RuntimeError(
                "CRIMSON_API_TOKEN is required; set CRIMSON_API_DEV_ALLOW_NO_TOKEN=1 "
                "only for loopback development without a token"
            )
        repo = repo or Repository()
        try:
            await asyncio.to_thread(repo.initialize)
            app.state.repository = repo
            app.state.workspace_service = WorkspaceService(repo)
            discovery_manager = DiscoveryJobManager(
                repo, app.state.workspace_service, discovery_transport
            )
            await discovery_manager.startup()
            app.state.discovery_manager = discovery_manager
            privacy_service = PrivacyService(
                repo, app.state.workspace_service, privacy_transport
            )
            await privacy_service.startup()
            app.state.privacy_service = privacy_service
            ai_service = AIService(repo, ai_provider, ai_settings)
            app.state.ai_service = ai_service
            verification_service = VerificationService(
                repo,
                app.state.workspace_service,
                verification_transport,
                provider=ai_service.provider if ai_service.settings.enabled else None,
                provider_gate=ai_service.gate,
                max_input_bytes=ai_service.settings.max_input_bytes,
            )
            app.state.verification_service = verification_service
            yield
        finally:
            try:
                if verification_service:
                    await verification_service.shutdown()
            finally:
                try:
                    if privacy_service:
                        await privacy_service.shutdown()
                finally:
                    try:
                        if discovery_manager:
                            await discovery_manager.shutdown()
                    finally:
                        try:
                            if ai_service:
                                await ai_service.shutdown()
                            pending = list(tasks.values())
                            for task in pending:
                                task.cancel()
                            await asyncio.gather(*pending, return_exceptions=True)
                            for report in list(active.values()):
                                if report.status in {"queued", "running"}:
                                    report.status, report.stop_reason = (
                                        "stopped",
                                        "server_shutdown",
                                    )
                                    report.finished_at = datetime.now(UTC)
                                    await asyncio.to_thread(repo.save, report)
                        finally:
                            repo.close()

    async def authorize(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = bearer_dependency,
    ) -> None:
        try:
            local = (
                request.client is not None
                and ipaddress.ip_address(request.client.host).is_loopback
            )
        except ValueError:
            local = False
        if token:
            if credentials is None or not secrets.compare_digest(
                credentials.credentials.encode(), token.encode()
            ):
                raise HTTPException(401, "Valid bearer token required")
        elif not allow_no_token:
            raise HTTPException(403, "API token required")
        elif not local:
            raise HTTPException(
                403, "Without an API token only loopback clients are accepted"
            )

    app = FastAPI(
        title="CrimsonWeb Phase 3",
        version="0.3.0",
        lifespan=lifespan,
        dependencies=[Depends(authorize)],
    )
    app.add_middleware(HostAllowlistMiddleware, allowlist=allowed_hosts)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        return JSONResponse(
            {"detail": "Database unavailable; retry after checking server storage"},
            status_code=503,
        )

    def get_repository() -> Repository:
        if repo is None:
            raise HTTPException(503, "Database not initialized")
        return repo

    async def persist(report: ScanReport) -> None:
        await asyncio.to_thread(get_repository().save, report.model_copy(deep=True))

    async def execute(report: ScanReport) -> None:
        try:
            await scanner.run(report, on_update=persist)
        except SQLAlchemyError:
            # No further requests after losing the audit store.
            report.status, report.error_category = "failed", "persistence_error"
            scan_logger.error('{"event":"persistence_error"}')

    def cleanup(task: asyncio.Task, scan_id: str) -> None:
        tasks.pop(scan_id, None)
        report = active.get(scan_id)
        if report and report.status not in {"queued", "running"}:
            active.pop(scan_id, None)
        if not task.cancelled() and task.exception() is not None:
            scan_logger.error('{"event":"scan_task_error"}')

    async def stop_scan(scan_id: str, reason: str = "operator_stop") -> ScanReport:
        report = active.get(scan_id) or await asyncio.to_thread(
            get_repository().get, scan_id
        )
        if report is None:
            raise HTTPException(404, "Scan not found")
        task = tasks.get(scan_id)
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        if task is not None or report.status in {"queued", "running"}:
            report.status = "blocked" if reason == "defense_log_block" else "stopped"
            report.stop_reason = reason
            report.finished_at = datetime.now(UTC)
            await persist(report)
        active.pop(scan_id, None)
        return await asyncio.to_thread(get_repository().get, scan_id)

    add_query_routes(app, get_repository, stop_scan)
    add_workspace_routes(app, lambda: app.state.workspace_service)
    add_discovery_routes(app, lambda: app.state.discovery_manager)

    @app.exception_handler(NotFound)
    async def workspace_not_found(request: Request, exc: NotFound):
        return JSONResponse(
            status_code=404, content={"detail": "Workspace or policy not found"}
        )

    @app.exception_handler(Conflict)
    async def workspace_conflict(request: Request, exc: Conflict):
        return JSONResponse(
            status_code=409,
            content={"detail": "Policy conflict; reload current revision"},
        )

    def get_ai_service() -> AIService:
        if ai_service is None:
            raise HTTPException(503, "AI service not initialized")
        return ai_service

    add_ai_routes(app, get_ai_service)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "phase": "3"}

    @app.post("/scans", status_code=202, response_model=ScanReport)
    async def start_scan(payload: ScanRequest) -> ScanReport:
        try:
            target = policy.validate_url(payload.url)
            await policy.resolve(target)
        except ScopeError as exc:
            raise HTTPException(422, str(exc)) from exc
        except (OSError, TimeoutError) as exc:
            raise HTTPException(422, "Target DNS resolution failed") from exc
        async with submission_lock:
            if len(tasks) >= 4:
                raise HTTPException(429, "Maximum four active scans")
            report = ScanReport(
                id=str(uuid4()),
                engagement_id=payload.engagement_id,
                target=str(target),
                scope=policy.snapshot(),
            )
            await persist(report)
            active[report.id] = report
            task = asyncio.create_task(execute(report))
            tasks[report.id] = task
            task.add_done_callback(lambda t: cleanup(t, report.id))
            return report.model_copy(deep=True)

    @app.get("/scans", response_model=list[ScanReport])
    async def list_scans() -> list[ScanReport]:
        return (await asyncio.to_thread(get_repository().history, 100, 0)).items

    async def find_report(scan_id: str) -> ScanReport:
        report = await asyncio.to_thread(get_repository().get, scan_id)
        if report is None:
            raise HTTPException(404, "Scan not found")
        return report

    @app.get("/scans/{scan_id}", response_model=ScanReport)
    async def get_scan(scan_id: str) -> ScanReport:
        return await find_report(scan_id)

    @app.get("/scans/{scan_id}/report")
    async def download_report(scan_id: str, include_ai: bool = False) -> JSONResponse:
        report = await find_report(scan_id)
        if report.status in {"queued", "running"}:
            raise HTTPException(409, "Scan is still running")
        if include_ai:
            report.ai_analysis = await asyncio.to_thread(
                get_ai_service().report_annotation, scan_id
            )
        return JSONResponse(
            report.model_dump(mode="json"),
            headers={
                "Content-Disposition": f'attachment; filename="crimsonweb_{report.id}.json"'
            },
        )

    add_privacy_routes(app, lambda: app.state.privacy_service)
    add_verification_routes(app, lambda: app.state.verification_service)
    return app


app = create_app()
