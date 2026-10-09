import asyncio
from collections.abc import Callable
from typing import Literal

from fastapi import FastAPI, HTTPException

from ..models import Page
from ..routes import Limit, Offset
from .models import AnalysisRecord, AnalysisRequest, ProviderStatus
from .provider import AIError
from .service import AIService


def add_ai_routes(app: FastAPI, get_service: Callable[[], AIService]) -> None:
    @app.get("/ai/providers", response_model=list[ProviderStatus])
    async def providers() -> list[ProviderStatus]:
        return [get_service().descriptor()]

    @app.get("/ai/status", response_model=ProviderStatus)
    async def status() -> ProviderStatus:
        return await get_service().status()

    @app.post("/ai/analyses", response_model=AnalysisRecord, status_code=202)
    async def start(payload: AnalysisRequest) -> AnalysisRecord:
        try:
            return await get_service().start(payload)
        except AIError as exc:
            status_code = {
                "evidence_not_found": 404,
                "scan_not_finished": 409,
                "input_too_large": 422,
                "single_scan_required": 422,
                "provider_capacity": 429,
            }.get(exc.code, 503)
            raise HTTPException(status_code, exc.code) from exc

    @app.get("/ai/analyses", response_model=Page[AnalysisRecord])
    async def history(
        limit: Limit = 50,
        offset: Offset = 0,
        scan_id: str | None = None,
        status: Literal["queued", "running", "completed", "failed", "stopped"]
        | None = None,
        kind: Literal["scan", "findings", "waf"] | None = None,
    ) -> Page[AnalysisRecord]:
        return await asyncio.to_thread(
            get_service().repository.analysis_history,
            limit,
            offset,
            scan_id,
            status,
            kind,
        )

    @app.get("/ai/analyses/{analysis_id}", response_model=AnalysisRecord)
    async def analysis(analysis_id: str) -> AnalysisRecord:
        record = await asyncio.to_thread(
            get_service().repository.get_analysis, analysis_id
        )
        if record is None:
            raise HTTPException(404, "Analysis not found")
        return record
