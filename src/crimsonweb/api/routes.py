import asyncio
from collections.abc import Awaitable, Callable
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Query

from .database import Repository
from .models import (
    FindingResult,
    ImportResult,
    Page,
    ScanReport,
    TargetResult,
    WAFEvent,
    WAFImport,
)
from .waf import parse_logs

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Status = Literal["queued", "running", "completed", "blocked", "failed", "stopped"]
Severity = Literal["info", "low", "medium", "high", "critical"]
EventType = Literal[
    "access_denied", "rate_limited", "rule_match", "waf_block", "ip_block"
]


def add_query_routes(
    app: FastAPI,
    get_repo: Callable[[], Repository],
    stop: Callable[[str, str], Awaitable[ScanReport]],
) -> None:
    @app.get("/history", response_model=Page[ScanReport])
    async def history(
        limit: Limit = 50,
        offset: Offset = 0,
        status: Status | None = None,
        target_id: str | None = None,
        engagement_id: str | None = None,
    ) -> Page[ScanReport]:
        return await asyncio.to_thread(
            get_repo().history, limit, offset, status, target_id, engagement_id
        )

    @app.get("/targets", response_model=Page[TargetResult])
    async def targets(limit: Limit = 50, offset: Offset = 0) -> Page[TargetResult]:
        return await asyncio.to_thread(get_repo().targets, limit, offset)

    @app.get("/findings", response_model=Page[FindingResult])
    async def findings(
        limit: Limit = 50,
        offset: Offset = 0,
        severity: Severity | None = None,
        scan_id: str | None = None,
    ) -> Page[FindingResult]:
        return await asyncio.to_thread(
            get_repo().findings, limit, offset, severity, scan_id
        )

    @app.get("/waf/events", response_model=Page[WAFEvent])
    async def events(
        limit: Limit = 50,
        offset: Offset = 0,
        scan_id: str | None = None,
        event_type: EventType | None = None,
        rule_id: str | None = None,
    ) -> Page[WAFEvent]:
        return await asyncio.to_thread(
            get_repo().events, limit, offset, scan_id, event_type, rule_id
        )

    @app.post("/waf/import", response_model=ImportResult)
    async def import_logs(payload: WAFImport) -> ImportResult:
        try:
            items = await asyncio.to_thread(parse_logs, payload)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        try:
            count = await asyncio.to_thread(get_repo().import_events, items)
        except LookupError as exc:
            raise HTTPException(404, "Scan not found") from exc
        if payload.scan_id and any(
            e.event_type in {"ip_block", "waf_block"} for e in items
        ):
            await stop(payload.scan_id, "defense_log_block")
        return ImportResult(imported=count, duplicates=len(items) - count)

    @app.post("/scans/{scan_id}/stop", response_model=ScanReport)
    async def stop_scan(scan_id: str) -> ScanReport:
        return await stop(scan_id, "operator_stop")
