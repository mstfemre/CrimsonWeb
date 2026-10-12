"""Workspace-qualified verification API with bounded, non-echoing validation.

Errors never echo request bodies (which may carry credentials): invalid payloads
return a fixed 422 message. Approval is a required, explicit step before execute.
"""

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, FastAPI, HTTPException, Request
from pydantic import ValidationError

from ..discovery.routes import body_schema
from ..models import Page
from ..workspaces.routes import Limit, Offset
from ..workspaces.service import AuthorizationDenied
from ..workspaces.store import Conflict, NotFound
from .models import (
    ComparativeAccessEvidence,
    ExecuteRequest,
    PlanApproval,
    PlanStatus,
    PolicyStopEvidence,
    VerificationFinding,
    VerificationPlan,
    VerificationPlanCreate,
    VerificationReport,
    VerificationTest,
    WebProbeEvidence,
)

Evidence = ComparativeAccessEvidence | PolicyStopEvidence | WebProbeEvidence


async def _payload(request: Request, model, max_bytes=1048576):
    if (
        request.headers.get("content-type", "").split(";", 1)[0].lower()
        != "application/json"
    ):
        raise HTTPException(415, "JSON request required")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > max_bytes:
            raise HTTPException(413, "Verification input exceeds byte limit")
        data.extend(chunk)
    try:
        return model.model_validate(json.loads(data))
    except (ValueError, ValidationError, RecursionError):
        # Never echo credentials, document values or input URLs.
        raise HTTPException(422, "Invalid verification request") from None


def add_verification_routes(app: FastAPI, get_service):
    router = APIRouter(
        prefix="/api/v1/workspaces/{workspace_id}/verification", tags=["verification"]
    )

    @router.post(
        "/plans",
        status_code=202,
        response_model=VerificationPlan,
        openapi_extra=body_schema(VerificationPlanCreate),
    )
    async def create_plan(workspace_id: UUID, request: Request):
        payload = await _payload(request, VerificationPlanCreate)
        try:
            return await get_service().create_plan(workspace_id, payload)
        except AuthorizationDenied as exc:
            raise HTTPException(403, {"reason": exc.reason}) from None
        except (Conflict, NotFound):
            raise
        except ValueError:
            raise HTTPException(422, "Invalid verification request") from None

    @router.post(
        "/plans/{plan_id}/approve",
        response_model=VerificationPlan,
        openapi_extra=body_schema(PlanApproval),
    )
    async def approve_plan(workspace_id: UUID, plan_id: UUID, request: Request):
        payload = await _payload(request, PlanApproval)
        try:
            return await asyncio.to_thread(
                get_service().approve_plan, workspace_id, plan_id, payload
            )
        except (Conflict, NotFound):
            raise
        except ValueError:
            raise HTTPException(422, "Invalid verification request") from None

    @router.post(
        "/plans/{plan_id}/execute",
        response_model=VerificationPlan,
        openapi_extra=body_schema(ExecuteRequest),
    )
    async def execute_plan(workspace_id: UUID, plan_id: UUID, request: Request):
        try:
            service = get_service()
            async with service.execution_admission():
                payload = await _payload(request, ExecuteRequest, max_bytes=16384)
                return await service.execute_plan(workspace_id, plan_id, payload)
        except AuthorizationDenied as exc:
            raise HTTPException(403, {"reason": exc.reason}) from None
        except (Conflict, NotFound):
            raise
        except ValueError:
            raise HTTPException(422, "Invalid verification request") from None

    @router.post("/plans/{plan_id}/cancel", response_model=VerificationPlan)
    async def cancel_plan(workspace_id: UUID, plan_id: UUID):
        service = get_service()
        return await asyncio.to_thread(
            service.store.cancel_plan, workspace_id, plan_id, service.clock()
        )

    @router.post("/plans/{plan_id}/next", response_model=VerificationPlan, status_code=202)
    async def next_plan(workspace_id: UUID, plan_id: UUID):
        try:
            return await get_service().next_plan(workspace_id, plan_id)
        except AuthorizationDenied as exc:
            raise HTTPException(403, {"reason": exc.reason}) from None

    @router.get("/catalog")
    async def catalog(workspace_id: UUID):
        from dataclasses import asdict

        from .catalog import catalog_entry, catalog_ids
        from .coverage import TOP10

        get_service().shared.store.get_workspace(workspace_id)
        return {"tests": [asdict(catalog_entry(i)) for i in catalog_ids()],
                "owasp_edition": "2025", "categories": [{"category": c, "title": t} for c, t in TOP10]}

    @router.get("/plans", response_model=Page[VerificationPlan])
    async def plans(
        workspace_id: UUID,
        limit: Limit = 50,
        offset: Offset = 0,
        status: PlanStatus | None = None,
    ):
        return await asyncio.to_thread(
            get_service().store.list_plans, workspace_id, limit, offset, status
        )

    @router.get("/plans/{plan_id}", response_model=VerificationPlan)
    async def plan(workspace_id: UUID, plan_id: UUID):
        return await asyncio.to_thread(
            get_service().store.get_plan, workspace_id, plan_id
        )

    @router.get("/plans/{plan_id}/tests", response_model=Page[VerificationTest])
    async def tests(
        workspace_id: UUID, plan_id: UUID, limit: Limit = 50, offset: Offset = 0
    ):
        return await asyncio.to_thread(
            get_service().store.tests, workspace_id, plan_id, limit, offset
        )

    @router.get("/plans/{plan_id}/evidence", response_model=Page[Evidence])
    async def evidence(
        workspace_id: UUID, plan_id: UUID, limit: Limit = 50, offset: Offset = 0
    ):
        return await asyncio.to_thread(
            get_service().store.evidence, workspace_id, plan_id, limit, offset
        )

    @router.get("/plans/{plan_id}/findings", response_model=Page[VerificationFinding])
    async def findings(
        workspace_id: UUID, plan_id: UUID, limit: Limit = 50, offset: Offset = 0
    ):
        return await asyncio.to_thread(
            get_service().store.findings, workspace_id, plan_id, limit, offset
        )

    @router.get("/plans/{plan_id}/report", response_model=VerificationReport)
    async def report(workspace_id: UUID, plan_id: UUID):
        return await asyncio.to_thread(
            get_service().store.report, workspace_id, plan_id
        )

    app.include_router(router)
