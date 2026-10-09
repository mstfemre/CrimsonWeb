import asyncio
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, FastAPI, Query, Request, Response

from ..discovery.routes import body_schema, bounded_payload
from ..models import Page
from ..workspaces.routes import Limit, Offset
from .models import (
    DiagnosticRequest,
    NetworkLeakFinding,
    PrivacyAssessment,
    PrivacyAuditLog,
    PrivacyEvidence,
    PrivacyPolicy,
    PrivacyPolicyRecord,
    PrivacyPreflight,
    PrivacyProfile,
    PrivacyProfileInput,
)

Revision = Annotated[int, Query(ge=1)]


def add_privacy_routes(app: FastAPI, get_service):
    router = APIRouter(
        prefix="/api/v1/workspaces/{workspace_id}/privacy", tags=["privacy"]
    )

    @router.post(
        "/profiles",
        status_code=201,
        response_model=PrivacyProfile,
        openapi_extra=body_schema(PrivacyProfileInput),
    )
    async def create(workspace_id: UUID, request: Request):
        payload = await bounded_payload(request, PrivacyProfileInput)
        service = get_service()
        return await asyncio.to_thread(
            service.store.create_profile, workspace_id, payload, service.shared.clock()
        )

    @router.get("/profiles", response_model=Page[PrivacyProfile])
    async def profiles(workspace_id: UUID, limit: Limit = 50, offset: Offset = 0):
        return await asyncio.to_thread(
            get_service().profiles, workspace_id, limit, offset
        )

    @router.get("/profiles/{profile_id}", response_model=PrivacyProfile)
    async def profile(workspace_id: UUID, profile_id: UUID):
        return (
            await asyncio.to_thread(
                get_service().store.snapshot, workspace_id, profile_id
            )
        )[0]

    @router.put(
        "/profiles/{profile_id}",
        response_model=PrivacyProfile,
        openapi_extra=body_schema(PrivacyProfileInput),
    )
    async def update(
        workspace_id: UUID,
        profile_id: UUID,
        request: Request,
        expected_revision: Revision,
    ):
        payload = await bounded_payload(request, PrivacyProfileInput)
        service = get_service()
        return await asyncio.to_thread(
            service.store.update_profile,
            workspace_id,
            profile_id,
            payload,
            expected_revision,
            service.shared.clock(),
        )

    @router.delete("/profiles/{profile_id}", status_code=204)
    async def delete(workspace_id: UUID, profile_id: UUID):
        service = get_service()
        await asyncio.to_thread(
            service.store.delete_profile,
            workspace_id,
            profile_id,
            service.shared.clock(),
        )
        return Response(status_code=204)

    @router.get("/profiles/{profile_id}/policy", response_model=PrivacyPolicyRecord)
    async def policy(workspace_id: UUID, profile_id: UUID):
        return (
            await asyncio.to_thread(
                get_service().store.snapshot, workspace_id, profile_id
            )
        )[1]

    @router.put(
        "/profiles/{profile_id}/policy",
        response_model=PrivacyPolicyRecord,
        openapi_extra=body_schema(PrivacyPolicy),
    )
    async def update_policy(
        workspace_id: UUID,
        profile_id: UUID,
        request: Request,
        expected_revision: Revision,
    ):
        payload = await bounded_payload(request, PrivacyPolicy)
        service = get_service()
        return await asyncio.to_thread(
            service.store.write_privacy_policy,
            workspace_id,
            profile_id,
            payload,
            expected_revision,
            service.shared.clock(),
        )

    @router.post(
        "/profiles/{profile_id}/preflight",
        response_model=PrivacyPreflight,
        openapi_extra=body_schema(DiagnosticRequest),
    )
    async def preflight(workspace_id: UUID, profile_id: UUID, request: Request):
        payload = await bounded_payload(request, DiagnosticRequest)
        return await get_service().preflight(workspace_id, profile_id, payload)

    @router.post(
        "/profiles/{profile_id}/observations",
        status_code=202,
        response_model=PrivacyAssessment,
        openapi_extra=body_schema(DiagnosticRequest),
    )
    async def observe(workspace_id: UUID, profile_id: UUID, request: Request):
        payload = await bounded_payload(request, DiagnosticRequest)
        return await get_service().start(workspace_id, profile_id, payload)

    @router.get("/assessments", response_model=Page[PrivacyAssessment])
    async def assessments(workspace_id: UUID, limit: Limit = 50, offset: Offset = 0):
        return await asyncio.to_thread(
            get_service().assessments, workspace_id, limit, offset
        )

    @router.get("/assessments/{assessment_id}", response_model=PrivacyAssessment)
    async def assessment(workspace_id: UUID, assessment_id: UUID):
        return await asyncio.to_thread(
            get_service().store.get_assessment, workspace_id, assessment_id
        )

    @router.post(
        "/assessments/{assessment_id}/cancel", response_model=PrivacyAssessment
    )
    async def cancel(workspace_id: UUID, assessment_id: UUID):
        return await get_service().cancel(workspace_id, assessment_id)

    @router.get(
        "/assessments/{assessment_id}/findings", response_model=list[NetworkLeakFinding]
    )
    async def findings(workspace_id: UUID, assessment_id: UUID):
        return await asyncio.to_thread(
            get_service().store.findings, workspace_id, assessment_id
        )

    @router.get("/evidence/{evidence_id}", response_model=PrivacyEvidence)
    async def evidence(workspace_id: UUID, evidence_id: UUID):
        return await asyncio.to_thread(
            get_service().store.evidence, workspace_id, evidence_id
        )

    @router.get("/audit", response_model=Page[PrivacyAuditLog])
    async def audit(workspace_id: UUID, limit: Limit = 50, offset: Offset = 0):
        return await asyncio.to_thread(
            get_service().audits, workspace_id, limit, offset
        )

    app.include_router(router)
