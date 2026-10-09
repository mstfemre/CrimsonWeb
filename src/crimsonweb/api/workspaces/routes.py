"""Versioned operator API; inherits the app's existing authentication dependency."""

import asyncio
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, FastAPI, Path, Query

from ..models import Page
from .models import (
    AuthorizationRequest,
    Decision,
    PolicyRecord,
    PolicyRevision,
    PolicyValidation,
    ProgramPolicy,
    ScopeAuditLog,
    Workspace,
    WorkspaceCreate,
    WorkspaceUpdate,
)

Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=1_000_000)]
Revision = Annotated[int, Query(ge=1)]


def add_workspace_routes(app: FastAPI, get_service):
    router = APIRouter(prefix="/api/v1/workspaces", tags=["workspaces"])

    @router.post("", response_model=Workspace, status_code=201)
    async def create_workspace(payload: WorkspaceCreate):
        service = get_service()
        return await asyncio.to_thread(
            service.store.create_workspace, payload, service.clock()
        )

    @router.get("", response_model=Page[Workspace])
    async def list_workspaces(limit: Limit = 50, offset: Offset = 0):
        return await asyncio.to_thread(
            get_service().store.list_workspaces, limit, offset
        )

    @router.get("/{workspace_id}", response_model=Workspace)
    async def get_workspace(workspace_id: UUID):
        return await asyncio.to_thread(get_service().store.get_workspace, workspace_id)

    @router.patch("/{workspace_id}", response_model=Workspace)
    async def update_workspace(workspace_id: UUID, payload: WorkspaceUpdate):
        service = get_service()
        return await asyncio.to_thread(
            service.store.update_workspace, workspace_id, payload, service.clock()
        )

    @router.post(
        "/{workspace_id}/policies", response_model=PolicyRecord, status_code=201
    )
    async def create_policy(workspace_id: UUID, payload: ProgramPolicy):
        service = get_service()
        return await asyncio.to_thread(
            service.store.write_policy, workspace_id, payload, service.clock()
        )

    @router.get("/{workspace_id}/policies/{policy_id}", response_model=PolicyRecord)
    async def get_policy(workspace_id: UUID, policy_id: UUID):
        _, policy = await asyncio.to_thread(
            get_service().store.snapshot, workspace_id, policy_id
        )
        return policy

    @router.get(
        "/{workspace_id}/policies/{policy_id}/revisions/{revision}",
        response_model=PolicyRevision,
    )
    async def policy_revision(
        workspace_id: UUID, policy_id: UUID, revision: Annotated[int, Path(ge=1)]
    ):
        return await asyncio.to_thread(
            get_service().store.policy_revision, workspace_id, policy_id, revision
        )

    @router.put("/{workspace_id}/policies/{policy_id}", response_model=PolicyRecord)
    async def update_policy(
        workspace_id: UUID,
        policy_id: UUID,
        payload: ProgramPolicy,
        expected_revision: Revision,
    ):
        service = get_service()
        return await asyncio.to_thread(
            service.store.write_policy,
            workspace_id,
            payload,
            service.clock(),
            policy_id,
            expected_revision,
        )

    @router.post(
        "/{workspace_id}/policies/{policy_id}/validate", response_model=PolicyValidation
    )
    async def validate_policy(workspace_id: UUID, policy_id: UUID):
        return await asyncio.to_thread(
            get_service().validate_policy, workspace_id, policy_id
        )

    @router.post(
        "/{workspace_id}/policies/{policy_id}/preflight", response_model=Decision
    )
    async def preflight(
        workspace_id: UUID, policy_id: UUID, payload: AuthorizationRequest
    ):
        return await get_service().preflight(workspace_id, policy_id, payload)

    @router.get("/{workspace_id}/audit", response_model=Page[ScopeAuditLog])
    async def audit(workspace_id: UUID, limit: Limit = 50, offset: Offset = 0):
        return await asyncio.to_thread(
            get_service().store.audits, workspace_id, limit, offset
        )

    app.include_router(router)
