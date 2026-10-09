"""Workspace-qualified operator API with bounded, non-echoing JSON validation."""

import asyncio
import json
from uuid import UUID

from fastapi import APIRouter, FastAPI, HTTPException, Request
from pydantic import ValidationError

from ..models import Page
from ..workspaces.routes import Limit, Offset
from ..workspaces.service import AuthorizationDenied
from ..workspaces.store import Conflict
from .models import (
    CrawlRequest,
    DiscoveryJob,
    DiscoverySummary,
    Endpoint,
    Evidence,
    JobStatus,
    OpenAPIImportRequest,
    SurfaceGraph,
)
from .openapi import DiscoveryInputError
from .summary import discovery_summary


async def bounded_payload(request, model):
    if (
        request.headers.get("content-type", "").split(";", 1)[0].lower()
        != "application/json"
    ):
        raise HTTPException(415, "JSON request required")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > 1048576:
            raise HTTPException(413, "Discovery input exceeds byte limit")
        data.extend(chunk)
    try:
        return model.model_validate(json.loads(data))
    except (ValueError, ValidationError, RecursionError):
        # Do not echo secret examples, descriptions, input URLs or document values.
        raise HTTPException(422, "Invalid discovery request") from None


def body_schema(model):
    schema = model.model_json_schema()
    definitions = schema.pop("$defs", {})

    def inline(value):
        if isinstance(value, dict):
            if "$ref" in value and value["$ref"].startswith("#/$defs/"):
                return inline(definitions[value["$ref"].removeprefix("#/$defs/")])
            return {key: inline(item) for key, item in value.items()}
        if isinstance(value, list):
            return [inline(item) for item in value]
        return value

    return {
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": inline(schema)}},
        }
    }


def add_discovery_routes(app: FastAPI, get_manager):
    router = APIRouter(
        prefix="/api/v1/workspaces/{workspace_id}/discovery", tags=["discovery"]
    )

    @router.post(
        "/jobs",
        status_code=202,
        response_model=DiscoveryJob,
        openapi_extra=body_schema(CrawlRequest),
    )
    async def crawl(workspace_id: UUID, request: Request):
        payload = await bounded_payload(request, CrawlRequest)
        try:
            return await get_manager().start_crawl(workspace_id, payload)
        except AuthorizationDenied as exc:
            raise HTTPException(403, {"reason": exc.reason}) from None
        except DiscoveryInputError as exc:
            raise HTTPException(422, {"reason": exc.code}) from None

    @router.post(
        "/openapi",
        status_code=202,
        response_model=DiscoveryJob,
        openapi_extra=body_schema(OpenAPIImportRequest),
    )
    async def import_openapi(workspace_id: UUID, request: Request):
        payload = await bounded_payload(request, OpenAPIImportRequest)
        try:
            return await get_manager().import_openapi(workspace_id, payload)
        except Conflict:
            raise
        except (DiscoveryInputError, ValueError) as exc:
            reason = (
                exc.code
                if isinstance(exc, DiscoveryInputError)
                else "invalid_openapi_origin"
            )
            raise HTTPException(422, {"reason": reason}) from None

    @router.get("/jobs", response_model=Page[DiscoveryJob])
    async def jobs(
        workspace_id: UUID,
        limit: Limit = 50,
        offset: Offset = 0,
        status: JobStatus | None = None,
    ):
        return await asyncio.to_thread(
            get_manager().store.jobs, workspace_id, limit, offset, status
        )

    @router.get("/jobs/{job_id}", response_model=DiscoveryJob)
    async def job(workspace_id: UUID, job_id: UUID):
        return await asyncio.to_thread(get_manager().store.get, workspace_id, job_id)

    @router.post("/jobs/{job_id}/cancel", response_model=DiscoveryJob)
    async def cancel(workspace_id: UUID, job_id: UUID):
        return await get_manager().cancel(workspace_id, job_id)

    @router.get("/jobs/{job_id}/endpoints", response_model=Page[Endpoint])
    async def endpoints(
        workspace_id: UUID, job_id: UUID, limit: Limit = 50, offset: Offset = 0
    ):
        return await asyncio.to_thread(
            get_manager().store.endpoints, workspace_id, job_id, limit, offset
        )

    @router.get("/jobs/{job_id}/evidence", response_model=Page[Evidence])
    async def evidence(
        workspace_id: UUID, job_id: UUID, limit: Limit = 50, offset: Offset = 0
    ):
        return await asyncio.to_thread(
            get_manager().store.evidence, workspace_id, job_id, limit, offset
        )

    @router.get("/jobs/{job_id}/graph", response_model=SurfaceGraph)
    async def graph(workspace_id: UUID, job_id: UUID):
        return await asyncio.to_thread(get_manager().store.graph, workspace_id, job_id)

    @router.get("/jobs/{job_id}/summary", response_model=DiscoverySummary)
    async def summary(workspace_id: UUID, job_id: UUID):
        return await asyncio.to_thread(
            discovery_summary, get_manager().store, workspace_id, job_id
        )

    app.include_router(router)
