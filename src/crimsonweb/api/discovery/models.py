"""Validated discovery contracts. Sources are observations, never vulnerabilities."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import Field

from ..workspaces.models import Contract, Method

JobStatus = Literal[
    "queued",
    "running",
    "completed",
    "partially_completed",
    "cancelled",
    "failed",
    "halted_by_policy",
]


class DiscoveryLimits(Contract):
    max_depth: int = Field(default=2, ge=0, le=8)
    max_pages: int = Field(default=20, ge=1, le=200)
    max_requests: int = Field(default=40, ge=1, le=500)
    max_body_bytes: int = Field(default=262144, ge=1024, le=1048576)
    max_endpoints: int = Field(default=200, ge=1, le=500)
    max_redirects: int = Field(default=5, ge=0, le=10)


class CrawlRequest(Contract):
    policy_id: UUID
    seeds: list[str] = Field(min_length=1, max_length=16, repr=False)
    limits: DiscoveryLimits = Field(default_factory=DiscoveryLimits)


class OpenAPIImportRequest(Contract):
    document: dict = Field(repr=False)
    # A label for relative routes, never a fetch destination.
    base_url: str | None = Field(default=None, max_length=2048, repr=False)
    policy_id: UUID | None = None
    limits: DiscoveryLimits = Field(default_factory=DiscoveryLimits)


class Parameter(Contract):
    name: str = Field(max_length=64)
    location: Literal["query", "path", "form", "body", "header"]
    data_type: Literal[
        "string", "integer", "number", "boolean", "array", "object", "unknown"
    ] = "unknown"
    object_identifier_candidate: bool = False
    owner_identifier_candidate: bool = False


class Form(Contract):
    action_path: str
    method: Method
    fields: list[Parameter] = Field(default_factory=list, max_length=50)
    password_field_present: bool = False
    observation_status: Literal["candidate_only"] = "candidate_only"


class Endpoint(Contract):
    id: UUID
    origin_ref: str
    path: str = Field(max_length=2048)
    method: Method
    sources: list[Literal["html_link", "html_form", "http_response", "openapi"]]
    observation_status: Literal["candidate_only", "request_guarded"] = "candidate_only"
    status_code: int | None = None
    content_type: str | None = None
    authentication_indicators: list[str] = Field(default_factory=list, max_length=10)
    parameters: list[Parameter] = Field(default_factory=list, max_length=100)
    forms: list[Form] = Field(default_factory=list, max_length=10)
    resource_type: str | None = None
    potentially_sensitive_operation: bool = False
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class Evidence(Contract):
    id: UUID
    ref: str
    source: Literal["http_metadata", "html_structure", "openapi_structure"]
    timestamp: datetime
    source_fingerprint: str
    status_code: int | None = None
    content_type: str | None = None
    body_bytes_examined: int = 0
    # Fixed codes only, never untrusted text or header values.
    limitations: list[str] = Field(default_factory=list, max_length=20)


class Relation(Contract):
    id: UUID
    source_endpoint_id: UUID
    source_resource_id: UUID | None = None
    related_endpoint_id: UUID | None = None
    kind: Literal[
        "method",
        "authentication",
        "parameter",
        "resource",
        "potential_owner",
        "link",
        "form_action",
        "redirect",
        "evidence",
    ]
    target_label: str = Field(max_length=128)
    evidence_ref: str


class DiscoveryJob(Contract):
    id: UUID
    workspace_id: UUID
    policy_id: UUID | None
    mode: Literal["crawl", "openapi_import"]
    status: JobStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cancel_requested: bool = False
    requests_made: int = 0
    pages_processed: int = 0
    endpoints_discovered: int = 0
    stop_reason: str | None = None
    policy_revision: int | None = None
    seed_fingerprints: list[str] = Field(default_factory=list, max_length=16)
    limits: DiscoveryLimits
    limitations: list[str] = Field(default_factory=list, max_length=30)


class ResourceNode(Contract):
    id: UUID
    origin_ref: str
    name: str
    endpoint_ids: list[UUID] = Field(default_factory=list, max_length=500)
    potential_owner_identifiers: list[str] = Field(default_factory=list, max_length=100)


class SurfaceGraph(Contract):
    workspace_id: UUID
    job_id: UUID
    endpoint_nodes: list[Endpoint]
    resource_nodes: list[ResourceNode] = Field(default_factory=list)
    relations: list[Relation]
    truncated: bool = False


class DiscoverySummary(Contract):
    schema_version: Literal["discovery.v1"] = "discovery.v1"
    workspace_id: UUID
    job_id: UUID
    discovered_endpoints: list[Endpoint]
    discovered_resources: list[ResourceNode] = Field(default_factory=list)
    authentication_indicators: list[dict]
    resource_relationships: list[Relation]
    potentially_sensitive_operations: list[UUID]
    evidence_refs: list[str]
    discovery_limitations: list[str]
    untrusted_discovery_data: Literal[True] = True
    model_claims_verified: Literal[False] = False
    network_execution_permitted: Literal[False] = False
