"""Validated Phase 4C contracts.

Design invariants enforced here:
- Requests are read-only (catalog methods only).
- Test-identity credentials are supplied in memory at execute time, never stored:
  ``header_value`` is ``repr=False`` and appears in no persisted model.
- No raw response body or credential is ever stored (``Literal[False]`` flags).
- Imported/discovered endpoint data is untrusted and never execution authority.
"""

import re
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, TypeAdapter, field_validator, model_validator

from ..engine import AUTH_HEADER_ALLOWLIST
from ..workspaces.models import Contract, Method
from .credentials import validate_auth_header

PlanStatus = Literal[
    "awaiting_approval",
    "approved",
    "executing",
    "completed",
    "halted",
    "failed",
    "cancelled",
]
TestStatus = Literal[
    "pending", "running", "completed", "blocked_by_policy", "failed", "skipped"
]
Outcome = Literal[
    "bola_confirmed",
    "access_control_enforced",
    "owner_binding_unverified",
    "inconclusive",
    "html_injection_suspected", "sql_injection_suspected",
    "configuration_observed", "no_signal_observed",
]
Confidence = Literal["confirmed", "unverified", "inconclusive", "not_applicable"]
EvidenceStatus = Literal[
    "bola_confirmed",
    "access_control_enforced",
    "owner_binding_unverified",
    "inconclusive",
    "blocked_by_policy",
    "html_injection_suspected", "sql_injection_suspected",
    "configuration_observed", "no_signal_observed",
]
Role = Literal["identity_a", "identity_b"]
OBJECT_ID = re.compile(r"[A-Za-z0-9_.~-]{1,64}")


class VerificationTarget(Contract):
    endpoint_ref: str = Field(max_length=128)
    source: Literal["discovery", "openapi"]
    origin_ref: str = Field(default="offline", max_length=128)
    path: str = Field(max_length=2048)
    method: Method
    object_identifier_parameter: str | None = Field(default=None, max_length=64)
    potentially_sensitive_operation: bool = False
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    query_parameters: list[str] = Field(default_factory=list, max_length=16)


class PlanProposal(Contract):
    catalog_id: str = Field(max_length=64)
    target_endpoint_ref: str = Field(max_length=128)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    query_parameter: str | None = Field(default=None, max_length=64)


class VerificationPlanCreate(Contract):
    policy_id: UUID
    source: Literal["discovery", "openapi"]
    discovery_job_id: UUID | None = None
    openapi_document: dict | None = Field(default=None, repr=False)
    base_url: str | None = Field(default=None, max_length=2048, repr=False)
    catalog_ids: list[str] = Field(default_factory=lambda: ["bola_cross_owner_read"], min_length=1, max_length=4)
    max_tests: int = Field(default=50, ge=1, le=50, strict=True)
    require_model: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def source_contract(self):
        if self.source == "discovery" and self.discovery_job_id is None:
            raise ValueError("discovery source requires discovery_job_id")
        if self.source == "openapi" and not self.openapi_document:
            raise ValueError("openapi source requires openapi_document")
        return self


class VerificationPlan(Contract):
    id: UUID
    workspace_id: UUID
    policy_id: UUID
    source: Literal["discovery", "openapi"]
    status: PlanStatus
    planner: Literal["model", "operator"]
    source_discovery_job_id: UUID | None = None
    targets: list[VerificationTarget] = Field(default_factory=list, max_length=500)
    proposals: list[PlanProposal] = Field(default_factory=list, max_length=500)
    approved_by: str | None = Field(default=None, max_length=100)
    scope_source: str | None = Field(default=None, max_length=2000)
    approved_at: datetime | None = None
    approved_origin_ref: str | None = Field(default=None, max_length=128)
    approved_binding_field: str | None = Field(default=None, max_length=64)
    approved_private_records_only: bool = False
    cancel_requested: bool = False
    created_at: datetime
    updated_at: datetime
    limitations: list[str] = Field(default_factory=list, max_length=30)
    source_data_trusted: Literal[False] = False
    network_execution_from_model: Literal[False] = False
    allowed_catalog_ids: list[str] = Field(default_factory=lambda: ["bola_cross_owner_read"], max_length=4)
    max_tests: int = Field(default=50, ge=1, le=50)
    parent_plan_id: UUID | None = None
    round_number: int = Field(default=1, ge=1, le=3)
    require_model: bool = Field(default=False, strict=True)


class PlanApproval(Contract):
    approved_by: str = Field(min_length=1, max_length=100)
    scope_source: str = Field(min_length=1, max_length=2000)
    base_url: str = Field(min_length=1, max_length=2048, repr=False)
    owner_binding_field: str = Field(min_length=1, max_length=64)
    private_records_only: bool = Field(default=False, strict=True)
    read_only_operations: Literal[True] = True

    @field_validator("owner_binding_field")
    @classmethod
    def safe_field(cls, value):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value):
            raise ValueError("Unsafe response field name")
        return value

    @field_validator("approved_by", "scope_source")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Value cannot be blank")
        return value.strip()


class IdentityInput(Contract):
    role: Role
    header_name: str = Field(max_length=64)
    header_value: str = Field(min_length=1, max_length=4096, repr=False)
    owner_object_id: str = Field(max_length=64)

    @field_validator("header_name")
    @classmethod
    def allowed_header(cls, value):
        if value.lower() not in AUTH_HEADER_ALLOWLIST:
            raise ValueError("header_not_allowed")
        return value

    @field_validator("owner_object_id")
    @classmethod
    def safe_object_id(cls, value):
        if not OBJECT_ID.fullmatch(value) or value in {".", ".."}:
            raise ValueError("Unsafe object identifier")
        return value

    @model_validator(mode="after")
    def credential_contract(self):
        validate_auth_header(self.header_name, self.header_value)
        return self


class ExecuteRequest(Contract):
    base_url: str = Field(min_length=1, max_length=2048)
    owner_binding_field: str = Field(max_length=64)
    identities: list[IdentityInput] = Field(default_factory=list, max_length=2)

    @field_validator("owner_binding_field")
    @classmethod
    def safe_field(cls, value):
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value):
            raise ValueError("Unsafe response field name")
        return value

    @model_validator(mode="after")
    def distinct_roles(self):
        if not self.identities:
            return self
        roles = [identity.role for identity in self.identities]
        if set(roles) != {"identity_a", "identity_b"}:
            raise ValueError("Exactly identity_a and identity_b are required")
        object_ids = [identity.owner_object_id for identity in self.identities]
        if len(set(object_ids)) != 2:
            raise ValueError("Test identities must reference distinct objects")
        if self.identities[0].header_value == self.identities[1].header_value:
            raise ValueError("Distinct test credentials are required")
        return self


class VerificationEvidenceBase(Contract):
    id: UUID
    ref: str
    workspace_id: UUID
    plan_id: UUID
    test_id: UUID
    timestamp: datetime
    status: EvidenceStatus
    reason: str = Field(max_length=64)


class ComparativeAccessEvidence(VerificationEvidenceBase):
    kind: Literal["comparative_access"] = "comparative_access"
    catalog_id: str = Field(max_length=64)
    target_endpoint_ref: str = Field(max_length=128)
    method: Method
    control_a_status: int | None = None
    control_b_status: int | None = None
    cross_status: int | None = None
    owner_binding_match: bool | None = None
    controls_distinct: bool | None = None
    scope_decision: str = Field(max_length=64)
    identities: list[Role] = Field(default_factory=list, max_length=2)
    raw_response_stored: Literal[False] = False
    credential_stored: Literal[False] = False


class PolicyStopEvidence(VerificationEvidenceBase):
    kind: Literal["policy_stop"] = "policy_stop"
    scope_decision: str = Field(max_length=64)
    raw_response_stored: Literal[False] = False
    credential_stored: Literal[False] = False


class WebProbeEvidence(VerificationEvidenceBase):
    kind: Literal["web_probe"] = "web_probe"
    catalog_id: str
    target_endpoint_ref: str
    query_parameter: str | None = None
    response_statuses: list[int] = Field(default_factory=list, max_length=3)
    signals: list[str] = Field(default_factory=list, max_length=40)
    scope_decision: Literal["authorized"] = "authorized"
    script_execution_tested: Literal[False] = False
    database_access_proven: Literal[False] = False
    raw_response_stored: Literal[False] = False
    credential_stored: Literal[False] = False


VerificationEvidence = Annotated[
    ComparativeAccessEvidence | PolicyStopEvidence | WebProbeEvidence,
    Field(discriminator="kind"),
]
EVIDENCE_ADAPTER = TypeAdapter(VerificationEvidence)


class AccessControlFinding(Contract):
    id: UUID
    workspace_id: UUID
    plan_id: UUID
    test_id: UUID
    code: Literal["bola_confirmed"]
    confidence: Literal["confirmed"]
    status: Literal["finding"]
    category: Literal["auth"]
    target_endpoint_ref: str = Field(max_length=128)
    source_evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    observation_evidence_ref: str = Field(max_length=128)
    test_identity_roles: list[Role] = Field(min_length=1, max_length=2)
    scope_decision: str = Field(max_length=64)


class ProbeFinding(Contract):
    id: UUID
    workspace_id: UUID
    plan_id: UUID
    test_id: UUID
    code: Literal["html_injection_suspected", "sql_injection_suspected"]
    confidence: Literal["unverified"] = "unverified"
    status: Literal["candidate"] = "candidate"
    category: Literal["xss", "sqli"]
    target_endpoint_ref: str
    source_evidence_refs: list[str] = Field(max_length=20)
    observation_evidence_ref: str
    scope_decision: Literal["authorized"] = "authorized"


VerificationFinding = Annotated[AccessControlFinding | ProbeFinding, Field(discriminator="code")]
FINDING_ADAPTER = TypeAdapter(VerificationFinding)


class Top10Coverage(Contract):
    category: str
    title: str
    status: Literal["not_tested", "partially_assessed"]
    test_ids: list[UUID] = Field(default_factory=list)
    limitations: list[str]


class VerificationTest(Contract):
    id: UUID
    workspace_id: UUID
    plan_id: UUID
    catalog_id: str = Field(max_length=64)
    target_endpoint_ref: str = Field(max_length=128)
    status: TestStatus
    outcome: Outcome | None = None
    confidence: Confidence | None = None
    reason: str | None = Field(default=None, max_length=64)
    evidence_refs: list[str] = Field(default_factory=list, max_length=8)
    finding_ids: list[UUID] = Field(default_factory=list, max_length=4)


class VerificationReport(Contract):
    schema_version: Literal["verification.v1"] = "verification.v1"
    workspace_id: UUID
    plan_id: UUID
    policy_id: UUID
    status: PlanStatus
    tests: list[VerificationTest]
    findings: list[AccessControlFinding | ProbeFinding]
    evidence: list[ComparativeAccessEvidence | PolicyStopEvidence | WebProbeEvidence]
    scope_source: str | None = None
    private_records_only: bool = False
    raw_response_retained: Literal[False] = False
    credentials_retained: Literal[False] = False
    model_claims_verified: Literal[False] = False
    owasp_edition: Literal["2025"] = "2025"
    top10_coverage: list[Top10Coverage] = Field(default_factory=list, max_length=10)
