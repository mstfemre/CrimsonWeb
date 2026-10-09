import ipaddress
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, TypeAdapter, field_validator, model_validator

from ..discovery.urls import active_url
from ..workspaces.models import Contract, ProgramPolicy

AssessmentStatus = Literal[
    "secure_observed",
    "leak_suspected",
    "leak_validated",
    "inconclusive",
    "not_tested",
    "blocked_by_policy",
]
TestKind = Literal["egress", "dns", "ipv6"]
Family = Literal["ipv4", "ipv6"]
Expectation = Literal["expected", "forbidden", "unspecified"]


class LoggingSettings(Contract):
    mask_ip_literals: Literal[True] = True
    store_raw_payloads: Literal[False] = False
    retention_days: int = Field(default=7, ge=1, le=90, strict=True)
    retention_enforced: Literal[False] = False


class DNSExpectations(Contract):
    approved_resolvers: list[str] = Field(
        default_factory=list, max_length=16, repr=False
    )
    path: Literal["application", "system", "proxy", "unspecified"] = "unspecified"

    @field_validator("approved_resolvers")
    @classmethod
    def addresses(cls, values):
        return sorted({str(ipaddress.ip_address(v)) for v in values})


class PrivacyProfileInput(Contract):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    active: bool = Field(default=True, strict=True)
    mode: Literal["direct_observation", "managed_egress"] = "direct_observation"
    allowed_network_interfaces: list[str] = Field(default_factory=list, max_length=16)
    ipv4_expectation: Expectation = "unspecified"
    ipv6_expectation: Expectation = "unspecified"
    approved_egress_identity: list[str] = Field(
        default_factory=list, max_length=16, repr=False
    )
    dns_expectations: DNSExpectations = Field(default_factory=DNSExpectations)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)

    @field_validator("approved_egress_identity")
    @classmethod
    def identities(cls, values):
        return DNSExpectations.addresses(values)

    @field_validator("allowed_network_interfaces")
    @classmethod
    def interfaces(cls, values):
        import re

        if any(not re.fullmatch(r"[A-Za-z0-9 _.-]{1,80}", v) for v in values):
            raise ValueError("Invalid interface label")
        return sorted(set(values))


class PrivacyProfile(Contract):
    id: UUID
    workspace_id: UUID
    revision: int
    name: str
    active: bool
    mode: Literal["direct_observation", "managed_egress"]
    allowed_network_interfaces: list[str]
    ipv4_expectation: Expectation
    ipv6_expectation: Expectation
    approved_egress_identity: dict[Family, list[str]]
    dns_expectations: dict
    logging: LoggingSettings
    created_at: datetime
    updated_at: datetime


class PrivacyPolicy(Contract):
    verification_urls: list[str] = Field(
        default_factory=list, max_length=16, repr=False
    )
    allowed_tests: list[TestKind] = Field(default_factory=list, max_length=3)
    operator_approved: bool = Field(default=False, strict=True)
    valid_until: datetime | None = None
    maximum_observations: int = Field(default=0, ge=0, le=10000, strict=True)
    rate_limit_per_minute: int = Field(default=1, ge=1, le=60, strict=True)
    maximum_concurrency: Literal[1] = 1
    allow_ipv6_probe: bool = Field(default=False, strict=True)

    @field_validator("verification_urls")
    @classmethod
    def urls(cls, values):
        if any("#" in v for v in values):
            raise ValueError("Fragments not accepted")
        return sorted({str(active_url(v)) for v in values})

    @field_validator("valid_until")
    @classmethod
    def aware(cls, value):
        return ProgramPolicy.aware(value)


class PrivacyPolicyRecord(PrivacyPolicy):
    id: UUID
    workspace_id: UUID
    profile_id: UUID
    revision: int
    used_observations: int
    updated_at: datetime


class DiagnosticRequest(Contract):
    kind: TestKind
    program_policy_id: UUID | None = None
    verification_url: str | None = Field(default=None, max_length=2048, repr=False)
    family: Literal["ipv4", "ipv6", "any"] = "any"

    @model_validator(mode="after")
    def network_contract(self):
        if self.kind != "ipv6" and not self.verification_url:
            raise ValueError("Verification URL required")
        if self.verification_url and not self.program_policy_id:
            raise ValueError("Program policy required")
        if self.verification_url:
            if "#" in self.verification_url:
                raise ValueError("Fragments not accepted")
            self.verification_url = str(active_url(self.verification_url))
        return self


class PrivacyPreflight(Contract):
    allowed: bool
    reason: str
    profile_revision: int
    privacy_policy_revision: int
    program_policy_revision: int | None = None
    network_performed: Literal[False] = False
    advisory_only: Literal[True] = True


class EvidenceBase(Contract):
    id: UUID
    ref: str
    workspace_id: UUID
    profile_id: UUID
    assessment_id: UUID
    timestamp: datetime
    status: AssessmentStatus
    reason: str


class EgressObservation(EvidenceBase):
    kind: Literal["egress"] = "egress"
    requested_family: Literal["ipv4", "ipv6", "any"]
    connection_family: Family | None = None
    reported_ip_family: Family | None = None
    reported_identity_fingerprint: str | None = None
    identity_matches: bool | None = None
    echo_trust: Literal["untrusted"] = "untrusted"
    http_status: int | None = None
    interface_verified: Literal[False] = False
    route_verified: Literal[False] = False


class DNSObservation(EvidenceBase):
    kind: Literal["dns"] = "dns"
    configuration_source: Literal[
        "os_configured_application", "provider_reported", "unknown"
    ] = "unknown"
    resolver_fingerprints: list[str] = Field(default_factory=list, max_length=16)
    observed_resolver_fingerprints: list[str] = Field(
        default_factory=list, max_length=16
    )
    path_observation_source: Literal["unobserved", "controlled_packet_capture"] = (
        "unobserved"
    )
    configured_resolver_matches: bool | None = None
    observed_path_matches: bool | None = None
    path_observed: bool = False
    ipv4_answer_count: int = 0
    ipv6_answer_count: int = 0
    cname_count: int = 0
    application_resolution_tested: bool = False
    system_resolution_tested: Literal[False] = False
    proxy_dns_tested: Literal[False] = False


class IPv6Observation(EvidenceBase):
    kind: Literal["ipv6"] = "ipv6"
    platform_has_ipv6: bool
    loopback_socket_available: bool | None
    egress_tested: Literal[False] = False


class PolicyObservation(EvidenceBase):
    kind: Literal["policy_decision"] = "policy_decision"
    allowed: Literal[False] = False


PrivacyEvidence = Annotated[
    EgressObservation | DNSObservation | IPv6Observation | PolicyObservation,
    Field(discriminator="kind"),
]
EVIDENCE_ADAPTER = TypeAdapter(PrivacyEvidence)


class NetworkLeakFinding(Contract):
    id: UUID
    workspace_id: UUID
    profile_id: UUID
    assessment_id: UUID
    status: AssessmentStatus
    code: str
    evidence_refs: list[str] = Field(min_length=1, max_length=4)


class PrivacyAssessment(Contract):
    id: UUID
    workspace_id: UUID
    profile_id: UUID
    program_policy_id: UUID | None
    kind: TestKind
    execution_status: Literal["queued", "running", "completed", "cancelled", "failed"]
    status: AssessmentStatus = "not_tested"
    reason: str | None = None
    cancel_requested: bool
    requests_made: int
    profile_revision: int
    privacy_policy_revision: int
    program_policy_revision: int | None
    created_at: datetime
    finished_at: datetime | None = None
    expires_at: datetime
    evidence_refs: list[str] = Field(default_factory=list, max_length=4)
    finding_ids: list[UUID] = Field(default_factory=list, max_length=4)
    anonymity_guaranteed: Literal[False] = False
    retention_enforced: Literal[False] = False


class PrivacyAuditLog(Contract):
    id: UUID
    workspace_id: UUID
    profile_id: UUID
    assessment_id: UUID | None
    test_category: str
    timestamp: datetime
    policy_decision: str
    safe_summary: str
    evidence_ref: str | None
