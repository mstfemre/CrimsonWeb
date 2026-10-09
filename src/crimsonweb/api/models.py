from datetime import UTC, datetime
from typing import Generic, Literal, TypeVar
from uuid import uuid4

from pydantic import BaseModel, Field

from .ai.models import AnalysisRecord


class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    engagement_id: str = Field(min_length=1, max_length=100)
    authorized: Literal[True]


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    code: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    classification: str = "configuration_observation"
    evidence: str
    recommendation: str
    reference: str = "https://owasp.org/www-project-secure-headers/"
    url: str | None = None


class TLSObservation(BaseModel):
    url: str | None = None
    verified: bool
    protocol: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_remaining: int | None = None
    issuer: str | None = None
    verification_error: str | None = None
    supported_versions_tested: bool = False


class WAFEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    scan_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: Literal["http", "normalized_json", "modsecurity_json"]
    event_type: Literal[
        "access_denied", "rate_limited", "rule_match", "waf_block", "ip_block"
    ]
    status_code: int | None = Field(default=None, ge=100, le=599)
    rule_id: str | None = Field(
        default=None, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$"
    )
    request_id: str | None = Field(default=None, max_length=128)
    retry_after_seconds: int | None = Field(default=None, ge=0)
    retry_after_valid: bool | None = None
    evidence: str
    assessment: Literal["undetermined", "candidate_false_positive"] = "undetermined"
    assessment_reason: str = (
        "Requires defense logs and analyst review; HTTP status alone is insufficient."
    )


class WAFImport(BaseModel):
    format: Literal["normalized_json", "modsecurity_json"]
    content: str = Field(min_length=1, max_length=1_048_576)
    scan_id: str | None = None
    expected_benign: bool = False
    timezone_offset_minutes: int | None = Field(default=None, ge=-840, le=840)


class ImportResult(BaseModel):
    imported: int
    duplicates: int


class FindingResult(Finding):
    scan_id: str
    target_id: str


class TargetResult(BaseModel):
    id: str
    url: str
    created_at: datetime


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class Hop(BaseModel):
    url: str
    resolved_ips: list[str]
    connected_ip: str
    status_code: int
    headers: dict[str, str]
    tls: TLSObservation | None = None


class ScanReport(BaseModel):
    id: str
    engagement_id: str
    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    status: Literal[
        "queued", "running", "completed", "blocked", "failed", "stopped"
    ] = "queued"
    scope: dict[str, list[str]]
    hops: list[Hop] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    waf_events: list[WAFEvent] = Field(default_factory=list)
    tls_failures: list[TLSObservation] = Field(default_factory=list)
    https_redirect: Literal[
        "not_applicable", "observed", "not_observed", "incomplete"
    ] = "incomplete"
    stop_reason: str | None = None
    error_category: str | None = None
    ai_analysis: AnalysisRecord | None = None
