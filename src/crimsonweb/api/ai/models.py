from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

Language = Literal["tr", "en"]
Kind = Literal["scan", "findings", "waf"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AnalysisRequest(StrictModel):
    kind: Kind = "scan"
    scan_id: str | None = Field(default=None, min_length=1, max_length=36)
    finding_ids: list[str] = Field(default_factory=list, max_length=100)
    waf_event_ids: list[str] = Field(default_factory=list, max_length=100)
    language: Language = "tr"

    @model_validator(mode="after")
    def selection(self) -> "AnalysisRequest":
        if self.kind == "scan" and (
            not self.scan_id or self.finding_ids or self.waf_event_ids
        ):
            raise ValueError("Scan analysis requires only scan_id")
        if self.kind == "findings" and (not self.finding_ids or self.waf_event_ids):
            raise ValueError("Finding analysis requires finding_ids only")
        if self.kind == "waf" and (not self.waf_event_ids or self.finding_ids):
            raise ValueError("WAF analysis requires waf_event_ids only")
        for ids in (self.finding_ids, self.waf_event_ids):
            if len(ids) != len(set(ids)) or any(
                not 1 <= len(value) <= 36 for value in ids
            ):
                raise ValueError("IDs must be unique and at most 36 characters")
        return self


class SectionBody(StrictModel):
    explanation: str = Field(min_length=1, max_length=2500)
    confidence: Literal["low", "medium", "high"]
    uncertainty: str = Field(min_length=1, max_length=1000)


class Section(SectionBody):
    evidence_refs: list[str] = Field(max_length=100)


class CommentBody(SectionBody):
    impact: str = Field(min_length=1, max_length=1500)
    false_positive: Literal["possible", "undetermined", "unlikely"]
    owasp_mapping: Literal[
        "OWASP Secure Headers", "OWASP ASVS", "manual_mapping_required"
    ]
    remediations: list[str] = Field(min_length=1, max_length=8)


class Comment(CommentBody):
    evidence_ref: str = Field(min_length=1, max_length=80)
    evidence_refs: list[str] = Field(max_length=100)


class Improvement(StrictModel):
    action: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(min_length=1, max_length=100)


class Relationship(StrictModel):
    explanation: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(min_length=2, max_length=100)


class AnalystOutput(StrictModel):
    language: Language
    executive_summary: str = Field(min_length=1, max_length=2500)
    technical_findings: list[Comment] = Field(max_length=100)
    risk_assessment: Section
    tls_analysis: Section
    waf_assessment: list[Comment] = Field(max_length=100)
    priority_improvements: list[Improvement] = Field(max_length=20)
    relationships: list[Relationship] = Field(max_length=20)
    limitations: list[str] = Field(min_length=1, max_length=10)


class Priority(StrictModel):
    evidence_ref: str
    technical_severity: Severity
    rank: int
    basis: str = "Technical severity from persisted evidence; AI cannot alter it."


class Usage(StrictModel):
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    provider_duration_ms: int | None = Field(default=None, ge=0)


class AnalysisRecord(StrictModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    scan_id: str | None = None
    kind: Kind
    language: Language
    provider: str
    model: str
    status: Literal["queued", "running", "completed", "failed", "stopped"] = "queued"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
    evidence_refs: list[str]
    input_digest: str
    safety_notes: list[str] = Field(default_factory=list)
    priorities: list[Priority] = Field(default_factory=list)
    output: AnalystOutput | None = None
    usage: Usage = Field(default_factory=Usage)
    error_code: str | None = None
    interpretation_only: Literal[True] = True
    model_claims_verified: Literal[False] = False
    stale: bool = False


class ProviderStatus(StrictModel):
    provider: str
    enabled: bool
    available: bool = False
    model: str
    models: list[str] = Field(default_factory=list, max_length=100)
    error_code: str | None = None
