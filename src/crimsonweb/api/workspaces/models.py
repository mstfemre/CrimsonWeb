"""Bounded authorization contracts. Empty allowlists authorize nothing."""

import ipaddress
import re
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ProgramType = Literal["owned", "authorized_pentest", "bug_bounty", "lab"]
Category = Literal["web_observation", "crawl", "xss", "sqli", "auth", "waf", "tls"]
Method = Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


def domain_name(value: str) -> str:
    value = value.lower()
    if len(value) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise ValueError("Invalid ASCII domain; use its IDNA form")
    if any(
        len(p) > 63 or p.startswith("-") or p.endswith("-") or not p
        for p in value.split(".")
    ):
        raise ValueError("Invalid domain label")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("IP literals belong in allowed_networks")


def path_rule(value: str) -> str:
    path = value.removesuffix("/*")
    path = path or "/"
    if (
        len(value) > 2048
        or not path.startswith("/")
        or any(c in value for c in "%?#\\")
        or "*" in path
        or "//" in path
        or any(p in {".", ".."} for p in path.split("/"))
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
    ):
        raise ValueError("Invalid path rule")
    return value


class WorkspaceCreate(Contract):
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=2000)
    program_type: ProgramType
    active: bool = Field(default=True, strict=True)

    @field_validator("name")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Name cannot be blank")
        return value.strip()


class WorkspaceUpdate(Contract):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=2000)
    active: bool | None = Field(default=None, strict=True)

    @model_validator(mode="after")
    def nonnull(self):
        if (
            not self.model_fields_set
            or any(getattr(self, k) is None for k in self.model_fields_set)
            or (self.name is not None and not self.name.strip())
        ):
            raise ValueError("Non-null update fields required")
        return self


class Workspace(WorkspaceCreate):
    id: UUID
    created_at: datetime
    updated_at: datetime


class TargetScope(Contract):
    allowed_domains: list[str] = Field(default_factory=list, max_length=100)
    allowed_networks: list[str] = Field(default_factory=list, max_length=100)
    allowed_paths: list[str] = Field(default_factory=list, max_length=100)
    forbidden_paths: list[str] = Field(default_factory=list, max_length=100)
    allowed_methods: list[Method] = Field(default_factory=list, max_length=7)
    allowed_ports: list[int] = Field(default_factory=list, max_length=100)
    allowed_categories: list[Category] = Field(default_factory=list, max_length=7)
    forbidden_categories: list[Category] = Field(default_factory=list, max_length=7)
    allow_private_networks: bool = Field(default=False, strict=True)

    @field_validator("allowed_domains")
    @classmethod
    def domains(cls, values):
        result = []
        for value in values:
            wildcard = value.startswith("*.")
            name = domain_name(value[2:] if wildcard else value)
            if wildcard and name.count(".") < 1:
                raise ValueError("Wildcard requires a full domain suffix")
            result.append(("*." if wildcard else "") + name)
        return sorted(set(result))

    @field_validator("allowed_networks")
    @classmethod
    def networks(cls, values):
        return sorted({str(ipaddress.ip_network(v, strict=True)) for v in values})

    @field_validator("allowed_paths", "forbidden_paths")
    @classmethod
    def paths(cls, values):
        return sorted({path_rule(v) for v in values})

    @field_validator("allowed_ports")
    @classmethod
    def ports(cls, values):
        if any(p < 1 or p > 65535 for p in values):
            raise ValueError("Port outside valid range")
        return sorted(set(values))


class ProgramPolicy(Contract):
    target_scope: TargetScope = Field(default_factory=TargetScope)
    rate_limit_per_minute: int = Field(default=1, ge=1, le=6000)
    maximum_concurrency: int = Field(default=1, ge=1, le=16)
    maximum_request_budget: int = Field(default=0, ge=0, le=1_000_000)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    test_window_start: datetime | None = None
    test_window_end: datetime | None = None
    operator_approved: bool = Field(default=False, strict=True)
    approved_by: str = Field(default="", max_length=100)
    scope_source: str = Field(default="", max_length=2000)

    @field_validator(
        "valid_from", "valid_until", "test_window_start", "test_window_end"
    )
    @classmethod
    def aware(cls, value):
        if value is not None and value.utcoffset() is None:
            raise ValueError("Timezone required")
        return value

    @model_validator(mode="after")
    def intervals(self):
        if self.valid_from and self.valid_until and self.valid_from >= self.valid_until:
            raise ValueError("Invalid validity interval")
        if bool(self.test_window_start) != bool(self.test_window_end):
            raise ValueError("Both test window boundaries required")
        if self.test_window_start and self.test_window_start >= self.test_window_end:
            raise ValueError("Invalid test window")
        if self.operator_approved and (
            not self.approved_by.strip() or not self.scope_source.strip()
        ):
            raise ValueError("Approval identity and scope source required")
        return self


class PolicyRecord(ProgramPolicy):
    id: UUID
    workspace_id: UUID
    revision: int
    used_requests: int
    halted_reason: str | None
    created_at: datetime
    updated_at: datetime


class PolicyRevision(Contract):
    workspace_id: UUID
    policy_id: UUID
    revision: int
    created_at: datetime
    policy: ProgramPolicy


class AuthorizationRequest(Contract):
    url: str = Field(min_length=1, max_length=2048, repr=False)
    method: Method = "GET"
    category: Category = "web_observation"


class Decision(Contract):
    allowed: bool
    reason: str
    policy_revision: int | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    cnames: list[str] = Field(default_factory=list)


class PolicyValidation(Contract):
    valid: bool
    reasons: list[str]


class ScopeAuditLog(Contract):
    id: UUID
    workspace_id: UUID
    policy_id: UUID | None
    policy_revision: int | None
    timestamp: datetime
    action: str
    allowed: bool
    reason: str
    request_fingerprint: str | None = None
    resolved_ips: list[str] = Field(default_factory=list)
