"""Shared data models for CrimsonWeb."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Target:
    original: str
    address: str
    family: int = socket.AF_INET


@dataclass(slots=True)
class WebFinding:
    path: str
    status: int
    size: int
    content_type: str = ""


@dataclass(slots=True)
class WebResponse:
    url: str
    status: int
    headers: dict[str, Any]
    body: bytes
    proxy: str | None = None
    latency_ms: float = 0.0
    egress_id: str | None = None


@dataclass(slots=True)
class WebBlockEvent:
    url: str
    status: int
    reason: str
    proxy: str | None = None
    egress_id: str | None = None


@dataclass(slots=True)
class ServiceResult:
    port: int
    state: str = "open"
    service: str = "unknown"
    version: str = "unknown"
    transport: str = "tcp"
    tls: bool = False
    http_status: int | None = None
    title: str | None = None
    headers: dict[str, Any] = field(default_factory=dict)
    waf: str | None = None
    sensitive_paths: list[WebFinding] = field(default_factory=list)
    api_paths: list[WebFinding] = field(default_factory=list)
    security_headers: list[dict[str, Any]] = field(default_factory=list)
    cookie_findings: list[dict[str, Any]] = field(default_factory=list)
    cors_findings: list[dict[str, Any]] = field(default_factory=list)
    tls_certificate: dict[str, Any] = field(default_factory=dict)
    mitre_attack: list[dict[str, str]] = field(default_factory=list)
    cves: list[dict[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    os_hint: str | None = None
