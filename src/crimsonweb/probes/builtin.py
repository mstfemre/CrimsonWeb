"""Built-in service fingerprint classifiers and probe payloads."""

from __future__ import annotations

import dataclasses
import re
from typing import Any

from ..formatting import format_banner_bytes
from ..models import ServiceResult
from .registry import ProbeRegistry


WAF_SIGNATURES: dict[str, tuple[str, ...]] = {
    "cloudflare": ("cf-ray", "cloudflare"),
    "aws_waf": ("x-amzn-requestid", "x-amzn-waf"),
    "akamai": ("akamai", "akamai-ghost"),
    "f5_bigip": ("bigip", "x-wa-info"),
    "sucuri": ("x-sucuri-id", "sucuri"),
    "imperva": ("incap_ses", "visid_incap"),
    "modsecurity": ("mod_security", "modsecurity", "owasp"),
    "reblaze": ("x-reblaze-protection",),
    "stackpath": ("x-sp-url", "x-sp-edge"),
    "azion": ("x-azion-", "server: azion"),
}

LOW_CONFIDENCE_PORT_HINTS: dict[int, tuple[str, str]] = {
    9929: ("nping-echo", "Nping Echo service (port heuristic)"),
    31337: ("elite", "Port-based heuristic on 31337/tcp"),
}


def default_active_probe_registry() -> ProbeRegistry:
    registry = ProbeRegistry()
    registry.register("tls_client_hello", b"\x16\x03\x01\x00\x41\x01\x00\x00\x3D\x03\x03")
    registry.register("rdp_routing_token", b"\x03\x00\x00\x13\x0E\xE0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x00\x00\x00\x00")
    registry.register("smbv2_negotiate", b"\x00\x00\x00\x54\xFE\x53\x4D\x42\x40\x00\x00\x00\x00\x00\x00\x00")
    return registry


ACTIVE_PROBE_REGISTRY = default_active_probe_registry()


def _trim_text(value: str | None, width: int) -> str:
    text = (value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def detect_waf(headers: dict[str, Any]) -> str | None:
    pairs = [f"{k}: {v}" for k, v in headers.items()]
    values = [str(value) for value in headers.values()]
    haystack = "\n".join([*headers.keys(), *values, *pairs]).lower()
    for name, signatures in WAF_SIGNATURES.items():
        if any(sig in haystack for sig in signatures):
            return name
    return None


def port_hint_result(port: int, prior: ServiceResult) -> ServiceResult | None:
    hint = LOW_CONFIDENCE_PORT_HINTS.get(port)
    if hint is None:
        return None
    service, version = hint
    notes = list(prior.notes)
    if prior.version and prior.version not in {"unknown", "open, no banner", "open, probe failed"}:
        notes.append(f"Original banner: {_trim_text(prior.version, 80)}")
    notes.append("Service name assigned by port heuristic")
    return dataclasses.replace(prior, service=service, version=version, notes=notes)


def service_result_from_greeting(port: int, greeting: bytes) -> ServiceResult | None:
    if not greeting:
        return None
    text = format_banner_bytes(greeting)
    if text.startswith("SSH-"):
        match = re.match(r"(SSH-[\d.]+-\S+)", text)
        version = match.group(1) if match else text.splitlines()[0]
        return ServiceResult(port=port, service="ssh", version=version)
    if text.startswith("220") and re.search(r"(ftp|filezilla|vsftpd|proftpd)", text, re.IGNORECASE):
        return ServiceResult(port=port, service="ftp", version=text.splitlines()[0])
    if text.startswith("220") and re.search(r"(smtp|mail|postfix|exim|sendmail)", text, re.IGNORECASE):
        return ServiceResult(port=port, service="smtp", version=text.splitlines()[0])
    if text.startswith("+OK"):
        service = "pop3" if port in {110, 995} else "imap/pop"
        return ServiceResult(port=port, service=service, version=text.splitlines()[0])
    if b"mysql_native_password" in greeting:
        printable = "".join(chr(b) for b in greeting if 32 <= b <= 126)
        match = re.search(r"(\d+\.\d+\.\d+[\w.-]*)", printable)
        version = f"MySQL {match.group(1)}" if match else "MySQL-compatible server"
        return ServiceResult(port=port, service="mysql", version=version)
    return None


def result_from_active_probe_response(port: int, probe_name: str, raw: bytes) -> ServiceResult | None:
    if not raw:
        return None
    if raw.startswith((b"\x15\x03", b"\x16\x03")):
        return ServiceResult(port=port, service="tls", version="TLS/SSL service", tls=True)
    if b"\x03\x00\x00" in raw[:8]:
        return ServiceResult(port=port, service="rdp", version="Microsoft Remote Desktop")
    if b"\xFE\x53\x4D\x42" in raw or b"\xFF\x53\x4D\x42" in raw:
        return ServiceResult(port=port, service="smb", version="Microsoft SMB service")
    version = f"{probe_name}: {format_banner_bytes(raw, max_text=72, max_hex=20)}"
    return ServiceResult(port=port, service="proprietary", version=version)
