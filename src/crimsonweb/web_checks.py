"""HTTP security header, cookie, CORS, and path check helpers."""

from __future__ import annotations

import re
from typing import Any


HTTP_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

CORS_TEST_ORIGIN = "https://crimsonweb.invalid"

SENSITIVE_PATHS = (
    "/.env", "/.git/config", "/.git/HEAD", "/robots.txt",
    "/server-status", "/server-info", "/admin", "/administrator",
    "/wp-config.php", "/config.php", "/config.json", "/.htpasswd",
    "/.well-known/security.txt", "/api/swagger.json", "/swagger.json",
    "/swagger-ui.html", "/openapi.json", "/graphql", "/graphiql",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/metrics",
    "/.DS_Store", "/phpinfo.php", "/backup.zip", "/db.sql",
)

API_DISCOVERY_PATHS = (
    "/api", "/api/", "/api/v1", "/api/v1/", "/api/v2", "/api/v2/",
    "/graphql", "/graphiql", "/swagger", "/swagger/", "/swagger-ui.html",
    "/swagger.json", "/api-docs", "/api-docs/", "/openapi.json",
    "/docs", "/redoc", "/health", "/status", "/metrics",
)


def analyze_security_headers(headers: dict[str, Any], tls: bool) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    lower = {str(k).lower(): str(v) for k, v in headers.items() if not isinstance(v, list)}
    for header in HTTP_SECURITY_HEADERS:
        value = lower.get(header)
        if value:
            continue
        if header == "strict-transport-security" and not tls:
            continue
        findings.append({
            "name": header,
            "severity": "LOW",
            "issue": "missing",
            "detail": f"{header} header not present",
        })
    xcto = lower.get("x-content-type-options", "")
    if xcto and xcto.lower() != "nosniff":
        findings.append({
            "name": "x-content-type-options",
            "severity": "LOW",
            "issue": "weak_value",
            "detail": f"expected nosniff, got {xcto}",
        })
    hsts = lower.get("strict-transport-security", "")
    if tls and hsts:
        max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
        if not max_age_match or int(max_age_match.group(1)) < 15_552_000:
            findings.append({
                "name": "strict-transport-security",
                "severity": "LOW",
                "issue": "short_max_age",
                "detail": "HSTS max-age is missing or shorter than 180 days",
            })
    return findings


def analyze_cookie_flags(headers: dict[str, Any], tls: bool) -> list[dict[str, Any]]:
    raw_values = headers.get("set-cookie-list") or headers.get("set-cookie") or headers.get("Set-Cookie") or ""
    if not raw_values:
        return []
    values = raw_values if isinstance(raw_values, list) else [str(raw_values)]
    findings: list[dict[str, Any]] = []
    for value in values:
        cookie_parts = [part.strip() for part in str(value).split(";") if part.strip()]
        if not cookie_parts:
            continue
        name = cookie_parts[0].split("=", 1)[0]
        attrs = {part.lower() for part in cookie_parts[1:]}
        issues: list[str] = []
        if "httponly" not in attrs:
            issues.append("missing HttpOnly")
        if tls and "secure" not in attrs:
            issues.append("missing Secure")
        if not any(attr.startswith("samesite") for attr in attrs):
            issues.append("missing SameSite")
        if issues:
            findings.append({
                "name": name,
                "severity": "LOW",
                "issues": issues,
            })
    return findings


def cors_findings_from_headers(headers: dict[str, Any]) -> list[dict[str, Any]]:
    lower = {str(k).lower(): str(v) for k, v in headers.items() if not isinstance(v, list)}
    acao = lower.get("access-control-allow-origin", "").strip()
    if not acao:
        return []
    allow_credentials = lower.get("access-control-allow-credentials", "").lower() == "true"
    if acao == "*" or acao == CORS_TEST_ORIGIN:
        severity = "HIGH" if allow_credentials else "MEDIUM"
        return [{
            "severity": severity,
            "allow_origin": acao,
            "allow_credentials": allow_credentials,
            "detail": "CORS policy reflects or broadly allows an untrusted Origin",
        }]
    return []
