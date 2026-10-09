"""Adapters reuse existing CLI helpers without inheriting their risk assumptions."""

import re

import httpx

from crimsonweb.web_checks import (
    CORS_TEST_ORIGIN,
    analyze_cookie_flags,
    analyze_security_headers,
    cors_findings_from_headers,
)

from .models import Finding


def analyze_web(headers: httpx.Headers, https: bool) -> list[Finding]:
    result = []
    # Keep Phase 1 missing-header behavior, adapt the existing HSTS analysis here.
    if https and headers.get("strict-transport-security"):
        hsts = headers["strict-transport-security"]
        existing = analyze_security_headers(dict(headers), tls=True)
        directives = [part.strip().lower() for part in hsts.split(";")]
        ages = [d for d in directives if d.startswith("max-age")]
        valid_age = len(ages) == 1 and re.fullmatch(
            r'max-age\s*=\s*(?:\d+|"\d+")', ages[0]
        )
        age = int(ages[0].split("=", 1)[1].strip().strip('"')) if valid_age else None
        if (
            age is not None
            and 0 < age < 15_552_000
            and any(
                f["name"] == "strict-transport-security"
                and f["issue"] == "short_max_age"
                for f in existing
            )
        ):
            result.append(
                Finding(
                    code="hsts_short_or_invalid",
                    severity="low",
                    evidence=f"HSTS: {hsts}",
                    recommendation="Review max-age after verifying HTTPS coverage.",
                )
            )
        if not valid_age:
            result.append(
                Finding(
                    code="hsts_invalid",
                    severity="low",
                    evidence=f"HSTS: {hsts}",
                    recommendation="Configure one valid max-age directive.",
                )
            )
        elif age == 0:
            result.append(
                Finding(
                    code="hsts_disabled",
                    severity="low",
                    evidence="HSTS max-age=0.",
                    recommendation="Enable HSTS where operationally appropriate.",
                )
            )
    for index, cookie in enumerate(headers.get_list("set-cookie"), start=1):
        flags = analyze_cookie_flags({"set-cookie-list": [cookie]}, tls=https)
        # Values and even names are omitted; only attribute evidence is retained.
        for entry in flags:
            result.append(
                Finding(
                    code="cookie_flags",
                    severity="low",
                    evidence=f"Cookie #{index}: {', '.join(entry['issues'])}. Cookie purpose unknown.",
                    recommendation="Review flags based on purpose; HttpOnly is appropriate for session cookies.",
                )
            )
        attributes = [part.strip().lower() for part in cookie.split(";")[1:]]
        same_sites = [
            part.split("=", 1)[1].strip()
            for part in attributes
            if part.startswith("samesite=")
        ]
        if same_sites and (
            len(same_sites) != 1 or same_sites[0] not in {"strict", "lax", "none"}
        ):
            result.append(
                Finding(
                    code="cookie_invalid_samesite",
                    severity="low",
                    evidence=f"Cookie #{index}: invalid or repeated SameSite attribute.",
                    recommendation="Use one valid SameSite attribute appropriate to the cookie.",
                )
            )
        if "none" in same_sites and "secure" not in attributes:
            result.append(
                Finding(
                    code="cookie_none_without_secure",
                    severity="low",
                    evidence=f"Cookie #{index}: SameSite=None without Secure.",
                    recommendation="Set Secure for cookies using SameSite=None.",
                )
            )
    origin = headers.get("access-control-allow-origin", "").strip()
    credentials = headers.get("access-control-allow-credentials") == "true"
    candidates = cors_findings_from_headers(dict(headers))
    if candidates and origin == "*":
        # Public resources can legitimately allow *. Browsers reject * plus credentials.
        result.append(
            Finding(
                code="cors_wildcard_credentials" if credentials else "cors_public",
                severity="low" if credentials else "info",
                evidence=f"Access-Control-Allow-Origin=*; credentials={credentials}.",
                recommendation="Review resource sensitivity; wildcard with credentials is rejected by browsers.",
            )
        )
    elif candidates or origin == "null":
        result.append(
            Finding(
                code="cors_untrusted_origin",
                severity="medium" if credentials else "low",
                evidence=f"ACAO={origin}; credentials={credentials}; test Origin={CORS_TEST_ORIGIN}.",
                recommendation="Verify whether this resource requires access by the observed origin.",
            )
        )
    if (
        origin
        and origin != "*"
        and "origin"
        not in {v.strip().lower() for v in headers.get("vary", "").split(",")}
    ):
        result.append(
            Finding(
                code="cors_vary_origin",
                severity="low",
                evidence="Specific ACAO without Vary: Origin; dynamic behavior not confirmed.",
                recommendation="Use Vary: Origin if ACAO changes based on the request origin.",
            )
        )
    return result
