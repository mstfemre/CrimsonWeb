import httpx

from .models import Finding


def analyze_headers(headers: httpx.Headers, https: bool) -> list[Finding]:
    findings = []
    required = {
        "content-security-policy": "Define a policy appropriate to the application's resources.",
        "x-content-type-options": "Set X-Content-Type-Options to nosniff.",
        "referrer-policy": "Set an explicit referrer policy appropriate to the application.",
    }
    if https:
        required["strict-transport-security"] = (
            "Deploy HSTS after verifying HTTPS coverage."
        )
    for name, recommendation in required.items():
        if not headers.get(name):
            findings.append(
                Finding(
                    code=f"missing_{name}",
                    severity="low",
                    evidence=f"Response does not include {name}.",
                    recommendation=recommendation,
                )
            )
    if (
        not headers.get("x-frame-options")
        and "frame-ancestors" not in headers.get("content-security-policy", "").lower()
    ):
        findings.append(
            Finding(
                code="missing_frame_policy",
                severity="low",
                evidence="No X-Frame-Options or CSP frame-ancestors observed.",
                recommendation="Configure a framing policy for sensitive pages.",
            )
        )
    if headers.get("x-content-type-options", "nosniff").lower().strip() != "nosniff":
        findings.append(
            Finding(
                code="invalid_nosniff",
                severity="low",
                evidence="X-Content-Type-Options has an unexpected value.",
                recommendation="Set the value to nosniff.",
            )
        )
    if not https:
        findings.append(
            Finding(
                code="plaintext_http",
                severity="medium",
                evidence="The analyzed response was transported over HTTP.",
                recommendation="Use HTTPS for sensitive traffic.",
            )
        )
    return findings
