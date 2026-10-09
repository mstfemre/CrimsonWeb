"""Inspect the already verified HTTP connection; do not add TLS probes after a block."""

import ssl
from datetime import UTC, datetime

import httpx

from .models import Finding, TLSObservation


def inspect_tls(response: httpx.Response) -> TLSObservation | None:
    stream = response.extensions.get("network_stream")
    ssl_object = stream.get_extra_info("ssl_object") if stream is not None else None
    if ssl_object is None:
        return None  # Mock transport or metadata unavailable: no verification claim.
    cert = ssl_object.getpeercert()

    def date(key: str) -> datetime | None:
        value = cert.get(key)
        return (
            datetime.fromtimestamp(ssl.cert_time_to_seconds(value), UTC)
            if value
            else None
        )

    not_after = date("notAfter")
    return TLSObservation(
        verified=True,
        protocol=ssl_object.version(),
        not_before=date("notBefore"),
        not_after=not_after,
        days_remaining=int((not_after - datetime.now(UTC)).total_seconds() // 86400)
        if not_after
        else None,
        issuer=next(
            (
                value
                for group in cert.get("issuer", ())
                for key, value in group
                if key == "commonName"
            ),
            None,
        ),
    )


def verification_failure(exc: BaseException) -> ssl.SSLCertVerificationError | None:
    seen = set()
    while exc is not None and id(exc) not in seen:
        if isinstance(exc, ssl.SSLCertVerificationError):
            return exc
        seen.add(id(exc))
        exc = exc.__cause__ or exc.__context__
    return None


def tls_findings(observation: TLSObservation) -> list[Finding]:
    result = []
    if not observation.verified:
        result.append(
            Finding(
                code="tls_verification_failed",
                severity="medium",
                evidence=f"TLS verification failed: {observation.verification_error}",
                recommendation="Check trust chain, hostname and certificate validity.",
            )
        )
        return result
    if observation.days_remaining is not None and observation.days_remaining <= 30:
        result.append(
            Finding(
                code="tls_expiry_soon",
                severity="low",
                evidence=f"Verified certificate expires at {observation.not_after}; "
                f"days_remaining={observation.days_remaining}.",
                recommendation="Renew the certificate before expiry.",
            )
        )
    if observation.protocol in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
        result.append(
            Finding(
                code="tls_legacy_negotiated",
                severity="medium",
                evidence=f"Observed negotiated protocol: {observation.protocol}.",
                recommendation="Use TLS 1.2 or newer; assess server policy separately.",
            )
        )
    return result
