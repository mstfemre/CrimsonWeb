"""Reproducible synthetic evidence only; no application, HTTP or target interaction."""

from datetime import UTC, datetime, timedelta

from ai_helpers import seeded_repository

from crimsonweb.api.database import Repository
from crimsonweb.api.models import Finding, ScanReport

DATASET_VERSION = "paired-models-v1"
FIXED_TIME = datetime(2026, 10, 9, tzinfo=UTC)


def identifier(number):
    return f"00000000-0000-4000-8000-{number:012d}"


def standard_repository():
    original, report = seeded_repository()
    original.close()
    report.id = identifier(1)
    report.started_at = report.finished_at = FIXED_TIME
    for index, finding in enumerate(report.findings, 2):
        finding.id = identifier(index)
    for event in report.waf_events:
        event.id, event.scan_id, event.timestamp = identifier(4), report.id, FIXED_TIME
    for hop in report.hops:
        if hop.tls:
            hop.tls.not_after = FIXED_TIME + timedelta(days=10)
    repository = Repository("sqlite://")
    repository.initialize()
    repository.save(report)
    return repository, report


API_CASES = (
    (
        "api_auth_enforced",
        "info",
        (
            "Synthetic read endpoint: request without a bearer credential returned HTTP 401; "
            "request with an invalid credential returned HTTP 401; valid principal A returned HTTP 200. "
            "No unauthorized object data was returned. Only this endpoint and these reads were observed; "
            "other endpoints and write methods were not tested."
        ),
        "Preserve the observed authentication control and review endpoint coverage.",
    ),
    (
        "api_cross_tenant_read_observed",
        "high",
        (
            "Isolated deliberately vulnerable sample, synthetic recorded read: authenticated principal A "
            "belongs to tenant A, requested an object whose recorded owner is tenant B. "
            "HTTP 200 returned that tenant-B object's synthetic data and owner marker; "
            "the lab access policy says principal A has no tenant-B permission. "
            "An unauthorized cross-tenant read is present in these supplied records. "
            "No write, deletion, privilege escalation or additional endpoint result is supplied."
        ),
        "Evaluate object ownership and tenant authorization for every read; add regression checks.",
    ),
    (
        "api_cross_tenant_read_denied",
        "info",
        (
            "Isolated protected sample: authenticated principal A in tenant A requested a tenant-B object. "
            "HTTP 403 returned no object data. Owner-matched principal B returned HTTP 200. "
            "The supplied paired observations show this read was denied across tenants. "
            "There is no WAF or IDS rule evidence; 403 alone cannot identify a WAF block."
        ),
        "Preserve the observed object authorization and inspect broader coverage independently.",
    ),
    (
        "api_http200_error_envelope",
        "low",
        (
            "Synthetic read returned HTTP 200 but the application envelope had success=false, "
            "error=forbidden and data=null. No object or secret data is supplied. "
            "The object's owner and requesting principal permissions were not recorded. "
            "HTTP status alone does not establish an IDOR/BOLA data disclosure; authorization coverage is unknown."
        ),
        "Review consistent HTTP error semantics; obtain ownership and data-access evidence before a BOLA conclusion.",
    ),
)


def api_repository():
    repository = Repository("sqlite://")
    repository.initialize()
    report = ScanReport(
        id=identifier(100),
        engagement_id="synthetic-api-analysis-only",
        target="https://localhost/",
        scope={"hosts": ["localhost"], "networks": ["127.0.0.0/8"]},
        status="completed",
        started_at=FIXED_TIME,
        finished_at=FIXED_TIME,
        findings=[
            Finding(
                id=identifier(index),
                code=code,
                severity=severity,
                classification="synthetic_record_observation",
                evidence=evidence,
                recommendation=recommendation,
                reference="OWASP API Security: object authorization",
            )
            for index, (code, severity, evidence, recommendation) in enumerate(
                API_CASES, 101
            )
        ],
    )
    repository.save(report)
    return repository, report
