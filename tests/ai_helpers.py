import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from crimsonweb.api.ai.models import ProviderStatus, Usage
from crimsonweb.api.ai.provider import ProviderReply
from crimsonweb.api.database import Repository
from crimsonweb.api.models import Finding, Hop, ScanReport, TLSObservation, WAFEvent


def seeded_repository(url="sqlite://"):
    repo = Repository(url)
    repo.initialize()
    report = ScanReport(
        id=str(uuid4()),
        engagement_id="ai-test-lab",
        target="https://localhost/",
        status="completed",
        finished_at=datetime.now(UTC),
        scope={"hosts": ["localhost"], "networks": ["127.0.0.0/8"]},
        findings=[
            Finding(
                code="missing_referrer-policy",
                severity="low",
                evidence="Referrer policy absent.",
                recommendation="Review privacy policy.",
            ),
            Finding(
                code="tls_expiry_soon",
                severity="medium",
                evidence="Certificate expires in 10 days.",
                recommendation="Renew certificate.",
            ),
        ],
        hops=[
            Hop(
                url="https://localhost/",
                resolved_ips=["127.0.0.1"],
                connected_ip="127.0.0.1",
                status_code=200,
                headers={},
                tls=TLSObservation(
                    verified=True,
                    protocol="TLSv1.3",
                    not_after=datetime.now(UTC) + timedelta(days=10),
                    days_remaining=10,
                ),
            )
        ],
    )
    report.waf_events.append(
        WAFEvent(
            scan_id=report.id,
            source="http",
            event_type="rate_limited",
            status_code=429,
            retry_after_seconds=60,
            retry_after_valid=True,
            evidence="HTTP 429; no retry made.",
        )
    )
    repo.save(report)
    return repo, report


def valid_output(data):
    refs = [item["ref"] for item in data["untrusted_evidence"]]
    language = data["language"]
    explanation = (
        "Review the observed configuration."
        if language == "en"
        else "Gözlenen yapılandırmayı inceleyin."
    )
    uncertainty = (
        "Application context is unknown."
        if language == "en"
        else "Uygulama bağlamı bilinmiyor."
    )

    def section(selected):
        return {
            "explanation": explanation,
            "evidence_refs": selected,
            "confidence": "low",
            "uncertainty": uncertainty,
        }

    def comment(ref):
        return {
            **section([ref]),
            "evidence_ref": ref,
            "impact": explanation,
            "false_positive": "undetermined",
            "owasp_mapping": "manual_mapping_required",
            "remediations": [explanation],
        }

    findings = [ref for ref in refs if ref.startswith("finding:")]
    waf = [ref for ref in refs if ref.startswith("waf:")]
    tls = [ref for ref in refs if ref.startswith(("tls:", "tls_failure:"))]
    return {
        "language": language,
        "executive_summary": explanation,
        "technical_findings": [comment(ref) for ref in findings],
        "waf_assessment": [comment(ref) for ref in waf],
        "risk_assessment": section(refs),
        "tls_analysis": section(tls),
        "priority_improvements": [
            {"action": explanation, "evidence_refs": [ref]} for ref in findings[:10]
        ],
        "relationships": [{"explanation": explanation, "evidence_refs": refs[:2]}]
        if len(refs) >= 2
        else [],
        "limitations": [uncertainty],
    }


class MockProvider:
    name = "mock"
    model = "test-local:latest"

    def __init__(self, transform=None, error=None, delay=0):
        self.transform = transform
        self.error = error
        self.delay = delay
        self.calls = []
        self.health_calls = 0

    async def health(self):
        self.health_calls += 1
        if self.error:
            raise self.error
        return ProviderStatus(
            provider=self.name,
            model=self.model,
            enabled=True,
            available=True,
            models=[self.model],
        )

    async def generate(self, system, evidence, schema):
        import asyncio

        self.calls.append((system, evidence, schema))
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error:
            raise self.error
        output = valid_output(evidence)
        if self.transform:
            output = self.transform(output)
        if isinstance(output, dict):
            for name in ("technical_findings", "waf_assessment"):
                output[name] = {
                    comment["evidence_ref"]: {
                        key: value
                        for key, value in comment.items()
                        if key not in {"evidence_ref", "evidence_refs"}
                    }
                    for comment in output[name]
                }
        return ProviderReply(
            content=json.dumps(output, ensure_ascii=False)
            if isinstance(output, dict)
            else output,
            usage=Usage(input_tokens=120, output_tokens=150, provider_duration_ms=10),
        )
