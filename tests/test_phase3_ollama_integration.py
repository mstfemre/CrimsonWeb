"""Opt-in test only; default suite does not require Ollama or an API key."""

import asyncio
import os

import pytest
from ai_helpers import seeded_repository

from crimsonweb.api.ai.contract import output_schema
from crimsonweb.api.ai.models import AnalysisRequest
from crimsonweb.api.ai.provider import AIError, AISettings, OllamaProvider
from crimsonweb.api.ai.security import (
    build_bundle,
    language_signals,
    system_prompt,
    validate_provider_output,
)


@pytest.mark.ollama
@pytest.mark.skipif(
    os.getenv("CRIMSON_TEST_OLLAMA") != "1",
    reason="Set CRIMSON_TEST_OLLAMA=1 for a real local Ollama test",
)
@pytest.mark.parametrize("kind", ["findings", "scan", "waf"])
def test_real_local_ollama_structured_analysis(kind):
    settings = AISettings.from_env()
    provider = OllamaProvider(settings)
    repo, report = seeded_repository()
    request = AnalysisRequest(
        kind=kind,
        scan_id=report.id if kind == "scan" else None,
        finding_ids=[report.findings[0].id] if kind == "findings" else [],
        waf_event_ids=[report.waf_events[0].id] if kind == "waf" else [],
        language="tr",
    )
    bundle = build_bundle(repo, request, settings.max_input_bytes)

    async def run():
        try:
            status = await provider.health()
            assert status.available, status.error_code
            reply = await provider.generate(
                system_prompt("tr"), bundle.data, output_schema(bundle.refs, "tr")
            )
            return validate_provider_output(reply.content, bundle, "tr")
        except AIError as exc:
            # Never print raw content/prompt or ValidationError inputs.
            pytest.fail(
                f"{exc.code}; safe_diagnostics={exc.diagnostics}", pytrace=False
            )

    try:
        output = asyncio.run(run())
        actual_findings = [c.evidence_ref for c in output.technical_findings]
        actual_waf = [c.evidence_ref for c in output.waf_assessment]
        assert actual_findings == sorted(
            r for r in bundle.refs if r.startswith("finding:")
        )
        assert actual_waf == sorted(r for r in bundle.refs if r.startswith("waf:"))
        signals = language_signals(output)
        assert signals["turkish_letters"] or signals["turkish_markers"] >= 2, signals
    finally:
        repo.close()
