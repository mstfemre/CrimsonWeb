"""Opt-in API/IDOR/BOLA evidence interpretation, never an active API security test."""

import asyncio
import os

import pytest
from model_comparison_data import api_repository

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
    os.getenv("CRIMSON_TEST_OLLAMA") != "1", reason="Opt-in local Ollama benchmark"
)
@pytest.mark.parametrize("kind", ["api_bola"])
def test_real_api_authorization_evidence_analysis(kind):
    settings = AISettings.from_env()
    provider = OllamaProvider(settings)
    repository, report = api_repository()
    bundle = build_bundle(
        repository,
        AnalysisRequest(kind="scan", scan_id=report.id, language="tr"),
        settings.max_input_bytes,
    )

    async def run():
        try:
            status = await provider.health()
            assert status.available, status.error_code
            reply = await provider.generate(
                system_prompt("tr"), bundle.data, output_schema(bundle.refs, "tr")
            )
            return validate_provider_output(reply.content, bundle, "tr")
        except AIError as exc:
            pytest.fail(
                f"{exc.code}; safe_diagnostics={exc.diagnostics}", pytrace=False
            )

    try:
        output = asyncio.run(run())
        assert [item.evidence_ref for item in output.technical_findings] == sorted(
            r for r in bundle.refs if r.startswith("finding:")
        )
        assert not output.waf_assessment and not output.tls_analysis.evidence_refs
        signals = language_signals(output)
        assert signals["turkish_letters"] or signals["turkish_markers"] >= 2, signals
        # These are schema/reference/language checks, not an automated semantic verdict.
        # The report separately reviews claims against the predefined synthetic truth.
    finally:
        repository.close()
