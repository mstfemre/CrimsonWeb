"""Opt-in local model planning against synthetic endpoint references only."""

import asyncio
import os

import pytest

from crimsonweb.api.ai.provider import AISettings, OllamaProvider, ProviderGate
from crimsonweb.api.verification.models import VerificationTarget
from crimsonweb.api.verification.planner import generate_proposals


@pytest.mark.ollama
@pytest.mark.skipif(os.getenv("CRIMSON_TEST_OLLAMA") != "1",
                    reason="Set CRIMSON_TEST_OLLAMA=1 for local Ollama integration")
def test_real_local_ollama_verification_plan():
    settings = AISettings.from_env()
    provider = OllamaProvider(settings)
    target = VerificationTarget(
        endpoint_ref="endpoint:synthetic-1", source="openapi",
        path="/api/objects/{object_id}", method="GET",
        object_identifier_parameter="object_id", evidence_refs=["openapi:synthetic-1"],
    )

    async def scenario():
        gate = ProviderGate(settings)
        status = await gate.call(provider.health)
        assert status.available, status.error_code
        return await generate_proposals(provider, [target], gate, settings.max_input_bytes)

    proposals = asyncio.run(scenario())
    # Empty output is valid JSON but fails this integration's planning expectation.
    assert len(proposals) == 1
    assert proposals[0].catalog_id == "bola_cross_owner_read"
    assert proposals[0].target_endpoint_ref == target.endpoint_ref
    assert proposals[0].evidence_refs == target.evidence_refs
