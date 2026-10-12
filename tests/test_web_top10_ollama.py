"""Opt-in local model catalog selection; never sends target requests."""

import asyncio
import os
from time import perf_counter

import pytest
from test_web_top10 import approve, configuration, execute_payload, lab, payload
from verification_helpers import setup

from crimsonweb.api.ai.provider import AISettings, OllamaProvider, ProviderGate
from crimsonweb.api.verification.models import VerificationTarget
from crimsonweb.api.verification.planner import generate_proposals
from crimsonweb.api.workspaces.store import Conflict


@pytest.mark.ollama
@pytest.mark.skipif(os.getenv("CRIMSON_TEST_OLLAMA") != "1", reason="Enable explicit local Ollama integration")
@pytest.mark.parametrize("tool", ["sql_error_probe", "xss_reflection_probe"])
def test_local_model_binds_injection_test_to_known_query_parameter(tool):
    settings = AISettings.from_env()
    provider, gate = OllamaProvider(settings), ProviderGate(settings)
    target = VerificationTarget(endpoint_ref="endpoint:synthetic-search", source="openapi",
                                path="/search", method="GET", query_parameters=["q"],
                                evidence_refs=["openapi:synthetic"])

    async def scenario():
        assert (await gate.call(provider.health)).available
        return await generate_proposals(provider, [target], gate, settings.max_input_bytes,
                                        allowed_catalog_ids=[tool])

    proposals = asyncio.run(scenario())
    assert len(proposals) == 1
    assert proposals[0].catalog_id == tool
    assert proposals[0].target_endpoint_ref == target.endpoint_ref
    assert proposals[0].query_parameter == "q"
    assert proposals[0].evidence_refs == target.evidence_refs


@pytest.mark.ollama
@pytest.mark.skipif(os.getenv("CRIMSON_TEST_OLLAMA") != "1", reason="Enable explicit local Ollama integration")
def test_real_model_drives_three_approved_rounds_against_synthetic_transport(record_property):
    """Real model decisions, mock target responses; fallback is never a model pass."""
    settings = AISettings.from_env()
    provider, gate = OllamaProvider(settings), ProviderGate(settings)
    calls, diagnostics = [], []
    sql_handler = lab("sql", calls)
    html_handler = lab("html", calls)

    def handler(request):
        # Fixed synthetic error for the quote; inert HTML reflection otherwise.
        return sql_handler(request) if request.url.params.get("q") == "1'" else html_handler(request)

    class ObservedProvider:
        async def generate(self, system, evidence, schema):
            # Assert privacy in memory, retain only counters/timing in the report.
            assert "SYNTHETIC_RESPONSE_SECRET" not in str(evidence)
            assert "<cw-probe" not in str(evidence)
            for observation in evidence["prior_observations"]:
                assert set(observation) == {"catalog_id", "endpoint_ref", "outcome", "confidence"}
            started = perf_counter()
            reply = await provider.generate(system, evidence, schema)
            diagnostics.append({"seconds": round(perf_counter() - started, 3),
                                "prior_observations": len(evidence["prior_observations"])})
            return reply

    repo, _, ws, pid, manager = setup(handler, configuration=configuration())
    manager.provider, manager.provider_gate = ObservedProvider(), gate

    async def scenario():
        assert (await gate.call(provider.health)).available
        request = payload(pid, [
            "sql_error_probe", "xss_reflection_probe", "web_security_observation",
        ], max_tests=1).model_copy(update={"require_model": True})
        plan = await manager.create_plan(ws.id, request)
        executed, outcomes = set(), set()
        for expected_round in (1, 2, 3):
            assert plan.planner == "model", "Operator fallback is not a successful real-model test"
            assert plan.require_model
            assert len(plan.proposals) == 1 and plan.round_number == expected_round
            assert plan.status == "awaiting_approval"
            proposal = plan.proposals[0]
            target = next(t for t in plan.targets if t.endpoint_ref == proposal.target_endpoint_ref)
            assert set(proposal.evidence_refs) <= set(target.evidence_refs)
            assert proposal.catalog_id not in executed
            before = len(calls)
            with pytest.raises(Conflict, match="approved"):
                await manager.execute_plan(ws.id, plan.id, execute_payload())
            assert len(calls) == before
            approve(manager, ws, plan)
            result = await manager.execute_plan(ws.id, plan.id, execute_payload())
            assert result.status == "completed"
            report = manager.store.report(ws.id, plan.id)
            executed.add(proposal.catalog_id)
            outcomes.add(report.tests[0].outcome)
            assert "SYNTHETIC_RESPONSE_SECRET" not in report.model_dump_json()
            for finding in report.findings:
                assert finding.confidence == "unverified" and finding.status == "candidate"
                assert finding.observation_evidence_ref in {e.ref for e in report.evidence}
            if expected_round < 3:
                plan = await manager.next_plan(ws.id, plan.id)
        assert outcomes == {"sql_injection_suspected", "html_injection_suspected", "configuration_observed"}
        assert len(calls) == 6 and len(diagnostics) == 3
        assert sorted(d["prior_observations"] for d in diagnostics) == [0, 1, 2]
        with pytest.raises(Conflict, match="round"):
            await manager.next_plan(ws.id, plan.id)

    try:
        asyncio.run(scenario())
        record_property("model", settings.model)
        record_property("planner_round_seconds", [d["seconds"] for d in diagnostics])
        record_property("target_requests", len(calls))
    finally:
        repo.close()
