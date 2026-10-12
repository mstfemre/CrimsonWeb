"""Top10 mapping and bounded injection signals against synthetic transports."""

import asyncio
import html
import json

import httpx
import pytest
from pydantic import ValidationError
from verification_helpers import setup, verification_policy

from crimsonweb.api.ai.provider import ProviderReply
from crimsonweb.api.verification.models import (
    ExecuteRequest,
    PlanApproval,
    VerificationPlanCreate,
)
from crimsonweb.api.verification.planner import PlannerError, validate_proposals
from crimsonweb.api.verification.probes import html_marker_present
from crimsonweb.api.workspaces.models import AuthorizationRequest, TargetScope
from crimsonweb.api.workspaces.store import Conflict

SPEC = {"openapi": "3.1.0", "paths": {"/search": {"get": {
    "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
    "responses": {"200": {}},
}}}}


def configuration(**scope_changes):
    scope = verification_policy().target_scope.model_dump()
    scope.update(allowed_categories=["auth", "web_observation", "xss", "sqli"],
                 allowed_query_parameters=["q"])
    scope.update(scope_changes)
    return verification_policy(target_scope=scope, maximum_request_budget=30)


def payload(record, ids, max_tests=50):
    return VerificationPlanCreate(policy_id=record.id, source="openapi", openapi_document=SPEC,
                                  catalog_ids=ids, max_tests=max_tests)


def approve(manager, ws, plan):
    return manager.approve_plan(ws.id, plan.id, PlanApproval(
        approved_by="synthetic", scope_source="owned lab", private_records_only=True,
        base_url="http://lab.test:8001", owner_binding_field="owner_id",
    ))


def execute_payload():
    return ExecuteRequest(base_url="http://lab.test:8001", owner_binding_field="owner_id", identities=[])


def lab(mode, calls):
    def handler(request):
        value = request.url.params.get("q", "1")
        calls.append(value)
        if mode in {"403", "429", "302"}:
            return httpx.Response(int(mode), headers={"location": "http://outside.invalid/"})
        if mode == "oversized":
            return httpx.Response(200, content="x" * 65537)
        if mode == "sql":
            return httpx.Response(500, json={"error": "sqlite3.OperationalError: SYNTHETIC_RESPONSE_SECRET"}) if value == "1'" else httpx.Response(200, json={"ok": True})
        if mode == "constant_sql_error":
            return httpx.Response(200, json={"error": "sqlite3.OperationalError: synthetic"})
        if mode == "escaped":
            value = html.escape(value)
        if mode == "comment":
            value = f"<!-- {value} -->"
        return httpx.Response(200, text=f"<html><body>{value}</body></html>",
                              headers={"content-type": "application/json" if mode == "json" else "text/html"})

    return handler


@pytest.mark.parametrize("mode,tool,expected", [
    ("html", "xss_reflection_probe", "html_injection_suspected"),
    ("escaped", "xss_reflection_probe", "no_signal_observed"),
    ("comment", "xss_reflection_probe", "no_signal_observed"),
    ("json", "xss_reflection_probe", "no_signal_observed"),
    ("sql", "sql_error_probe", "sql_injection_suspected"),
    ("constant_sql_error", "sql_error_probe", "no_signal_observed"),
    ("html", "sql_error_probe", "no_signal_observed"),
])
def test_injection_signals_have_controls_and_never_claim_exploit_execution(mode, tool, expected):
    calls = []
    repo, _, ws, pid, manager = setup(lab(mode, calls), configuration=configuration())

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, [tool]))
        assert len(plan.proposals) == 1 and plan.proposals[0].query_parameter == "q"
        approve(manager, ws, plan)
        assert (await manager.execute_plan(ws.id, plan.id, execute_payload())).status == "completed"
        report = manager.store.report(ws.id, plan.id)
        assert report.tests[0].outcome == expected
        assert len(calls) == (3 if tool == "sql_error_probe" else 2)
        assert all("<script" not in v and "UNION" not in v and "SLEEP" not in v for v in calls)
        assert report.evidence[0].script_execution_tested is False
        assert report.evidence[0].database_access_proven is False
        assert "SYNTHETIC_RESPONSE_SECRET" not in report.model_dump_json()
        if report.findings:
            assert report.findings[0].confidence == "unverified"
            assert report.findings[0].status == "candidate"
        assert len(report.top10_coverage) == 10
        assert next(r for r in report.top10_coverage if r.category == "A05").status == "partially_assessed"
        assert next(r for r in report.top10_coverage if r.category == "A03").status == "not_tested"

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


@pytest.mark.parametrize("mode,status", [("403", "halted"), ("429", "halted"), ("302", "halted"), ("oversized", "failed")])
def test_probe_stop_prevents_subsequent_requests(mode, status):
    calls = []
    repo, _, ws, pid, manager = setup(lab(mode, calls), configuration=configuration())

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, ["sql_error_probe", "xss_reflection_probe"]))
        approve(manager, ws, plan)
        result = await manager.execute_plan(ws.id, plan.id, execute_payload())
        assert result.status == status and len(calls) == 1
        assert manager.store.report(ws.id, plan.id).findings == []

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


@pytest.mark.parametrize("changes,reason", [
    ({"allowed_query_parameters": []}, "query_parameter_denied"),
    ({"allowed_categories": ["web_observation"]}, "category_denied"),
    ({"forbidden_paths": ["/search"]}, "path_denied"),
])
def test_active_tests_require_category_path_and_query_permission(changes, reason):
    calls = []
    repo, _, ws, pid, manager = setup(lab("html", calls), configuration=configuration(**changes))

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, ["xss_reflection_probe"]))
        approve(manager, ws, plan)
        await manager.execute_plan(ws.id, plan.id, execute_payload())
        report = manager.store.report(ws.id, plan.id)
        assert report.tests[0].reason == reason and calls == []

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


@pytest.mark.parametrize("name", ["token", "X-API-Key", "client_secret", "q\r\nHost", "*"])
def test_query_controls_reject_secrets_and_ambiguous_names(name):
    with pytest.raises(ValidationError):
        TargetScope(allowed_query_parameters=[name])
    with pytest.raises(ValidationError):
        AuthorizationRequest(url="https://lab.test/", query_parameters={name: "synthetic"})


def test_query_values_are_bounded_and_never_part_of_repr():
    request = AuthorizationRequest(url="https://lab.test/", query_parameters={"q": "synthetic-sensitive"})
    assert "synthetic-sensitive" not in repr(request)
    for value in ("x" * 257, "x\r\nInjected: y"):
        with pytest.raises(ValidationError):
            AuthorizationRequest(url="https://lab.test/", query_parameters={"q": value})


def test_planner_cannot_select_unapproved_tools_or_invent_query_parameter():
    repo, _, ws, pid, manager = setup(configuration=configuration())
    try:
        plan = asyncio.run(manager.create_plan(ws.id, payload(pid, ["sql_error_probe"])))
        proposal = plan.proposals[0].model_dump()
        for changed in ({"catalog_id": "xss_reflection_probe"}, {"query_parameter": "invented"}):
            with pytest.raises(PlannerError):
                validate_proposals({"proposals": [{**proposal, **changed}]}, plan.targets, plan.allowed_catalog_ids)
    finally:
        repo.close()


def test_configuration_reuses_existing_analysis_and_keeps_only_codes():
    calls = []

    def handler(request):
        calls.append(True)
        return httpx.Response(200, headers={"set-cookie": "sid=SYNTHETIC_COOKIE_SECRET", "content-type": "text/html"}, text="synthetic")

    repo, _, ws, pid, manager = setup(handler, configuration=configuration())

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, ["web_security_observation"]))
        approve(manager, ws, plan)
        await manager.execute_plan(ws.id, plan.id, execute_payload())
        report = manager.store.report(ws.id, plan.id)
        assert report.tests[0].outcome == "configuration_observed" and len(calls) == 1
        assert "SYNTHETIC_COOKIE_SECRET" not in report.model_dump_json()
        assert "cookie_attributes_observed" in report.evidence[0].signals
        assert next(r for r in report.top10_coverage if r.category == "A07").status == "partially_assessed"
        assert next(r for r in report.top10_coverage if r.category == "A04").status == "not_tested"

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


class SelectingProvider:
    def __init__(self):
        self.inputs = []

    async def generate(self, system, evidence, schema):
        self.inputs.append(evidence)
        if evidence["available_bindings"]:
            proposal = evidence["available_bindings"][0]
        else:
            target = evidence["candidate_endpoints"][0]
            tool = evidence["catalog"][0]
            proposal = {"catalog_id": tool["id"], "target_endpoint_ref": target["endpoint_ref"],
                        "evidence_refs": target["evidence_refs"],
                        "query_parameter": target["query_parameters"][0] if tool["requires_query_parameter"] else None}
        return ProviderReply(content=json.dumps({"proposals": [proposal]}))


def test_model_feedback_selects_remaining_tests_with_fresh_approval_and_three_round_limit():
    calls = []
    repo, _, ws, pid, manager = setup(lab("html", calls), configuration=configuration())
    manager.provider = SelectingProvider()

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, ["sql_error_probe", "web_security_observation", "xss_reflection_probe"], 1))
        for expected_round in (1, 2, 3):
            assert plan.round_number == expected_round and plan.status == "awaiting_approval"
            before = len(calls)
            with pytest.raises(Conflict, match="approved"):
                await manager.execute_plan(ws.id, plan.id, execute_payload())
            assert len(calls) == before
            approve(manager, ws, plan)
            await manager.execute_plan(ws.id, plan.id, execute_payload())
            if expected_round < 3:
                parent_id = plan.id
                plan = await manager.next_plan(ws.id, parent_id)
                with pytest.raises(Conflict):
                    await manager.next_plan(ws.id, parent_id)
        with pytest.raises(Conflict, match="round"):
            await manager.next_plan(ws.id, plan.id)
        assert manager.provider.inputs[-1]["prior_observations"]
        assert "<cw-probe" not in json.dumps(manager.provider.inputs)
        assert "SYNTHETIC_RESPONSE_SECRET" not in json.dumps(manager.provider.inputs)
        executed = [p.catalog_id for p in manager.store.get_plan(ws.id, plan.id).proposals]
        assert executed == ["xss_reflection_probe"]

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_html_parser_does_not_treat_script_text_or_comments_as_elements():
    tag = '<cw-probe data-id="marker">marker</cw-probe>'
    assert html_marker_present(tag, "marker")
    assert not html_marker_present(f"<script>{tag}</script>", "marker")
    assert not html_marker_present(f"<!--{tag}-->", "marker")
    for parent in ("textarea", "title", "xmp", "noscript"):
        assert not html_marker_present(f"<{parent}>{tag}</{parent}>", "marker")


def test_bola_still_requires_identities_even_if_anonymous_model_is_valid():
    from test_phase4c_api import OPENAPI

    repo, _, ws, pid, manager = setup(configuration=configuration())

    async def scenario():
        plan = await manager.create_plan(ws.id, VerificationPlanCreate(
            policy_id=pid.id, source="openapi", openapi_document=OPENAPI,
        ))
        approve(manager, ws, plan)
        with pytest.raises(Conflict, match="two test identities"):
            await manager.execute_plan(ws.id, plan.id, execute_payload())

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_generic_probe_findings_round_trip_sqlite_without_response_data(tmp_path):
    from crimsonweb.api.database import Repository
    from crimsonweb.api.verification.store import VerificationStore

    path = tmp_path / "probes.sqlite"
    url = f"sqlite:///{path.as_posix()}"
    repo, _, ws, pid, manager = setup(lab("sql", []), configuration=configuration(), url=url)

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, ["sql_error_probe"]))
        approve(manager, ws, plan)
        await manager.execute_plan(ws.id, plan.id, execute_payload())
        return plan.id

    try:
        plan_id = asyncio.run(scenario())
    finally:
        repo.close()
    reopened = Repository(url)
    try:
        report = VerificationStore(reopened).report(ws.id, plan_id)
        assert report.findings[0].code == "sql_injection_suspected"
        assert b"SYNTHETIC_RESPONSE_SECRET" not in path.read_bytes()
        assert report.findings[0].observation_evidence_ref == report.evidence[0].ref
    finally:
        reopened.close()


def test_request_budget_applies_to_every_injection_probe():
    cfg = configuration().model_copy(update={"maximum_request_budget": 1})
    calls = []
    repo, _, ws, pid, manager = setup(lab("html", calls), configuration=cfg)

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, ["xss_reflection_probe"]))
        approve(manager, ws, plan)
        result = await manager.execute_plan(ws.id, plan.id, execute_payload())
        assert result.status == "halted" and len(calls) == 1
        assert manager.store.report(ws.id, plan.id).tests[0].reason == "budget_exhausted"

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_follow_up_is_rejected_when_policy_stops():
    repo, guard, ws, pid, manager = setup(lab("html", []), configuration=configuration())

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, ["xss_reflection_probe", "web_security_observation"], 1))
        approve(manager, ws, plan)
        await manager.execute_plan(ws.id, plan.id, execute_payload())
        guard.store.halt(ws.id, pid.id, "waf_block", guard.clock())
        from crimsonweb.api.workspaces.service import AuthorizationDenied

        with pytest.raises(AuthorizationDenied, match="policy_halted"):
            await manager.next_plan(ws.id, plan.id)

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_api_candidate_evidence_catalog_and_follow_up_remain_workspace_isolated():
    from test_phase4c_api import client, policy, vbase, workspace

    calls = []
    with client() as c:
        ws = workspace(c)
        pid = policy(c, ws, target_scope=configuration().target_scope.model_dump())
        c.app.state.verification_service.executor.transport = httpx.MockTransport(lab("html", calls))
        created = c.post(f"{vbase(ws)}/plans", json={
            "policy_id": pid, "source": "openapi", "openapi_document": SPEC,
            "catalog_ids": ["xss_reflection_probe", "web_security_observation"], "max_tests": 1,
        })
        assert created.status_code == 202
        plan_id = created.json()["id"]
        approval = {"approved_by": "op", "scope_source": "controlled lab", "base_url": "http://lab.test:8001",
                    "owner_binding_field": "owner_id", "read_only_operations": True}
        assert c.post(f"{vbase(ws)}/plans/{plan_id}/approve", json=approval).status_code == 200
        assert c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json=execute_payload().model_dump()).status_code == 200
        report = c.get(f"{vbase(ws)}/plans/{plan_id}/report").json()
        # Operator seeding sorts catalog IDs; configuration first, then XSS in the follow-up.
        assert report["private_records_only"] is False
        follow_up = c.post(f"{vbase(ws)}/plans/{plan_id}/next")
        assert follow_up.status_code == 202 and follow_up.json()["status"] == "awaiting_approval"
        child = follow_up.json()["id"]
        assert c.post(f"{vbase(ws)}/plans/{child}/execute", json=execute_payload().model_dump()).status_code == 409
        assert c.post(f"{vbase(ws)}/plans/{child}/approve", json=approval).status_code == 200
        assert c.post(f"{vbase(ws)}/plans/{child}/execute", json=execute_payload().model_dump()).status_code == 200
        findings = c.get(f"{vbase(ws)}/plans/{child}/findings").json()
        assert findings["items"][0]["status"] == "candidate"
        assert c.get(f"{vbase(ws)}/plans/{child}/evidence").json()["items"][0]["kind"] == "web_probe"
        catalog = c.get(f"{vbase(ws)}/catalog")
        assert catalog.status_code == 200 and len(catalog.json()["categories"]) == 10
        other = workspace(c)
        assert c.post(f"{vbase(other)}/plans/{plan_id}/next").status_code == 404
        assert c.get(f"{vbase(other)}/plans/{child}/findings").status_code == 404


def test_cli_top10_plan_and_anonymous_execution_use_actual_api_without_credentials(tmp_path, capsys):
    from test_phase4c_api import client, policy, workspace

    from crimsonweb.web_cli import main

    spec_path = tmp_path / "query.json"
    spec_path.write_text(json.dumps(SPEC), encoding="utf-8")
    with client() as c:
        ws = workspace(c)
        pid = policy(c, ws, target_scope=configuration().target_scope.model_dump())
        c.app.state.verification_service.executor.transport = httpx.MockTransport(lab("html", []))

        def handler(request):
            return c.request(request.method, request.url.path, content=request.content, headers=dict(request.headers))

        transport = httpx.MockTransport(handler)
        common = ["--workspace", ws]
        assert main(["plan", *common, "--policy", pid, "--openapi", str(spec_path), "--top10", "--max-tests", "1"], transport=transport) == 0
        plan_id = json.loads(capsys.readouterr().out)["plan_id"]
        identity = [*common, "--plan", plan_id]
        target = ["--base-url", "http://lab.test:8001", "--binding-field", "owner_id"]
        assert main(["approve", *identity, *target, "--approved-by", "op", "--scope-source", "lab"], transport=transport) == 0
        assert main(["execute", *identity, *target, "--anonymous"], transport=transport,
                    interactive=False, secret_reader=lambda prompt: pytest.fail("No credentials needed")) == 0
        assert main(["report", *identity], transport=transport) == 0
        assert len(json.loads(capsys.readouterr().out.splitlines()[-1])["coverage"]) == 10
        assert main(["next", *identity], transport=transport) == 0
        assert json.loads(capsys.readouterr().out)["status"] == "awaiting_approval"


def test_encoded_response_is_rejected_before_decompression_or_body_read():
    class MustNotRead(httpx.AsyncByteStream):
        async def __aiter__(self):
            pytest.fail("Encoded body must not be read")
            yield b"unreachable"

    repo, _, ws, pid, manager = setup(lambda r: httpx.Response(
        200, headers={"content-encoding": "gzip"}, stream=MustNotRead(),
    ), configuration=configuration())

    async def scenario():
        plan = await manager.create_plan(ws.id, payload(pid, ["sql_error_probe"]))
        approve(manager, ws, plan)
        assert (await manager.execute_plan(ws.id, plan.id, execute_payload())).status == "failed"
        assert manager.store.report(ws.id, plan.id).tests[0].reason == "encoded_response_not_supported"

    try:
        asyncio.run(scenario())
    finally:
        repo.close()
