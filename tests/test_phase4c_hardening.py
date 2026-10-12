"""Controlled laboratory checks for the Phase 4C trust and lifecycle boundaries."""

import asyncio
import json
from datetime import timedelta
from uuid import UUID

import httpx
import pytest
from test_phase4c_api import (
    APPROVAL,
    IDENTITIES,
    OPENAPI,
    client,
    create_plan,
    policy,
    vbase,
    workspace,
)
from test_phase4c_planner import FakeProvider, content, target
from verification_helpers import setup, verification_policy
from workspace_helpers import NOW, FakeResolver

from crimsonweb.api.ai.provider import AIError, AISettings, ProviderGate
from crimsonweb.api.app import create_app
from crimsonweb.api.database import Repository
from crimsonweb.api.verification.models import (
    ExecuteRequest,
    PlanApproval,
    VerificationPlanCreate,
)
from crimsonweb.api.verification.planner import generate_proposals
from crimsonweb.api.workspaces.dns import Resolution
from crimsonweb.api.workspaces.models import AuthorizationRequest
from crimsonweb.api.workspaces.service import AuthorizationDenied
from crimsonweb.api.workspaces.store import Conflict


def execute_request():
    return ExecuteRequest(base_url=APPROVAL["base_url"],
                          owner_binding_field="owner_id", identities=IDENTITIES)


async def approved(manager, ws, pid):
    plan = await manager.create_plan(ws, VerificationPlanCreate(
        policy_id=pid, source="openapi", openapi_document=OPENAPI,
    ))
    return manager.approve_plan(ws, plan.id, PlanApproval(
        approved_by="test-operator", scope_source="synthetic lab", **APPROVAL,
    ))


def test_planner_uses_shared_provider_gate_and_capacity():
    async def scenario():
        gate = ProviderGate(AISettings(max_concurrency=1))
        entered, release = asyncio.Event(), asyncio.Event()
        calls = []

        class Provider:
            async def generate(self, *args):
                calls.append(True)
                entered.set()
                await release.wait()
                return type("Reply", (), {"content": content([{
                    "catalog_id": "bola_cross_owner_read",
                    "target_endpoint_ref": "endpoint:e1", "evidence_refs": ["evidence:v1"],
                }])})()

        first = asyncio.create_task(generate_proposals(Provider(), [target()], gate))
        await entered.wait()
        try:
            with pytest.raises(AIError, match="provider_capacity"):
                await generate_proposals(Provider(), [target()], gate)
            assert len(calls) == 1
        finally:
            release.set()
            await first
        assert gate._active == 0

    asyncio.run(scenario())


def test_planner_bounds_input_before_provider_call():
    class NeverCalled:
        async def generate(self, *args):
            pytest.fail("Oversized planner input must not reach the provider")

    with pytest.raises(AIError, match="input_too_large"):
        asyncio.run(generate_proposals(NeverCalled(), [target()], max_input_bytes=64))


def test_planner_omits_ineligible_targets_from_schema_and_input():
    class Provider(FakeProvider):
        async def generate(self, system, evidence, schema):
            assert len(evidence["candidate_endpoints"]) == 1
            assert "endpoint:write" not in json.dumps(schema)
            return await super().generate(system, evidence, schema)

    result = asyncio.run(generate_proposals(Provider(content([])), [
        target(), target("endpoint:write", method="DELETE"),
    ]))
    assert result == []


@pytest.mark.parametrize("case", ["same_value", "null", "boolean", "array", "duplicate", "wrong_type", "oversized"])
def test_ambiguous_response_cannot_produce_a_finding(case):
    def handler(request):
        obj = request.url.path.rsplit("/", 1)[-1]
        cross = obj == "222" and request.headers["authorization"] == IDENTITIES[0]["header_value"]
        if case == "duplicate":
            return httpx.Response(200, headers={"content-type": "application/json"},
                                  content='{"owner_id":"111","owner_id":"222"}')
        if case == "oversized":
            return httpx.Response(200, json={"owner_id": obj, "padding": "x" * 65536})
        value = {"same_value": "shared", "null": None, "boolean": True,
                 "array": [obj], "wrong_type": int(obj) if cross else obj}[case]
        return httpx.Response(200, json={"owner_id": value})

    repo, _, ws, pid, manager = setup(handler)

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        await manager.execute_plan(ws.id, plan.id, execute_request())
        report = manager.store.report(ws.id, plan.id)
        assert report.findings == []
        assert report.tests[0].outcome == "owner_binding_unverified"

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


@pytest.mark.parametrize("status", [403, 429, 302])
def test_defense_or_redirect_stops_after_one_request(status):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status, headers={"location": "http://outside.test/"})

    repo, guard, ws, pid, manager = setup(handler)

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        result = await manager.execute_plan(ws.id, plan.id, execute_request())
        assert result.status == "halted"
        assert len(calls) == 1
        assert manager.store.report(ws.id, plan.id).findings == []
        assert "policy_halted" in guard.validate_policy(ws.id, pid.id).reasons

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_failed_control_stops_before_cross_read():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(401)

    repo, _, ws, pid, manager = setup(handler)

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        result = await manager.execute_plan(ws.id, plan.id, execute_request())
        assert result.status == "failed"
        assert len(calls) == 1
        assert manager.store.report(ws.id, plan.id).findings == []

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_network_error_is_failed_and_never_discloses_exception_secret(caplog):
    def handler(request):
        raise httpx.ConnectError("SECRET_from_transport", request=request)

    repo, _, ws, pid, manager = setup(handler)

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        result = await manager.execute_plan(ws.id, plan.id, execute_request())
        assert result.status == "failed"
        report = manager.store.report(ws.id, plan.id)
        assert "SECRET_from_transport" not in report.model_dump_json() + caplog.text
        assert report.findings == []

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_cancel_between_controls_prevents_next_request():
    calls = []
    plan_id = None

    def handler(request):
        calls.append(request)
        manager.store.cancel_plan(ws.id, plan_id, manager.clock())
        return httpx.Response(200, json={"owner_id": "111"})

    repo, _, ws, pid, manager = setup(handler)

    async def scenario():
        nonlocal plan_id
        plan_id = (await approved(manager, ws.id, pid.id)).id
        result = await manager.execute_plan(ws.id, plan_id, execute_request())
        assert result.status == "cancelled"
        assert len(calls) == 1
        assert manager.store.report(ws.id, plan_id).findings == []

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_shutdown_cancels_active_execution_before_database_close():
    async def scenario():
        entered = asyncio.Event()

        async def handler(request):
            entered.set()
            await asyncio.Event().wait()

        repo, _, ws, pid, manager = setup(handler)
        try:
            plan = await approved(manager, ws.id, pid.id)
            task = asyncio.create_task(manager.execute_plan(ws.id, plan.id, execute_request()))
            await entered.wait()
            await manager.shutdown()
            assert task.cancelled()
            assert manager.store.get_plan(ws.id, plan.id).status == "cancelled"
            assert manager._executions == set()
            with pytest.raises(Conflict, match="shutting down"):
                await manager.execute_plan(ws.id, plan.id, execute_request())
        finally:
            repo.close()

    asyncio.run(scenario())


def test_verification_respects_an_existing_shared_concurrency_lease():
    calls = []
    repo, guard, ws, pid, manager = setup(
        lambda request: calls.append(request),
        configuration=verification_policy(maximum_concurrency=1),
    )

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        decision, lease_id = await guard.decide(ws.id, pid.id, AuthorizationRequest(
            url="http://lab.test:8001/api/objects/111", method="GET", category="auth",
        ), reserve=True)
        assert decision.allowed
        try:
            result = await manager.execute_plan(ws.id, plan.id, execute_request())
            assert result.status == "halted"
            assert calls == []
            report = manager.store.report(ws.id, plan.id)
            assert report.tests[0].reason == "concurrency_exceeded"
        finally:
            guard.store.release(ws.id, pid.id, lease_id, None, manager.clock())

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_execution_origin_and_binding_cannot_change_after_approval():
    with client() as c:
        ws = workspace(c)
        plan_id = create_plan(c, ws, policy(c, ws)).json()["id"]
        response = c.post(f"{vbase(ws)}/plans/{plan_id}/approve", json={
            "approved_by": "op", "scope_source": "lab", **APPROVAL,
        })
        assert response.status_code == 200
        assert response.json()["approved_private_records_only"] is True
        for changes in ({"base_url": "http://outside.test:8001"}, {"owner_binding_field": "other"}):
            response = c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json={
                **execute_request().model_dump(mode="json"), **changes,
            })
            assert response.status_code == 409
        assert c.get(f"{vbase(ws)}/plans/{plan_id}/report").json()["tests"] == []


def test_discovery_or_openapi_origin_cannot_be_rebound_by_approval():
    with client() as c:
        ws = workspace(c)
        response = c.post(f"{vbase(ws)}/plans", json={
            "policy_id": policy(c, ws), "source": "openapi", "openapi_document": OPENAPI,
            "base_url": "http://original.test:8001",
        })
        plan_id = response.json()["id"]
        denied = c.post(f"{vbase(ws)}/plans/{plan_id}/approve", json={
            "approved_by": "op", "scope_source": "lab", **APPROVAL,
        })
        assert denied.status_code == 409


def test_invalid_credential_payload_is_not_echoed_or_logged(caplog):
    with client() as c:
        ws = workspace(c)
        plan_id = create_plan(c, ws, policy(c, ws)).json()["id"]
        request = execute_request().model_dump(mode="json")
        request["identities"][0]["header_value"] = "private-token\r\ninjected"
        response = c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json=request)
        assert response.status_code == 422
        assert "private-token" not in response.text + caplog.text
        unauthorized = c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json=request,
                              headers={"Authorization": "Bearer incorrect"})
        assert unauthorized.status_code == 401


def test_workspace_isolation_applies_to_all_verification_routes():
    with client() as c:
        ws = workspace(c)
        plan_id = create_plan(c, ws, policy(c, ws)).json()["id"]
        other = workspace(c)
        for suffix in ("", "/tests", "/evidence", "/findings", "/report"):
            assert c.get(f"{vbase(other)}/plans/{plan_id}{suffix}").status_code == 404
        approval = {"approved_by": "op", "scope_source": "lab", **APPROVAL}
        assert c.post(f"{vbase(other)}/plans/{plan_id}/approve", json=approval).status_code == 404
        assert c.post(f"{vbase(other)}/plans/{plan_id}/execute",
                      json=execute_request().model_dump(mode="json")).status_code == 404
        assert c.post(f"{vbase(other)}/plans/{plan_id}/cancel").status_code == 404
        # Original plan remains unchanged after attempted cross-workspace writes.
        assert c.get(f"{vbase(ws)}/plans/{plan_id}").json()["status"] == "awaiting_approval"
        assert UUID(other) != UUID(ws)


@pytest.mark.parametrize("resolution,reason", [
    (Resolution(("8.8.8.8",)), "ip_out_of_scope"),
    (Resolution(("127.0.0.1",), ("outside.test",)), "cname_out_of_scope"),
])
def test_dns_change_is_rechecked_before_sending_next_credential(resolution, reason):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"owner_id": "111"})

    resolver = FakeResolver(Resolution(("127.0.0.1",)), resolution)
    repo, _, ws, pid, manager = setup(handler, resolver=resolver)

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        result = await manager.execute_plan(ws.id, plan.id, execute_request())
        assert result.status == "halted" and len(calls) == 1
        assert manager.store.report(ws.id, plan.id).tests[0].reason == reason

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


@pytest.mark.parametrize("change,reason", [
    ("path", "path_denied"), ("method", "method_denied"),
    ("private", "private_network_denied"),
])
def test_scope_denial_sends_no_credential(change, reason):
    configuration = verification_policy()
    scope = configuration.target_scope.model_dump()
    if change == "path":
        scope["forbidden_paths"] = ["/api/*"]
    elif change == "method":
        scope["allowed_methods"] = ["HEAD"]
    else:
        scope["allow_private_networks"] = False
    configuration = verification_policy(target_scope=scope)
    calls = []
    repo, _, ws, pid, manager = setup(lambda r: calls.append(r), configuration=configuration)

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        result = await manager.execute_plan(ws.id, plan.id, execute_request())
        assert result.status == "halted" and not calls
        assert manager.store.report(ws.id, plan.id).tests[0].reason == reason

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_expired_policy_prevents_execution():
    repo, guard, ws, pid, manager = setup()

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        guard.clock = lambda: NOW + timedelta(days=2)
        with pytest.raises(AuthorizationDenied, match="policy_expired"):
            await manager.execute_plan(ws.id, plan.id, execute_request())
        assert manager.store.get_plan(ws.id, plan.id).status == "approved"
        assert manager.store.report(ws.id, plan.id).tests == []

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_results_persist_without_tokens_or_response_values(tmp_path, caplog):
    from crimsonweb.api.verification.store import VerificationStore

    db = tmp_path / "verification.sqlite"
    url = f"sqlite:///{db.as_posix()}"
    values = {"111": "private-owner-alpha", "222": "private-owner-beta"}
    repo, _, ws, pid, manager = setup(
        lambda r: httpx.Response(200, json={"owner_id": values[r.url.path.rsplit("/", 1)[-1]]}),
        url=url,
    )

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        await manager.execute_plan(ws.id, plan.id, execute_request())
        return plan.id

    try:
        plan_id = asyncio.run(scenario())
    finally:
        repo.close()
    reopened = Repository(url)
    try:
        report = VerificationStore(reopened).report(ws.id, plan_id)
        assert report.private_records_only is True
        assert len(report.findings) == 1
        blob = report.model_dump_json().encode() + db.read_bytes() + caplog.text.encode()
        for secret in ("tokA-secret", "tokB-secret", *values.values()):
            assert secret.encode() not in blob
    finally:
        reopened.close()


def test_application_wires_the_same_ai_gate_to_verification(monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("CRIMSON_API_TOKEN", "synthetic-token")
    settings = AISettings(enabled=True, model="gemma4:26b", max_concurrency=1)
    app = create_app(repository=Repository("sqlite://"),
                     ai_provider=FakeProvider(content([])), ai_settings=settings)
    with TestClient(app):
        assert app.state.verification_service.provider_gate is app.state.ai_service.gate
        assert app.state.verification_service.max_input_bytes == settings.max_input_bytes
