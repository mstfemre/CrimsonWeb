"""Privacy and safe-stop regressions; synthetic targets and credentials only."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from test_phase4c_hardening import approved, execute_request
from verification_helpers import setup, verification_policy

from crimsonweb.api.ai.security import mask_data
from crimsonweb.api.engine import pinned_response
from crimsonweb.api.scope import ScopeError
from crimsonweb.core_engine import WebRequestController
from crimsonweb.egress import (
    EgressKind,
    EgressMode,
    EgressNode,
    EgressPool,
    _validate_proxy_url,
)
from crimsonweb.privacy import sanitize


@pytest.mark.parametrize("key", ["X-API-Key", "client_secret", "id_token", "header_value", "session_id"])
def test_secret_alias_is_masked_in_shared_and_ai_layers(key):
    for masked in (sanitize({key: "synthetic-private-value"}),
                   mask_data({key: "synthetic-private-value"}, set())):
        assert "synthetic-private-value" not in str(masked)


def test_unstructured_log_credentials_and_proxy_errors_are_redacted():
    value = sanitize('Authorization: Bearer synthetic-secret, client_secret="private phrase"')
    assert "synthetic-secret" not in value and "private phrase" not in value
    with pytest.raises(SystemExit) as exc:
        _validate_proxy_url("ftp://user:synthetic-private-password@example.invalid")
    assert "synthetic-private-password" not in str(exc.value)


def controller(status=403):
    pool = SimpleNamespace(mode=EgressMode.DIRECT,
                           select=lambda url: SimpleNamespace(id="synthetic", url=None),
                           mark_banned=lambda *args: None, mark_success=lambda *args: None)

    async def wait(url):
        pass

    pacer = SimpleNamespace(wait=wait, record_latency=lambda value: None, base_delay=0)
    ban = SimpleNamespace(record=lambda *args: None, evaluate=lambda *args: (False, None))
    decoy = SimpleNamespace(should_inject=lambda: False)
    instance = WebRequestController(pool, pacer, ban, decoy, max_retries=3)
    calls = []

    async def send(**kwargs):
        calls.append(kwargs["url"])
        return SimpleNamespace(status=status, body="synthetic", latency_ms=0, egress_id=None)

    instance._send_request = send
    return instance, calls


@pytest.mark.parametrize("status", [403, 429])
@pytest.mark.parametrize("inspect_response", [False, True])
def test_cli_block_stops_retries_and_other_paths(status, inspect_response):
    instance, calls = controller(status)

    async def scenario():
        await instance.request(None, "http://lab.invalid/one", None, None,
                               block_on_ban=not inspect_response)
        await instance.request(None, "http://lab.invalid/two", None, None)

    asyncio.run(scenario())
    assert len(calls) == 1


def test_egress_ban_never_changes_identity():
    calls = []
    node = EgressNode(id="tor", kind=EgressKind.TOR, url="socks5h://127.0.0.1:9050")
    pool = EgressPool([node], EgressMode.TOR_ONLY,
                      tor_control=SimpleNamespace(signal_new_identity=lambda: calls.append(True)))
    pool.mark_banned(node, "synthetic_block")
    assert calls == [] and not node.is_available()


def test_primitive_requires_https_before_transmitting_credential():
    calls = []

    async def scenario():
        async with pinned_response(httpx.URL("http://lab.test/"), ["127.0.0.1"],
                                   httpx.MockTransport(lambda r: calls.append(r)),
                                   auth_header=("Authorization", "synthetic-secret")):
            pytest.fail("Credential must not be sent")

    with pytest.raises(ScopeError, match="credential_https_required"):
        asyncio.run(scenario())
    assert calls == []


def test_primitive_lab_override_cannot_allow_public_plaintext_credentials():
    async def scenario():
        async with pinned_response(httpx.URL("http://lab.test/"), ["8.8.8.8"],
                                   httpx.MockTransport(lambda r: pytest.fail("must not send")),
                                   auth_header=("Authorization", "synthetic-secret"),
                                   allow_insecure_lab_auth=True):
            pytest.fail("Public plaintext credential must be rejected")

    with pytest.raises(ScopeError, match="credential_https_required"):
        asyncio.run(scenario())


def test_execution_payload_has_a_small_credential_specific_limit():
    from test_phase4c_api import client, create_plan, policy, vbase, workspace

    with client() as c:
        ws = workspace(c)
        plan_id = create_plan(c, ws, policy(c, ws)).json()["id"]
        response = c.post(f"{vbase(ws)}/plans/{plan_id}/execute",
                          content="x" * 16385, headers={"Content-Type": "application/json"})
        assert response.status_code == 413
        assert not c.app.state.verification_service._accepting_execution


def test_private_lab_http_exception_and_scope_audit_minimization():
    repo, guard, ws, pid, manager = setup(lambda r: httpx.Response(
        200, json={"owner_id": r.url.path.rsplit("/", 1)[-1]},
    ))

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        assert (await manager.execute_plan(ws.id, plan.id, execute_request())).status == "completed"
        admissions = [a for a in guard.store.audits(ws.id, 100, 0).items
                      if a.action == "request_admitted"]
        assert len(admissions) == 3
        assert all(not a.resolved_ips and a.request_fingerprint is None for a in admissions)

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_http_credentials_denied_without_explicit_private_lab_permission():
    calls = []
    cfg = verification_policy()
    scope = cfg.target_scope.model_dump()
    scope["allow_private_networks"] = False
    repo, _, ws, pid, manager = setup(lambda r: calls.append(r),
                                     configuration=verification_policy(target_scope=scope))

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        assert (await manager.execute_plan(ws.id, plan.id, execute_request())).status == "halted"
        assert not calls

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_execution_overload_is_rejected_before_body_is_read():
    from test_phase4c_api import client, create_plan, policy, vbase, workspace

    # A malformed body would yield 422 if parsed; admission must reject it first.
    with client() as c:
        ws = workspace(c)
        plan_id = create_plan(c, ws, policy(c, ws)).json()["id"]
        c.app.state.verification_service._accepting_execution = True
        try:
            response = c.post(
                f"{vbase(ws)}/plans/{plan_id}/execute",
                content="not JSON", headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 409
        finally:
            c.app.state.verification_service._accepting_execution = False


def test_public_http_target_cannot_receive_credentials_even_in_lab_workspace():
    from workspace_helpers import FakeResolver

    from crimsonweb.api.workspaces.dns import Resolution

    scope = verification_policy().target_scope.model_dump()
    scope["allowed_networks"] = ["8.8.8.8/32"]
    calls = []
    repo, _, ws, pid, manager = setup(
        lambda r: calls.append(r), configuration=verification_policy(target_scope=scope),
        resolver=FakeResolver(Resolution(("8.8.8.8",))),
    )

    async def scenario():
        plan = await approved(manager, ws.id, pid.id)
        assert (await manager.execute_plan(ws.id, plan.id, execute_request())).status == "halted"
        assert manager.store.report(ws.id, plan.id).tests[0].reason == "credential_https_required"
        assert calls == []

    try:
        asyncio.run(scenario())
    finally:
        repo.close()
