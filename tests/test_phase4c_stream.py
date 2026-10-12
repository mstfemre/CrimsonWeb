"""The shared guard carries a Phase 4C credential header and still safe-stops."""

import asyncio

import httpx
from verification_helpers import verification_policy
from workspace_helpers import NOW, FakeResolver, seeded

from crimsonweb.api.workspaces.models import AuthorizationRequest
from crimsonweb.api.workspaces.service import AuthorizationDenied, WorkspaceService


def guarded(handler):
    repo, _, workspace, record = seeded(
        configuration=verification_policy(), resolver=FakeResolver()
    )
    service = WorkspaceService(repo, FakeResolver(), lambda: NOW)
    return service, workspace, record, httpx.MockTransport(handler)


def test_stream_injects_credential_header_and_uses_phase4c_identity():
    seen = {}

    def handler(request):
        seen["auth"] = request.headers.get("authorization")
        seen["ua"] = request.headers.get("user-agent")
        seen["origin"] = request.headers.get("origin")
        return httpx.Response(200, json={"ok": True})

    service, workspace, record, transport = guarded(handler)

    async def go():
        async with service.stream(
            workspace.id,
            record.id,
            AuthorizationRequest(
                url="http://lab.test:8001/api/objects/222",
                method="GET",
                category="auth",
            ),
            transport,
            user_agent="CrimsonWeb/Phase4C",
            observation_only=True,
            auth_header=("Authorization", "Bearer A"),
        ) as response:
            return response.status_code

    assert asyncio.run(go()) == 200
    assert seen["auth"] == "Bearer A"
    assert seen["ua"] == "CrimsonWeb/Phase4C"
    assert seen["origin"] is None


def test_stream_still_halts_on_403_without_classifying_cause():
    service, workspace, record, transport = guarded(
        lambda r: httpx.Response(403, json={})
    )

    async def go():
        async with service.stream(
            workspace.id,
            record.id,
            AuthorizationRequest(
                url="http://lab.test:8001/api/objects/222",
                method="GET",
                category="auth",
            ),
            transport,
            user_agent="CrimsonWeb/Phase4C",
            observation_only=True,
            auth_header=("Authorization", "Bearer A"),
        ) as response:
            return response.status_code

    assert asyncio.run(go()) == 403
    # The policy is halted with the neutral reason; a second request is denied.
    validation = service.validate_policy(workspace.id, record.id)
    assert "policy_halted" in validation.reasons

    async def again():
        async with service.stream(
            workspace.id,
            record.id,
            AuthorizationRequest(
                url="http://lab.test:8001/api/objects/222",
                method="GET",
                category="auth",
            ),
            transport,
        ):
            return "sent"

    try:
        asyncio.run(again())
        sent = True
    except AuthorizationDenied as exc:
        sent = False
        assert exc.reason == "policy_halted"
    assert sent is False
