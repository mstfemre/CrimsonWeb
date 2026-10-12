"""pinned_response injects at most one allowlisted auth header, read-only."""

import asyncio

import httpx
import pytest

from crimsonweb.api.engine import pinned_response
from crimsonweb.api.scope import ScopeError


def capture():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["method"] = request.method
        return httpx.Response(200, json={"ok": True})

    return seen, httpx.MockTransport(handler)


def run(auth_header=None, observation_only=True):
    async def go():
        seen, transport = capture()
        url = httpx.URL("https://lab.test/api/objects/1")
        async with pinned_response(
            url,
            ["127.0.0.1"],
            transport,
            "GET",
            "CrimsonWeb/Phase4C",
            observation_only,
            auth_header=auth_header,
        ) as response:
            assert response.status_code == 200
        return seen

    return asyncio.run(go())


def test_injects_allowlisted_auth_header():
    seen = run(auth_header=("Authorization", "Bearer token-A"))
    assert seen["headers"]["authorization"] == "Bearer token-A"
    # Observation requests never carry a CORS Origin probe header.
    assert "origin" not in seen["headers"]
    assert seen["headers"]["accept-encoding"] == "identity"


def test_primitive_refuses_non_allowlisted_header_as_defence_in_depth():
    with pytest.raises(ScopeError):
        run(auth_header=("Host", "evil"))


def test_no_auth_header_sends_no_authorization():
    seen = run(auth_header=None)
    assert "authorization" not in seen["headers"]
