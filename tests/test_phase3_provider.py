import asyncio
import json

import httpx
import pytest

from crimsonweb.api.ai.provider import AIError, AISettings, OllamaProvider, ProviderGate


@pytest.mark.parametrize(
    "url,model",
    [
        ("http://example.com", "local:latest"),
        ("http://127.0.0.1/api", "local:latest"),
        ("http://user:secret@localhost", "local:latest"),
        ("http://localhost/?token=secret", "local:latest"),
        ("http://localhost", "remote-cloud"),
        ("http://localhost", ""),
        ("http://localhost", "model;command"),
    ],
)
def test_only_local_origin_and_local_model_configuration(url, model):
    with pytest.raises(AIError, match="invalid_configuration"):
        OllamaProvider(AISettings(enabled=True, base_url=url, model=model))


def test_chat_schema_stats_no_tools_no_retry():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.url.host == "127.0.0.1" and request.url.path == "/api/chat"
        assert request.headers["host"] == "127.0.0.1:11434"
        payload = json.loads(request.content)
        assert payload["format"] == {"type": "object"} and payload["stream"] is False
        assert "tools" not in payload and payload["messages"][0]["role"] == "system"
        assert "think" not in payload
        assert "Trusted output JSON schema:" in payload["messages"][0]["content"]
        assert (
            json.loads(
                payload["messages"][0]["content"].split(
                    "Trusted output JSON schema:\n"
                )[1]
            )
            == payload["format"]
        )
        assert "untrusted" not in payload["messages"][0]["content"]
        return httpx.Response(
            200,
            json={
                "model": "local:latest",
                "done": True,
                "message": {"role": "assistant", "content": "{}"},
                "prompt_eval_count": 11,
                "eval_count": 22,
                "total_duration": 2_000_000,
            },
        )

    provider = OllamaProvider(
        AISettings(enabled=True, model="local:latest"), httpx.MockTransport(handler)
    )
    reply = asyncio.run(
        provider.generate("trusted", {"evidence": "untrusted"}, {"type": "object"})
    )
    assert reply.usage.input_tokens == 11 and reply.usage.provider_duration_ms == 2
    assert len(calls) == 1


@pytest.mark.parametrize(
    "status,error",
    [
        (302, "provider_unavailable"),
        (404, "provider_unavailable"),
        (500, "provider_unavailable"),
    ],
)
def test_http_errors_no_redirect_or_retry(status, error):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            status, headers={"Location": "https://external.invalid/"}, text="secret"
        )

    provider = OllamaProvider(
        AISettings(enabled=True, model="local:latest"), httpx.MockTransport(handler)
    )
    with pytest.raises(AIError, match=error):
        asyncio.run(provider.health())
    assert len(calls) == 1


@pytest.mark.parametrize(
    "exception,error",
    [
        (httpx.ConnectError("api-key-secret"), "provider_unavailable"),
        (httpx.ReadTimeout("api-key-secret"), "provider_timeout"),
    ],
)
def test_connection_and_timeout_safe_errors(exception, error):
    def handler(request):
        raise exception

    provider = OllamaProvider(
        AISettings(enabled=True, model="local:latest"), httpx.MockTransport(handler)
    )
    with pytest.raises(AIError, match=error) as failure:
        asyncio.run(provider.health())
    assert "secret" not in str(failure.value)


@pytest.mark.parametrize("body", ["bad-json", "[]", '{"models":["invalid"]}'])
def test_invalid_provider_json(body):
    provider = OllamaProvider(
        AISettings(enabled=True, model="local:latest"),
        httpx.MockTransport(lambda request: httpx.Response(200, text=body)),
    )
    with pytest.raises(AIError, match="invalid_provider_response"):
        asyncio.run(provider.health())


def test_response_size_limit():
    provider = OllamaProvider(
        AISettings(enabled=True, model="local:latest", max_response_bytes=1024),
        httpx.MockTransport(lambda request: httpx.Response(200, text="x" * 1025)),
    )
    with pytest.raises(AIError, match="response_too_large"):
        asyncio.run(provider.health())


@pytest.mark.parametrize(
    "changes",
    [
        {"done": False},
        {"model": "other:latest"},
        {"done_reason": "length"},
        {"message": {"role": "assistant", "content": "{}", "tool_calls": [{}]}},
    ],
)
def test_incomplete_wrong_model_or_tools_rejected(changes):
    body = {
        "model": "local:latest",
        "done": True,
        "message": {"role": "assistant", "content": "{}"},
        **changes,
    }
    provider = OllamaProvider(
        AISettings(enabled=True, model="local:latest"),
        httpx.MockTransport(lambda request: httpx.Response(200, json=body)),
    )
    with pytest.raises(AIError):
        asyncio.run(provider.generate("system", {}, {}))


def test_model_status_and_cloud_names_hidden():
    body = {"models": [{"name": "local:latest"}, {"name": "remote-cloud"}]}
    provider = OllamaProvider(
        AISettings(enabled=True, model="local:latest"),
        httpx.MockTransport(lambda request: httpx.Response(200, json=body)),
    )
    status = asyncio.run(provider.health())
    assert status.available and status.models == ["local:latest"]


def test_gate_concurrency_and_rolling_call_limit():
    async def exercise():
        gate = ProviderGate(AISettings(max_concurrency=1, calls_per_minute=2))
        entered, release = asyncio.Event(), asyncio.Event()

        async def operation():
            entered.set()
            await release.wait()
            return "ok"

        pending = asyncio.create_task(gate.call(operation))
        await entered.wait()
        with pytest.raises(AIError, match="provider_capacity"):
            await gate.call(operation)
        release.set()
        assert await pending == "ok"
        assert await gate.call(operation) == "ok"
        with pytest.raises(AIError, match="provider_capacity"):
            await gate.call(operation)

    asyncio.run(exercise())
