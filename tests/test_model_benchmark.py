import asyncio
import json

import httpx
import pytest

from crimsonweb.api.ai.provider import AISettings, OllamaProvider


@pytest.mark.parametrize(
    "value,expected", [("false", False), ("true", True), ("default", None)]
)
def test_thinking_env_controls_wire_request_without_changing_schema(
    monkeypatch, value, expected
):
    monkeypatch.setenv("CRIMSON_OLLAMA_THINK", value)
    monkeypatch.setenv("CRIMSON_OLLAMA_MODEL", "gemma4:26b")
    settings = AISettings.from_env()
    schema = {"type": "object", "additionalProperties": False}

    def handler(request):
        payload = json.loads(request.content)
        assert payload["format"] == schema
        assert payload["options"]["num_predict"] == settings.max_output_tokens
        assert payload["options"]["num_ctx"] == settings.context_tokens
        assert payload["stream"] is False and "tools" not in payload
        if expected is None:
            assert "think" not in payload
        else:
            assert payload["think"] is expected
        return httpx.Response(
            200,
            json={
                "model": "gemma4:26b",
                "done": True,
                "message": {"role": "assistant", "content": "{}"},
            },
        )

    provider = OllamaProvider(settings, httpx.MockTransport(handler))
    asyncio.run(provider.generate("trusted", {}, schema))


@pytest.mark.parametrize("value", ["low", "yes", ""])
def test_unsupported_thinking_env_is_not_silently_enabled(monkeypatch, value):
    monkeypatch.setenv("CRIMSON_OLLAMA_THINK", value)
    with pytest.raises(ValueError, match="Invalid thinking configuration"):
        AISettings.from_env()


def test_thinking_trace_never_becomes_provider_reply_or_repr():
    provider = OllamaProvider(
        AISettings(model="gemma4:26b", thinking=True),
        httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "model": "gemma4:26b",
                    "done": True,
                    "message": {
                        "role": "assistant",
                        "content": "{}",
                        "thinking": "private-secret",
                    },
                },
            )
        ),
    )
    reply = asyncio.run(provider.generate("trusted", {}, {"type": "object"}))
    assert reply.content == "{}" and "private-secret" not in repr(reply)
