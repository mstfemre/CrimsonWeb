"""Provider boundary: text and JSON only, no tools, retries, downloads or cloud fallback."""

import asyncio
import json
import os
import re
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Protocol, TypeVar

import httpx
from pydantic import BaseModel, ConfigDict, Field

from ..scope import Scope, ScopeError
from .models import ProviderStatus, Usage


class AIError(Exception):
    def __init__(self, code: str, *, diagnostics: dict | None = None) -> None:
        allowed = {
            "invalid_configuration",
            "ai_disabled",
            "provider_unavailable",
            "provider_timeout",
            "provider_capacity",
            "invalid_provider_response",
            "incomplete_provider_response",
            "response_too_large",
            "input_too_large",
            "evidence_not_found",
            "single_scan_required",
            "scan_not_finished",
            "invalid_model_output",
            "invalid_evidence_reference",
            "model_language_mismatch",
            "unsupported_model_claim",
            "unsafe_model_output",
            "model_not_installed",
        }
        code = code if code in allowed else "provider_error"
        super().__init__(code)
        self.code = code
        # Only safe reference IDs, fixed labels, counts and status flags.
        # Never included in the exception message, logs or persisted raw output.
        self.diagnostics = diagnostics


class AISettings(BaseModel):
    enabled: bool = False
    base_url: str = "http://127.0.0.1:11434"
    model: str = ""
    timeout_seconds: float = Field(default=90, ge=0.01, le=300)
    max_concurrency: int = Field(default=2, ge=1, le=4)
    calls_per_minute: int = Field(default=20, ge=1, le=60)
    max_input_bytes: int = Field(default=32768, ge=1024, le=65536)
    max_response_bytes: int = Field(default=262144, ge=1024, le=524288)
    max_output_tokens: int = Field(default=4096, ge=128, le=8192)
    context_tokens: int = Field(default=16384, ge=2048, le=32768)
    thinking: bool | None = None

    @classmethod
    def from_env(cls) -> "AISettings":
        thinking = os.getenv("CRIMSON_OLLAMA_THINK", "default").lower()
        if thinking not in {"default", "true", "false"}:
            raise ValueError("Invalid thinking configuration")
        return cls(
            enabled=os.getenv("CRIMSON_AI_ENABLED", "false").lower() == "true",
            base_url=os.getenv("CRIMSON_OLLAMA_URL", "http://127.0.0.1:11434"),
            model=os.getenv("CRIMSON_OLLAMA_MODEL", ""),
            timeout_seconds=os.getenv("CRIMSON_AI_TIMEOUT", "90"),
            max_concurrency=os.getenv("CRIMSON_AI_MAX_CONCURRENCY", "2"),
            calls_per_minute=os.getenv("CRIMSON_AI_CALLS_PER_MINUTE", "20"),
            max_input_bytes=os.getenv("CRIMSON_AI_MAX_INPUT_BYTES", "32768"),
            max_output_tokens=os.getenv("CRIMSON_AI_MAX_OUTPUT_TOKENS", "4096"),
            context_tokens=os.getenv("CRIMSON_AI_CONTEXT_TOKENS", "16384"),
            thinking={"default": None, "true": True, "false": False}[thinking],
        )


class ProviderReply(BaseModel):
    content: str = Field(repr=False)
    usage: Usage = Field(default_factory=Usage)


class LLMProvider(Protocol):
    name: str
    model: str

    async def health(self) -> ProviderStatus: ...

    async def generate(
        self, system: str, evidence: dict, schema: dict
    ) -> ProviderReply: ...


class OllamaEnvelope(BaseModel):
    model_config = ConfigDict(extra="ignore")
    model: str
    message: dict
    done: bool
    done_reason: str | None = None
    prompt_eval_count: int | None = Field(default=None, ge=0)
    eval_count: int | None = Field(default=None, ge=0)
    total_duration: int | None = Field(default=None, ge=0)


class OllamaProvider:
    name = "ollama"

    def __init__(
        self, settings: AISettings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self.model = settings.model
        self.transport = transport
        self.scope = Scope()
        try:
            self.base = self.scope.validate_url(settings.base_url)
            if self.base.path != "/" or self.base.host not in {
                "localhost",
                "127.0.0.1",
                "::1",
            }:
                raise ScopeError("Local provider origin required")
            if (
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.model)
                or "cloud" in self.model.lower()
            ):
                raise ValueError("Local model required")
        except (ValueError, ScopeError) as exc:
            raise AIError("invalid_configuration") from exc

    async def _request(
        self, method: str, path: str, payload: dict | None = None
    ) -> dict:
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                ips = await self.scope.resolve(self.base)
                url = self.base.copy_with(path=path, host=ips[0])
                async with (
                    httpx.AsyncClient(
                        transport=self.transport,
                        trust_env=False,
                        follow_redirects=False,
                        timeout=self.settings.timeout_seconds,
                    ) as client,
                    client.stream(
                        method,
                        url,
                        headers={"Host": self.base.netloc.decode("ascii")},
                        json=payload,
                        extensions={"sni_hostname": self.base.host},
                    ) as response,
                ):
                    if response.status_code != 200:
                        raise AIError("provider_unavailable")
                    chunks = bytearray()
                    async for chunk in response.aiter_bytes():
                        chunks.extend(chunk)
                        if len(chunks) > self.settings.max_response_bytes:
                            raise AIError("response_too_large")
                    result = json.loads(chunks)
                    if not isinstance(result, dict):
                        raise AIError("invalid_provider_response")
                    return result
        except AIError:
            raise
        except (TimeoutError, httpx.TimeoutException) as exc:
            raise AIError("provider_timeout") from exc
        except (httpx.HTTPError, OSError, ScopeError) as exc:
            raise AIError("provider_unavailable") from exc
        except (ValueError, RecursionError) as exc:
            raise AIError("invalid_provider_response") from exc

    async def health(self) -> ProviderStatus:
        result = await self._request("GET", "/api/tags")
        models = result.get("models")
        if not isinstance(models, list) or len(models) > 100:
            raise AIError("invalid_provider_response")
        if any(not isinstance(item, dict) for item in models):
            raise AIError("invalid_provider_response")
        names = [item.get("name") for item in models if isinstance(item, dict)]
        if any(not isinstance(name, str) or len(name) > 128 for name in names):
            raise AIError("invalid_provider_response")
        # Reject remote/cloud model names even if the local daemon lists them.
        names = [name for name in names if "cloud" not in name.lower()]
        available = self.model in names
        return ProviderStatus(
            provider=self.name,
            enabled=True,
            model=self.model,
            available=available,
            models=names,
            error_code=None if available else "model_not_installed",
        )

    async def generate(
        self, system: str, evidence: dict, schema: dict
    ) -> ProviderReply:
        thinking = (
            {} if self.settings.thinking is None else {"think": self.settings.thinking}
        )
        result = await self._request(
            "POST",
            "/api/chat",
            {
                **thinking,
                "model": self.model,
                "stream": False,
                "format": schema,
                "messages": [
                    {
                        "role": "system",
                        "content": system
                        + "\nTrusted output JSON schema:\n"
                        + json.dumps(schema, ensure_ascii=False, separators=(",", ":")),
                    },
                    {
                        "role": "user",
                        "content": json.dumps(evidence, ensure_ascii=False),
                    },
                ],
                "options": {
                    "temperature": 0,
                    "num_predict": self.settings.max_output_tokens,
                    "num_ctx": self.settings.context_tokens,
                },
            },
        )
        try:
            envelope = OllamaEnvelope.model_validate(result)
            if (
                not envelope.done
                or envelope.model != self.model
                or envelope.done_reason == "length"
            ):
                raise AIError(
                    "incomplete_provider_response",
                    diagnostics={
                        "location": "provider_completion",
                        "done": envelope.done,
                        "model_matches": envelope.model == self.model,
                        "output_token_count": envelope.eval_count,
                        "token_limit_reached": envelope.done_reason == "length",
                    },
                )
            message = envelope.message
            if (
                message.get("role") != "assistant"
                or message.get("tool_calls")
                or not isinstance(message.get("content"), str)
            ):
                raise AIError("invalid_provider_response")
            return ProviderReply(
                content=message["content"],
                usage=Usage(
                    input_tokens=envelope.prompt_eval_count,
                    output_tokens=envelope.eval_count,
                    provider_duration_ms=envelope.total_duration // 1_000_000
                    if envelope.total_duration is not None
                    else None,
                ),
            )
        except ValueError as exc:
            raise AIError("invalid_provider_response") from exc


T = TypeVar("T")


class ProviderGate:
    """One shared rolling window includes health checks and generation requests."""

    def __init__(self, settings: AISettings) -> None:
        self.settings = settings
        self._active = 0
        self._calls: deque[float] = deque()

    async def call(self, operation: Callable[[], Awaitable[T]]) -> T:
        now = asyncio.get_running_loop().time()
        while self._calls and self._calls[0] <= now - 60:
            self._calls.popleft()
        if (
            self._active >= self.settings.max_concurrency
            or len(self._calls) >= self.settings.calls_per_minute
        ):
            raise AIError("provider_capacity")
        self._active += 1
        self._calls.append(now)
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                return await operation()
        except TimeoutError as exc:
            raise AIError("provider_timeout") from exc
        finally:
            self._active -= 1
