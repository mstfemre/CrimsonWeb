"""Exact Host header allowlist for the operator API.

Runs as raw ASGI middleware so it also covers routes outside the app-level
authorization dependency (``/docs``, ``/openapi.json``). Matching is exact:
no wildcards, no suffix matching, and non-canonical spellings are rejected.
"""

import ipaddress
import os
import re
from dataclasses import dataclass

from fastapi.responses import JSONResponse

DEFAULT_ALLOWED_HOSTS = ("127.0.0.1", "localhost", "[::1]")
_NAME = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
_PORT = re.compile(r"[0-9]{1,5}")


def split_host(value: str) -> tuple[str, int | None]:
    """Parse ``host``, ``host:port``, ``[ipv6]`` or ``[ipv6]:port``.

    Returns a lower-case name or canonical IPv6 text plus an optional port;
    raises ValueError for anything else (userinfo, paths, zone ids, bare IPv6).
    """
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or "%" in value:
            raise ValueError("invalid_host")
        host = str(ipaddress.IPv6Address(value[1:end]))
        rest = value[end + 1 :]
        if rest and not rest.startswith(":"):
            raise ValueError("invalid_host")
        port_text = rest[1:] if rest else None
    else:
        if value.count(":") > 1:
            raise ValueError("invalid_host")
        host, separator, port_text = value.partition(":")
        host = host.lower()
        if not _NAME.fullmatch(host):
            raise ValueError("invalid_host")
        if not separator:
            port_text = None
    port = None
    if port_text is not None:
        if not _PORT.fullmatch(port_text) or not 1 <= int(port_text) <= 65535:
            raise ValueError("invalid_port")
        port = int(port_text)
    return host, port


@dataclass(frozen=True)
class HostAllowlist:
    entries: tuple[tuple[str, int | None], ...]

    @classmethod
    def parse(cls, values) -> "HostAllowlist":
        entries = tuple(split_host(v.strip()) for v in values if v.strip())
        if not entries:
            raise ValueError("At least one allowed API host is required")
        return cls(entries)

    @classmethod
    def from_env(cls) -> "HostAllowlist":
        raw = os.getenv("CRIMSON_API_ALLOWED_HOSTS")
        values = DEFAULT_ALLOWED_HOSTS if raw is None else raw.split(",")
        try:
            return cls.parse(values)
        except ValueError as exc:
            raise ValueError("Invalid CRIMSON_API_ALLOWED_HOSTS") from exc

    def allows(self, header: str, scheme: str) -> bool:
        try:
            host, port = split_host(header)
        except ValueError:
            return False
        effective = port or (443 if scheme in {"https", "wss"} else 80)
        return any(
            host == allowed and (allowed_port is None or allowed_port == effective)
            for allowed, allowed_port in self.entries
        )


class HostAllowlistMiddleware:
    def __init__(self, app, allowlist: HostAllowlist):
        self.app = app
        self.allowlist = allowlist

    async def __call__(self, scope, receive, send):
        if scope["type"] not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        values = [v for k, v in scope.get("headers", ()) if k == b"host"]
        try:
            allowed = len(values) == 1 and self.allowlist.allows(
                values[0].decode("ascii"), scope.get("scheme", "http")
            )
        except UnicodeDecodeError:
            allowed = False
        if allowed:
            await self.app(scope, receive, send)
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
        else:
            # The rejected value is never echoed back or logged.
            await JSONResponse({"detail": "Host not allowed"}, status_code=403)(
                scope, receive, send
            )
