"""Egress routing, proxy validation, pacing, and block-signal helpers."""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import socket
import statistics
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .audit import audit_event

try:
    import yaml as _yaml  # type: ignore[import]
except ImportError:
    _yaml = None  # type: ignore[assignment]


DEFAULT_WEB_REQUEST_DELAY = 3.0
DEFAULT_WEB_SENSITIVE_DELAY = 5.0
DEFAULT_WEB_MAX_GLOBAL_RATE = 20
DEFAULT_WEB_STOP_STATUSES = frozenset({403, 429, 503})
DEFAULT_TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"
DEFAULT_TOR_CONTROL_HOST = "127.0.0.1"
DEFAULT_TOR_CONTROL_PORT = 9051
DEFAULT_TOR_NEW_IDENTITY_WAIT = 10.0
HTTP_PROXY_SCHEMES = frozenset({"http", "https"})
SOCKS_PROXY_SCHEMES = frozenset({"socks4", "socks4a", "socks5", "socks5h"})
REMOTE_DNS_SOCKS_SCHEMES = frozenset({"socks4a", "socks5h"})
SUPPORTED_PROXY_SCHEMES = HTTP_PROXY_SCHEMES | SOCKS_PROXY_SCHEMES
DEFAULT_BAN_COOLDOWN_SECONDS = 900
DEFAULT_BAN_SOFT_THRESHOLD = 3
DEFAULT_BAN_COOLDOWN_MULTIPLIER = 2.0
DEFAULT_BAN_COOLDOWN_MAX = 7200
BLOCK_CONTEXT_STATUS_CODES = frozenset({401, 403, 406, 407, 409, 418, 429, 451, 503})
JITTER_LOW = 0.7
JITTER_HIGH = 1.5
PACING_BASELINE_WINDOW = 10
PACING_SLOWDOWN_THRESHOLD = 1.5
DEFAULT_DECOY_RATE = 0.0
DECOY_FALLBACK_PATHS = (
    "/", "/hakkimizda", "/iletisim", "/duyurular", "/haberler",
    "/etkinlikler", "/belediye-meclisi", "/baskan", "/hizmetler", "/robots.txt",
)
BLOCK_BODY_PATTERNS = (
    r"\bcaptcha\b",
    r"\baccess denied\b",
    r"\brequest blocked\b",
    r"\bblocked by\b",
    r"\bweb application firewall\b",
    r"\bcloudflare ray id\b",
    r"\bincapsula\b",
    r"\bsucuri\b",
    r"\bakamai bot manager\b",
)
SENSITIVE_ENDPOINT_KEYWORDS = (
    "login", "signin", "auth", "oauth", "account", "payment",
    "checkout", "pay", "form", "contact", "admin",
)
_BLOCK_BODY_RE = re.compile("|".join(BLOCK_BODY_PATTERNS), re.IGNORECASE)


def redact_proxy_url(proxy_url: str | None) -> str | None:
    if not proxy_url:
        return proxy_url
    parsed = urlsplit(proxy_url)
    if parsed.username is None and parsed.password is None:
        return proxy_url
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return urlunsplit(
        (parsed.scheme, f"<credentials>@{host}", parsed.path, parsed.query, parsed.fragment)
    )


def is_sensitive_url(url: str) -> bool:
    parsed = urlsplit(url)
    haystack = f"{parsed.path}?{parsed.query}".lower()
    return any(keyword in haystack for keyword in SENSITIVE_ENDPOINT_KEYWORDS)


def parse_status_codes(value: str | None) -> set[int]:
    if value is None:
        return set(DEFAULT_WEB_STOP_STATUSES)
    statuses: set[int] = set()
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue
        try:
            status = int(part)
        except ValueError as exc:
            raise SystemExit(f"Invalid HTTP status code: {part!r}") from exc
        if status < 100 or status > 599:
            raise SystemExit(f"Invalid HTTP status code: {status}")
        statuses.add(status)
    return statuses


class TorControlClient:
    """Speaks the Tor control protocol over a local socket."""

    def __init__(
        self,
        host: str = DEFAULT_TOR_CONTROL_HOST,
        port: int = DEFAULT_TOR_CONTROL_PORT,
        password: str | None = None,
        cookie_file: str | None = None,
        new_identity_wait: float = DEFAULT_TOR_NEW_IDENTITY_WAIT,
    ) -> None:
        self.host = host
        self.port = port
        self.password = password
        self.cookie_file = cookie_file
        self.new_identity_wait = max(0.0, new_identity_wait)

    @staticmethod
    def _quoted(value: str) -> str:
        return json.dumps(value)

    @staticmethod
    def _allowed_cookie_roots() -> tuple[Path, ...]:
        roots = (Path("/var/run/tor"), Path("/var/lib/tor"), Path("/run/tor"), Path.home())
        resolved: list[Path] = []
        for root in roots:
            try:
                resolved.append(root.expanduser().resolve(strict=True))
            except OSError:
                continue
        return tuple(dict.fromkeys(resolved))

    @classmethod
    def _resolve_cookie_file(cls, cookie_file: str) -> Path:
        path = Path(cookie_file).expanduser()
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise RuntimeError(f"Tor cookie file not found: {path}") from exc
        if not resolved.is_file():
            raise RuntimeError(f"Tor cookie path is not a file: {resolved}")
        allowed_roots = cls._allowed_cookie_roots()
        if not allowed_roots or not any(
            resolved == root or resolved.is_relative_to(root) for root in allowed_roots
        ):
            allowed = ", ".join(str(root) for root in allowed_roots) or "<none>"
            raise RuntimeError(
                f"Refusing to read Tor cookie outside permitted directories: {resolved} "
                f"(allowed roots: {allowed})"
            )
        return resolved

    def _auth_command(self) -> str:
        if self.password is not None:
            return f"AUTHENTICATE {self._quoted(self.password)}"
        if self.cookie_file:
            path = self._resolve_cookie_file(self.cookie_file)
            return f"AUTHENTICATE {path.read_bytes().hex()}"
        return "AUTHENTICATE"

    @staticmethod
    def _read_response(reader) -> list[str]:
        lines: list[str] = []
        while True:
            raw_line = reader.readline()
            if not raw_line:
                raise RuntimeError("Tor control connection closed unexpectedly")
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            lines.append(line)
            if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
                return lines

    @staticmethod
    def _ensure_ok(lines: list[str], command: str) -> None:
        if not lines or not lines[-1].startswith("250 "):
            detail = lines[-1] if lines else "no response"
            raise RuntimeError(f"Tor control command failed during {command}: {detail}")

    def _send_command(self, sock: socket.socket, reader, command: str, require_ok: bool = True) -> list[str]:
        sock.sendall((command + "\r\n").encode("utf-8"))
        lines = self._read_response(reader)
        if require_ok:
            self._ensure_ok(lines, command)
        return lines

    def signal_new_identity(self, strict: bool = False) -> None:
        try:
            with socket.create_connection((self.host, self.port), timeout=8.0) as sock:
                reader = sock.makefile("rb")
                self._send_command(sock, reader, self._auth_command())
                self._send_command(sock, reader, "SIGNAL NEWNYM")
                self._send_command(sock, reader, "QUIT", require_ok=False)
        except (OSError, RuntimeError) as exc:
            audit_event("tor_newnym_failed", error=str(exc))
            logging.warning("SIGNAL NEWNYM failed: %s", exc)
            if strict:
                raise SystemExit(f"Tor NEWNYM failed: {exc}") from exc
            return
        audit_event("tor_newnym_ok", wait_seconds=self.new_identity_wait)
        if self.new_identity_wait:
            time.sleep(self.new_identity_wait)


class EgressKind(str, Enum):
    DIRECT = "direct"
    TOR = "tor"
    PROXY = "proxy"


class EgressMode(str, Enum):
    DIRECT = "direct"
    TOR_ONLY = "tor_only"
    MULTI_EGRESS = "multi_egress"


@dataclass(slots=True)
class EgressNode:
    id: str
    kind: EgressKind
    url: str | None
    role: str = "general"
    consecutive_failures: int = 0
    cooldown_until: float = 0.0
    last_used: float = 0.0
    total_requests: int = 0
    total_failures: int = 0

    def is_available(self, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        return self.cooldown_until <= now


def _validate_proxy_url(proxy_url: str) -> str:
    parsed = urlsplit(proxy_url)
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_PROXY_SCHEMES:
        allowed = ", ".join(sorted(SUPPORTED_PROXY_SCHEMES))
        raise SystemExit(
            f"Unsupported proxy scheme. Allowed: {allowed}"
        )
    if not parsed.hostname:
        raise SystemExit("Proxy URL must include a host")
    if scheme in SOCKS_PROXY_SCHEMES and scheme not in REMOTE_DNS_SOCKS_SCHEMES:
        raise SystemExit(
            f"SOCKS proxy URL must use remote-DNS scheme socks5h/socks4a, got {scheme!r}: "
            f"{redact_proxy_url(proxy_url)}"
        )
    return proxy_url


class EgressPool:
    """Selects egress nodes per request and manages cooldowns."""

    def __init__(
        self,
        nodes: list[EgressNode],
        mode: EgressMode,
        tor_control: TorControlClient | None = None,
        cooldown_seconds: float = DEFAULT_BAN_COOLDOWN_SECONDS,
        cooldown_multiplier: float = DEFAULT_BAN_COOLDOWN_MULTIPLIER,
        cooldown_max: float = DEFAULT_BAN_COOLDOWN_MAX,
    ) -> None:
        if not nodes:
            raise ValueError("EgressPool requires at least one node")
        self.nodes = nodes
        self.mode = mode
        self.tor_control = tor_control
        self.cooldown_seconds = cooldown_seconds
        self.cooldown_multiplier = cooldown_multiplier
        self.cooldown_max = cooldown_max
        self._rr_cursor = 0
        audit_event(
            "egress_pool_init",
            mode=mode.value,
            node_count=len(nodes),
            nodes=[{"id": n.id, "kind": n.kind.value, "role": n.role} for n in nodes],
        )

    def select(self, url: str) -> EgressNode | None:
        now = time.monotonic()
        candidates = self._candidates_for(url)
        available = [n for n in candidates if n.is_available(now)]
        if not available:
            return None
        if self.mode == EgressMode.MULTI_EGRESS:
            available.sort(key=lambda n: n.last_used)
            picked = available[0]
        else:
            picked = available[self._rr_cursor % len(available)]
            self._rr_cursor = (self._rr_cursor + 1) % len(available)
        picked.last_used = now
        picked.total_requests += 1
        return picked

    def _candidates_for(self, url: str) -> list[EgressNode]:
        if self.mode == EgressMode.DIRECT:
            return [n for n in self.nodes if n.kind == EgressKind.DIRECT]
        if self.mode == EgressMode.TOR_ONLY:
            return [n for n in self.nodes if n.kind == EgressKind.TOR]
        if is_sensitive_url(url):
            tor_nodes = [n for n in self.nodes if n.kind == EgressKind.TOR]
            if tor_nodes:
                return tor_nodes
        return [n for n in self.nodes if n.kind in (EgressKind.PROXY, EgressKind.TOR)]

    def mark_failure(self, node: EgressNode, reason: str) -> None:
        node.consecutive_failures += 1
        node.total_failures += 1
        audit_event(
            "egress_failure",
            egress_id=node.id,
            reason=reason,
            consecutive=node.consecutive_failures,
        )

    def mark_success(self, node: EgressNode) -> None:
        node.consecutive_failures = 0

    def mark_banned(self, node: EgressNode, reason: str) -> None:
        base = self.cooldown_seconds * (
            self.cooldown_multiplier ** max(0, node.consecutive_failures - 1)
        )
        cooldown = min(base, self.cooldown_max)
        node.cooldown_until = time.monotonic() + cooldown
        audit_event(
            "egress_banned",
            egress_id=node.id,
            kind=node.kind.value,
            reason=reason,
            cooldown_seconds=cooldown,
        )
        # A defense event must never trigger a new identity to continue testing.

    def has_available(self) -> bool:
        now = time.monotonic()
        return any(n.is_available(now) for n in self.nodes)

    def summary(self) -> dict:
        return {
            "mode": self.mode.value,
            "nodes": [
                {
                    "id": n.id,
                    "kind": n.kind.value,
                    "role": n.role,
                    "total_requests": n.total_requests,
                    "total_failures": n.total_failures,
                    "in_cooldown": not n.is_available(),
                }
                for n in self.nodes
            ],
        }


def build_pool_direct() -> EgressPool:
    direct = EgressNode(id="direct", kind=EgressKind.DIRECT, url=None, role="general")
    return EgressPool([direct], mode=EgressMode.DIRECT)


def build_pool_tor_only(
    socks_url: str = DEFAULT_TOR_SOCKS_PROXY,
    tor_control: TorControlClient | None = None,
) -> EgressPool:
    _validate_proxy_url(socks_url)
    tor = EgressNode(id="tor-default", kind=EgressKind.TOR, url=socks_url, role="general")
    return EgressPool([tor], mode=EgressMode.TOR_ONLY, tor_control=tor_control)


def _proxy_kind(proxy_url: str) -> EgressKind:
    scheme = urlsplit(proxy_url).scheme.lower()
    return EgressKind.TOR if scheme in SOCKS_PROXY_SCHEMES else EgressKind.PROXY


def _read_legacy_proxy_urls(args) -> list[str]:
    urls: list[str] = []
    if getattr(args, "web_proxy", None):
        urls.append(args.web_proxy)
    proxy_file = getattr(args, "web_proxy_file", None)
    if proxy_file:
        path = Path(proxy_file).expanduser()
        if not path.exists():
            raise SystemExit(f"Proxy file not found: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                urls.append(value)
    return urls


def build_pool_from_legacy_args(args, tor_control: TorControlClient | None = None) -> EgressPool:
    urls = _read_legacy_proxy_urls(args)
    nodes: list[EgressNode] = []
    for index, proxy_url in enumerate(urls, start=1):
        _validate_proxy_url(proxy_url)
        kind = _proxy_kind(proxy_url)
        nodes.append(
            EgressNode(
                id=f"legacy-{kind.value}-{index}",
                kind=kind,
                url=proxy_url,
                role="general",
            )
        )
    if not nodes:
        return build_pool_direct()
    mode = EgressMode.TOR_ONLY if all(n.kind == EgressKind.TOR for n in nodes) else EgressMode.MULTI_EGRESS
    return EgressPool(nodes, mode=mode, tor_control=tor_control)


def build_pool_from_yaml(yaml_path: str, tor_control: TorControlClient | None = None) -> EgressPool:
    if _yaml is None:
        raise SystemExit("PyYAML required for --egress-config. Install: pip install pyyaml")
    path = Path(yaml_path)
    if not path.exists():
        raise SystemExit(f"Egress config not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = _yaml.safe_load(fh) or {}
    mode_str = str(data.get("mode", "multi_egress")).lower()
    try:
        mode = EgressMode(mode_str)
    except ValueError as exc:
        raise SystemExit(f"Invalid egress mode in YAML: {mode_str}") from exc
    if mode == EgressMode.DIRECT:
        raise SystemExit(
            "--egress-config cannot use mode: direct. Omit --egress-config for direct mode, "
            "or use mode: multi_egress/tor_only for proxy-routed web-only checks."
        )
    nodes: list[EgressNode] = []
    tor_cfg = data.get("tor") or {}
    if tor_cfg.get("enabled"):
        socks_url = tor_cfg.get("socks_url", DEFAULT_TOR_SOCKS_PROXY)
        _validate_proxy_url(socks_url)
        nodes.append(
            EgressNode(id="tor-default", kind=EgressKind.TOR, url=socks_url, role="sensitive")
        )
    for entry in data.get("proxies") or []:
        url = entry.get("url")
        if not url:
            continue
        _validate_proxy_url(url)
        nodes.append(
            EgressNode(
                id=str(entry.get("id") or url),
                kind=EgressKind.PROXY,
                url=url,
                role=str(entry.get("role", "recon")),
            )
        )
    if not nodes:
        raise SystemExit("Egress config produced zero nodes")
    if mode == EgressMode.MULTI_EGRESS and not any(n.kind == EgressKind.PROXY for n in nodes):
        logging.warning("multi_egress mode but no proxies - falling back to tor_only")
        mode = EgressMode.TOR_ONLY
    return EgressPool(nodes, mode=mode, tor_control=tor_control)


def _maybe_tor_control(args) -> TorControlClient | None:
    return TorControlClient(
        host=getattr(args, "tor_control_host", DEFAULT_TOR_CONTROL_HOST),
        port=getattr(args, "tor_control_port", DEFAULT_TOR_CONTROL_PORT),
        password=getattr(args, "tor_control_password", None),
        cookie_file=getattr(args, "tor_control_cookie", None),
        new_identity_wait=getattr(args, "tor_new_identity_wait", DEFAULT_TOR_NEW_IDENTITY_WAIT),
    )


def build_egress_from_args(args) -> EgressPool:
    if getattr(args, "egress_config", None):
        return build_pool_from_yaml(args.egress_config, tor_control=_maybe_tor_control(args))
    if getattr(args, "web_tor", False):
        return build_pool_tor_only(tor_control=_maybe_tor_control(args))
    if getattr(args, "web_proxy", None) or getattr(args, "web_proxy_file", None):
        return build_pool_from_legacy_args(args, tor_control=_maybe_tor_control(args))
    return build_pool_direct()


class BanSignalAnalyzer:
    """Multi-signal ban detection. Aggregates soft signals until threshold."""

    def __init__(
        self,
        stop_statuses: set[int],
        soft_threshold: int = DEFAULT_BAN_SOFT_THRESHOLD,
        window: int = 20,
    ) -> None:
        self.stop_statuses = stop_statuses
        self.soft_threshold = soft_threshold
        self.window = window
        self._stats: dict[str, deque] = {}
        self._soft_count: dict[str, int] = {}

    def _bucket(self, egress_id: str) -> deque:
        if egress_id not in self._stats:
            self._stats[egress_id] = deque(maxlen=self.window)
        return self._stats[egress_id]

    def record(self, egress_id: str, status: int, latency_ms: float, size: int) -> None:
        self._bucket(egress_id).append((status, latency_ms, size, time.monotonic()))

    def evaluate(
        self,
        egress_id: str,
        status: int,
        body: bytes,
        latency_ms: float,
    ) -> tuple[bool, str | None]:
        if status in self.stop_statuses:
            self._soft_count[egress_id] = 0
            return True, f"hard:http_{status}"
        soft_reasons: list[str] = []
        text_sample = memoryview(body)[:4096].tobytes().decode("utf-8", errors="ignore")
        match = _BLOCK_BODY_RE.search(text_sample)
        if match:
            reason = f"body_pattern:{match.group(0)[:32]}"
            if status in BLOCK_CONTEXT_STATUS_CODES:
                self._soft_count[egress_id] = 0
                return True, f"hard:{reason}"
            soft_reasons.append(f"soft:{reason}")
        bucket = self._bucket(egress_id)
        if len(bucket) >= 5:
            recent_latencies = [item[1] for item in bucket if item[1] > 0]
            if recent_latencies:
                baseline = statistics.median(recent_latencies)
                if baseline > 0 and latency_ms > baseline * PACING_SLOWDOWN_THRESHOLD:
                    soft_reasons.append("soft:latency_spike")
            sizes = [item[2] for item in bucket if item[2] > 0]
            if len(sizes) >= 5:
                median_size = statistics.median(sizes)
                current_size = len(body)
                if median_size > 100 and current_size < median_size * 0.3:
                    soft_reasons.append("soft:size_dropoff")
        for reason in soft_reasons:
            self._soft_count[egress_id] = self._soft_count.get(egress_id, 0) + 1
            audit_event("ban_soft_signal", egress_id=egress_id, reason=reason,
                        count=self._soft_count[egress_id])
        if self._soft_count.get(egress_id, 0) >= self.soft_threshold:
            self._soft_count[egress_id] = 0
            return True, "soft:threshold_exceeded"
        return False, None

    def record_error(self, egress_id: str, error_kind: str) -> tuple[bool, str | None]:
        self._soft_count[egress_id] = self._soft_count.get(egress_id, 0) + 1
        audit_event(
            "ban_soft_signal",
            egress_id=egress_id,
            reason=f"soft:{error_kind}",
            count=self._soft_count[egress_id],
        )
        if self._soft_count[egress_id] >= self.soft_threshold:
            self._soft_count[egress_id] = 0
            return True, f"soft:network_errors:{error_kind}"
        return False, None


class AdaptivePacer:
    """Per-target jittered delay with adaptive slowdown on degradation."""

    def __init__(self, base_delay: float, sensitive_delay: float, max_global_rate: int) -> None:
        self.base_delay = max(0.0, base_delay)
        self.sensitive_delay = max(self.base_delay, sensitive_delay)
        self.max_global_rate = max(1, max_global_rate)
        self._lock = asyncio.Lock()
        self._last_request = 0.0
        self._latency_history: deque = deque(maxlen=PACING_BASELINE_WINDOW)
        self._slowdown_factor = 1.0

    def record_latency(self, latency_ms: float) -> None:
        self._latency_history.append(latency_ms)

    def _adjust_slowdown(self) -> None:
        if len(self._latency_history) < 5:
            return
        median = statistics.median(self._latency_history)
        recent = list(self._latency_history)[-3:]
        avg_recent = sum(recent) / len(recent)
        if median > 0 and avg_recent > median * PACING_SLOWDOWN_THRESHOLD:
            self._slowdown_factor = min(4.0, self._slowdown_factor * 1.5)
            audit_event("pacer_slowdown", factor=self._slowdown_factor)
        else:
            if self._slowdown_factor > 1.0:
                self._slowdown_factor = max(1.0, self._slowdown_factor * 0.9)

    async def wait(self, url: str) -> None:
        async with self._lock:
            self._adjust_slowdown()
            global_floor = 60.0 / self.max_global_rate
            endpoint_delay = self.sensitive_delay if is_sensitive_url(url) else self.base_delay
            jitter = random.uniform(JITTER_LOW, JITTER_HIGH)
            required = max(global_floor, endpoint_delay) * jitter * self._slowdown_factor
            # Reserve a future send slot for this request, then release the lock so
            # concurrent callers stagger across the timeline instead of serializing.
            target_time = max(time.monotonic(), self._last_request + required)
            self._last_request = target_time
        wait_time = target_time - time.monotonic()
        if wait_time > 0:
            await asyncio.sleep(wait_time)


class DecoyInjector:
    """Decides whether to enqueue a decoy request before a sensitive one."""

    def __init__(self, rate: float, paths: list[str]) -> None:
        self.rate = max(0.0, min(1.0, rate))
        self.paths = paths or list(DECOY_FALLBACK_PATHS)

    def should_inject(self) -> bool:
        if not self.paths or self.rate <= 0.0:
            return False
        return random.random() < self.rate

    def pick(self) -> str:
        return random.choice(self.paths)
