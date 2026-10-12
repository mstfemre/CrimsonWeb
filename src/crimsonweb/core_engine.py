#!/usr/bin/env python3
"""
CrimsonWeb Core Engine v2.1
Authorized adversary-emulation web/service scanner.
USE ONLY against targets in an authorized lab, school project,
or assessment scope. An optional engagement identifier can be
logged to the audit trail when available.
What this engine does:
  - Resolves IPv4 and IPv6 targets.
  - Scans TCP ports (async-connect default, optional SYN with Scapy).
  - Detects services via lightweight protocol probes.
  - Auto-detects HTTP vs HTTPS regardless of port.
  - Passive WAF/header fingerprinting.
  - Checks a fixed list of sensitive web paths.
  - Queries NVD CVEs with caching and bounded concurrency.
  - Multi-egress routing: direct, Tor-only, or Tor+dedicated proxies.
  - Adaptive pacing with jitter and ban-aware backoff.
  - Multi-signal ban detection (status, body pattern, RST rate,
    response-time anomalies, response-size anomalies).
  - Optional JA3/TLS fingerprint spoofing via curl_cffi.
  - Decoy traffic injection from passive recon + fallback list.
  - Checkpoint/resume.
  - Dual audit log (text + JSONL).
  - Executive-summary Markdown report.
Hukuki uyarı:
Bu araç YALNIZCA yazılı izninizin olduğu sistemlere karşı kullanılabilir.
İzinsiz tarama TCK 243-244 kapsamında suçtur.
"""
from __future__ import annotations
import argparse
import asyncio
import csv
import ctypes
import getpass
import json
import logging
import os
import random
import re
import socket
import sys
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from .audit import (
    audit_event,
    close_audit_log,
    redact_cli_args,
    setup_logging,
)
from .cve import CveLookup, HTTPX_IMPORT_ERROR, THROTTLE_IMPORT_ERROR
from .cli_commands import normalize_command_argv, run_utility_command
from .discovery.connect import (
    AsyncConnectScanner,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_PORT_CONCURRENCY,
)
from .discovery.syn import SynScanner
from .discovery.udp import DEFAULT_UDP_TIMEOUT, UdpScanner
from .egress import (
    AdaptivePacer,
    BanSignalAnalyzer,
    DECOY_FALLBACK_PATHS,
    DEFAULT_BAN_COOLDOWN_SECONDS,
    DEFAULT_BAN_SOFT_THRESHOLD,
    DEFAULT_DECOY_RATE,
    DEFAULT_TOR_CONTROL_HOST,
    DEFAULT_TOR_CONTROL_PORT,
    DEFAULT_TOR_NEW_IDENTITY_WAIT,
    DEFAULT_TOR_SOCKS_PROXY,
    DEFAULT_WEB_MAX_GLOBAL_RATE,
    DEFAULT_WEB_REQUEST_DELAY,
    DEFAULT_WEB_SENSITIVE_DELAY,
    DecoyInjector,
    EgressKind,
    EgressMode,
    EgressNode,
    EgressPool,
    SOCKS_PROXY_SCHEMES,
    TorControlClient,
    build_egress_from_args,
    parse_status_codes,
    redact_proxy_url,
)
from .models import ServiceResult, WebBlockEvent, WebResponse
from .state import ScanState, default_state_path, load_state, save_state
from .ports import DEFAULT_TOP_PORTS_COUNT, looks_like_ip, parse_ports, target_from_args
from .reporting import web_finding_count, write_executive_report
from .service_detection import (
    DEFAULT_BANNER_TIMEOUT,
    DEFAULT_SERVICE_CONCURRENCY,
    ServiceDetector,
    extract_san_dns_names,
)

# --------------------------------------------------------------------------
# Optional dependencies — gracefully degraded
# --------------------------------------------------------------------------
try:
    import aiohttp
except ImportError as exc:
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_IMPORT_ERROR = exc
else:
    AIOHTTP_IMPORT_ERROR = None
try:
    from aiohttp_socks import ProxyConnector
except ImportError as exc:
    ProxyConnector = None  # type: ignore[assignment]
    AIOHTTP_SOCKS_IMPORT_ERROR = exc
else:
    AIOHTTP_SOCKS_IMPORT_ERROR = None
try:
    from curl_cffi.requests import AsyncSession as _CurlCffiAsyncSession  # type: ignore[import]
    CURL_CFFI_AVAILABLE = True
except ImportError:
    _CurlCffiAsyncSession = None  # type: ignore[assignment]
    CURL_CFFI_AVAILABLE = False
try:
    from colorama import Fore, Style, init as colorama_init
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        LIGHTBLACK_EX = RESET_ALL = BRIGHT = ""
    Fore = Style = _NoColor()  # type: ignore[assignment]
    def colorama_init(*_args, **_kwargs):
        return None
# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
APP_NAME = "CrimsonWeb"
APP_VERSION = "2.1.0"
REPORT_PREFIX = "crimsonweb"
RECON_MAX_LINKS = 30
RECON_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"
)
GENERIC_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
)
# curl_cffi fingerprint profile names
FINGERPRINT_PROFILES = {
    "chrome120": "chrome120",
    "chrome119": "chrome119",
    "firefox120": "firefox120",
    "safari17": "safari17_0",
}
ROE_REF_PATTERN = re.compile(r"^[A-Za-z0-9._\-:/]{4,128}$")
# Common second-level labels under multi-part public suffixes (co.uk, gov.tr, ...).
# Heuristic — no public-suffix-list dependency — kept conservative so scope
# derivation never over-expands beyond the target's own registrable domain.
SCOPE_SECOND_LEVEL_LABELS = frozenset(
    {"co", "com", "org", "net", "gov", "edu", "ac", "mil", "gob", "or", "ne", "go", "k12"}
)


def derive_scope_root(hostname: str) -> str:
    """Best-effort registrable domain of the target, used as the scope anchor.

    ``api.dev.example.com`` -> ``example.com``; ``portal.example.co.uk`` ->
    ``example.co.uk``. Only this registrable domain and its subdomains are ever
    treated as in-scope for dynamic discovery.
    """
    host = (hostname or "").strip().lower().rstrip(".")
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return host
    if labels[-2] in SCOPE_SECOND_LEVEL_LABELS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_in_scope(candidate: str, scope_root: str) -> bool:
    """True iff ``candidate`` is the scope root or a subdomain of it."""
    candidate = (candidate or "").strip().lower().rstrip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    root = (scope_root or "").strip().lower().rstrip(".")
    if not candidate or not root:
        return False
    return candidate == root or candidate.endswith("." + root)
class TimingScope:
    __slots__ = ("_started", "elapsed_ms")
    def __init__(self) -> None:
        self._started = 0.0
        self.elapsed_ms = 0.0
    def __enter__(self) -> "TimingScope":
        self._started = time.monotonic()
        return self
    def __exit__(self, *_exc) -> None:
        self.elapsed_ms = (time.monotonic() - self._started) * 1000.0
def _add_mitre_mapping(
    mappings: list[dict[str, str]],
    seen: set[str],
    technique_id: str,
    technique: str,
    reason: str,
) -> None:
    if technique_id in seen:
        return
    seen.add(technique_id)
    mappings.append({"id": technique_id, "technique": technique, "reason": reason})
def mitre_mappings_for_result(result: ServiceResult) -> list[dict[str, str]]:
    mappings: list[dict[str, str]] = []
    seen: set[str] = set()
    if result.state == "open":
        _add_mitre_mapping(
            mappings,
            seen,
            "T1046",
            "Network Service Discovery",
            "Open service exposed during authorized discovery",
        )
    if result.service in {"http", "https"} and (
        result.cves or result.cors_findings or result.security_headers or result.cookie_findings
    ):
        _add_mitre_mapping(
            mappings,
            seen,
            "T1190",
            "Exploit Public-Facing Application",
            "Public-facing web weakness or vulnerable component indicator",
        )
    if any(re.search(r"(\.env|\.git|config|wp-config|\.htpasswd)", item.path, re.IGNORECASE)
           for item in result.sensitive_paths):
        _add_mitre_mapping(
            mappings,
            seen,
            "T1552.001",
            "Credentials In Files",
            "Sensitive configuration or credential-like path exposure",
        )
    if result.api_paths:
        _add_mitre_mapping(
            mappings,
            seen,
            "T1595.002",
            "Vulnerability Scanning",
            "API documentation or endpoint indicator useful for external reconnaissance",
        )
    remote_service_map = {
        "ssh": ("T1021.004", "SSH"),
        "rdp": ("T1021.001", "Remote Desktop Protocol"),
        "smb": ("T1021.002", "SMB/Windows Admin Shares"),
    }
    mapped = remote_service_map.get(result.service)
    if mapped:
        _add_mitre_mapping(
            mappings,
            seen,
            mapped[0],
            mapped[1],
            f"{result.service.upper()} remote access service exposed",
        )
    return mappings
# --------------------------------------------------------------------------
# Passive recon — discover real paths for decoy pool
# --------------------------------------------------------------------------
async def passive_recon(
    target_url: str,
    timeout: float = 5.0,
    web_controller: Any | None = None,
    verify_tls: bool = True,
    max_links: int = RECON_MAX_LINKS,
) -> list[str]:
    """Fetch robots.txt + sitemap.xml + homepage; extract internal paths."""
    if aiohttp is None:
        return []
    discovered: set[str] = set()
    headers = {"User-Agent": RECON_USER_AGENT}
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    parsed = urlsplit(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    candidate_urls = [
        f"{base}/robots.txt",
        f"{base}/sitemap.xml",
        f"{base}/",
    ]
    async def fetch(session, url: str) -> tuple[str, int, bytes] | None:
        try:
            if web_controller is not None:
                ssl_policy = web_controller.ssl_policy() if hasattr(web_controller, "ssl_policy") else None
                response = await web_controller.request(
                    session,
                    url,
                    client_timeout,
                    ssl_policy=ssl_policy,
                    allow_redirects=True,
                    is_decoy=True,
                )
                if response is None:
                    return None
                return url, response.status, response.body
            async with session.get(
                url,
                allow_redirects=True,
                ssl=None if verify_tls else False,
            ) as resp:
                body = await resp.read()
                return url, resp.status, body
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return None
    # JS recon: SPA (React/Vue) API endpoints often live only inside JS bundles.
    from urllib.parse import urljoin
    max_js_files = 5
    max_js_bytes = 512_000
    js_src_re = re.compile(
        r'<script[^>]+src=["\']([^"\']+?\.js(?:[?#][^"\']*)?)["\']', re.IGNORECASE
    )
    js_api_re = re.compile(
        r'["\'](/(?:api|v[0-9]|users|auth|login|admin|graphql)[a-zA-Z0-9_\-./]*)["\']'
    )
    js_path_re = re.compile(r'["\'](/[a-zA-Z0-9_\-./]+)["\']')
    js_static_ext = (
        ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp",
    )
    js_urls: list[str] = []
    async with aiohttp.ClientSession(timeout=client_timeout, headers=headers) as session:
        results = await asyncio.gather(
            *(fetch(session, url) for url in candidate_urls),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception) or result is None:
                continue
            url, status, body = result
            if status != 200:
                continue
            text = body.decode("utf-8", errors="ignore")
            if url.endswith("robots.txt"):
                for line in text.splitlines():
                    line = line.strip()
                    if line.lower().startswith(("allow:", "disallow:")):
                        _, _, path = line.partition(":")
                        path = path.strip()
                        if path and path.startswith("/") and path != "/":
                            discovered.add(path)
            elif url.endswith("sitemap.xml"):
                for match in re.finditer(r"<loc>([^<]+)</loc>", text):
                    loc = match.group(1).strip()
                    loc_parsed = urlsplit(loc)
                    if loc_parsed.netloc == parsed.netloc and loc_parsed.path:
                        discovered.add(loc_parsed.path)
            else:
                for match in re.finditer(
                    r'href=["\'](/[^"\'#?\s]+)', text, re.IGNORECASE
                ):
                    href = match.group(1)
                    if not href.startswith("//"):
                        discovered.add(href)
                # Collect same-origin <script src="...js"> bundles for JS recon.
                for match in js_src_re.finditer(text):
                    js_abs = urljoin(url, match.group(1).strip())
                    if urlsplit(js_abs).netloc == parsed.netloc and js_abs not in js_urls:
                        js_urls.append(js_abs)
        # Fetch a bounded set of JS bundles and mine them for API/relative paths.
        if js_urls:
            js_results = await asyncio.gather(
                *(fetch(session, js_url) for js_url in js_urls[:max_js_files]),
                return_exceptions=True,
            )
            for js_result in js_results:
                if isinstance(js_result, Exception) or js_result is None:
                    continue
                _js_url, js_status, js_body = js_result
                if js_status != 200:
                    continue
                js_text = js_body[:max_js_bytes].decode("utf-8", errors="ignore")
                for match in js_api_re.finditer(js_text):
                    discovered.add(match.group(1))
                for match in js_path_re.finditer(js_text):
                    candidate = match.group(1)
                    if 2 <= len(candidate) <= 120 and not candidate.lower().endswith(js_static_ext):
                        discovered.add(candidate)
    paths = sorted(discovered)[:max(0, max_links)]
    audit_event("passive_recon_done", target=target_url, paths_found=len(paths))
    return paths
# --------------------------------------------------------------------------
# Web request controller — aiohttp + optional curl_cffi backend
# --------------------------------------------------------------------------
class WebRequestController:
    """
    Routes web requests through the egress pool. Applies adaptive pacing,
    ban detection, optional fingerprint spoofing, and decoy injection.
    """
    def __init__(
        self,
        egress: EgressPool,
        pacer: AdaptivePacer,
        ban_analyzer: BanSignalAnalyzer,
        decoy: DecoyInjector,
        max_retries: int = 0,
        user_agent: str | None = None,
        fingerprint: str | None = None,
        verify_tls: bool = True,
        state: ScanState | None = None,
        state_path: Path | None = None,
    ) -> None:
        self.egress = egress
        self.pacer = pacer
        self.ban_analyzer = ban_analyzer
        self.decoy = decoy
        self.max_retries = max(0, max_retries)
        self.user_agent = user_agent
        self.fingerprint = fingerprint if (fingerprint and CURL_CFFI_AVAILABLE) else None
        self.verify_tls = verify_tls
        self.state = state
        self.state_path = state_path
        self.block_events: list[WebBlockEvent] = []
        self._blocked_targets: set[tuple[str, str]] = set()
        self._halted = False
        self._socks_sessions: dict[str, aiohttp.ClientSession] = {}
        self._curl_session = None
        if fingerprint and not CURL_CFFI_AVAILABLE:
            logging.warning(
                "--fingerprint requested but curl_cffi not installed; falling back to aiohttp"
            )
    @property
    def uses_proxy(self) -> bool:
        return self.egress.mode != EgressMode.DIRECT
    def ssl_policy(self):
        return None if self.verify_tls else False
    @staticmethod
    def _target_key(url: str) -> tuple[str, str]:
        parsed = urlsplit(url)
        return parsed.netloc.lower(), parsed.path or "/"
    def is_blocked(self, url: str) -> bool:
        return self._halted or self._target_key(url) in self._blocked_targets
    def _build_headers(self, extra_headers: dict[str, str] | None = None) -> dict[str, str]:
        ua = self.user_agent or random.choice(GENERIC_USER_AGENTS)
        # Chrome-like header ordering (Python dicts preserve insertion order)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers
    @staticmethod
    def _response_headers(headers) -> dict[str, Any]:
        normalized = {str(k).lower(): v for k, v in dict(headers).items()}
        getall = getattr(headers, "getall", None)
        if callable(getall):
            cookies = list(getall("Set-Cookie", []))
            if cookies:
                normalized["set-cookie-list"] = cookies
                normalized["set-cookie"] = cookies[0] if len(cookies) == 1 else cookies
        return normalized
    async def _persist_state_if_any(self) -> None:
        if self.state is None or self.state_path is None:
            return
        try:
            await asyncio.to_thread(save_state, self.state, self.state_path)
        except Exception as exc:
            logging.warning("state persistence failed: %s", exc)
    async def aclose(self) -> None:
        sessions = list(self._socks_sessions.values())
        self._socks_sessions.clear()
        for session in sessions:
            if not session.closed:
                await session.close()
    def _socks_session(self, proxy_url: str, timeout) -> aiohttp.ClientSession:
        session = self._socks_sessions.get(proxy_url)
        if session is not None and not session.closed:
            return session
        if ProxyConnector is None:
            raise RuntimeError("aiohttp_socks not installed")
        connector = ProxyConnector.from_url(proxy_url)
        session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        self._socks_sessions[proxy_url] = session
        return session
    async def request(
        self,
        session,  # aiohttp.ClientSession
        url: str,
        timeout,
        ssl_policy,
        allow_redirects: bool = False,
        is_decoy: bool = False,
        extra_headers: dict[str, str] | None = None,
        block_on_ban: bool = True,
    ) -> WebResponse | None:
        if self.is_blocked(url):
            audit_event("skip_blocked", url=url)
            return None
        # Maybe inject a decoy before this real request (don't recurse on decoys themselves)
        if not is_decoy and self.decoy.should_inject():
            decoy_path = self.decoy.pick()
            parsed = urlsplit(url)
            decoy_url = f"{parsed.scheme}://{parsed.netloc}{decoy_path}"
            await self.request(session, decoy_url, timeout, ssl_policy, allow_redirects, is_decoy=True)
        for attempt in range(self.max_retries + 1):
            if self.is_blocked(url):
                return None
            node = self.egress.select(url)
            if node is None:
                audit_event("no_egress_available", url=url)
                logging.warning("All egress nodes in cooldown — pausing 30s")
                await asyncio.sleep(30.0)
                continue
            await self.pacer.wait(url)
            if self.is_blocked(url):
                return None
            headers = self._build_headers(extra_headers)
            timer = TimingScope()
            try:
                with timer:
                    response = await self._send_request(
                        session=session,
                        url=url,
                        timeout=timeout,
                        ssl_policy=ssl_policy,
                        node=node,
                        headers=headers,
                        allow_redirects=allow_redirects,
                    )
                response.latency_ms = timer.elapsed_ms
                response.egress_id = node.id
            except Exception as exc:
                self.egress.mark_failure(node, f"transport:{type(exc).__name__}")
                banned, reason = self.ban_analyzer.record_error(node.id, type(exc).__name__)
                if banned and reason is not None:
                    self.egress.mark_banned(node, reason)
                    self._halted = True
                audit_event(
                    "http_error",
                    url=url,
                    egress_id=node.id,
                    error=type(exc).__name__,
                )
                if self._halted or attempt >= self.max_retries:
                    return None
                await asyncio.sleep(min(30.0, max(1.0, self.pacer.base_delay) * (2 ** attempt)))
                continue
            self.pacer.record_latency(response.latency_ms)
            self.ban_analyzer.record(node.id, response.status, response.latency_ms, len(response.body))
            audit_event(
                "http_request",
                url=url,
                status=response.status,
                egress_id=node.id,
                latency_ms=round(response.latency_ms, 2),
                size=len(response.body),
                decoy=is_decoy,
            )
            banned, reason = self.ban_analyzer.evaluate(
                node.id, response.status, response.body, response.latency_ms
            )
            if response.status in {403, 429}:
                banned, reason = True, f"http_{response.status}_safe_stop"
            if banned and reason is not None:
                self._halted = True
                self.egress.mark_banned(node, reason)
                self._blocked_targets.add(self._target_key(url))
                event = WebBlockEvent(
                    url=url,
                    status=response.status,
                    reason=reason,
                    proxy=redact_proxy_url(node.url),
                    egress_id=node.id,
                )
                self.block_events.append(event)
                if self.state is not None:
                    self.state.egress_cooldowns[node.id] = time.time()
                    await self._persist_state_if_any()
                # Fingerprinting may inspect this response, but cannot send again.
                return response if not block_on_ban and not is_decoy else None
            self.egress.mark_success(node)
            return response
        return None
    async def _send_request(
        self,
        session,
        url: str,
        timeout,
        ssl_policy,
        node: EgressNode,
        headers: dict[str, str],
        allow_redirects: bool,
    ) -> WebResponse:
        # curl_cffi path: full JA3/TLS fingerprint spoofing
        if self.fingerprint:
            return await self._send_via_curl_cffi(url, node, headers, timeout, allow_redirects)
        # SOCKS proxy via aiohttp_socks. Sessions are pooled per proxy URL.
        if node.url and urlsplit(node.url).scheme.lower() in SOCKS_PROXY_SCHEMES:
            proxy_session = self._socks_session(node.url, timeout)
            async with proxy_session.get(
                url,
                timeout=timeout,
                ssl=ssl_policy,
                allow_redirects=allow_redirects,
                headers=headers,
            ) as response:
                body = await response.read()
                return WebResponse(
                    url=url,
                    status=response.status,
                    headers=self._response_headers(response.headers),
                    body=body,
                    proxy=redact_proxy_url(node.url),
                )
        # HTTP proxy via aiohttp native
        proxy_arg = node.url if node.kind == EgressKind.PROXY else None
        async with session.get(
            url,
            timeout=timeout,
            ssl=ssl_policy,
            allow_redirects=allow_redirects,
            headers=headers,
            proxy=proxy_arg,
        ) as response:
            body = await response.read()
            return WebResponse(
                url=url,
                status=response.status,
                headers=self._response_headers(response.headers),
                body=body,
                proxy=redact_proxy_url(node.url),
            )
    async def _send_via_curl_cffi(
        self,
        url: str,
        node: EgressNode,
        headers: dict[str, str],
        timeout,
        allow_redirects: bool,
    ) -> WebResponse:
        if _CurlCffiAsyncSession is None:
            raise RuntimeError("curl_cffi not available")
        impersonate = FINGERPRINT_PROFILES.get(self.fingerprint, "chrome120")
        proxies = None
        if node.url:
            proxies = {"http": node.url, "https": node.url}
        total_timeout = getattr(timeout, "total", None) or 10.0
        async with _CurlCffiAsyncSession(impersonate=impersonate) as cs:
            r = await cs.get(
                url,
                headers=headers,
                proxies=proxies,
                allow_redirects=allow_redirects,
                timeout=total_timeout,
                verify=self.verify_tls,
            )
            body = r.content if isinstance(r.content, bytes) else (r.content or b"")
            return WebResponse(
                url=url,
                status=r.status_code,
                headers=self._response_headers(dict(r.headers)),
                body=body,
                proxy=redact_proxy_url(node.url),
            )
    def report_metadata(self) -> dict:
        return {
            "egress": self.egress.summary(),
            "blocked_targets": [asdict(event) for event in self.block_events],
            "fingerprint_profile": self.fingerprint,
            "decoy_rate": self.decoy.rate,
        }
# --------------------------------------------------------------------------
# Platform helpers
# --------------------------------------------------------------------------
def has_elevated_privileges() -> bool:
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    try:
        return geteuid() == 0
    except Exception:
        return False
# Diff engine
# --------------------------------------------------------------------------
class DiffEngine:
    @staticmethod
    def compare(old_report_path: str, current: dict[int, ServiceResult], base_dir: str | Path = ".") -> list[str]:
        base_path = Path(base_dir).resolve()
        path = Path(old_report_path)
        if not path.is_absolute():
            path = base_path / path
        if path.suffix.lower() != ".json":
            return [f"Rejected compare path with non-JSON extension: {path}"]
        if not path.exists():
            return [f"Previous report not found: {path}"]
        path = path.resolve(strict=True)
        try:
            path.relative_to(base_path)
        except ValueError:
            return [f"Rejected compare path outside output directory: {path}"]
        if not path.is_file():
            return [f"Rejected compare path that is not a file: {path}"]
        with path.open("r", encoding="utf-8") as handle:
            old_report = json.load(handle)
        old_ports = {int(item["port"]): item for item in old_report.get("ports", [])}
        messages: list[str] = []
        for port, result in current.items():
            old = old_ports.get(port)
            if old is None:
                messages.append(f"New open port: {port}/{result.transport} ({result.service} {result.version})")
                continue
            if result.version != old.get("version"):
                messages.append(f"Version changed on port {port}: {old.get('version')} -> {result.version}")
        for old_port in sorted(set(old_ports) - set(current)):
            messages.append(f"Previously open port is no longer open: {old_port}")
        return messages
# --------------------------------------------------------------------------
# UI helpers
# --------------------------------------------------------------------------
def print_banner() -> None:
    from .ui import print_banner as show_banner
    show_banner(APP_VERSION)
def print_stage(title: str, detail: str = "") -> None:
    from .ui import print_stage as show_stage
    show_stage(title, detail)
def render_progress(prefix: str, done: int, total: int, width: int = 28) -> str:
    total = max(total, 1)
    ratio = min(max(done / total, 0.0), 1.0)
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    percent = int(ratio * 100)
    return f"{prefix} [{bar}] {percent:>3}% ({done}/{total})"
def trim_text(value: str | None, width: int) -> str:
    text = (value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."
def result_color(result: ServiceResult) -> str:
    if result.service in {"http", "https"}:
        return Fore.GREEN
    if result.service in {"ssh", "smtp", "ftp", "mysql", "pop3", "imap/pop"}:
        return Fore.CYAN
    if result.cves or result.sensitive_paths or result.api_paths or result.security_headers or result.cookie_findings or result.cors_findings:
        return Fore.YELLOW
    return Fore.WHITE
# --------------------------------------------------------------------------
# BlueScanner — orchestrator
# --------------------------------------------------------------------------
class BlueScanner:
    def __init__(self, args: argparse.Namespace) -> None:
        apply_runtime_profile(args)
        self.args = args
        self.target = target_from_args(args)
        self.target_is_ip = looks_like_ip(self.target.original)
        self.scope_root = (
            self.target.original.lower().rstrip(".")
            if self.target_is_ip
            else derive_scope_root(self.target.original)
        )
        self.ports = parse_ports(args)
        self.scan_mode = self._select_scan_mode()
        self.state_path = self._resolve_state_path()
        self.state = self._load_or_init_state()
        egress = build_egress_from_args(args)
        decoy_paths = self._build_decoy_paths()
        pacer = AdaptivePacer(
            base_delay=args.web_request_delay,
            sensitive_delay=args.web_sensitive_delay,
            max_global_rate=args.web_max_global_rate,
        )
        ban = BanSignalAnalyzer(
            stop_statuses=parse_status_codes(args.web_stop_statuses),
            soft_threshold=args.ban_soft_threshold,
        )
        decoy = DecoyInjector(rate=args.decoy_rate, paths=decoy_paths)
        self.web_controller = WebRequestController(
            egress=egress,
            pacer=pacer,
            ban_analyzer=ban,
            decoy=decoy,
            max_retries=args.web_max_retries,
            user_agent=args.user_agent,
            fingerprint=args.fingerprint,
            verify_tls=not args.tls_no_verify,
            state=self.state,
            state_path=self.state_path,
        )
    def _resolve_state_path(self) -> Path:
        if self.args.state_file:
            return Path(self.args.state_file).expanduser().resolve()
        return default_state_path(self.target.original)
    def _load_or_init_state(self) -> ScanState:
        if self.args.resume:
            existing = load_state(self.state_path)
            if existing is not None:
                audit_event("state_resumed", state_path=str(self.state_path),
                            completed_ports=len(existing.completed_ports))
                return existing
            logging.info("No prior state found at %s — starting fresh", self.state_path)
        state = ScanState.new(self.target.original, roe_ref=self.args.roe_confirmed)
        save_state(state, self.state_path)
        return state
    def _build_decoy_paths(self) -> list[str]:
        if self.state.discovered_decoy_paths:
            return sorted(self.state.discovered_decoy_paths)
        return list(DECOY_FALLBACK_PATHS)
    def _select_scan_mode(self) -> str:
        if self.args.web_only:
            return "web-only"
        if self.args.syn:
            return "syn"
        return "connect"  # SYN no longer auto-selected; must be explicit
    async def _maybe_recon_decoys(self) -> None:
        """If state has no recon paths, run passive recon now."""
        if self.args.no_recon:
            return
        if self.args.decoy_rate <= 0.0:
            return
        if self.state.discovered_decoy_paths:
            return
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target.original}/"
            controller = self.web_controller if self.web_controller.uses_proxy else None
            paths = await passive_recon(
                url,
                timeout=5.0,
                web_controller=controller,
                verify_tls=not self.args.tls_no_verify,
                max_links=self.args.recon_max_links,
            )
            if paths:
                self.state.add_decoy_paths(paths)
                save_state(self.state, self.state_path)
                # Rebuild decoy injector with new paths
                self.web_controller.decoy = DecoyInjector(rate=self.args.decoy_rate, paths=paths)
                break
    async def run(self) -> int:
        print_banner()
        print_stage(
            "Session",
            f"Target: {self.target.original} ({self.target.address}) | "
            f"Ports: {len(self.ports)} | Mode: {self.scan_mode} | "
            f"Engagement: {self.args.roe_confirmed or 'N/A'}",
        )
        logging.info("Scan started for %s (%s)", self.target.original, self.target.address)
        audit_event(
            "scan_started",
            target=self.target.original,
            address=self.target.address,
            scan_mode=self.scan_mode,
            ports=len(self.ports),
            engagement_id=self.args.roe_confirmed,
        )
        if self.web_controller.uses_proxy:
            print_stage(
                "Egress Policy",
                f"Mode: {self.web_controller.egress.mode.value} | "
                f"Nodes: {len(self.web_controller.egress.nodes)} | "
                f"Pacer base: {self.web_controller.pacer.base_delay:.1f}s | "
                f"Sensitive: {self.web_controller.pacer.sensitive_delay:.1f}s | "
                f"Global cap: {self.web_controller.pacer.max_global_rate} req/min | "
                f"Decoy rate: {self.web_controller.decoy.rate:.2f}",
            )
        if not self.args.port_scan_only:
            await self._maybe_recon_decoys()
        if self.scan_mode == "web-only":
            open_ports = self.ports
            os_hints: dict[int, str] = {}
        elif self.scan_mode == "syn":
            open_ports = await asyncio.get_running_loop().run_in_executor(None, self._run_syn_scan)
            os_hints = getattr(self, "_syn_os_hints", {})
        else:
            scanner = AsyncConnectScanner(
                self.target,
                concurrency=self.args.port_concurrency,
                timeout=self.args.timeout,
            )
            open_ports = await scanner.scan(self.ports)
            os_hints = {}
        if not open_ports and not self.args.udp:
            print(Fore.YELLOW + "No open TCP ports found.")
            audit_event("scan_no_open_ports")
            return 0
        results: dict[int, ServiceResult] = {}
        if self.args.port_scan_only:
            results = {
                port: ServiceResult(
                    port=port,
                    service="unknown",
                    version="open, fingerprinting skipped",
                    notes=["Port scan only mode"],
                )
                for port in open_ports
            }
            await self.web_controller.aclose()
        else:
            cve_lookup = CveLookup(enabled=not self.args.no_cve)
            try:
                detector = ServiceDetector(
                    self.target,
                    concurrency=self.args.service_concurrency,
                    timeout=self.args.banner_timeout,
                    check_sensitive_paths=not self.args.no_web_checks,
                    cve_lookup=cve_lookup,
                    web_controller=self.web_controller,
                    web_only=self.args.web_only,
                    verify_tls=not self.args.tls_no_verify,
                )
                if open_ports:
                    results = await detector.detect(open_ports)
            finally:
                await cve_lookup.aclose()
                await self.web_controller.aclose()
        for port, hint in os_hints.items():
            if port in results:
                results[port].os_hint = hint
        if self.args.udp:
            udp_results = await UdpScanner(
                self.target,
                timeout=self.args.udp_timeout,
                include_syslog=self.args.udp_include_syslog,
            ).scan()
            for port, udp_result in udp_results.items():
                if port in results:
                    results[port].notes.append(f"UDP {udp_result.service}: {udp_result.version}")
                    continue
                results[port] = udp_result
        if not results:
            print(Fore.YELLOW + "No open TCP ports or UDP responders found.")
            return 0
        for result in results.values():
            result.mitre_attack = mitre_mappings_for_result(result)
        self._print_results(results)
        self._print_web_blocks()
        self._report_scope_discoveries(results)
        if self.args.compare:
            self._print_diff(DiffEngine.compare(self.args.compare, results, self.args.output_dir))
        report_path = self._write_report(results)
        print(Fore.CYAN + f"\nRaw report saved: {report_path}")
        # Executive markdown report (always written alongside)
        exec_path = report_path.with_suffix(".executive.md")
        write_executive_report(
            target=self.target,
            results=results,
            engagement_id=self.args.roe_confirmed,
            scan_mode=self.scan_mode,
            web_policy=self.web_controller.report_metadata(),
            raw_report_path=report_path,
            output_path=exec_path,
            tool_name=APP_NAME,
            tool_version=APP_VERSION,
        )
        print(Fore.CYAN + f"Executive report: {exec_path}")
        audit_event("scan_finished", target=self.target.original, open_services=len(results))
        logging.info("Scan finished for %s", self.target.address)
        # Save final state
        for port in results:
            self.state.mark_port_done(port)
        save_state(self.state, self.state_path)
        return 0
    def _run_syn_scan(self) -> list[int]:
        try:
            scanner = SynScanner(
                self.target,
                timeout=self.args.timeout,
                retry=self.args.retry,
                batch_size=self.args.batch_size,
            )
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
        ports = scanner.scan(self.ports)
        self._syn_os_hints = scanner.os_hints
        return ports
    @staticmethod
    def _print_diff(messages: list[str]) -> None:
        if not messages:
            return
        print_stage("Diff Report")
        for message in messages:
            print(Fore.MAGENTA + f"  - {message}")
    @staticmethod
    def _print_results(results: dict[int, ServiceResult]) -> None:
        from .ui import print_results
        print_results(results)
    def _print_web_blocks(self) -> None:
        if not self.web_controller.block_events:
            return
        print_stage("Web Blocks", f"Blocked host/path targets observed: {len(self.web_controller.block_events)}")
        for event in self.web_controller.block_events:
            print(
                Fore.YELLOW
                + f"  - {event.status} {event.url} | {event.reason} | egress={event.egress_id}"
            )
    def _collect_scope_discoveries(
        self, results: dict[int, ServiceResult]
    ) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
        """Mine TLS SANs from results, split into in-scope vs. out-of-scope.

        Scope is anchored on the original target's registrable domain
        (``self.scope_root``). When the target is an IP there is no domain scope,
        so every SAN is merely "observed" (reported, never treated as in-scope)
        to avoid straying into shared-hosting or third-party CDN infrastructure.
        """
        target_host = self.target.original.lower().rstrip(".")
        in_scope: list[tuple[str, int]] = []
        observed: list[tuple[str, int]] = []
        seen: set[str] = set()
        for port in sorted(results):
            certificate = results[port].tls_certificate
            if not certificate:
                continue
            for host in extract_san_dns_names(certificate):
                if host == target_host or host in seen:
                    continue
                seen.add(host)
                if not self.target_is_ip and is_in_scope(host, self.scope_root):
                    in_scope.append((host, port))
                else:
                    observed.append((host, port))
        return in_scope, observed
    def _report_scope_discoveries(self, results: dict[int, ServiceResult]) -> None:
        in_scope, observed = self._collect_scope_discoveries(results)
        if not in_scope and not observed:
            return
        print_stage(
            "Dynamic Scope Discovery",
            f"Scope root: {self.scope_root} | In-scope SANs: {len(in_scope)} | "
            f"Other SANs observed: {len(observed)}",
        )
        for host, port in in_scope:
            print(Fore.GREEN + Style.BRIGHT + f"  [+] Discovered Subdomain: {host} (via :{port})")
        for host, port in observed:
            print(Fore.LIGHTBLACK_EX + f"  [~] Out-of-scope SAN (not scanned): {host} (via :{port})")
        audit_event(
            "scope_discovery",
            scope_root=self.scope_root,
            in_scope=[host for host, _ in in_scope],
            observed=[host for host, _ in observed],
        )
    def _write_report(self, results: dict[int, ServiceResult]) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        safe_target = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.target.address)
        output_dir = Path(self.args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        extension = {"json": "json", "csv": "csv", "markdown": "md"}[self.args.format]
        report_path = output_dir / f"{REPORT_PREFIX}_{safe_target}_{timestamp}.{extension}"
        payload = {
            "scanner": APP_NAME,
            "version": APP_VERSION,
            "target": asdict(self.target),
            "timestamp_utc": timestamp,
            "scan_mode": self.scan_mode,
            "engagement_id": self.args.roe_confirmed,
            "web_policy": self.web_controller.report_metadata(),
            "ports": [self._serialize_result(results[port]) for port in sorted(results)],
        }
        from .privacy import sanitize
        payload = sanitize(payload)
        if self.args.format == "json":
            with report_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        elif self.args.format == "csv":
            with report_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=["port", "service", "version", "web_findings", "cves"],
                )
                writer.writeheader()
                for result in (results[port] for port in sorted(results)):
                    writer.writerow({
                        "port": result.port,
                        "service": result.service,
                        "version": result.version,
                        "web_findings": web_finding_count(result),
                        "cves": ",".join(cve.get("id", "") for cve in result.cves),
                    })
        else:
            with report_path.open("w", encoding="utf-8") as handle:
                handle.write("| Port | Service | Version | Web Findings | CVEs |\n")
                handle.write("| --- | --- | --- | --- | --- |\n")
                for result in (results[port] for port in sorted(results)):
                    cves = ", ".join(cve.get("id", "") for cve in result.cves) or "-"
                    web_findings = str(web_finding_count(result)) if web_finding_count(result) else "-"
                    handle.write(
                        f"| {result.port}/{result.transport} | {result.service} | "
                        f"{result.version.replace('|', '/')} | {web_findings} | {cves} |\n"
                    )
        return report_path
    @staticmethod
    def _serialize_result(result: ServiceResult) -> dict:
        from .privacy import sanitize
        return sanitize(asdict(result))
# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="crimsonweb",
        description=f"{APP_NAME} v{APP_VERSION} — authorized lab and assessment scanner. "
                    "Use ONLY on systems you own or have permission to assess.",
        epilog=(
            "Examples: "
            "crimsonweb -t 127.0.0.1 -p 80,443 --web-only; "
            "crimsonweb -u http://localhost:8000; "
            "crimsonweb -t example.edu --top-ports --engagement-id school-project"
        ),
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {APP_VERSION}")
    # Optional authorization / project context. --roe is kept as a legacy alias.
    parser.add_argument(
        "--engagement-id",
        "--roe",
        "--r",
        "--roe-confirmed",
        dest="roe_confirmed",
        help="Optional project, lab, or engagement identifier logged to the audit trail.",
    )
    parser.add_argument("target", nargs="?", help="Target IP or domain")
    parser.add_argument("-t", "--target", dest="target_option",
                        help="Target IP or domain (tool-style alternative to positional target)")
    parser.add_argument("-u", "--url", dest="target_url",
                        help="HTTP/HTTPS URL; host becomes target, default port derives from URL")
    parser.add_argument("-s", "--start", type=int, default=1, help="Start port for range scans")
    parser.add_argument("-e", "--end", type=int, default=65535, help="End port for range scans")
    parser.add_argument("-p", "--ports", help="Comma-separated ports/ranges, e.g.: 22,80,443,8000-8100")
    parser.add_argument("--top-ports", action="store_true", help="Use the ranked top TCP ports list")
    parser.add_argument("--top-ports-count", type=int, default=DEFAULT_TOP_PORTS_COUNT,
                        help=f"Number of ranked ports to use with --top-ports (default: {DEFAULT_TOP_PORTS_COUNT})")
    parser.add_argument("--syn", action="store_true", help="Use privileged SYN scanning via Scapy (explicit)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    parser.add_argument("--banner-timeout", type=float, default=DEFAULT_BANNER_TIMEOUT)
    parser.add_argument("--retry", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--port-concurrency", type=int, default=DEFAULT_PORT_CONCURRENCY)
    parser.add_argument("--service-concurrency", type=int, default=DEFAULT_SERVICE_CONCURRENCY)
    parser.add_argument("--fast", action="store_true",
                        help="Fast first-pass profile: shorter timeouts, higher concurrency, no CVE/recon/web path checks")
    parser.add_argument("--port-scan-only", action="store_true",
                        help="Only discover open TCP ports; skip service fingerprinting and web checks")
    parser.add_argument("--no-cve", action="store_true")
    parser.add_argument("--no-web-checks", action="store_true")
    parser.add_argument("--no-recon", action="store_true",
                        help="Skip passive recon for decoy path discovery")
    parser.add_argument("--recon-max-links", type=int, default=RECON_MAX_LINKS,
                        help=f"Maximum passive recon links to add to decoys (default: {RECON_MAX_LINKS})")
    parser.add_argument("--compare", help="Compare against a previous JSON report")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--udp-include-syslog", action="store_true",
                        help="Include UDP/514 syslog probe; may create SIEM/log entries on the target")
    parser.add_argument("--udp-timeout", type=float, default=DEFAULT_UDP_TIMEOUT)
    parser.add_argument("--format", choices=("json", "csv", "markdown"), default="json")
    parser.add_argument("--web-only", action="store_true",
                        help="Skip TCP/UDP discovery, treat selected ports as HTTP(S) targets")
    # Egress: --web-tor and --egress-config are mutually exclusive
    parser.add_argument("--web-tor", action="store_true",
                        help=f"Route web requests through local Tor SOCKS at {DEFAULT_TOR_SOCKS_PROXY}")
    parser.add_argument("--egress-config",
                        help="Path to YAML egress config (multi_egress mode)")
    # Tor control
    parser.add_argument("--tor-new-identity", action="store_true",
                        help="Request a fresh Tor circuit before scan starts")
    parser.add_argument("--tor-control-host", default=DEFAULT_TOR_CONTROL_HOST)
    parser.add_argument("--tor-control-port", type=int, default=DEFAULT_TOR_CONTROL_PORT)
    parser.add_argument("--tor-control-password")
    parser.add_argument("--tor-control-cookie")
    parser.add_argument("--tor-new-identity-wait", type=float, default=DEFAULT_TOR_NEW_IDENTITY_WAIT)
    # Legacy single-proxy (kept for backwards compatibility)
    parser.add_argument("--web-proxy", help="DEPRECATED: use --egress-config")
    parser.add_argument("--web-proxy-file", help="DEPRECATED: use --egress-config")
    # Pacing
    parser.add_argument("--web-request-delay", type=float, default=DEFAULT_WEB_REQUEST_DELAY)
    parser.add_argument("--web-sensitive-delay", type=float, default=DEFAULT_WEB_SENSITIVE_DELAY)
    parser.add_argument("--web-max-global-rate", type=int, default=DEFAULT_WEB_MAX_GLOBAL_RATE)
    parser.add_argument("--web-max-retries", type=int, default=0)
    parser.add_argument("--web-stop-statuses", default="403,429,503")
    # Ban detection
    parser.add_argument("--ban-soft-threshold", type=int, default=DEFAULT_BAN_SOFT_THRESHOLD,
                        help="Number of soft signals before egress cooldown")
    parser.add_argument("--ban-cooldown", type=float, default=DEFAULT_BAN_COOLDOWN_SECONDS,
                        help="Base cooldown seconds for banned egress nodes")
    # Optional browser/request realism controls; disabled by default.
    parser.add_argument("--user-agent", help="Fixed User-Agent string")
    parser.add_argument("--fingerprint", choices=tuple(FINGERPRINT_PROFILES),
                        help="TLS fingerprint profile via curl_cffi (optional dep)")
    parser.add_argument("--tls-no-verify", action="store_true",
                        help="Disable TLS certificate verification for both aiohttp and curl_cffi paths")
    parser.add_argument("--decoy-rate", type=float, default=DEFAULT_DECOY_RATE,
                        help="Probability of injecting a decoy request (0.0-1.0)")
    # State / resume
    parser.add_argument("--state-file", help="Custom state file path "
                                             "(default: ~/.crimsonweb/state/<hash>.json)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from prior state if available")
    return parser
def apply_runtime_profile(args: argparse.Namespace) -> None:
    if not getattr(args, "fast", False):
        return
    if args.timeout == DEFAULT_CONNECT_TIMEOUT:
        args.timeout = 0.75
    if args.banner_timeout == DEFAULT_BANNER_TIMEOUT:
        args.banner_timeout = 1.0
    if args.port_concurrency == DEFAULT_PORT_CONCURRENCY:
        args.port_concurrency = 1000
    if args.service_concurrency == DEFAULT_SERVICE_CONCURRENCY:
        args.service_concurrency = 100
    if args.batch_size == 512:
        args.batch_size = 1024
    if args.web_request_delay == DEFAULT_WEB_REQUEST_DELAY:
        args.web_request_delay = 0.0
    if args.web_sensitive_delay == DEFAULT_WEB_SENSITIVE_DELAY:
        args.web_sensitive_delay = 0.0
    if args.web_max_global_rate == DEFAULT_WEB_MAX_GLOBAL_RATE:
        args.web_max_global_rate = 6000
    args.no_cve = True
    args.no_recon = True
    args.no_web_checks = True
def normalize_target_args(args: argparse.Namespace) -> None:
    supplied = [
        name
        for name, value in (
            ("positional target", getattr(args, "target", None)),
            ("--target", getattr(args, "target_option", None)),
            ("--url", getattr(args, "target_url", None)),
        )
        if value
    ]
    if not supplied:
        raise SystemExit("target is required. Use: crimsonweb <target>, crimsonweb -t <target>, or crimsonweb -u <url>")
    if len(supplied) > 1:
        raise SystemExit("Provide only one target form: positional target, --target, or --url")
    if getattr(args, "target_option", None):
        args.target = args.target_option.strip()
        return
    if getattr(args, "target_url", None):
        parsed = urlsplit(args.target_url.strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SystemExit("--url must be an http:// or https:// URL")
        args.target = parsed.hostname
        if not args.ports and not args.top_ports:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            args.ports = str(port)
        args.web_only = True
        return
    args.target = args.target.strip()
def validate_args(args: argparse.Namespace) -> None:
    normalize_target_args(args)
    # Optional authorization context format.
    if args.roe_confirmed and not ROE_REF_PATTERN.match(args.roe_confirmed):
        raise SystemExit(
            "--engagement-id/--roe must be a token of 4-128 chars "
            "(letters, digits, ._-:/)."
        )
    # Egress mutex
    if args.web_tor and args.egress_config:
        raise SystemExit("--web-tor cannot be combined with --egress-config")
    if args.web_tor and (args.web_proxy or args.web_proxy_file):
        raise SystemExit("--web-tor cannot be combined with --web-proxy or --web-proxy-file")
    if args.egress_config and (args.web_proxy or args.web_proxy_file):
        raise SystemExit("--egress-config cannot be combined with legacy --web-proxy(-file)")
    # Tor flag implications
    if args.web_tor and not args.web_only:
        raise SystemExit("--web-tor requires --web-only (direct TCP discovery would leak your IP)")
    if args.egress_config and not args.web_only:
        raise SystemExit(
            "--egress-config requires --web-only. Run TCP port discovery from the VPS first, "
            "then run web-only checks through the approved proxy pool."
        )
    if (args.web_proxy or args.web_proxy_file) and not args.web_only:
        raise SystemExit("--web-proxy and --web-proxy-file require --web-only")
    if args.tor_new_identity and not args.web_only:
        raise SystemExit("--tor-new-identity requires --web-only")
    if args.tor_new_identity and not args.web_tor and not (args.web_proxy or "").startswith("socks5"):
        raise SystemExit("--tor-new-identity requires --web-tor or a local Tor SOCKS --web-proxy")
    # Mode combinations
    if args.web_only and args.syn:
        raise SystemExit("--web-only cannot be combined with --syn")
    if args.web_only and args.udp:
        raise SystemExit("--web-only cannot be combined with --udp")
    if args.port_scan_only and args.web_only:
        raise SystemExit("--port-scan-only cannot be combined with --web-only")
    if args.port_scan_only and args.udp:
        raise SystemExit("--port-scan-only cannot be combined with --udp")
    if args.udp_include_syslog and not args.udp:
        raise SystemExit("--udp-include-syslog requires --udp")
    if not 1 <= args.top_ports_count <= 65535:
        raise SystemExit("--top-ports-count must be between 1 and 65535")
    # SYN privilege check
    if args.syn and not has_elevated_privileges():
        raise SystemExit("--syn requires elevated privileges (run as root / Administrator)")
    # Decoy rate range
    if not 0.0 <= args.decoy_rate <= 1.0:
        raise SystemExit("--decoy-rate must be between 0.0 and 1.0")
    if args.recon_max_links < 0:
        raise SystemExit("--recon-max-links must be zero or greater")
def write_authorization_context(args: argparse.Namespace) -> None:
    """Record optional lab/engagement context as the first audit event."""
    try:
        operator = getpass.getuser()
    except Exception:
        operator = "unknown"
    sudo_user = os.environ.get("SUDO_USER") or None
    sudo_uid = os.environ.get("SUDO_UID") or None
    audit_event(
        "authorization_context",
        operator=operator,
        sudo_user=sudo_user,
        sudo_uid=sudo_uid,
        elevated=has_elevated_privileges(),
        engagement_id=args.roe_confirmed,
        host=socket.gethostname(),
        cli=redact_cli_args(sys.argv),
        version=APP_VERSION,
    )
# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main(argv: Iterable[str] | None = None) -> int:
    colorama_init(
        autoreset=True,
        strip=True if os.environ.get("NO_COLOR") or not sys.stdout.isatty() else None,
    )
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    command, parser_argv = normalize_command_argv(raw_argv)
    if command in {"doctor", "config", "init"}:
        return run_utility_command(command, parser_argv, version=APP_VERSION)
    args = build_parser().parse_args(parser_argv)
    args.command = command
    if command == "web":
        args.web_only = True
    apply_runtime_profile(args)
    validate_args(args)
    setup_logging(args.output_dir)
    try:
        write_authorization_context(args)
        if args.tls_no_verify:
            logging.warning("TLS certificate verification disabled by --tls-no-verify")
            audit_event("tls_verification_disabled")
        if AIOHTTP_IMPORT_ERROR is not None:
            raise SystemExit(
                f"Missing dependency: {AIOHTTP_IMPORT_ERROR}. "
                "Install with: python -m pip install -e ."
            )
        if HTTPX_IMPORT_ERROR is not None and not args.no_cve:
            raise SystemExit(
                f"Missing dependency for CVE lookup: {HTTPX_IMPORT_ERROR}. "
                "Install with: python -m pip install -e .[cve], or pass --no-cve."
            )
        if THROTTLE_IMPORT_ERROR is not None and not args.no_cve:
            logging.warning("asyncio_throttle not installed; CVE rate limiting disabled")
        if args.web_tor and AIOHTTP_SOCKS_IMPORT_ERROR is not None:
            raise SystemExit(
                "aiohttp_socks required for --web-tor. "
                "Install with: python -m pip install -e .[egress]"
            )
        if args.fingerprint and not CURL_CFFI_AVAILABLE:
            logging.warning(
                "--fingerprint requested but curl_cffi missing - falling back to aiohttp. "
                "Install with: python -m pip install -e .[fingerprint]"
            )
        if args.tor_new_identity:
            print(Fore.CYAN + "Requesting new Tor identity before scan...")
            TorControlClient(
                host=args.tor_control_host,
                port=args.tor_control_port,
                password=args.tor_control_password,
                cookie_file=args.tor_control_cookie,
                new_identity_wait=args.tor_new_identity_wait,
            ).signal_new_identity(strict=True)
        try:
            return asyncio.run(BlueScanner(args).run())
        except KeyboardInterrupt:
            print("\nScan interrupted.")
            audit_event("scan_interrupted")
            return 130
    finally:
        close_audit_log()
if __name__ == "__main__":
    raise SystemExit(main())
