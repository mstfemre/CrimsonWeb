"""Service fingerprint orchestration and web-service checks."""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import aiohttp
except ImportError as exc:
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_IMPORT_ERROR = exc
else:
    AIOHTTP_IMPORT_ERROR = None

try:
    from colorama import Fore, Style
except ImportError:
    class _NoColor:
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        LIGHTBLACK_EX = RESET_ALL = BRIGHT = ""
    Fore = Style = _NoColor()  # type: ignore[assignment]

from .cve import CveLookup
from .formatting import format_banner_bytes
from .models import ServiceResult, Target, WebFinding, WebResponse
from .ports import looks_like_ip
from .probes.builtin import (
    ACTIVE_PROBE_REGISTRY,
    detect_waf,
    port_hint_result,
    result_from_active_probe_response,
    service_result_from_greeting,
)
from .web_checks import (
    API_DISCOVERY_PATHS,
    CORS_TEST_ORIGIN,
    SENSITIVE_PATHS,
    analyze_cookie_flags,
    analyze_security_headers,
    cors_findings_from_headers,
)


DEFAULT_BANNER_TIMEOUT = 3.0
DEFAULT_SERVICE_CONCURRENCY = 50
MAX_HTTP_READ_BYTES = 8192
MAX_BANNER_READ_BYTES = 1024
GENERIC_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
)
WEB_PORT_HINTS = frozenset({
    80, 81, 82, 83, 84, 85, 443, 8000, 8008, 8080, 8081, 8082, 8083, 8084,
    8085, 8086, 8087, 8088, 8089, 8090, 8180, 8181, 8443, 8834, 9000, 9090,
    9443, 10000,
})
TLS_PORT_HINTS = frozenset({
    443, 465, 563, 587, 636, 853, 989, 990, 992, 993, 995, 8443, 8834, 9443,
})

# --------------------------------------------------------------------------
# Native send-expect probe engine (replaces reliance on nmap-service-probes)
# --------------------------------------------------------------------------
PROBE_DEFINITIONS_PATH = Path(__file__).with_name("probes.json")
SEND_EXPECT_READ_TIMEOUT = 3.0

# Built-in fallback mirror of probes.json, used if the file is missing/invalid
# so the scanner degrades gracefully instead of losing active fingerprinting.
DEFAULT_PROBE_DEFINITIONS: list[dict[str, Any]] = [
    {"name": "http", "probe": "GET / HTTP/1.0\r\n\r\n",
     "match_regex": r"(?i)^HTTP/1\.[01] \d{3}", "fallback_ports": [80, 8080, 443, 8443]},
    {"name": "ssh", "probe": "",
     "match_regex": r"(?i)^SSH-([\d\.]+)-([A-Za-z0-9_\-\.]+)", "fallback_ports": [22, 2222]},
    {"name": "ftp", "probe": "", "match_regex": r"(?i)^220[- ]", "fallback_ports": [21]},
    {"name": "smtp", "probe": "EHLO crimson\r\n", "match_regex": r"(?i)^220[- ]",
     "fallback_ports": [25, 587]},
]


@dataclass(slots=True)
class SendExpectProbe:
    name: str
    probe: str
    match_regex: re.Pattern[str]
    fallback_ports: frozenset[int]


# Catch-all "null" probe: sends nothing, accepts any non-empty banner.
NULL_PROBE = SendExpectProbe(
    name="unknown", probe="", match_regex=re.compile(r"(?s).+"), fallback_ports=frozenset()
)

_PROBE_CACHE: dict[str, list[SendExpectProbe]] = {}


def _compile_probe_definitions(raw_defs: Any) -> list[SendExpectProbe]:
    probes: list[SendExpectProbe] = []
    if not isinstance(raw_defs, list):
        return probes
    for entry in raw_defs:
        if not isinstance(entry, dict):
            continue
        try:
            probes.append(
                SendExpectProbe(
                    name=str(entry["name"]),
                    probe=str(entry.get("probe", "")),
                    match_regex=re.compile(str(entry["match_regex"])),
                    fallback_ports=frozenset(int(p) for p in entry.get("fallback_ports", [])),
                )
            )
        except (KeyError, ValueError, TypeError, re.error) as exc:
            logging.warning("Skipping invalid probe definition %r: %s", entry, exc)
    return probes


def load_probe_definitions(path: Path = PROBE_DEFINITIONS_PATH) -> list[SendExpectProbe]:
    """Load and compile send-expect probes, caching per path. Never raises."""
    key = str(path)
    cached = _PROBE_CACHE.get(key)
    if cached is not None:
        return cached
    raw_defs: Any = None
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            raw_defs = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning(
            "Could not load probe definitions from %s (%s); using built-in defaults", path, exc
        )
    probes = _compile_probe_definitions(raw_defs)
    if not probes:
        probes = _compile_probe_definitions(DEFAULT_PROBE_DEFINITIONS)
    _PROBE_CACHE[key] = probes
    return probes


def _print_stage(title: str, detail: str = "") -> None:
    line = "=" * 78
    print(Fore.CYAN + line)
    print(Fore.WHITE + Style.BRIGHT + f"[ {title} ]")
    if detail:
        print(Fore.LIGHTBLACK_EX + detail)
    print(Fore.CYAN + line)


def _render_progress(prefix: str, done: int, total: int, width: int = 28) -> str:
    total = max(total, 1)
    ratio = min(max(done / total, 0.0), 1.0)
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    percent = int(ratio * 100)
    return f"{prefix} [{bar}] {percent:>3}% ({done}/{total})"


# Service detector
# --------------------------------------------------------------------------
class ServiceDetector:
    def __init__(
        self,
        target: Target,
        concurrency: int,
        timeout: float,
        check_sensitive_paths: bool,
        cve_lookup: CveLookup,
        web_controller: Any | None = None,
        web_only: bool = False,
        verify_tls: bool = True,
    ) -> None:
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout
        self.check_sensitive_paths = check_sensitive_paths
        self.cve_lookup = cve_lookup
        self.web_controller = web_controller
        self.web_only = web_only
        self.verify_tls = verify_tls
        self.probes = load_probe_definitions()
        self._probe_by_name = {probe.name: probe for probe in self.probes}
    def _host_header(self, port: int) -> str:
        if ":" in self.target.original and not self.target.original.startswith("["):
            host = f"[{self.target.original}]"
        else:
            host = self.target.original
        if port in {80, 443}:
            return host
        return f"{host}:{port}"
    def _http_request_bytes(self, port: int, path: str = "/") -> bytes:
        ua = (self.web_controller.user_agent if self.web_controller and self.web_controller.user_agent
              else random.choice(GENERIC_USER_AGENTS))
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self._host_header(port)}\r\n"
            f"User-Agent: {ua}\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii", errors="ignore")
    def _http_url(self, port: int, tls: bool, path: str = "/") -> str:
        scheme = "https" if tls else "http"
        host = self.target.original
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        default_port = 443 if tls else 80
        netloc = host if port == default_port else f"{host}:{port}"
        return f"{scheme}://{netloc}{path}"
    @staticmethod
    def _parse_headers(raw_response: str) -> tuple[int | None, dict[str, str], str | None]:
        head, _, body = raw_response.partition("\r\n\r\n")
        lines = head.splitlines()
        status = None
        headers: dict[str, str] = {}
        if lines:
            match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", lines[0])
            if match:
                status = int(match.group(1))
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else None
        return status, headers, title
    @staticmethod
    def _extract_title(body: bytes) -> str | None:
        text = body.decode("utf-8", errors="ignore")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        return re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else None
    @staticmethod
    def _subject_part(value: tuple, key: str) -> str | None:
        for group in value or ():
            for name, item in group:
                if name == key:
                    return str(item)
        return None
    @staticmethod
    def _cert_time(value: str | None) -> str | None:
        if not value:
            return None
        try:
            epoch = ssl.cert_time_to_seconds(value)
        except (TypeError, ValueError):
            return value
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    @classmethod
    def _format_certificate(cls, cert: dict[str, Any], ssl_obj: ssl.SSLObject | None) -> dict[str, Any]:
        if not cert:
            return {}
        san = [
            item
            for name, item in cert.get("subjectAltName", ())
            if str(name).lower() == "dns"
        ]
        not_after_raw = cert.get("notAfter")
        expires_at = cls._cert_time(not_after_raw)
        days_until_expiry = None
        expired = None
        if not_after_raw:
            try:
                expires_epoch = ssl.cert_time_to_seconds(not_after_raw)
                days_until_expiry = int((expires_epoch - time.time()) // 86400)
                expired = days_until_expiry < 0
            except (TypeError, ValueError):
                pass
        cipher = ssl_obj.cipher() if ssl_obj is not None else None
        return {
            "subject_cn": cls._subject_part(cert.get("subject", ()), "commonName"),
            "issuer_cn": cls._subject_part(cert.get("issuer", ()), "commonName"),
            "not_before": cls._cert_time(cert.get("notBefore")),
            "not_after": expires_at,
            "days_until_expiry": days_until_expiry,
            "expired": expired,
            "subject_alt_names": san[:20],
            "cipher": cipher[0] if cipher else None,
            "tls_version": cipher[1] if cipher else None,
            "alpn": ssl_obj.selected_alpn_protocol() if ssl_obj is not None else None,
        }
    def _base_url_for_result(self, result: ServiceResult) -> str:
        scheme = result.service
        host = self.target.original
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host if result.port in {80, 443} else f"{host}:{result.port}"
        return f"{scheme}://{netloc}"
    def _result_from_web_response(self, port: int, tls: bool, response: WebResponse) -> ServiceResult:
        headers = {str(k).lower(): v for k, v in response.headers.items()}
        server = headers.get("server") or headers.get("x-powered-by") or "HTTP service"
        scheme = "https" if tls else "http"
        notes = []
        if self.web_controller:
            for event in self.web_controller.block_events:
                if event.url == response.url:
                    notes.append(f"Web block observed: {event.reason}")
                    break
        if response.egress_id:
            notes.append(f"egress={response.egress_id}")
        return ServiceResult(
            port=port,
            service=scheme,
            version=server,
            tls=tls,
            http_status=response.status,
            title=self._extract_title(response.body),
            headers=headers,
            waf=detect_waf(headers),
            security_headers=analyze_security_headers(headers, tls),
            cookie_findings=analyze_cookie_flags(headers, tls),
            notes=notes,
        )
    async def _open_plain(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(self.target.address, port), timeout=self.timeout
        )
    async def _open_tls(self, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        context = ssl.create_default_context()
        if not self.verify_tls or looks_like_ip(self.target.original):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            context.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass
        server_hostname = self.target.original
        return await asyncio.wait_for(
            asyncio.open_connection(
                self.target.address, port, ssl=context, server_hostname=server_hostname
            ),
            timeout=self.timeout,
        )
    def _request_ssl_policy(self):
        return None if self.verify_tls else False
    async def _read_greeting(self, reader: asyncio.StreamReader) -> bytes:
        try:
            return await asyncio.wait_for(reader.read(MAX_BANNER_READ_BYTES), timeout=min(1.2, self.timeout))
        except asyncio.TimeoutError:
            return b""
    async def _first_successful_http_probe(self, port: int, session) -> ServiceResult | None:
        tls_order = [True, False] if port in TLS_PORT_HINTS else [False, True]
        for tls in tls_order:
            result = await self._probe_http_via_session(port, tls=tls, session=session)
            if result is not None:
                return result
        return None
    async def _probe_http_via_session(self, port: int, tls: bool, session, path: str = "/") -> ServiceResult | None:
        if self.web_controller is None or aiohttp is None:
            return None
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        url = self._http_url(port, tls=tls, path=path)
        response = await self.web_controller.request(
            session=session,
            url=url,
            timeout=timeout,
            ssl_policy=self._request_ssl_policy(),
            allow_redirects=False,
        )
        if response is None:
            return None
        return self._result_from_web_response(port, tls, response)
    async def _probe_http(self, port: int, tls: bool, reader=None, writer=None) -> ServiceResult | None:
        close_writer = False
        try:
            if reader is None or writer is None:
                reader, writer = await (self._open_tls(port) if tls else self._open_plain(port))
                close_writer = True
            writer.write(self._http_request_bytes(port))
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(MAX_HTTP_READ_BYTES), timeout=self.timeout)
            text = raw.decode("utf-8", errors="ignore")
            if not text.startswith("HTTP/"):
                return None
            status, headers, title = self._parse_headers(text)
            server = headers.get("server") or headers.get("x-powered-by") or "HTTP service"
            scheme = "https" if tls else "http"
            notes = []
            if tls and looks_like_ip(self.target.original):
                notes.append("TLS verification disabled (IP target)")
            return ServiceResult(
                port=port, service=scheme, version=server, tls=tls,
                http_status=status, title=title, headers=headers,
                waf=detect_waf(headers),
                security_headers=analyze_security_headers(headers, tls),
                cookie_findings=analyze_cookie_flags(headers, tls),
                notes=notes,
            )
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            return None
        finally:
            if close_writer and writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    def _ordered_probes_for_port(self, port: int) -> list[SendExpectProbe]:
        """Route probes: port-specific first, then http, then the null probe."""
        ordered: list[SendExpectProbe] = []
        seen: set[str] = set()
        for probe in self.probes:
            if port in probe.fallback_ports and probe.name not in seen:
                ordered.append(probe)
                seen.add(probe.name)
        http = self._probe_by_name.get("http")
        if http is not None and http.name not in seen:
            ordered.append(http)
            seen.add(http.name)
        ordered.append(NULL_PROBE)
        return ordered
    async def _send_expect_exchange(self, port: int, probe: SendExpectProbe) -> bytes | None:
        """One connect/send/read cycle. Returns raw bytes or None on any failure."""
        reader = writer = None
        try:
            reader, writer = await self._open_plain(port)
            if probe.probe:
                writer.write(probe.probe.encode("latin-1", errors="ignore"))
                await writer.drain()
            raw = await asyncio.wait_for(
                reader.read(MAX_HTTP_READ_BYTES),
                timeout=min(self.timeout, SEND_EXPECT_READ_TIMEOUT),
            )
            return raw or None
        except (OSError, ssl.SSLError, asyncio.TimeoutError):
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    async def _probe_send_expect(self, port: int) -> ServiceResult | None:
        """Native send-expect engine. Tries routed probes until one matches."""
        for probe in self._ordered_probes_for_port(port):
            raw = await self._send_expect_exchange(port, probe)
            if not raw:
                continue
            text = raw.decode("utf-8", errors="ignore")
            match = probe.match_regex.search(text)
            if match is None:
                continue
            result = self._result_from_send_expect(port, probe, raw, match)
            if result is not None:
                return result
        return None
    def _http_result_from_raw(self, port: int, raw: bytes, tls: bool) -> ServiceResult | None:
        text = raw.decode("utf-8", errors="ignore")
        if not text.startswith("HTTP/"):
            return None
        status, headers, title = self._parse_headers(text)
        server = headers.get("server") or headers.get("x-powered-by") or "HTTP service"
        scheme = "https" if tls else "http"
        return ServiceResult(
            port=port, service=scheme, version=server, tls=tls,
            http_status=status, title=title, headers=headers,
            waf=detect_waf(headers),
            security_headers=analyze_security_headers(headers, tls),
            cookie_findings=analyze_cookie_flags(headers, tls),
        )
    def _result_from_send_expect(
        self, port: int, probe: SendExpectProbe, raw: bytes, match: re.Match[str]
    ) -> ServiceResult | None:
        if probe.name in {"http", "https"}:
            http_result = self._http_result_from_raw(port, raw, tls=probe.name == "https")
            if http_result is not None:
                return http_result
        # Prefer the richer built-in classifier when it recognizes the banner
        # (extracts clean SSH/FTP/SMTP/MySQL versions); otherwise fall back to
        # the probe name plus regex capture groups or the raw banner line.
        greeting = service_result_from_greeting(port, raw)
        if greeting is not None:
            return greeting
        groups = [group.strip() for group in match.groups() if group]
        banner = format_banner_bytes(raw)
        if groups:
            version = " ".join(groups)
        elif banner and banner != "open, no banner":
            version = banner.splitlines()[0]
        else:
            version = "open, no banner"
        return ServiceResult(port=port, service=probe.name, version=version)
    async def _probe_known_greeting(self, port: int) -> ServiceResult:
        reader = writer = None
        try:
            reader, writer = await self._open_plain(port)
            greeting = await self._read_greeting(reader)
            parsed = service_result_from_greeting(port, greeting)
            if parsed is not None:
                return parsed
            if self.web_controller is None or not self.web_controller.uses_proxy:
                http = await self._probe_http(port, tls=False, reader=reader, writer=writer)
                if http:
                    writer = None
                    return http
            if greeting:
                return ServiceResult(port=port, service="unknown", version=format_banner_bytes(greeting))
            return ServiceResult(port=port, service="unknown", version="open, no banner")
        except (OSError, asyncio.TimeoutError):
            return ServiceResult(port=port, service="unknown", version="open, probe failed")
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    async def _probe_active_payloads(self, port: int) -> ServiceResult | None:
        for probe in ACTIVE_PROBE_REGISTRY:
            reader = writer = None
            try:
                reader, writer = await self._open_plain(port)
                writer.write(probe.payload)
                await writer.drain()
                raw = await asyncio.wait_for(reader.read(MAX_BANNER_READ_BYTES), timeout=min(1.5, self.timeout))
                result = result_from_active_probe_response(port, probe.name, raw)
                if result is not None:
                    return result
            except (OSError, asyncio.TimeoutError):
                continue
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
        return None
    async def _check_sensitive_paths(self, result: ServiceResult, session) -> list[WebFinding]:
        if not self.check_sensitive_paths or result.service not in {"http", "https"}:
            return []
        if self.web_controller is None or aiohttp is None:
            return []
        base_url = self._base_url_for_result(result)
        findings: list[WebFinding] = []
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async def fetch_path(path: str) -> WebFinding | None:
            response = await self.web_controller.request(
                session=session,
                url=base_url + path,
                timeout=timeout,
                ssl_policy=self._request_ssl_policy(),
                allow_redirects=False,
            )
            if response is None:
                return None
            if response.status == 200:
                return WebFinding(
                    path=path,
                    status=response.status,
                    size=len(response.body),
                    content_type=response.headers.get("content-type", ""),
                )
            return None
        path_results = await asyncio.gather(
            *(fetch_path(path) for path in SENSITIVE_PATHS),
            return_exceptions=True,
        )
        for item in path_results:
            if isinstance(item, WebFinding):
                findings.append(item)
        return findings
    async def _check_api_paths(self, result: ServiceResult, session) -> list[WebFinding]:
        if not self.check_sensitive_paths or result.service not in {"http", "https"}:
            return []
        if self.web_controller is None or aiohttp is None:
            return []
        base_url = self._base_url_for_result(result)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        useful_statuses = {200, 201, 204, 301, 302, 307, 308, 401, 405}
        async def fetch_path(path: str) -> WebFinding | None:
            response = await self.web_controller.request(
                session=session,
                url=base_url + path,
                timeout=timeout,
                ssl_policy=self._request_ssl_policy(),
                allow_redirects=False,
                block_on_ban=False,
            )
            if response is None or response.status not in useful_statuses:
                return None
            return WebFinding(
                path=path,
                status=response.status,
                size=len(response.body),
                content_type=response.headers.get("content-type", ""),
            )
        path_results = await asyncio.gather(
            *(fetch_path(path) for path in API_DISCOVERY_PATHS),
            return_exceptions=True,
        )
        return [item for item in path_results if isinstance(item, WebFinding)]
    async def _check_cors(self, result: ServiceResult, session) -> list[dict[str, Any]]:
        if not self.check_sensitive_paths or result.service not in {"http", "https"}:
            return []
        if self.web_controller is None or aiohttp is None:
            return []
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        response = await self.web_controller.request(
            session=session,
            url=self._base_url_for_result(result) + "/",
            timeout=timeout,
            ssl_policy=self._request_ssl_policy(),
            allow_redirects=False,
            extra_headers={"Origin": CORS_TEST_ORIGIN},
            block_on_ban=False,
        )
        if response is None:
            return []
        headers = {k.lower(): v for k, v in response.headers.items()}
        return cors_findings_from_headers(headers)
    async def _probe_tls_certificate(self, port: int) -> dict[str, Any]:
        if self.web_controller is not None and self.web_controller.uses_proxy:
            return {"skipped": "direct TLS certificate probe disabled while proxy egress is active"}
        if self.target.family == socket.AF_UNSPEC:
            return {"skipped": "target resolution deferred"}
        reader = writer = None
        try:
            reader, writer = await self._open_tls(port)
            ssl_obj = writer.get_extra_info("ssl_object")
            cert = ssl_obj.getpeercert() if ssl_obj is not None else {}
            return self._format_certificate(cert, ssl_obj)
        except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
            return {"error": str(exc)[:160]}
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    async def _run_web_checks(self, result: ServiceResult, session) -> None:
        if result.tls:
            result.tls_certificate = await self._probe_tls_certificate(result.port)
            if result.tls_certificate.get("alpn") == "h2":
                result.notes.append("HTTP/2 supported")
        if result.service not in {"http", "https"}:
            return
        result.sensitive_paths = await self._check_sensitive_paths(result, session)
        result.api_paths = await self._check_api_paths(result, session)
        result.cors_findings = await self._check_cors(result, session)
    async def detect_one(self, port: int, semaphore: asyncio.Semaphore, session) -> ServiceResult:
        async with semaphore:
            result: ServiceResult | None = None
            prefer_http = self.web_only or port in WEB_PORT_HINTS or port in TLS_PORT_HINTS
            if prefer_http:
                result = await self._first_successful_http_probe(port, session)
            if self.web_only:
                if result is None:
                    return ServiceResult(
                        port=port,
                        service="unknown",
                        version="web probe failed",
                        notes=["Web-only mode skipped direct TCP fallback probes"],
                    )
                await self._run_web_checks(result, session)
                result.cves = await self.cve_lookup.query(result.service, result.version, session)
                return result
            if result is None:
                result = await self._probe_send_expect(port)
            if result is None:
                result = await self._probe_known_greeting(port)
            if result.service == "unknown" and not prefer_http and port in WEB_PORT_HINTS:
                fallback = await self._probe_http_via_session(port, tls=False, session=session)
                if fallback is not None:
                    result = fallback
            if result.service == "unknown" and not prefer_http and port not in TLS_PORT_HINTS:
                tls_result = await self._probe_http_via_session(port, tls=True, session=session)
                if tls_result is not None:
                    result = tls_result
            if result.service == "unknown" and (
                result.version in {"open, no banner", "open, probe failed"}
                or result.version.startswith("<Binary Data:")
            ):
                active_result = await self._probe_active_payloads(port)
                if active_result is not None:
                    if active_result.service in {"tls", "rdp", "smb"}:
                        result = active_result
                    elif result.version in {"open, no banner", "open, probe failed"}:
                        result = active_result
            if result.service == "unknown":
                hinted = port_hint_result(port, result)
                if hinted is not None:
                    result = hinted
            await self._run_web_checks(result, session)
            result.cves = await self.cve_lookup.query(result.service, result.version, session)
            return result
    async def detect(self, ports: list[int]) -> dict[int, ServiceResult]:
        semaphore = asyncio.Semaphore(self.concurrency)
        if aiohttp is None:
            raise SystemExit("aiohttp required for service detection")
        connector = aiohttp.TCPConnector(ssl=self._request_ssl_policy(), limit=max(self.concurrency, 20))
        timeout = aiohttp.ClientTimeout(total=max(self.timeout, 5.0))
        collected: dict[int, ServiceResult] = {}
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = [self.detect_one(port, semaphore, session) for port in ports]
            _print_stage(
                "Service Detection",
                f"Timeout: {self.timeout:.2f}s | Concurrency: {self.concurrency} | Targets: {len(ports)} open ports",
            )
            for idx, task in enumerate(asyncio.as_completed(tasks), start=1):
                result = await task
                collected[result.port] = result
                if idx % 10 == 0 or idx == len(tasks):
                    sys.stdout.write(Fore.CYAN + "\r" + _render_progress("Fingerprinting", idx, len(tasks)))
                    sys.stdout.flush()
        print()
        return collected
# --------------------------------------------------------------------------
