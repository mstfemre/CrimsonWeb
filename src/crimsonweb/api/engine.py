import asyncio
import ipaddress
import json
import logging
import socket
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx

from crimsonweb.web_checks import CORS_TEST_ORIGIN

from .headers import analyze_headers
from .models import Hop, ScanReport, TLSObservation
from .scope import Scope, ScopeError
from .tls import inspect_tls, tls_findings, verification_failure
from .waf import http_event
from .web_analysis import analyze_web

logger = logging.getLogger("crimsonweb.api")
# Only these request header names may carry a Phase 4C test-identity credential.
# Enforced here as defence in depth; the verification layer validates values too.
AUTH_HEADER_ALLOWLIST = frozenset({"authorization", "cookie", "x-api-key"})


def checked_auth_header(name, value):
    """Validate credentials without including supplied names or values in errors."""
    if not isinstance(name, str) or name.lower() not in AUTH_HEADER_ALLOWLIST:
        raise ScopeError("auth_header_not_allowed")
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > 4096
        or any(ord(c) < 32 or ord(c) > 126 for c in value)
    ):
        raise ScopeError("invalid_header_value")
    return name, value


SAFE_HEADERS = {
    "content-security-policy",
    "x-content-type-options",
    "referrer-policy",
    "strict-transport-security",
    "x-frame-options",
    "content-type",
    "retry-after",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "vary",
}


@asynccontextmanager
async def pinned_response(
    url,
    addresses,
    transport=None,
    method="GET",
    user_agent="CrimsonWeb/Phase1",
    observation_only=False,
    auth_header=None,
    allow_insecure_lab_auth=False,
    query_parameters=None,
):
    """Transport primitive: callers must authorize and resolve before entering.

    ``auth_header`` is an optional ``(name, value)`` test-identity credential. Its
    name must be in AUTH_HEADER_ALLOWLIST (structural headers can never be set),
    and its value is never logged. The value is placed only in the outgoing
    request headers.
    """
    headers = {
        "Host": url.netloc.decode("ascii"),
        "User-Agent": user_agent,
        **(
            {"Accept-Encoding": "identity"}
            if observation_only
            else {"Origin": CORS_TEST_ORIGIN}
        ),
    }
    if auth_header is not None:
        name, value = checked_auth_header(*auth_header)
        lab_http = (
            url.scheme == "http" and allow_insecure_lab_auth and bool(addresses)
            and all(ipaddress.ip_address(ip).is_private for ip in addresses)
        )
        if url.scheme != "https" and not lab_http:
            raise ScopeError("credential_https_required")
        headers[name] = value
    pinned = url.copy_with(host=addresses[0])
    async with (
        httpx.AsyncClient(
            transport=transport, trust_env=False, follow_redirects=False, timeout=5.0
        ) as client,
        client.stream(
            method,
            pinned,
            headers=headers,
            params=query_parameters or None,
            extensions={"sni_hostname": url.host},
        ) as response,
    ):
        yield response


class ScanEngine:
    def __init__(
        self,
        scope: Scope,
        transport: httpx.AsyncBaseTransport | None = None,
        interval: float = 1.0,
        authorization=None,
    ) -> None:
        self.scope = scope
        self.transport = transport
        self.interval = interval
        self.authorization = authorization
        self._lock = asyncio.Lock()
        self._last_request = 0.0

    async def _pace(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            await asyncio.sleep(
                max(0, self._last_request + self.interval - loop.time())
            )
            self._last_request = loop.time()

    async def run(
        self,
        report: ScanReport,
        on_update: Callable[[ScanReport], Awaitable[None]] | None = None,
    ) -> None:
        report.status = "running"
        report.started_at = datetime.now(UTC)
        report.https_redirect = (
            "not_applicable" if report.target.startswith("https:") else "incomplete"
        )
        try:
            async with asyncio.timeout(60):
                if on_update:
                    await on_update(report)
                await self._scan(report, on_update)
        except ScopeError:
            report.status, report.stop_reason = "blocked", "scope_violation"
        except (TimeoutError, httpx.TimeoutException):
            report.status, report.error_category = "failed", "timeout"
        except socket.gaierror:
            report.status, report.error_category = "failed", "dns_error"
        except httpx.HTTPError as exc:
            report.status, report.error_category = "failed", "connection_or_tls_error"
            failure = verification_failure(exc)
            if failure:
                observation = TLSObservation(
                    verified=False,
                    verification_error=failure.verify_message,
                    url=report.target,
                )
                report.tls_failures.append(observation)
                report.findings.extend(tls_findings(observation))
                report.error_category = "tls_certificate_error"
        except asyncio.CancelledError:
            report.status, report.stop_reason = "stopped", "cancelled"
            raise
        except Exception:  # noqa: BLE001 -- Task boundary must finalize unexpected failures.
            report.status, report.error_category = "failed", "internal_error"
        finally:
            if report.https_redirect != "not_applicable":
                if any(h.url.startswith("https:") for h in report.hops):
                    report.https_redirect = "observed"
                elif report.status == "completed":
                    report.https_redirect = "not_observed"
            report.finished_at = datetime.now(UTC)
            if on_update:
                await on_update(report)
            logger.info(
                json.dumps(
                    {
                        "event": "scan_finished",
                        "id": report.id,
                        "status": report.status,
                        "hops": len(report.hops),
                    }
                )
            )

    @asynccontextmanager
    async def _stream(self, url):
        if self.authorization is not None:
            await self._pace()
            async with self.authorization.stream(url) as response:
                yield response, response.extensions["crimson_resolved_ips"]
            return
        addresses = await self.scope.resolve(url)
        await self._pace()
        async with pinned_response(url, addresses, self.transport) as response:
            yield response, addresses

    async def _scan(
        self,
        report: ScanReport,
        on_update: Callable[[ScanReport], Awaitable[None]] | None = None,
    ) -> None:
        validate = (
            Scope.parse_url
            if self.authorization is not None
            else self.scope.validate_url
        )
        url = validate(report.target)
        visited: set[str] = set()
        for _ in range(6):
            url = validate(str(url))
            if str(url) in visited:
                report.status, report.stop_reason = "blocked", "redirect_loop"
                return
            visited.add(str(url))
            async with self._stream(url) as (response, addresses):
                # Do not buffer response bodies, cookies or authorization material.
                report.hops.append(
                    Hop(
                        url=str(url),
                        resolved_ips=addresses,
                        connected_ip=addresses[0],
                        status_code=response.status_code,
                        headers={
                            k: v
                            for k, v in response.headers.items()
                            if k in SAFE_HEADERS
                        },
                        tls=inspect_tls(response) if url.scheme == "https" else None,
                    )
                )
                report.findings.extend(
                    analyze_headers(response.headers, url.scheme == "https")
                )
                report.findings.extend(
                    analyze_web(response.headers, url.scheme == "https")
                )
                if report.hops[-1].tls:
                    report.hops[-1].tls.url = str(url)
                    report.findings.extend(tls_findings(report.hops[-1].tls))
                for finding in report.findings:
                    if finding.url is None:
                        finding.url = str(url)
                if response.status_code in {403, 429}:
                    report.waf_events.append(
                        http_event(
                            report.id,
                            response.status_code,
                            response.headers.get("retry-after"),
                        )
                    )
                if on_update:
                    await on_update(report)
                if response.status_code in {403, 429}:
                    report.status = "blocked"
                    report.stop_reason = (
                        "http_403_access_denied"
                        if response.status_code == 403
                        else "http_429_rate_limited"
                    )
                    return
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("location")
                    if not location:
                        report.status, report.stop_reason = (
                            "blocked",
                            "redirect_without_location",
                        )
                        return
                    destination = url.join(location)
                    if url.scheme == "http" and destination.scheme == "https":
                        for finding in report.findings:
                            if (
                                finding.url == str(url)
                                and finding.code == "plaintext_http"
                            ):
                                finding.code, finding.severity = (
                                    "http_redirects_to_https",
                                    "info",
                                )
                                finding.evidence = "HTTP response redirects to HTTPS; final coverage is recorded separately."
                    if url.scheme == "https" and destination.scheme == "http":
                        report.status, report.stop_reason = (
                            "blocked",
                            "https_downgrade",
                        )
                        return
                    url = destination
                    continue
                report.status = "completed"
                return
        report.status, report.stop_reason = "blocked", "redirect_limit"
