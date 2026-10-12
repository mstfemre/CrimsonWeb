"""Fixed bounded GET probes. No script execution, extraction, delays or writes."""

import asyncio
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from uuid import uuid4

import httpx

from ..headers import analyze_headers
from ..tls import inspect_tls, tls_findings
from ..web_analysis import analyze_web
from ..workspaces.models import AuthorizationRequest
from ..workspaces.service import AuthorizationDenied

MAX_BODY_BYTES = 65536
SQL_ERROR = re.compile(
    r"sqlite3\.(?:OperationalError|DatabaseError)|SQLSTATE\[[A-Z0-9]{5}\]|"
    r"You have an error in your SQL syntax|ORA-009(?:33|36)|"
    r"unclosed quotation mark after the character string", re.IGNORECASE,
)
STACK_TRACE = re.compile(r"Traceback \(most recent call last\)|\b(?:java\.[\w.]+Exception|at System\.)")


class MarkerParser(HTMLParser):
    def __init__(self, marker):
        super().__init__()
        self.marker = marker
        self.found = False
        self.text_only = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "textarea", "title", "xmp", "plaintext", "noscript"}:
            self.text_only.append(tag)
        if not self.text_only and tag == "cw-probe" and dict(attrs).get("data-id") == self.marker:
            self.found = True

    def handle_endtag(self, tag):
        if tag in self.text_only:
            self.text_only = self.text_only[:self.text_only.index(tag)]


def html_marker_present(body, marker):
    parser = MarkerParser(marker)
    try:
        parser.feed(body)
    except (ValueError, AssertionError):
        return False
    return parser.found


@dataclass
class ProbeResult:
    statuses: list[int] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    outcome: str = "inconclusive"
    reason: str = "probe_not_evaluable"
    stop_reason: str | None = None
    blocked: bool = False


@dataclass
class Observation:
    status: int
    body: str = field(repr=False)
    content_type: str = ""
    codes: list[str] = field(default_factory=list)


class WebProbeRunner:
    def __init__(self, guard, transport=None):
        self.guard, self.transport = guard, transport

    async def run(self, workspace_id, policy_id, proposal, target, request, cancelled=None):
        result = ProbeResult()
        category = {"xss_reflection_probe": "xss", "sql_error_probe": "sqli",
                    "web_security_observation": "web_observation"}[proposal.catalog_id]
        marker = "cw_" + uuid4().hex[:16]
        recipe = {
            "xss_reflection_probe": [marker, f'<cw-probe data-id="{marker}">{marker}</cw-probe>'],
            "sql_error_probe": ["1", "cw_invalid_value", "1'"],
            "web_security_observation": [None],
        }[proposal.catalog_id]
        auth = None
        if request.identities:
            identity = next(i for i in request.identities if i.role == "identity_a")
            auth = (identity.header_name, identity.header_value)
        url = request.base_url.rstrip("/") + "/" + target.path.lstrip("/")
        observations = []
        for value in recipe:
            if cancelled is not None and cancelled():
                result.stop_reason = "verification_cancelled"
                return result
            query = {proposal.query_parameter: value} if value is not None else {}
            try:
                async with asyncio.timeout(30), self.guard.stream(
                    workspace_id, policy_id,
                    AuthorizationRequest(url=url, category=category, query_parameters=query),
                    self.transport, user_agent="CrimsonWeb/WebVerification",
                    observation_only=True, auth_header=auth, minimize_audit=True,
                ) as response:
                    status = response.status_code
                    result.statuses.append(status)
                    if status in {403, 429} or 300 <= status < 400:
                        result.stop_reason = {403: "http_403_access_denied", 429: "http_429_rate_limited"}.get(
                            status, "redirect_not_followed")
                        result.blocked = True
                        if 300 <= status < 400:
                            await asyncio.to_thread(self.guard.store.halt, workspace_id, policy_id,
                                                    result.stop_reason, self.guard.clock())
                        return result
                    if response.headers.get("content-encoding", "identity").strip().lower() not in {"", "identity"}:
                        result.stop_reason = "encoded_response_not_supported"
                        return result
                    chunks = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(chunks) + len(chunk) > MAX_BODY_BYTES:
                            result.stop_reason = "response_limit_exceeded"
                            return result
                        chunks.extend(chunk)
                    codes = []
                    if proposal.catalog_id == "web_security_observation":
                        findings = analyze_headers(response.headers, response.url.scheme == "https")
                        findings += analyze_web(response.headers, response.url.scheme == "https")
                        tls = inspect_tls(response) if response.url.scheme == "https" else None
                        if tls:
                            findings += tls_findings(tls)
                            codes.append("negotiated_tls_observed")
                        codes += sorted({f.code for f in findings})
                        if response.headers.get_list("set-cookie"):
                            codes.append("cookie_attributes_observed")
                    observations.append(Observation(status, bytes(chunks).decode("utf-8", errors="replace"),
                                                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower(), codes))
            except AuthorizationDenied as exc:
                result.stop_reason, result.blocked = exc.reason, True
                return result
            except (httpx.HTTPError, TimeoutError, OSError, ValueError):
                result.stop_reason = "network_or_response_inconclusive"
                return result
            if observations[0].status != 200:
                result.reason = "baseline_requests_failed"
                return result

        result.outcome, result.reason = "no_signal_observed", "no_signal_in_bounded_observation"
        if any(STACK_TRACE.search(o.body) for o in observations):
            result.signals.append("exception_detail_observed")
        if proposal.catalog_id == "xss_reflection_probe":
            probe = observations[1]
            if (probe.status == 200 and probe.content_type == "text/html"
                and html_marker_present(probe.body, marker)
                and not html_marker_present(observations[0].body, marker)):
                result.outcome, result.reason = "html_injection_suspected", "inert_html_element_reflected"
                result.signals += ["inert_element_parsed", "script_execution_not_tested"]
        elif proposal.catalog_id == "sql_error_probe":
            if (not SQL_ERROR.search(observations[0].body)
                and not SQL_ERROR.search(observations[1].body)
                and observations[2].content_type in {"application/json", "text/plain", "text/html"}
                and SQL_ERROR.search(observations[2].body)):
                result.outcome, result.reason = "sql_injection_suspected", "quote_specific_sql_error_observed"
                result.signals += ["quote_specific_sql_error", "database_access_not_proven"]
        else:
            result.outcome, result.reason = "configuration_observed", "bounded_configuration_observation"
            result.signals += observations[0].codes
        result.signals = sorted(set(result.signals))[:40]
        return result
