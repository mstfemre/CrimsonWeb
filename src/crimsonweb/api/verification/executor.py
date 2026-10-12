"""Deterministic, read-only BOLA/IDOR executor. No model input reaches here.

Every request is authorized by the shared guard (scope, DNS, budget, concurrency,
rate limit, safe-stop). The executor adds: read-only method only, three ordered
reads (two controls then the cross read), owner binding compared in memory, and
only the boolean match retained. Credentials live only in local variables for the
duration of the run; they are never stored, logged, fingerprinted or echoed.
"""

import asyncio
import json
from dataclasses import dataclass
from uuid import uuid4

import httpx

from ..discovery.store import DiscoveryLimit
from ..workspaces.models import AuthorizationRequest
from ..workspaces.service import AuthorizationDenied
from .comparison import BOLA_CONFIRMED, classify_bola
from .credentials import validate_auth_header
from .models import (
    AccessControlFinding,
    ComparativeAccessEvidence,
    ExecuteRequest,
    PlanProposal,
    PolicyStopEvidence,
    ProbeFinding,
    VerificationFinding,
    VerificationTarget,
    VerificationTest,
    WebProbeEvidence,
)
from .planner import validate_proposals

MAX_BODY_BYTES = 65536
_CONFIDENCE = {
    "bola_confirmed": "confirmed",
    "access_control_enforced": "not_applicable",
    "owner_binding_unverified": "unverified",
    "inconclusive": "inconclusive",
}


@dataclass
class _Stop:
    reason: str
    blocked: bool


@dataclass
class _Read:
    status: int | None = None
    value: object | None = None
    stop: _Stop | None = None


@dataclass
class ExecutionResult:
    test: VerificationTest
    evidence: list
    finding: VerificationFinding | None


class VerificationExecutor:
    def __init__(self, guard, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.guard = guard
        self.transport = transport

    async def execute(
        self,
        workspace_id,
        policy_id,
        plan_id,
        proposal: PlanProposal,
        target: VerificationTarget,
        request: ExecuteRequest,
        cancelled=None,
    ) -> ExecutionResult:
        validate_proposals({"proposals": [proposal.model_dump()]}, [target])
        if proposal.catalog_id != "bola_cross_owner_read":
            return await self._probe(workspace_id, policy_id, plan_id, proposal, target, request, cancelled)
        test_id = uuid4()
        creds = {
            identity.role: validate_auth_header(
                identity.header_name, identity.header_value
            )
            for identity in request.identities
        }
        owners = {i.role: i.owner_object_id for i in request.identities}
        param = target.object_identifier_parameter
        url_a = self._url(request.base_url, target.path, param, owners["identity_a"])
        url_b = self._url(request.base_url, target.path, param, owners["identity_b"])
        field = request.owner_binding_field

        control_a = await self._read(workspace_id, policy_id, url_a, creds["identity_a"], field, cancelled)
        if control_a.stop:
            return self._stopped(workspace_id, plan_id, test_id, proposal, target, control_a.stop)
        if control_a.status != 200:
            return self._stopped(
                workspace_id, plan_id, test_id, proposal, target,
                _Stop("control_requests_failed", blocked=False),
            )
        control_b = await self._read(workspace_id, policy_id, url_b, creds["identity_b"], field, cancelled)
        if control_b.stop:
            return self._stopped(workspace_id, plan_id, test_id, proposal, target, control_b.stop)
        if control_b.status != 200:
            return self._stopped(
                workspace_id, plan_id, test_id, proposal, target,
                _Stop("control_requests_failed", blocked=False),
            )
        cross = await self._read(workspace_id, policy_id, url_b, creds["identity_a"], field, cancelled)
        if cross.stop:
            return self._stopped(workspace_id, plan_id, test_id, proposal, target, cross.stop)

        controls_distinct = (
            control_a.value is not None and control_b.value is not None
            and not self._equal(control_a.value, control_b.value)
        )
        if controls_distinct and cross.value is not None:
            owner_binding_match = self._equal(control_b.value, cross.value)
        else:
            owner_binding_match = None
        verdict = classify_bola(
            control_a.status, control_b.status, cross.status, owner_binding_match
        )
        evidence = ComparativeAccessEvidence(
            id=uuid4(),
            ref="",
            workspace_id=workspace_id,
            plan_id=plan_id,
            test_id=test_id,
            timestamp=self.guard.clock(),
            status=verdict.outcome,
            reason=verdict.reason,
            catalog_id=proposal.catalog_id,
            target_endpoint_ref=target.endpoint_ref,
            method=target.method,
            control_a_status=control_a.status,
            control_b_status=control_b.status,
            cross_status=cross.status,
            owner_binding_match=owner_binding_match,
            controls_distinct=controls_distinct,
            scope_decision="authorized",
            identities=["identity_a", "identity_b"],
        )
        evidence.ref = f"verification_evidence:{evidence.id}"
        finding = None
        finding_ids = []
        if verdict.outcome == BOLA_CONFIRMED:
            finding = AccessControlFinding(
                id=uuid4(),
                workspace_id=workspace_id,
                plan_id=plan_id,
                test_id=test_id,
                code="bola_confirmed",
                confidence="confirmed",
                status="finding",
                category="auth",
                target_endpoint_ref=target.endpoint_ref,
                source_evidence_refs=list(proposal.evidence_refs),
                observation_evidence_ref=evidence.ref,
                test_identity_roles=["identity_a", "identity_b"],
                scope_decision="authorized",
            )
            finding_ids = [finding.id]
        test = VerificationTest(
            id=test_id,
            workspace_id=workspace_id,
            plan_id=plan_id,
            catalog_id=proposal.catalog_id,
            target_endpoint_ref=target.endpoint_ref,
            status="completed",
            outcome=verdict.outcome,
            confidence=_CONFIDENCE[verdict.outcome],
            reason=verdict.reason,
            evidence_refs=[evidence.ref],
            finding_ids=finding_ids,
        )
        return ExecutionResult(test=test, evidence=[evidence], finding=finding)

    async def _probe(self, workspace_id, policy_id, plan_id, proposal, target, request, cancelled):
        from .catalog import catalog_entry
        from .probes import WebProbeRunner

        test_id = uuid4()
        result = await WebProbeRunner(self.guard, self.transport).run(
            workspace_id, policy_id, proposal, target, request, cancelled,
        )
        if result.stop_reason:
            return self._stopped(workspace_id, plan_id, test_id, proposal, target,
                                 _Stop(result.stop_reason, result.blocked))
        evidence_id = uuid4()
        evidence = WebProbeEvidence(
            id=evidence_id, ref=f"verification_evidence:{evidence_id}", workspace_id=workspace_id,
            plan_id=plan_id, test_id=test_id, timestamp=self.guard.clock(),
            status=result.outcome, reason=result.reason, catalog_id=proposal.catalog_id,
            target_endpoint_ref=target.endpoint_ref, query_parameter=proposal.query_parameter,
            response_statuses=result.statuses, signals=result.signals,
        )
        finding = None
        if result.outcome in {"html_injection_suspected", "sql_injection_suspected"}:
            finding = ProbeFinding(
                id=uuid4(), workspace_id=workspace_id, plan_id=plan_id, test_id=test_id,
                code=result.outcome, category=catalog_entry(proposal.catalog_id).category,
                target_endpoint_ref=target.endpoint_ref, source_evidence_refs=proposal.evidence_refs,
                observation_evidence_ref=evidence.ref,
            )
        test = VerificationTest(
            id=test_id, workspace_id=workspace_id, plan_id=plan_id, catalog_id=proposal.catalog_id,
            target_endpoint_ref=target.endpoint_ref, status="completed", outcome=result.outcome,
            confidence="unverified" if finding else "inconclusive" if result.outcome == "inconclusive" else "not_applicable",
            reason=result.reason, evidence_refs=[evidence.ref], finding_ids=[finding.id] if finding else [],
        )
        return ExecutionResult(test, [evidence], finding)

    @staticmethod
    def _equal(first, second):
        return type(first) is type(second) and first == second

    async def _read(self, workspace_id, policy_id, url, auth_header, field, cancelled=None) -> _Read:
        if cancelled is not None and cancelled():
            return _Read(stop=_Stop("verification_cancelled", blocked=False))
        try:
            async with asyncio.timeout(30), self.guard.stream(
                workspace_id,
                policy_id,
                AuthorizationRequest(url=url, method="GET", category="auth"),
                self.transport,
                user_agent="CrimsonWeb/Phase4C",
                observation_only=True,
                auth_header=auth_header,
                minimize_audit=True,
            ) as response:
                status = response.status_code
                if status in {403, 429}:
                    reason = (
                        "http_403_access_denied"
                        if status == 403
                        else "http_429_rate_limited"
                    )
                    return _Read(status=status, stop=_Stop(reason, blocked=True))
                if 300 <= status < 400:
                    await asyncio.to_thread(
                        self.guard.store.halt, workspace_id, policy_id,
                        "redirect_not_followed", self.guard.clock(),
                    )
                    return _Read(status=status, stop=_Stop("redirect_not_followed", True))
                value = await self._field(response, field) if status == 200 else None
                return _Read(status=status, value=value)
        except AuthorizationDenied as exc:
            return _Read(stop=_Stop(exc.reason, blocked=True))
        except (httpx.HTTPError, TimeoutError, OSError, ValueError, DiscoveryLimit):
            return _Read(stop=_Stop("network_or_response_inconclusive", blocked=False))

    async def _field(self, response, field):
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json" and not content_type.endswith("+json"):
            return None
        chunks = bytearray()
        async for chunk in response.aiter_bytes():
            if len(chunks) + len(chunk) > MAX_BODY_BYTES:
                return None
            chunks.extend(chunk)
        try:
            data = json.loads(bytes(chunks), object_pairs_hook=self._unique_fields)
        except (ValueError, RecursionError):
            return None
        if isinstance(data, dict):
            value = data.get(field)
            if type(value) is int or (type(value) is str and value.strip()):
                return value
        return None

    @staticmethod
    def _unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ambiguous_json_response")
            result[key] = value
        return result

    def _stopped(self, workspace_id, plan_id, test_id, proposal, target, stop: _Stop):
        evidence = PolicyStopEvidence(
            id=uuid4(),
            ref="",
            workspace_id=workspace_id,
            plan_id=plan_id,
            test_id=test_id,
            timestamp=self.guard.clock(),
            status="blocked_by_policy" if stop.blocked else "inconclusive",
            reason=stop.reason,
            scope_decision=stop.reason,
        )
        evidence.ref = f"verification_evidence:{evidence.id}"
        test = VerificationTest(
            id=test_id,
            workspace_id=workspace_id,
            plan_id=plan_id,
            catalog_id=proposal.catalog_id,
            target_endpoint_ref=target.endpoint_ref,
            status="blocked_by_policy" if stop.blocked else "failed",
            outcome=None,
            confidence="inconclusive",
            reason=stop.reason,
            evidence_refs=[evidence.ref],
        )
        return ExecutionResult(test=test, evidence=[evidence], finding=None)

    @staticmethod
    def _url(base: str, path: str, param: str | None, value: str) -> str:
        filled = path.replace("{" + (param or "") + "}", value) if param else path
        return base.rstrip("/") + "/" + filled.lstrip("/")
