"""Shared authorization interface for existing scans and future 4B/4C callers."""

import asyncio
import hashlib
import ipaddress
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID

import httpx

from ..database import Repository
from ..engine import pinned_response
from ..scope import ScopeError
from .dns import Resolver, SystemResolver
from .models import AuthorizationRequest, Decision, PolicyValidation
from .policy import evaluate, parsed_target, readiness
from .store import WorkspaceStore

Identifier = UUID | str


class AuthorizationDenied(ScopeError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class WorkspaceService:
    def __init__(
        self,
        repository: Repository,
        resolver: Resolver | None = None,
        clock: Callable[[], datetime] | None = None,
    ):
        self.store = WorkspaceStore(repository)
        self.resolver = resolver or SystemResolver()
        self.clock = clock or (lambda: datetime.now(UTC))

    def validate_policy(
        self, workspace_id: Identifier, policy_id: Identifier
    ) -> PolicyValidation:
        workspace, policy = self.store.snapshot(workspace_id, policy_id)
        reasons = readiness(policy, self.clock())
        if not workspace.active:
            reasons.append("workspace_inactive")
        if policy.halted_reason:
            reasons.append("policy_halted")
        if (
            policy.used_requests >= policy.maximum_request_budget
            and "budget_exhausted" not in reasons
        ):
            reasons.append("budget_exhausted")
        if (
            policy.target_scope.allow_private_networks
            and workspace.program_type not in {"owned", "lab"}
        ):
            reasons.append("private_network_permission_invalid")
        return PolicyValidation(valid=not reasons, reasons=reasons)

    async def decide(
        self,
        workspace_id: Identifier,
        policy_id: Identifier,
        request: AuthorizationRequest,
        reserve: bool = False,
        discovery_owner: tuple[str, str] | None = None,
        privacy_owner: tuple[str, str] | None = None,
        credential_required: bool = False,
        minimize_audit: bool = False,
    ) -> tuple[Decision, str | None]:
        workspace, policy = await asyncio.to_thread(
            self.store.snapshot, workspace_id, policy_id
        )
        first = evaluate(workspace, policy, request, self.clock())
        resolution = None
        dns_error = None
        # Rejected syntax/authorization NEVER performs even a DNS lookup.
        if first.allowed and not policy.halted_reason:
            try:
                resolution = await asyncio.wait_for(
                    self.resolver.resolve(parsed_target(request).host), timeout=5
                )
            except (ScopeError, ValueError, OSError, TimeoutError):
                dns_error = "dns_unavailable"

        def recheck(current_workspace, current_policy, now):
            decision = evaluate(
                current_workspace, current_policy, request, now, resolution
            )
            if decision.allowed and (dns_error or resolution is None):
                return Decision(allowed=False, reason=dns_error or "dns_unknown")
            if decision.allowed and credential_required and parsed_target(request).scheme != "https":
                lab_http = (
                    current_workspace.program_type == "lab"
                    and current_policy.target_scope.allow_private_networks
                    and bool(decision.resolved_ips)
                    and all(ipaddress.ip_address(ip).is_private for ip in decision.resolved_ips)
                )
                if not lab_http:
                    return Decision(allowed=False, reason="credential_https_required")
            return decision

        # Raw URLs are never logged; digest only, including method/category.
        fingerprint = hashlib.sha256(
            (f"{request.method}\n{request.category}\n{request.url}"
             + ("\n" + json.dumps(request.query_parameters, sort_keys=True)
                if request.query_parameters else "")).encode()
        ).hexdigest()
        admission = asyncio.create_task(
            asyncio.to_thread(
                self.store.decide,
                workspace_id,
                policy_id,
                policy.revision,
                recheck,
                self.clock,
                fingerprint,
                reserve,
                discovery_owner,
                privacy_owner,
                minimize_audit,
            )
        )
        try:
            return await asyncio.shield(admission)
        except asyncio.CancelledError:
            # A cancelled to_thread await cannot cancel the database transaction.
            # Retrieve its result and release an admitted slot before propagating.
            _, lease_id = await admission
            if lease_id is not None:
                await asyncio.to_thread(
                    self.store.release,
                    workspace_id,
                    policy_id,
                    lease_id,
                    None,
                    self.clock(),
                )
            raise

    async def preflight(
        self,
        workspace_id: Identifier,
        policy_id: Identifier,
        request: AuthorizationRequest,
    ) -> Decision:
        decision, _ = await self.decide(workspace_id, policy_id, request)
        return decision

    @asynccontextmanager
    async def stream(
        self,
        workspace_id: Identifier,
        policy_id: Identifier,
        request: AuthorizationRequest,
        transport: httpx.AsyncBaseTransport | None = None,
        discovery_owner: tuple[str, str] | None = None,
        privacy_owner: tuple[str, str] | None = None,
        user_agent: str | None = None,
        observation_only: bool | None = None,
        auth_header: tuple[str, str] | None = None,
        minimize_audit: bool = False,
    ) -> AsyncIterator[httpx.Response]:
        """Authorize freshly, reserve atomically, pin IP, close response, release slot.

        A preflight is advisory; this method ALWAYS repeats authorization. No proxies,
        automatic redirects, retries, alternative IPs or AI-supplied policy changes.
        ``auth_header`` (Phase 4C) carries one allowlisted test-identity credential;
        its value is never logged, stored, fingerprinted or sent to the model.
        """
        decision, lease_id = await self.decide(
            workspace_id,
            policy_id,
            request,
            reserve=True,
            discovery_owner=discovery_owner,
            privacy_owner=privacy_owner,
            credential_required=auth_header is not None,
            minimize_audit=minimize_audit,
        )
        if not decision.allowed:
            raise AuthorizationDenied(decision.reason)
        reason = None
        try:
            url = parsed_target(request)
            async with pinned_response(
                url,
                decision.resolved_ips,
                transport,
                request.method,
                user_agent
                or ("CrimsonWeb/Phase4B" if discovery_owner else "CrimsonWeb/Phase4A"),
                observation_only=(
                    discovery_owner is not None
                    if observation_only is None
                    else observation_only
                ),
                auth_header=auth_header,
                # Admission permits HTTP credentials only for explicitly scoped
                # private-network lab targets. Public targets require HTTPS.
                allow_insecure_lab_auth=auth_header is not None and url.scheme == "http",
                query_parameters=request.query_parameters,
            ) as response:
                response.extensions["crimson_resolved_ips"] = decision.resolved_ips
                if response.status_code in {403, 429}:
                    reason = (
                        "http_403_access_denied"
                        if response.status_code == 403
                        else "http_429_rate_limited"
                    )
                    # Halt is persisted before the consumer can submit another request.
                    await asyncio.to_thread(
                        self.store.halt,
                        workspace_id,
                        policy_id,
                        reason,
                        self.clock(),
                    )
                yield response
        finally:
            await asyncio.shield(
                asyncio.to_thread(
                    self.store.release,
                    workspace_id,
                    policy_id,
                    lease_id,
                    reason,
                    self.clock(),
                )
            )

    async def notify_defense(
        self, workspace_id: Identifier, policy_id: Identifier, reason: str
    ) -> None:
        if reason not in {"waf_block", "ip_block", "authorization_violation"}:
            raise ValueError("Unsupported stop reason")
        await asyncio.to_thread(
            self.store.halt, workspace_id, policy_id, reason, self.clock()
        )

    def scan_guard(
        self,
        workspace_id: Identifier,
        policy_id: Identifier,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> "WorkspaceScanGuard":
        return WorkspaceScanGuard(self, workspace_id, policy_id, transport)


class WorkspaceScanGuard:
    def __init__(self, service, workspace_id, policy_id, transport):
        self.service, self.workspace_id, self.policy_id, self.transport = (
            service,
            workspace_id,
            policy_id,
            transport,
        )

    def stream(self, url):
        return self.service.stream(
            self.workspace_id,
            self.policy_id,
            AuthorizationRequest(url=str(url)),
            self.transport,
        )
