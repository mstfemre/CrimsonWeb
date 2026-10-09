"""Serial, authorized direct observations; no proxy/OS/AI configuration actions."""

import asyncio
import ipaddress
from uuid import uuid4

import httpx
from sqlalchemy.exc import SQLAlchemyError

from ..database import PrivacyAssessmentRow, PrivacyAuditRow, PrivacyProfileRow
from ..discovery.crawler import AuthorizedCrawler, durable
from ..discovery.store import DiscoveryLimit
from ..discovery.worker import WorkerLock
from ..workspaces.models import AuthorizationRequest
from ..workspaces.policy import evaluate
from ..workspaces.service import AuthorizationDenied, WorkspaceService
from ..workspaces.store import Conflict, NotFound
from .dns import ObservedResolver
from .evaluation import (
    connection_family,
    egress_verdict,
    identity_digest,
    ipv6_capability,
    parse_echo,
    privacy_reason,
)
from .models import (
    DNSObservation,
    EgressObservation,
    IPv6Observation,
    PolicyObservation,
    PrivacyAssessment,
    PrivacyAuditLog,
    PrivacyPreflight,
    PrivacyProfile,
)
from .store import PrivacyStop, PrivacyStore


class PrivacyService:
    def __init__(self, repository, workspace_service, transport=None):
        self.shared = workspace_service
        self.store = PrivacyStore(repository)
        self.resolver = ObservedResolver(lambda: self.shared.resolver)
        self.guard = WorkspaceService(
            repository, self.resolver, lambda: self.shared.clock()
        )
        self.transport = transport
        self.worker_id = str(uuid4())
        self.worker_lock = WorkerLock(repository, "privacy")
        self.tasks = {}
        self.gate = asyncio.Semaphore(1)
        self.submission = asyncio.Lock()
        self.closed = False
        self.reader = AuthorizedCrawler(
            self.guard, self.store, self.worker_id, transport
        )

    async def startup(self):
        if self.worker_lock.held:
            return 0
        if self.worker_lock.acquire():
            try:
                return await durable(
                    self.store.recover, self.worker_lock, self.shared.clock()
                )
            except BaseException:
                self.worker_lock.release()
                raise
        return 0

    async def preflight(self, workspace_id, profile_id, request):
        profile, policy, _ = await asyncio.to_thread(
            self.store.snapshot, workspace_id, profile_id
        )
        reason = privacy_reason(profile, policy, request, self.shared.clock())
        revision = None
        # Check foreign policy identity even if privacy has already denied admission.
        if request.program_policy_id:
            workspace, program = await asyncio.to_thread(
                self.shared.store.snapshot, workspace_id, request.program_policy_id
            )
            revision = program.revision
            if request.verification_url:
                decision = evaluate(
                    workspace,
                    program,
                    AuthorizationRequest(url=request.verification_url),
                    self.shared.clock(),
                )
                if not decision.allowed:
                    reason = reason or decision.reason
                if program.halted_reason:
                    reason = reason or "policy_halted"
                if program.used_requests >= program.maximum_request_budget:
                    reason = reason or "budget_exhausted"
        reason = await asyncio.to_thread(
            self.store.preflight_audit,
            workspace_id,
            profile_id,
            reason,
            self.shared.clock(),
        )
        return PrivacyPreflight(
            allowed=not bool(reason),
            reason=reason or "advisory_allowed_no_network",
            profile_revision=profile.revision,
            privacy_policy_revision=policy.revision,
            program_policy_revision=revision,
        )

    async def start(self, workspace_id, profile_id, request):
        if self.closed or not self.worker_lock.held:
            raise Conflict("Privacy worker unavailable")
        result = await self.preflight(workspace_id, profile_id, request)
        async with self.submission:
            if self.closed or not self.worker_lock.held or len(self.tasks) >= 8:
                raise Conflict("Privacy worker or queue unavailable")
            assessment = await durable(
                self.store.create_assessment,
                workspace_id,
                profile_id,
                request,
                result,
                self.shared.clock(),
            )
            key = (str(workspace_id), str(assessment.id))
            task = asyncio.create_task(self.execute(assessment, request))
            self.tasks[key] = task

            def done(future):
                self.tasks.pop(key, None)
                if not future.cancelled():
                    future.exception()  # no raw exception/response/prompt logging

            task.add_done_callback(done)
            return assessment

    def base(self, assessment, status, reason):
        identifier = uuid4()
        return {
            "id": identifier,
            "ref": f"privacy_evidence:{identifier}",
            "workspace_id": assessment.workspace_id,
            "profile_id": assessment.profile_id,
            "assessment_id": assessment.id,
            "timestamp": self.shared.clock(),
            "status": status,
            "reason": reason,
        }

    async def dns_observation(self, assessment, request, profile, key):
        decision, lease = await self.guard.decide(
            assessment.workspace_id,
            assessment.program_policy_id,
            AuthorizationRequest(url=request.verification_url),
            reserve=True,
            privacy_owner=(str(assessment.id), self.worker_id),
        )
        try:
            if not decision.allowed and decision.reason not in {
                "dns_unavailable",
                "dns_unknown",
            }:
                raise PrivacyStop(decision.reason)
            values = self.resolver.last
            config = [identity_digest(key, v) for v in values.get("configured", [])]
            observed = [identity_digest(key, v) for v in values.get("observed", [])]
            expected = set(profile.dns_expectations["approved_resolvers"])
            configuration_match = (
                set(config) <= expected if expected and config else None
            )
            path_match = set(observed) <= expected if expected and observed else None
            status, reason = "inconclusive", "resolver_path_not_observed"
            if not decision.allowed:
                reason = decision.reason
            elif values.get("literal_target"):
                status, reason = "not_tested", "dns_not_tested_for_ip_literal"
            elif values.get("path_observed") and path_match is not None:
                status, reason = (
                    ("secure_observed", "controlled_dns_path_matched")
                    if path_match
                    else ("leak_validated", "controlled_dns_path_mismatch")
                )
            elif configuration_match is False:
                status, reason = "leak_suspected", "resolver_configuration_mismatch"
            addresses = (
                () if values.get("literal_target") else values.get("addresses", ())
            )
            return DNSObservation(
                **self.base(assessment, status, reason),
                configuration_source=values.get("configuration_source", "unknown"),
                resolver_fingerprints=config,
                observed_resolver_fingerprints=observed,
                path_observation_source="controlled_packet_capture"
                if values.get("path_observed", False)
                else "unobserved",
                configured_resolver_matches=configuration_match,
                observed_path_matches=path_match,
                path_observed=values.get("path_observed", False),
                ipv4_answer_count=sum(
                    ipaddress.ip_address(v).version == 4 for v in addresses
                ),
                ipv6_answer_count=sum(
                    ipaddress.ip_address(v).version == 6 for v in addresses
                ),
                cname_count=len(values.get("cnames", ())),
                application_resolution_tested=bool(values)
                and not values.get("literal_target", False),
            )
        finally:
            if lease:
                await durable(
                    self.guard.store.release,
                    assessment.workspace_id,
                    assessment.program_policy_id,
                    lease,
                    None,
                    self.shared.clock(),
                )

    async def egress_observation(self, assessment, request, profile, key):
        async with self.guard.stream(
            assessment.workspace_id,
            assessment.program_policy_id,
            AuthorizationRequest(url=request.verification_url),
            self.transport,
            privacy_owner=(str(assessment.id), self.worker_id),
        ) as response:
            family = connection_family(response)
            status = response.status_code
            if status in {403, 429}:
                raise PrivacyStop(
                    "http_403_access_denied"
                    if status == 403
                    else "http_429_rate_limited"
                )
            await asyncio.to_thread(
                self.store.check,
                assessment.workspace_id,
                assessment.id,
                self.worker_id,
                self.shared.clock(),
            )
            if 300 <= status < 400:
                raise PrivacyStop("privacy_redirect_not_followed")
            if (
                status != 200
                or response.headers.get("content-type", "")
                .split(";", 1)[0]
                .strip()
                .lower()
                != "application/json"
            ):
                raise ValueError("invalid_echo_response")
            body = await self.reader.read_body(response, 4096)
            address = parse_echo(body)
            reported = "ipv4" if ipaddress.ip_address(address).version == 4 else "ipv6"
            identity = identity_digest(key, address)
            approved = profile.approved_egress_identity[reported]
            matches = identity in approved if approved else None
            verdict, reason = egress_verdict(profile, family, reported, matches)
            return EgressObservation(
                **self.base(assessment, verdict, reason),
                requested_family=request.family,
                connection_family=family,
                reported_ip_family=reported,
                reported_identity_fingerprint=identity,
                identity_matches=matches,
                http_status=status,
            )

    async def execute(self, assessment, request):
        observation = None
        execution = "completed"
        bypass = False
        try:
            async with self.gate:
                claim = await durable(
                    self.store.claim,
                    assessment.workspace_id,
                    assessment.id,
                    self.worker_id,
                )
                if claim is None:
                    return
                _, denial = claim
                if denial:
                    raise PrivacyStop(denial)
                await asyncio.to_thread(
                    self.store.check,
                    assessment.workspace_id,
                    assessment.id,
                    self.worker_id,
                    self.shared.clock(),
                )
                profile, _, key = await asyncio.to_thread(
                    self.store.snapshot, assessment.workspace_id, assessment.profile_id
                )
                if request.kind == "ipv6" and not request.verification_url:
                    supported, available = await asyncio.to_thread(ipv6_capability)
                    verdict = (
                        "leak_suspected"
                        if profile.ipv6_expectation == "forbidden" and available
                        else "inconclusive"
                    )
                    observation = IPv6Observation(
                        **self.base(
                            assessment, verdict, "ipv6_capability_not_egress_proof"
                        ),
                        platform_has_ipv6=supported,
                        loopback_socket_available=available,
                    )
                elif request.kind == "dns":
                    observation = await self.dns_observation(
                        assessment, request, profile, key
                    )
                else:
                    observation = await self.egress_observation(
                        assessment, request, profile, key
                    )
                # Includes a post-response revision/cancel fence before publication.
                await durable(
                    self.store.complete,
                    assessment.workspace_id,
                    assessment.id,
                    self.worker_id,
                    observation,
                    self.shared.clock(),
                )
                observation = None
                return
        except asyncio.CancelledError:
            execution, bypass = "cancelled", True
            observation = PolicyObservation(
                **self.base(assessment, "not_tested", "operator_cancelled")
            )
        except (PrivacyStop, AuthorizationDenied) as exc:
            bypass = True
            reason = exc.reason
            if reason == "privacy_cancelled":
                execution = "cancelled"
            observation = PolicyObservation(
                **self.base(
                    assessment,
                    "not_tested" if execution == "cancelled" else "blocked_by_policy",
                    reason,
                )
            )
        except NotFound:
            bypass = True
            observation = PolicyObservation(
                **self.base(assessment, "blocked_by_policy", "privacy_profile_deleted")
            )
        except (SQLAlchemyError, Conflict):
            execution, bypass = "failed", True
            observation = PolicyObservation(
                **self.base(assessment, "inconclusive", "storage_or_ownership_error")
            )
        except (httpx.HTTPError, TimeoutError, OSError, ValueError, DiscoveryLimit):
            observation = PolicyObservation(
                **self.base(assessment, "inconclusive", "network_or_echo_inconclusive")
            )
        except Exception:  # noqa: BLE001 -- terminate the job safely without logging untrusted exception data
            execution, bypass = "failed", True
            observation = PolicyObservation(
                **self.base(assessment, "inconclusive", "worker_error")
            )
        finally:
            if observation is not None:
                try:
                    await durable(
                        self.store.complete,
                        assessment.workspace_id,
                        assessment.id,
                        self.worker_id,
                        observation,
                        self.shared.clock(),
                        execution,
                        bypass,
                    )
                except PrivacyStop as exc:
                    cancelled = exc.reason == "privacy_cancelled"
                    replacement = PolicyObservation(
                        **self.base(
                            assessment,
                            "not_tested" if cancelled else "blocked_by_policy",
                            exc.reason,
                        )
                    )
                    await durable(
                        self.store.complete,
                        assessment.workspace_id,
                        assessment.id,
                        self.worker_id,
                        replacement,
                        self.shared.clock(),
                        "cancelled" if cancelled else "completed",
                        True,
                    )

    async def cancel(self, workspace_id, assessment_id):
        await durable(
            self.store.cancel, workspace_id, assessment_id, self.shared.clock()
        )
        task = self.tasks.get((str(workspace_id), str(assessment_id)))
        if task:
            if not task.cancelling():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return await asyncio.to_thread(
            self.store.get_assessment, workspace_id, assessment_id
        )

    async def shutdown(self):
        self.closed = True
        pending = list(self.tasks.items())
        try:
            for (workspace_id, assessment_id), task in pending:
                await durable(
                    self.store.cancel, workspace_id, assessment_id, self.shared.clock()
                )
                if not task.cancelling():
                    task.cancel()
        finally:
            for _, task in pending:
                if not task.done() and not task.cancelling():
                    task.cancel()
            await asyncio.gather(*(task for _, task in pending), return_exceptions=True)
            self.worker_lock.release()

    def profiles(self, workspace_id, limit=50, offset=0):
        return self.store.list_records(
            workspace_id, PrivacyProfileRow, PrivacyProfile, limit, offset
        )

    def assessments(self, workspace_id, limit=50, offset=0):
        return self.store.list_records(
            workspace_id, PrivacyAssessmentRow, PrivacyAssessment, limit, offset
        )

    def audits(self, workspace_id, limit=50, offset=0):
        return self.store.list_records(
            workspace_id, PrivacyAuditRow, PrivacyAuditLog, limit, offset
        )
