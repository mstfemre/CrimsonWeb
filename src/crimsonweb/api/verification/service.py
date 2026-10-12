"""Orchestration: build a plan, gate on operator approval, then execute read-only.

The model (when available) only proposes catalog tests, validated against known
ids; otherwise proposals are seeded deterministically for the operator to review.
Execution is serial and inline, each request authorized by the shared guard. On
any safe-stop the plan halts and no further requests are made. Credentials in the
execute request are held in memory for the run only and never persisted.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import uuid4

from ..discovery.store import DiscoveryEvidenceStore
from ..workspaces.service import AuthorizationDenied
from ..workspaces.store import Conflict
from .catalog import catalog_entry
from .executor import VerificationExecutor
from .models import (
    PlanApproval,
    PlanProposal,
    VerificationPlan,
    VerificationPlanCreate,
)
from .planner import (
    MAX_PROPOSALS,
    eligible_target,
    generate_proposals,
    validate_proposals,
)
from .store import VerificationStore
from .targets import approved_origin, targets_from_endpoints, targets_from_openapi


class VerificationService:
    def __init__(
        self, repository, workspace_service, transport=None, provider=None,
        provider_gate=None, max_input_bytes=32768,
    ):
        self.shared = workspace_service
        self.store = VerificationStore(repository)
        self.discovery = DiscoveryEvidenceStore(repository)
        # The executor drives every request through the shared authorization guard.
        self.executor = VerificationExecutor(workspace_service, transport)
        self.provider = provider
        self.provider_gate = provider_gate
        self.max_input_bytes = max_input_bytes
        self._execution_gate = asyncio.Lock()
        self._executions: set[asyncio.Task] = set()
        self._closed = False
        self._accepting_execution = False

    @asynccontextmanager
    async def execution_admission(self):
        """Reject overload before the API reads a credential-bearing body."""
        if self._closed or self._accepting_execution or self._execution_gate.locked():
            raise Conflict("Verification execution unavailable; retry without sending credentials")
        self._accepting_execution = True
        try:
            yield
        finally:
            self._accepting_execution = False

    def clock(self) -> datetime:
        return self.shared.clock() if self.shared.clock else datetime.now(UTC)

    async def create_plan(
        self, workspace_id, payload: VerificationPlanCreate
    ) -> VerificationPlan:
        # Validate workspace + policy existence (raises NotFound).
        self.shared.store.snapshot(workspace_id, payload.policy_id)
        ids = sorted(set(payload.catalog_ids))
        if any(catalog_entry(i) is None for i in ids):
            raise Conflict("Unknown verification catalog")
        limitations: list[str] = []
        if payload.source == "discovery":
            job = self.discovery.get(workspace_id, payload.discovery_job_id)
            endpoints = self.discovery.endpoints(
                workspace_id, payload.discovery_job_id, 500, 0
            ).items
            targets = targets_from_endpoints(endpoints)
            source_job = job.id
        else:
            targets = targets_from_openapi(payload.openapi_document, payload.base_url)
            source_job = None
            limitations.append("openapi_candidates_declared_not_observed")

        proposals, planner, model_limitations = await self._select_proposals(
            targets, ids, require_model=payload.require_model,
        )
        limitations.extend(model_limitations)
        proposals = proposals[:payload.max_tests]

        now = self.clock()
        plan = VerificationPlan(
            id=uuid4(),
            workspace_id=workspace_id,
            policy_id=payload.policy_id,
            source=payload.source,
            status="awaiting_approval",
            planner=planner,
            source_discovery_job_id=source_job,
            targets=targets,
            proposals=proposals,
            created_at=now,
            updated_at=now,
            limitations=sorted(set(limitations)),
            allowed_catalog_ids=ids, max_tests=payload.max_tests,
            require_model=payload.require_model,
        )
        return self.store.create_plan(plan)

    async def _select_proposals(self, targets, ids, *, require_model=False,
                                observations=None, available_bindings=None):
        """Shared initial/follow-up selection; strict mode never seeds an operator plan."""
        fallback = available_bindings if available_bindings is not None else self._seed_proposals(targets, ids)
        if self.provider is None:
            if require_model:
                raise Conflict("Required model planner unavailable")
            return fallback, "operator", []
        try:
            selected = await generate_proposals(
                self.provider, targets, self.provider_gate, self.max_input_bytes,
                allowed_catalog_ids=ids, observations=observations,
                available_bindings=available_bindings,
            )
            if require_model and not selected:
                raise ValueError("No model selection")
            return selected, "model", []
        except Exception:  # noqa: BLE001 -- fixed error only, never expose provider/model text
            if require_model:
                raise Conflict("Required model planner unavailable") from None
            return fallback, "operator", ["model_planner_unavailable_operator_seeded"]

    @staticmethod
    def _seed_proposals(targets, ids=None) -> list[PlanProposal]:
        proposals = []
        for entry_id in (ids or ["bola_cross_owner_read"]):
            for target in targets:
                entry = catalog_entry(entry_id)
                if eligible_target(target, entry) and target.evidence_refs:
                    parameters = target.query_parameters if entry.requires_query_parameter else [None]
                    for parameter in parameters:
                        proposals.append(
                            PlanProposal(
                                catalog_id=entry_id,
                                target_endpoint_ref=target.endpoint_ref,
                                evidence_refs=list(target.evidence_refs),
                                query_parameter=parameter,
                            )
                        )
        return proposals[:MAX_PROPOSALS]

    def approve_plan(self, workspace_id, plan_id, approval: PlanApproval):
        origin_ref = approved_origin(approval.base_url)
        plan = self.store.get_plan(workspace_id, plan_id)
        if not plan.proposals:
            raise Conflict("No eligible verification tests")
        if (any(p.catalog_id == "bola_cross_owner_read" for p in plan.proposals)
            and not approval.private_records_only):
            raise Conflict("BOLA approval requires private test-record expectations")
        targets = {t.endpoint_ref: t for t in plan.targets}
        if any(targets[p.target_endpoint_ref].origin_ref not in {"offline", origin_ref}
               for p in plan.proposals):
            raise Conflict("Approval origin does not match endpoint provenance")
        return self.store.approve_plan(workspace_id, plan_id, approval, self.clock())

    async def execute_plan(self, workspace_id, plan_id, request) -> VerificationPlan:
        if self._closed:
            raise Conflict("Verification service is shutting down")
        if self._execution_gate.locked():
            raise Conflict("Verification execution busy")
        task = asyncio.current_task()
        self._executions.add(task)
        try:
            async with self._execution_gate:
                return await self._execute_plan(workspace_id, plan_id, request)
        finally:
            self._executions.discard(task)

    async def _execute_plan(self, workspace_id, plan_id, request) -> VerificationPlan:
        plan = self.store.get_plan(workspace_id, plan_id)
        if plan.status != "approved":
            raise Conflict("Plan must be approved before execution")
        if (any(p.catalog_id == "bola_cross_owner_read" for p in plan.proposals)
            and not plan.approved_private_records_only):
            raise Conflict("Private test record authorization must be approved")
        if (approved_origin(request.base_url) != plan.approved_origin_ref
            or request.owner_binding_field != plan.approved_binding_field):
            raise Conflict("Execution must match the approved origin and binding field")
        validate_proposals({"proposals": [p.model_dump() for p in plan.proposals]}, plan.targets,
                           plan.allowed_catalog_ids)
        if any(p.catalog_id == "bola_cross_owner_read" for p in plan.proposals) and len(request.identities) != 2:
            raise Conflict("BOLA verification requires two test identities")
        validation = self.shared.validate_policy(workspace_id, plan.policy_id)
        if not validation.valid:
            raise AuthorizationDenied(validation.reasons[0])
        # Atomically claim the approved plan so a second execute cannot race.
        self.store.set_status(
            workspace_id, plan_id, "executing", self.clock(), expected="approved"
        )
        targets = {t.endpoint_ref: t for t in plan.targets}
        halted = False
        failed = False
        try:
            for proposal in plan.proposals:
                if self.store.get_plan(workspace_id, plan_id).cancel_requested:
                    return self.store.set_status(workspace_id, plan_id, "cancelled", self.clock())
                target = targets.get(proposal.target_endpoint_ref)
                if target is None:
                    continue
                result = await self.executor.execute(
                    workspace_id, plan.policy_id, plan.id, proposal, target, request,
                    cancelled=lambda: self.store.get_plan(workspace_id, plan_id).cancel_requested,
                )
                self.store.save_result(result)
                if result.test.status == "blocked_by_policy":
                    halted = True
                    break
                if result.test.status == "failed":
                    failed = True
                    break
        except asyncio.CancelledError:
            self.store.set_status(workspace_id, plan_id, "cancelled", self.clock())
            raise
        except Exception:
            self.store.set_status(workspace_id, plan_id, "failed", self.clock())
            raise
        if self.store.get_plan(workspace_id, plan_id).cancel_requested:
            return self.store.set_status(workspace_id, plan_id, "cancelled", self.clock())
        return self.store.set_status(
            workspace_id, plan_id,
            "halted" if halted else "failed" if failed else "completed", self.clock()
        )

    async def shutdown(self) -> None:
        self._closed = True
        pending = [task for task in self._executions if task is not asyncio.current_task()]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    async def next_plan(self, workspace_id, plan_id):
        """Use minimized observations to suggest remaining tools; approval is renewed."""
        parent = self.store.get_plan(workspace_id, plan_id)
        if parent.status != "completed" or parent.round_number >= 3:
            raise Conflict("Follow-up requires a completed plan below the round limit")
        validation = self.shared.validate_policy(workspace_id, parent.policy_id)
        if not validation.valid:
            raise AuthorizationDenied(validation.reasons[0])
        seen = set()
        observations = []
        current = parent
        for _ in range(3):
            for test in self.store.tests(workspace_id, current.id, 500, 0).items:
                # Do not send bodies, identities, URLs or arbitrary report text to the model.
                observations.append({"catalog_id": test.catalog_id, "endpoint_ref": test.target_endpoint_ref,
                                     "outcome": test.outcome, "confidence": test.confidence})
            seen.update((p.catalog_id, p.target_endpoint_ref, p.query_parameter) for p in current.proposals)
            if current.parent_plan_id is None:
                break
            current = self.store.get_plan(workspace_id, current.parent_plan_id)
        available = [p for p in self._seed_proposals(parent.targets, parent.allowed_catalog_ids)
                     if (p.catalog_id, p.target_endpoint_ref, p.query_parameter) not in seen]
        if not available:
            raise Conflict("No remaining approved-catalog tests")
        limitations = ["follow_up_requires_new_operator_approval"]
        proposals, planner, model_limitations = await self._select_proposals(
            parent.targets, parent.allowed_catalog_ids, require_model=parent.require_model,
            observations=observations, available_bindings=available,
        )
        limitations.extend(model_limitations)
        if not proposals:
            raise Conflict("Planner selected no remaining tests")
        now = self.clock()
        targets = [t.model_copy(update={"origin_ref": parent.approved_origin_ref})
                   if t.origin_ref == "offline" else t for t in parent.targets]
        plan = VerificationPlan(
            id=uuid4(), workspace_id=workspace_id, policy_id=parent.policy_id, source=parent.source,
            status="awaiting_approval", planner=planner, targets=targets,
            proposals=proposals[:parent.max_tests], created_at=now, updated_at=now,
            allowed_catalog_ids=parent.allowed_catalog_ids, max_tests=parent.max_tests,
            parent_plan_id=parent.id, round_number=parent.round_number + 1, limitations=limitations,
            source_discovery_job_id=parent.source_discovery_job_id,
            require_model=parent.require_model,
        )
        return self.store.create_plan(plan)
