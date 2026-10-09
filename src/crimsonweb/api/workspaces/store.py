"""Workspace-qualified storage on the existing repository engine.

SQLite BEGIN IMMEDIATE serializes policy changes and admissions across connections.
Reservations count even on connection failure; a crash never restores consumed budget.
"""

from contextlib import contextmanager
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..database import (
    DiscoveryJobRow,
    PolicyRevisionRow,
    ProgramPolicyRow,
    ScopeAuditRow,
    ScopeLeaseRow,
    TargetScopeRow,
    WorkspaceRow,
)
from ..models import Page
from .models import Decision, PolicyRecord, PolicyRevision, ScopeAuditLog, Workspace


class NotFound(LookupError):
    pass


class Conflict(ValueError):
    pass


class WorkspaceStore:
    def __init__(self, repository):
        self.repository = repository

    @contextmanager
    def transaction(self):
        with self.repository._lock, Session(self.repository.engine) as session:
            session.execute(text("BEGIN IMMEDIATE"))
            try:
                yield session
                session.commit()
            except BaseException:
                session.rollback()
                raise

    @staticmethod
    def workspace(session, workspace_id):
        row = session.get(WorkspaceRow, str(workspace_id))
        if row is None:
            raise NotFound("Workspace not found")
        return Workspace.model_validate(row.data)

    @staticmethod
    def policy_row(session, workspace_id, policy_id):
        row = session.scalar(
            select(ProgramPolicyRow).where(
                ProgramPolicyRow.id == str(policy_id),
                ProgramPolicyRow.workspace_id == str(workspace_id),
            )
        )
        if row is None:
            raise NotFound("Policy not found")
        return row

    @staticmethod
    def policy(session, row):
        scope = session.scalar(
            select(TargetScopeRow).where(
                TargetScopeRow.workspace_id == row.workspace_id,
                TargetScopeRow.policy_id == row.id,
            )
        )
        return PolicyRecord(
            **row.data,
            target_scope=scope.data,
            id=row.id,
            workspace_id=row.workspace_id,
            revision=row.revision,
            used_requests=row.used_requests,
            halted_reason=row.halted_reason,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    @staticmethod
    def audit(
        session,
        workspace_id,
        policy_id,
        action,
        allowed,
        reason,
        now,
        fingerprint=None,
        resolved_ips=None,
    ):
        policy = session.get(ProgramPolicyRow, str(policy_id)) if policy_id else None
        session.add(
            ScopeAuditRow(
                id=str(uuid4()),
                workspace_id=str(workspace_id),
                policy_id=str(policy_id) if policy_id else None,
                policy_revision=policy.revision if policy else None,
                timestamp=now.isoformat(),
                action=action,
                allowed=allowed,
                reason=reason,
                request_fingerprint=fingerprint,
                resolved_ips=resolved_ips or [],
            )
        )

    def create_workspace(self, payload, now):
        item = Workspace(
            **payload.model_dump(), id=uuid4(), created_at=now, updated_at=now
        )
        with self.transaction() as session:
            session.add(
                WorkspaceRow(id=str(item.id), data=item.model_dump(mode="json"))
            )
            session.flush()
            self.audit(
                session,
                item.id,
                None,
                "workspace_created",
                True,
                "operator_action",
                now,
            )
        return item

    def get_workspace(self, workspace_id):
        with self.repository._lock, Session(self.repository.engine) as session:
            return self.workspace(session, workspace_id)

    def list_workspaces(self, limit, offset):
        with self.repository._lock, Session(self.repository.engine) as session:
            rows = session.scalars(
                select(WorkspaceRow)
                .order_by(WorkspaceRow.id)
                .limit(limit)
                .offset(offset)
            )
            return Page(
                items=[Workspace.model_validate(r.data) for r in rows],
                total=session.scalar(select(func.count()).select_from(WorkspaceRow)),
                limit=limit,
                offset=offset,
            )

    def update_workspace(self, workspace_id, payload, now):
        with self.transaction() as session:
            old = self.workspace(session, workspace_id)
            item = Workspace.model_validate(
                {
                    **old.model_dump(),
                    **payload.model_dump(exclude_unset=True),
                    "updated_at": now,
                }
            )
            session.get(WorkspaceRow, str(workspace_id)).data = item.model_dump(
                mode="json"
            )
            self.audit(
                session,
                workspace_id,
                None,
                "workspace_updated",
                True,
                "operator_action",
                now,
            )
            return item

    def write_policy(
        self, workspace_id, payload, now, policy_id=None, expected_revision=None
    ):
        with self.transaction() as session:
            self.workspace(session, workspace_id)
            if policy_id is None:
                if session.scalar(
                    select(ProgramPolicyRow.id).where(
                        ProgramPolicyRow.workspace_id == str(workspace_id)
                    )
                ):
                    raise Conflict("Workspace already has a policy")
                row = ProgramPolicyRow(
                    id=str(uuid4()),
                    workspace_id=str(workspace_id),
                    revision=1,
                    used_requests=0,
                    halted_reason=None,
                    created_at=now.isoformat(),
                    updated_at=now.isoformat(),
                    data=payload.model_dump(mode="json", exclude={"target_scope"}),
                )
                session.add(row)
                session.flush()
                scope = TargetScopeRow(
                    id=str(uuid4()),
                    policy_id=row.id,
                    workspace_id=row.workspace_id,
                    data=payload.target_scope.model_dump(mode="json"),
                )
                session.add(scope)
                action = "policy_created"
            else:
                row = self.policy_row(session, workspace_id, policy_id)
                if row.revision != expected_revision:
                    raise Conflict("Policy revision changed")
                # Updating an approved policy is an explicit operator re-authorization.
                row.data = payload.model_dump(mode="json", exclude={"target_scope"})
                row.revision += 1
                row.updated_at = now.isoformat()
                row.halted_reason = None
                scope = session.scalar(
                    select(TargetScopeRow).where(
                        TargetScopeRow.policy_id == row.id,
                        TargetScopeRow.workspace_id == row.workspace_id,
                    )
                )
                scope.data = payload.target_scope.model_dump(mode="json")
                action = "policy_updated"
            session.flush()
            self.audit(
                session, workspace_id, row.id, action, True, "operator_action", now
            )
            session.add(
                PolicyRevisionRow(
                    policy_id=row.id,
                    revision=row.revision,
                    workspace_id=row.workspace_id,
                    created_at=now.isoformat(),
                    data=payload.model_dump(mode="json"),
                )
            )
            return self.policy(session, row)

    def snapshot(self, workspace_id, policy_id):
        with self.repository._lock, Session(self.repository.engine) as session:
            workspace = self.workspace(session, workspace_id)
            return workspace, self.policy(
                session, self.policy_row(session, workspace_id, policy_id)
            )

    def policy_revision(self, workspace_id, policy_id, revision):
        with self.repository._lock, Session(self.repository.engine) as session:
            self.workspace(session, workspace_id)
            self.policy_row(session, workspace_id, policy_id)
            row = session.scalar(
                select(PolicyRevisionRow).where(
                    PolicyRevisionRow.policy_id == str(policy_id),
                    PolicyRevisionRow.workspace_id == str(workspace_id),
                    PolicyRevisionRow.revision == revision,
                )
            )
            if row is None:
                raise NotFound("Policy revision not found")
            return PolicyRevision(
                workspace_id=row.workspace_id,
                policy_id=row.policy_id,
                revision=row.revision,
                created_at=row.created_at,
                policy=row.data,
            )

    def decide(
        self,
        workspace_id,
        policy_id,
        revision,
        evaluate,
        clock,
        fingerprint,
        reserve=False,
        discovery_owner=None,
        privacy_owner=None,
    ):
        with self.transaction() as session:
            now = clock()
            workspace = self.workspace(session, workspace_id)
            row = self.policy_row(session, workspace_id, policy_id)
            policy = self.policy(session, row)
            decision = evaluate(workspace, policy, now)
            if row.revision != revision:
                decision = Decision(allowed=False, reason="policy_changed")
            elif row.halted_reason:
                decision = Decision(allowed=False, reason="policy_halted")
            discovery_job = None
            privacy_job = None
            if reserve and decision.allowed and privacy_owner is not None:
                if discovery_owner is not None:
                    decision = Decision(allowed=False, reason="privacy_owner_conflict")
                else:
                    from ..privacy.admission import privacy_admission

                    privacy_job, reason = privacy_admission(
                        self.repository,
                        session,
                        workspace_id,
                        policy_id,
                        privacy_owner,
                        decision,
                        fingerprint,
                        now,
                    )
                    if reason:
                        decision = Decision(allowed=False, reason=reason)
            if reserve and decision.allowed and discovery_owner is not None:
                job_id, worker_id = discovery_owner
                discovery_job = session.scalar(
                    select(DiscoveryJobRow).where(
                        DiscoveryJobRow.id == str(job_id),
                        DiscoveryJobRow.workspace_id == str(workspace_id),
                        DiscoveryJobRow.policy_id == str(policy_id),
                        DiscoveryJobRow.worker_id == str(worker_id),
                        DiscoveryJobRow.status == "running",
                    )
                )
                reason = (
                    "discovery_worker_inactive"
                    if discovery_job is None
                    else "discovery_cancelled"
                    if discovery_job.cancel_requested
                    else "discovery_policy_changed"
                    if discovery_job.data["policy_revision"] != row.revision
                    else "discovery_budget_exhausted"
                    if discovery_job.requests_made
                    >= discovery_job.data["limits"]["max_requests"]
                    else None
                )
                if reason:
                    decision = Decision(allowed=False, reason=reason)
            if decision.allowed:
                inflight = session.scalar(
                    select(func.count())
                    .select_from(ScopeLeaseRow)
                    .where(
                        ScopeLeaseRow.policy_id == row.id,
                        ScopeLeaseRow.workspace_id == row.workspace_id,
                        ScopeLeaseRow.released.is_(False),
                    )
                )
                recent = session.scalar(
                    select(func.count())
                    .select_from(ScopeLeaseRow)
                    .where(
                        ScopeLeaseRow.policy_id == row.id,
                        ScopeLeaseRow.workspace_id == row.workspace_id,
                        ScopeLeaseRow.created_at
                        > (now - timedelta(minutes=1)).isoformat(),
                    )
                )
                reason = (
                    "budget_exhausted"
                    if row.used_requests >= policy.maximum_request_budget
                    else "concurrency_exceeded"
                    if inflight >= policy.maximum_concurrency
                    else "rate_limit_exceeded"
                    if recent >= policy.rate_limit_per_minute
                    else None
                )
                if reason:
                    decision = Decision(allowed=False, reason=reason)
            lease_id = None
            if reserve and decision.allowed:
                lease_id = str(uuid4())
                row.used_requests += 1
                session.add(
                    ScopeLeaseRow(
                        id=lease_id,
                        workspace_id=row.workspace_id,
                        policy_id=row.id,
                        created_at=now.isoformat(),
                        released=False,
                        discovery_job_id=str(discovery_owner[0])
                        if discovery_owner
                        else None,
                        discovery_worker_id=str(discovery_owner[1])
                        if discovery_owner
                        else None,
                        privacy_assessment_id=str(privacy_owner[0])
                        if privacy_owner
                        else None,
                        privacy_worker_id=str(privacy_owner[1])
                        if privacy_owner
                        else None,
                    )
                )
                if discovery_job is not None:
                    discovery_job.requests_made += 1
                if privacy_job is not None:
                    privacy_job.requests_made += 1
            if (
                reserve
                and not decision.allowed
                and not decision.reason.startswith("privacy_")
                and decision.reason
                not in {
                    "budget_exhausted",
                    "concurrency_exceeded",
                    "rate_limit_exceeded",
                    "policy_halted",
                    "discovery_worker_inactive",
                    "discovery_cancelled",
                    "discovery_policy_changed",
                    "discovery_budget_exhausted",
                }
            ):
                row.halted_reason = decision.reason
            decision.policy_revision = row.revision
            self.audit(
                session,
                workspace_id,
                policy_id,
                "request_admitted" if reserve else "preflight",
                decision.allowed,
                decision.reason,
                now,
                fingerprint,
                [] if privacy_owner else decision.resolved_ips,
            )
            return decision, lease_id

    def release(self, workspace_id, policy_id, lease_id, reason, now):
        with self.transaction() as session:
            row = self.policy_row(session, workspace_id, policy_id)
            lease = session.scalar(
                select(ScopeLeaseRow).where(
                    ScopeLeaseRow.id == lease_id,
                    ScopeLeaseRow.workspace_id == str(workspace_id),
                    ScopeLeaseRow.policy_id == str(policy_id),
                )
            )
            if lease is None:
                raise NotFound("Reservation not found")
            if lease.released:
                return
            lease.released = True
            if reason:
                row.halted_reason = reason
            self.audit(
                session,
                workspace_id,
                policy_id,
                "request_finished",
                reason is None,
                reason or "released",
                now,
            )

    def halt(self, workspace_id, policy_id, reason, now):
        with self.transaction() as session:
            row = self.policy_row(session, workspace_id, policy_id)
            row.halted_reason = reason
            self.audit(
                session, workspace_id, policy_id, "defense_stop", False, reason, now
            )

    def audits(self, workspace_id, limit, offset):
        with self.repository._lock, Session(self.repository.engine) as session:
            self.workspace(session, workspace_id)
            query = select(ScopeAuditRow).where(
                ScopeAuditRow.workspace_id == str(workspace_id)
            )
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(
                query.order_by(ScopeAuditRow.timestamp.desc(), ScopeAuditRow.id)
                .limit(limit)
                .offset(offset)
            )
            return Page(
                items=[
                    ScopeAuditLog(
                        **{k: getattr(r, k) for k in ScopeAuditLog.model_fields}
                    )
                    for r in rows
                ],
                total=total,
                limit=limit,
                offset=offset,
            )
