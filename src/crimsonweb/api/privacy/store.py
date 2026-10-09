"""Workspace-qualified, minimal privacy evidence and atomic observation bookkeeping."""

import hashlib
import secrets
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import (
    PrivacyAssessmentRow,
    PrivacyAuditRow,
    PrivacyEvidenceRow,
    PrivacyFindingRow,
    PrivacyPolicyRow,
    PrivacyProfileRow,
    ScopeLeaseRow,
)
from ..discovery.worker import WorkerLock
from ..models import Page
from ..workspaces.policy import readiness
from ..workspaces.store import Conflict, NotFound, WorkspaceStore
from .evaluation import privacy_reason, profile_data
from .models import (
    EVIDENCE_ADAPTER,
    NetworkLeakFinding,
    PolicyObservation,
    PrivacyAssessment,
    PrivacyAuditLog,
    PrivacyPolicy,
    PrivacyPolicyRecord,
    PrivacyProfile,
)


class PrivacyStop(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class PrivacyStore(WorkspaceStore):
    @staticmethod
    def profile_row(session, workspace_id, profile_id, historical=False):
        row = session.scalar(
            select(PrivacyProfileRow).where(
                PrivacyProfileRow.id == str(profile_id),
                PrivacyProfileRow.workspace_id == str(workspace_id),
            )
        )
        if row is None or (row.deleted and not historical):
            raise NotFound("Privacy profile not found")
        return row

    @staticmethod
    def profile_record(row):
        return PrivacyProfile(
            **row.data, id=row.id, workspace_id=row.workspace_id, revision=row.revision
        )

    @staticmethod
    def privacy_policy_row(session, workspace_id, profile_id):
        return session.scalar(
            select(PrivacyPolicyRow).where(
                PrivacyPolicyRow.workspace_id == str(workspace_id),
                PrivacyPolicyRow.profile_id == str(profile_id),
            )
        )

    @staticmethod
    def policy_record(row):
        return PrivacyPolicyRecord(
            **row.data,
            id=row.id,
            workspace_id=row.workspace_id,
            profile_id=row.profile_id,
            revision=row.revision,
            used_observations=row.used_observations,
        )

    @staticmethod
    def assessment_row(session, workspace_id, assessment_id):
        row = session.scalar(
            select(PrivacyAssessmentRow).where(
                PrivacyAssessmentRow.id == str(assessment_id),
                PrivacyAssessmentRow.workspace_id == str(workspace_id),
            )
        )
        if row is None:
            raise NotFound("Privacy assessment not found")
        return row

    @staticmethod
    def assessment_record(row):
        return PrivacyAssessment(
            **{
                k: v for k, v in row.data.items() if k in PrivacyAssessment.model_fields
            },
            id=row.id,
            workspace_id=row.workspace_id,
            profile_id=row.profile_id,
            program_policy_id=row.program_policy_id,
            execution_status=row.execution_status,
            cancel_requested=row.cancel_requested,
            requests_made=row.requests_made,
            created_at=row.created_at,
        )

    @staticmethod
    def privacy_audit(
        session,
        workspace_id,
        profile_id,
        kind,
        reason,
        now,
        assessment_id=None,
        evidence_ref=None,
    ):
        value = PrivacyAuditLog(
            id=uuid4(),
            workspace_id=workspace_id,
            profile_id=profile_id,
            assessment_id=assessment_id,
            test_category=kind,
            timestamp=now,
            policy_decision=reason,
            safe_summary="metadata_only_no_raw_ip_or_payload",
            evidence_ref=evidence_ref,
        )
        session.add(
            PrivacyAuditRow(
                id=str(value.id),
                workspace_id=str(workspace_id),
                profile_id=str(profile_id),
                assessment_id=str(assessment_id) if assessment_id else None,
                data=value.model_dump(mode="json"),
            )
        )

    def create_profile(self, workspace_id, payload, now):
        with self.transaction() as session:
            self.workspace(session, workspace_id)
            key = secrets.token_hex(32)
            row = PrivacyProfileRow(
                id=str(uuid4()),
                workspace_id=str(workspace_id),
                revision=1,
                deleted=False,
                identity_key=key,
                data={
                    **profile_data(payload, key),
                    "created_at": now.isoformat(),
                    "updated_at": now.isoformat(),
                },
            )
            session.add(row)
            session.flush()
            policy = PrivacyPolicyRow(
                id=str(uuid4()),
                workspace_id=str(workspace_id),
                profile_id=row.id,
                revision=1,
                used_observations=0,
                data={
                    **PrivacyPolicy().model_dump(mode="json"),
                    "updated_at": now.isoformat(),
                },
            )
            session.add(policy)
            self.privacy_audit(
                session,
                workspace_id,
                row.id,
                "profile",
                "profile_created_deny_default",
                now,
            )
            return self.profile_record(row)

    def snapshot(self, workspace_id, profile_id):
        with self.repository._lock, Session(self.repository.engine) as session:
            self.workspace(session, workspace_id)
            row = self.profile_row(session, workspace_id, profile_id)
            return (
                self.profile_record(row),
                self.policy_record(
                    self.privacy_policy_row(session, workspace_id, profile_id)
                ),
                row.identity_key,
            )

    def update_profile(self, workspace_id, profile_id, payload, revision, now):
        with self.transaction() as session:
            row = self.profile_row(session, workspace_id, profile_id)
            if revision != row.revision:
                raise Conflict("Privacy profile revision changed")
            row.data = {
                **profile_data(payload, row.identity_key),
                "created_at": row.data["created_at"],
                "updated_at": now.isoformat(),
            }
            row.revision += 1
            self.privacy_audit(
                session, workspace_id, profile_id, "profile", "profile_updated", now
            )
            return self.profile_record(row)

    def delete_profile(self, workspace_id, profile_id, now):
        with self.transaction() as session:
            row = self.profile_row(session, workspace_id, profile_id)
            row.deleted = True
            row.revision += 1
            row.data = {**row.data, "active": False, "updated_at": now.isoformat()}
            self.privacy_audit(
                session,
                workspace_id,
                profile_id,
                "profile",
                "profile_tombstoned_history_retained",
                now,
            )

    def write_privacy_policy(self, workspace_id, profile_id, payload, revision, now):
        with self.transaction() as session:
            self.profile_row(session, workspace_id, profile_id)
            row = self.privacy_policy_row(session, workspace_id, profile_id)
            if revision != row.revision:
                raise Conflict("Privacy policy revision changed")
            row.revision += 1
            row.data = {
                **payload.model_dump(mode="json"),
                "updated_at": now.isoformat(),
            }
            self.privacy_audit(
                session,
                workspace_id,
                profile_id,
                "policy",
                "privacy_policy_updated",
                now,
            )
            return self.policy_record(row)

    def list_records(self, workspace_id, table, model, limit, offset):
        with self.repository._lock, Session(self.repository.engine) as session:
            self.workspace(session, workspace_id)
            query = select(table).where(table.workspace_id == str(workspace_id))
            if table is PrivacyProfileRow:
                query = query.where(table.deleted.is_(False))
            count = session.scalar(select(func.count()).select_from(query.subquery()))
            records = session.scalars(
                query.order_by(table.id).limit(limit).offset(offset)
            )
            converter = (
                self.profile_record
                if table is PrivacyProfileRow
                else self.assessment_record
                if table is PrivacyAssessmentRow
                else lambda row: model.model_validate(row.data)
            )
            return Page(
                items=[converter(row) for row in records],
                total=count,
                limit=limit,
                offset=offset,
            )

    def create_assessment(self, workspace_id, profile_id, request, preflight, now):
        with self.transaction() as session:
            profile_row = self.profile_row(session, workspace_id, profile_id)
            policy_row = self.privacy_policy_row(session, workspace_id, profile_id)
            profile, policy = (
                self.profile_record(profile_row),
                self.policy_record(policy_row),
            )
            if (
                profile.revision != preflight.profile_revision
                or policy.revision != preflight.privacy_policy_revision
            ):
                raise Conflict("Privacy revision changed")
            if request.program_policy_id:
                program = self.policy_row(
                    session, workspace_id, request.program_policy_id
                )
                if program.revision != preflight.program_policy_revision:
                    raise Conflict("Program policy revision changed")
            reason = privacy_reason(profile, policy, request, now) or (
                None if preflight.allowed else preflight.reason
            )
            if not self.workspace(session, workspace_id).active:
                reason = "workspace_inactive"
            if not reason:
                recent = session.scalar(
                    select(func.count())
                    .select_from(PrivacyAssessmentRow)
                    .where(
                        PrivacyAssessmentRow.workspace_id == str(workspace_id),
                        PrivacyAssessmentRow.profile_id == str(profile_id),
                        PrivacyAssessmentRow.created_at
                        > (now - timedelta(minutes=1)).isoformat(),
                        PrivacyAssessmentRow.data["diagnostic_admitted"]
                        .as_boolean()
                        .is_(True),
                    )
                )
                if recent >= policy.rate_limit_per_minute:
                    reason = "privacy_rate_limit_exceeded"
                else:
                    policy_row.used_observations += 1
            fingerprint = (
                hashlib.sha256(
                    f"GET\nweb_observation\n{request.verification_url}".encode()
                ).hexdigest()
                if request.verification_url
                else None
            )
            row = PrivacyAssessmentRow(
                id=str(uuid4()),
                workspace_id=str(workspace_id),
                profile_id=str(profile_id),
                program_policy_id=str(request.program_policy_id)
                if request.program_policy_id
                else None,
                execution_status="queued",
                worker_id=None,
                cancel_requested=False,
                requests_made=0,
                created_at=now.isoformat(),
                data={
                    "kind": request.kind,
                    "status": "not_tested",
                    "profile_revision": profile.revision,
                    "privacy_policy_revision": policy.revision,
                    "program_policy_revision": preflight.program_policy_revision,
                    "expires_at": (
                        now + timedelta(days=profile.logging.retention_days)
                    ).isoformat(),
                    "evidence_refs": [],
                    "finding_ids": [],
                    "requested_family": request.family,
                    "request_fingerprint": fingerprint,
                    "diagnostic_admitted": not bool(reason),
                    "initial_denial": reason,
                },
            )
            session.add(row)
            session.flush()
            self.privacy_audit(
                session,
                workspace_id,
                profile_id,
                request.kind,
                reason or "diagnostic_admitted",
                now,
                row.id,
            )
            return self.assessment_record(row)

    def get_assessment(self, workspace_id, assessment_id):
        with self.repository._lock, Session(self.repository.engine) as session:
            return self.assessment_record(
                self.assessment_row(session, workspace_id, assessment_id)
            )

    def claim(self, workspace_id, assessment_id, worker_id):
        with self.transaction() as session:
            row = self.assessment_row(session, workspace_id, assessment_id)
            if row.execution_status != "queued" or row.cancel_requested:
                return None
            row.execution_status, row.worker_id = "running", str(worker_id)
            return self.assessment_record(row), row.data.get("initial_denial")

    def check_owner(
        self,
        session,
        workspace_id,
        assessment_id,
        worker_id,
        now,
        expected_dns_halt=None,
    ):
        row = self.assessment_row(session, workspace_id, assessment_id)
        if row.execution_status != "running" or row.worker_id != str(worker_id):
            raise PrivacyStop("privacy_worker_inactive")
        if row.cancel_requested:
            raise PrivacyStop("privacy_cancelled")
        profile_row = self.profile_row(
            session, workspace_id, row.profile_id, historical=True
        )
        policy_row = self.privacy_policy_row(session, workspace_id, row.profile_id)
        if (
            profile_row.deleted
            or profile_row.revision != row.data["profile_revision"]
            or policy_row.revision != row.data["privacy_policy_revision"]
        ):
            raise PrivacyStop("privacy_revision_changed")
        profile, policy = (
            self.profile_record(profile_row),
            self.policy_record(policy_row),
        )
        if not self.workspace(session, workspace_id).active:
            raise PrivacyStop("privacy_workspace_inactive")
        if (
            not profile.active
            or not policy.operator_approved
            or policy.valid_until is None
            or now >= policy.valid_until
        ):
            raise PrivacyStop("privacy_permission_changed")
        if row.program_policy_id:
            workspace = self.workspace(session, workspace_id)
            program = self.policy_row(session, workspace_id, row.program_policy_id)
            if (
                not workspace.active
                or program.revision != row.data["program_policy_revision"]
                or (
                    program.halted_reason and program.halted_reason != expected_dns_halt
                )
                or readiness(self.policy(session, program), now)
            ):
                raise PrivacyStop("privacy_program_permission_changed")
        return row

    def check(self, workspace_id, assessment_id, worker_id, now):
        with self.transaction() as session:
            self.check_owner(session, workspace_id, assessment_id, worker_id, now)

    def complete(
        self,
        workspace_id,
        assessment_id,
        worker_id,
        evidence,
        now,
        execution="completed",
        bypass_revision=False,
    ):
        with self.transaction() as session:
            row = self.assessment_row(session, workspace_id, assessment_id)
            if row.execution_status != "running" or row.worker_id != str(worker_id):
                return self.assessment_record(row)
            evidence = EVIDENCE_ADAPTER.validate_python(evidence)
            if bypass_revision and evidence.status not in {
                "inconclusive",
                "not_tested",
                "blocked_by_policy",
            }:
                raise Conflict("Positive privacy verdict requires current permission")
            if not bypass_revision:
                expected_dns_halt = (
                    evidence.reason
                    if evidence.kind == "dns"
                    and evidence.status == "inconclusive"
                    and evidence.reason in {"dns_unavailable", "dns_unknown"}
                    else None
                )
                self.check_owner(
                    session,
                    workspace_id,
                    assessment_id,
                    worker_id,
                    now,
                    expected_dns_halt,
                )
            if (
                evidence.ref != f"privacy_evidence:{evidence.id}"
                or str(evidence.workspace_id) != str(workspace_id)
                or str(evidence.profile_id) != row.profile_id
                or str(evidence.assessment_id) != row.id
            ):
                raise Conflict("Privacy evidence contract violation")
            # Never publish a positive verdict after a cancellation race.
            if row.cancel_requested and execution == "completed":
                raise PrivacyStop("privacy_cancelled")
            session.add(
                PrivacyEvidenceRow(
                    id=str(evidence.id),
                    workspace_id=row.workspace_id,
                    profile_id=row.profile_id,
                    assessment_id=row.id,
                    data=evidence.model_dump(mode="json"),
                )
            )
            session.flush()
            finding_ids = []
            if evidence.status in {"leak_suspected", "leak_validated"}:
                finding = NetworkLeakFinding(
                    id=uuid4(),
                    workspace_id=workspace_id,
                    profile_id=row.profile_id,
                    assessment_id=row.id,
                    status=evidence.status,
                    code=evidence.reason,
                    evidence_refs=[evidence.ref],
                )
                finding_ids.append(str(finding.id))
                session.add(
                    PrivacyFindingRow(
                        id=str(finding.id),
                        workspace_id=row.workspace_id,
                        profile_id=row.profile_id,
                        assessment_id=row.id,
                        evidence_id=str(evidence.id),
                        data=finding.model_dump(mode="json"),
                    )
                )
            row.execution_status = execution
            row.data = {
                **row.data,
                "status": evidence.status,
                "reason": evidence.reason,
                "finished_at": now.isoformat(),
                "evidence_refs": [evidence.ref],
                "finding_ids": finding_ids,
            }
            self.privacy_audit(
                session,
                workspace_id,
                row.profile_id,
                row.data["kind"],
                evidence.status,
                now,
                row.id,
                evidence.ref,
            )
            return self.assessment_record(row)

    @staticmethod
    def interruption_evidence(session, row, now, status, reason):
        identifier = uuid4()
        evidence = PolicyObservation(
            id=identifier,
            ref=f"privacy_evidence:{identifier}",
            workspace_id=row.workspace_id,
            profile_id=row.profile_id,
            assessment_id=row.id,
            timestamp=now,
            status=status,
            reason=reason,
        )
        session.add(
            PrivacyEvidenceRow(
                id=str(identifier),
                workspace_id=row.workspace_id,
                profile_id=row.profile_id,
                assessment_id=row.id,
                data=evidence.model_dump(mode="json"),
            )
        )
        row.data = {**row.data, "evidence_refs": [evidence.ref]}
        return evidence.ref

    def cancel(self, workspace_id, assessment_id, now):
        with self.transaction() as session:
            row = self.assessment_row(session, workspace_id, assessment_id)
            if row.execution_status in {"queued", "running"}:
                row.cancel_requested = True
                if row.execution_status == "queued":
                    row.execution_status = "cancelled"
                    row.data = {
                        **row.data,
                        "status": "not_tested",
                        "reason": "operator_cancelled",
                        "finished_at": now.isoformat(),
                    }
                    evidence_ref = self.interruption_evidence(
                        session, row, now, "not_tested", "operator_cancelled"
                    )
                else:
                    evidence_ref = None
                self.privacy_audit(
                    session,
                    workspace_id,
                    row.profile_id,
                    row.data["kind"],
                    "operator_cancelled",
                    now,
                    row.id,
                    evidence_ref,
                )
            return self.assessment_record(row)

    def evidence(self, workspace_id, evidence_id):
        with self.repository._lock, Session(self.repository.engine) as session:
            row = session.scalar(
                select(PrivacyEvidenceRow).where(
                    PrivacyEvidenceRow.id == str(evidence_id),
                    PrivacyEvidenceRow.workspace_id == str(workspace_id),
                )
            )
            if row is None:
                raise NotFound("Privacy evidence not found")
            return EVIDENCE_ADAPTER.validate_python(row.data)

    def findings(self, workspace_id, assessment_id):
        with self.repository._lock, Session(self.repository.engine) as session:
            self.assessment_row(session, workspace_id, assessment_id)
            return [
                NetworkLeakFinding.model_validate(r.data)
                for r in session.scalars(
                    select(PrivacyFindingRow).where(
                        PrivacyFindingRow.workspace_id == str(workspace_id),
                        PrivacyFindingRow.assessment_id == str(assessment_id),
                    )
                )
            ]

    def preflight_audit(self, workspace_id, profile_id, reason, now):
        with self.transaction() as session:
            self.profile_row(session, workspace_id, profile_id)
            if not self.workspace(session, workspace_id).active:
                reason = "workspace_inactive"
            self.privacy_audit(
                session,
                workspace_id,
                profile_id,
                "preflight",
                reason or "advisory_allowed_no_network",
                now,
            )
        return reason

    def recover(self, worker_lock, now):
        if (
            not isinstance(worker_lock, WorkerLock)
            or worker_lock.namespace != "privacy"
            or not worker_lock.held
            or not worker_lock.recovery_pending
            or worker_lock.repository is not self.repository
        ):
            raise Conflict("Exclusive fresh privacy worker lock required")
        count = 0
        with self.transaction() as session:
            for lease in session.scalars(
                select(ScopeLeaseRow).where(
                    ScopeLeaseRow.privacy_assessment_id.is_not(None),
                    ScopeLeaseRow.released.is_(False),
                )
            ):
                owner = session.get(PrivacyAssessmentRow, lease.privacy_assessment_id)
                if (
                    owner
                    and owner.worker_id
                    and owner.worker_id == lease.privacy_worker_id
                    and owner.workspace_id == lease.workspace_id
                    and owner.program_policy_id == lease.policy_id
                ):
                    lease.released = True
                    self.privacy_audit(
                        session,
                        owner.workspace_id,
                        owner.profile_id,
                        "recovery",
                        "privacy_lease_recovered",
                        now,
                        owner.id,
                    )
            for row in session.scalars(
                select(PrivacyAssessmentRow).where(
                    PrivacyAssessmentRow.execution_status.in_(["queued", "running"])
                )
            ):
                row.execution_status = "failed"
                row.data = {
                    **row.data,
                    "status": "inconclusive",
                    "reason": "worker_interrupted_verified",
                    "finished_at": now.isoformat(),
                }
                evidence_ref = self.interruption_evidence(
                    session, row, now, "inconclusive", "worker_interrupted_verified"
                )
                self.privacy_audit(
                    session,
                    row.workspace_id,
                    row.profile_id,
                    "recovery",
                    "worker_interrupted_verified",
                    now,
                    row.id,
                    evidence_ref,
                )
                count += 1
        worker_lock.recovery_pending = False
        return count
