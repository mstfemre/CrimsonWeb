"""Workspace-isolated persistence for verification plans, tests, evidence, findings.

Every read and write is scoped by ``workspace_id``; composite foreign keys keep a
plan's children inside the same workspace. No credential or raw response is ever
written -- only the validated models, which forbid those fields by construction.
"""

from contextlib import contextmanager

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from ..database import (
    VerificationEvidenceRow,
    VerificationFindingRow,
    VerificationPlanRow,
    VerificationTestRow,
)
from ..models import Page
from ..workspaces.store import Conflict, NotFound
from .models import (
    EVIDENCE_ADAPTER,
    FINDING_ADAPTER,
    AccessControlFinding,
    PlanApproval,
    VerificationPlan,
    VerificationReport,
    VerificationTest,
)
from .targets import approved_origin


class VerificationStore:
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
    def _plan_row(session, workspace_id, plan_id):
        row = session.scalar(
            select(VerificationPlanRow).where(
                VerificationPlanRow.id == str(plan_id),
                VerificationPlanRow.workspace_id == str(workspace_id),
            )
        )
        if row is None:
            raise NotFound("Verification plan not found")
        return row

    def create_plan(self, plan: VerificationPlan) -> VerificationPlan:
        if plan.require_model and plan.planner != "model":
            raise Conflict("Required model planner unavailable")
        with self.transaction() as session:
            if plan.parent_plan_id is not None:
                parent = VerificationPlan.model_validate(
                    self._plan_row(session, plan.workspace_id, plan.parent_plan_id).data
                )
                child = session.scalar(select(VerificationPlanRow.id).where(
                    VerificationPlanRow.workspace_id == str(plan.workspace_id),
                    VerificationPlanRow.data["parent_plan_id"].as_string() == str(parent.id),
                ))
                if (child is not None or parent.status != "completed"
                    or plan.round_number != parent.round_number + 1
                    or plan.require_model != parent.require_model
                    or set(plan.allowed_catalog_ids) - set(parent.allowed_catalog_ids)):
                    raise Conflict("Follow-up ownership, round or uniqueness conflict")
            session.add(
                VerificationPlanRow(
                    id=str(plan.id),
                    workspace_id=str(plan.workspace_id),
                    policy_id=str(plan.policy_id),
                    status=plan.status,
                    created_at=plan.created_at.isoformat(),
                    data=plan.model_dump(mode="json"),
                )
            )
        return plan

    def get_plan(self, workspace_id, plan_id) -> VerificationPlan:
        with self.repository._lock, Session(self.repository.engine) as session:
            return VerificationPlan.model_validate(
                self._plan_row(session, workspace_id, plan_id).data
            )

    def list_plans(self, workspace_id, limit, offset, status=None) -> Page:
        with self.repository._lock, Session(self.repository.engine) as session:
            query = select(VerificationPlanRow).where(
                VerificationPlanRow.workspace_id == str(workspace_id)
            )
            if status:
                query = query.where(VerificationPlanRow.status == status)
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(
                query.order_by(
                    VerificationPlanRow.created_at.desc(), VerificationPlanRow.id
                )
                .limit(limit)
                .offset(offset)
            )
            return Page(
                items=[VerificationPlan.model_validate(r.data) for r in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def approve_plan(
        self, workspace_id, plan_id, approval: PlanApproval, now
    ) -> VerificationPlan:
        with self.transaction() as session:
            row = self._plan_row(session, workspace_id, plan_id)
            plan = VerificationPlan.model_validate(row.data)
            if plan.status != "awaiting_approval":
                raise Conflict("Plan is not awaiting approval")
            updated = plan.model_copy(
                update={
                    "status": "approved",
                    "approved_by": approval.approved_by,
                    "scope_source": approval.scope_source,
                    "approved_at": now,
                    "approved_origin_ref": approved_origin(approval.base_url),
                    "approved_binding_field": approval.owner_binding_field,
                    "approved_private_records_only": approval.private_records_only,
                    "updated_at": now,
                }
            )
            row.status = updated.status
            row.data = updated.model_dump(mode="json")
            return updated

    def cancel_plan(self, workspace_id, plan_id, now):
        with self.transaction() as session:
            row = self._plan_row(session, workspace_id, plan_id)
            plan = VerificationPlan.model_validate(row.data)
            if plan.status not in {"awaiting_approval", "approved", "executing"}:
                raise Conflict("Plan is no longer cancellable")
            updated = plan.model_copy(update={
                "cancel_requested": True,
                "status": "executing" if plan.status == "executing" else "cancelled",
                "updated_at": now,
            })
            row.status = updated.status
            row.data = updated.model_dump(mode="json")
            return updated

    def save_result(self, result):
        """Commit the test and its evidence/finding together, or roll back all."""
        test = result.test
        evidence_refs = {item.ref for item in result.evidence}
        if set(test.evidence_refs) != evidence_refs or any(
            (item.workspace_id, item.plan_id, item.test_id)
            != (test.workspace_id, test.plan_id, test.id)
            for item in result.evidence
        ):
            raise Conflict("Verification evidence relationship mismatch")
        finding = result.finding
        if finding is not None and (
            (finding.workspace_id, finding.plan_id, finding.test_id)
            != (test.workspace_id, test.plan_id, test.id)
            or finding.observation_evidence_ref not in evidence_refs
            or test.finding_ids != [finding.id]
        ):
            raise Conflict("Verification finding relationship mismatch")
        with self.transaction() as session:
            self._plan_row(session, test.workspace_id, test.plan_id)
            session.add(VerificationTestRow(
                id=str(test.id), workspace_id=str(test.workspace_id),
                plan_id=str(test.plan_id), status=test.status,
                data=test.model_dump(mode="json"),
            ))
            session.flush()
            for item in result.evidence:
                session.add(VerificationEvidenceRow(
                    id=str(item.id), workspace_id=str(item.workspace_id),
                    plan_id=str(item.plan_id), data=item.model_dump(mode="json"),
                ))
            if finding is not None:
                session.add(VerificationFindingRow(
                    id=str(finding.id), workspace_id=str(finding.workspace_id),
                    plan_id=str(finding.plan_id), test_id=str(finding.test_id),
                    data=finding.model_dump(mode="json"),
                ))

    def set_status(
        self, workspace_id, plan_id, status, now, expected=None
    ) -> VerificationPlan:
        with self.transaction() as session:
            row = self._plan_row(session, workspace_id, plan_id)
            plan = VerificationPlan.model_validate(row.data)
            if expected is not None and plan.status != expected:
                raise Conflict("Plan status changed")
            updated = plan.model_copy(update={"status": status, "updated_at": now})
            row.status = status
            row.data = updated.model_dump(mode="json")
            return updated

    def save_test(self, test: VerificationTest) -> None:
        with self.transaction() as session:
            self._plan_row(session, test.workspace_id, test.plan_id)
            row = session.get(VerificationTestRow, str(test.id))
            if row is not None and (row.workspace_id, row.plan_id) != (
                str(test.workspace_id), str(test.plan_id)
            ):
                raise Conflict("Verification test ownership mismatch")
            if row is None:
                row = VerificationTestRow(
                    id=str(test.id),
                    workspace_id=str(test.workspace_id),
                    plan_id=str(test.plan_id),
                )
                session.add(row)
            row.status = test.status
            row.data = test.model_dump(mode="json")

    def save_evidence(self, evidence) -> None:
        with self.transaction() as session:
            self._plan_row(session, evidence.workspace_id, evidence.plan_id)
            session.add(
                VerificationEvidenceRow(
                    id=str(evidence.id),
                    workspace_id=str(evidence.workspace_id),
                    plan_id=str(evidence.plan_id),
                    data=evidence.model_dump(mode="json"),
                )
            )

    def save_finding(self, finding: AccessControlFinding) -> None:
        with self.transaction() as session:
            self._plan_row(session, finding.workspace_id, finding.plan_id)
            session.add(
                VerificationFindingRow(
                    id=str(finding.id),
                    workspace_id=str(finding.workspace_id),
                    plan_id=str(finding.plan_id),
                    test_id=str(finding.test_id),
                    data=finding.model_dump(mode="json"),
                )
            )

    def tests(self, workspace_id, plan_id, limit, offset) -> Page:
        return self._children(
            workspace_id,
            plan_id,
            VerificationTestRow,
            lambda data: VerificationTest.model_validate(data),
            limit,
            offset,
        )

    def evidence(self, workspace_id, plan_id, limit, offset) -> Page:
        return self._children(
            workspace_id,
            plan_id,
            VerificationEvidenceRow,
            EVIDENCE_ADAPTER.validate_python,
            limit,
            offset,
        )

    def findings(self, workspace_id, plan_id, limit, offset) -> Page:
        return self._children(
            workspace_id,
            plan_id,
            VerificationFindingRow,
            FINDING_ADAPTER.validate_python,
            limit,
            offset,
        )

    def _children(self, workspace_id, plan_id, row_type, build, limit, offset) -> Page:
        with self.repository._lock, Session(self.repository.engine) as session:
            self._plan_row(session, workspace_id, plan_id)
            query = select(row_type).where(
                row_type.workspace_id == str(workspace_id),
                row_type.plan_id == str(plan_id),
            )
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(
                query.order_by(row_type.id).limit(limit).offset(offset)
            )
            return Page(
                items=[build(r.data) for r in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def report(self, workspace_id, plan_id) -> VerificationReport:
        from .coverage import coverage_for
        plan = self.get_plan(workspace_id, plan_id)
        tests = self.tests(workspace_id, plan_id, 500, 0).items
        evidence = self.evidence(workspace_id, plan_id, 500, 0).items
        findings = self.findings(workspace_id, plan_id, 500, 0).items
        return VerificationReport(
            workspace_id=plan.workspace_id,
            plan_id=plan.id,
            policy_id=plan.policy_id,
            status=plan.status,
            tests=tests,
            findings=findings,
            evidence=evidence,
            scope_source=plan.scope_source,
            private_records_only=plan.approved_private_records_only,
            top10_coverage=coverage_for(tests, evidence),
        )
