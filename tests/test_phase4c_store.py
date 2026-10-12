"""Verification persistence is workspace-isolated and gates approval transitions."""

from uuid import uuid4

import pytest
from verification_helpers import verification_policy
from workspace_helpers import NOW, seeded

from crimsonweb.api.verification.models import (
    AccessControlFinding,
    ComparativeAccessEvidence,
    VerificationPlan,
    VerificationTest,
)
from crimsonweb.api.verification.store import VerificationStore
from crimsonweb.api.workspaces.models import WorkspaceCreate
from crimsonweb.api.workspaces.store import Conflict, NotFound


def make_plan(workspace_id, policy_id, status="awaiting_approval"):
    return VerificationPlan(
        id=uuid4(),
        workspace_id=workspace_id,
        policy_id=policy_id,
        source="discovery",
        status=status,
        planner="operator",
        created_at=NOW,
        updated_at=NOW,
    )


def test_plan_round_trips_and_is_isolated_per_workspace():
    repo, service, workspace, record = seeded(configuration=verification_policy())
    store = VerificationStore(repo)
    plan = store.create_plan(make_plan(workspace.id, record.id))
    assert store.get_plan(workspace.id, plan.id).id == plan.id

    other = service.store.create_workspace(
        WorkspaceCreate(name="Other", program_type="lab"), NOW
    )
    with pytest.raises(NotFound):
        store.get_plan(other.id, plan.id)


def test_approval_is_one_shot_and_records_the_operator():
    repo, _, workspace, record = seeded(configuration=verification_policy())
    store = VerificationStore(repo)
    plan = store.create_plan(make_plan(workspace.id, record.id))
    from crimsonweb.api.verification.models import PlanApproval

    approved = store.approve_plan(
        workspace.id,
        plan.id,
        PlanApproval(approved_by="lab-operator", scope_source="owned lab", base_url="http://lab.test:8001", owner_binding_field="owner_id", private_records_only=True),
        NOW,
    )
    assert approved.status == "approved" and approved.approved_by == "lab-operator"
    with pytest.raises(Conflict):
        store.approve_plan(
            workspace.id,
            plan.id,
            PlanApproval(approved_by="x", scope_source="y", base_url="http://lab.test:8001", owner_binding_field="owner_id", private_records_only=True),
            NOW,
        )


def test_report_collects_tests_evidence_and_findings():
    repo, _, workspace, record = seeded(configuration=verification_policy())
    store = VerificationStore(repo)
    plan = store.create_plan(make_plan(workspace.id, record.id))
    test_id = uuid4()
    evidence = ComparativeAccessEvidence(
        id=uuid4(),
        ref="verification_evidence:x",
        workspace_id=workspace.id,
        plan_id=plan.id,
        test_id=test_id,
        timestamp=NOW,
        status="bola_confirmed",
        reason="cross_account_record_returned",
        catalog_id="bola_cross_owner_read",
        target_endpoint_ref="endpoint:e1",
        method="GET",
        control_a_status=200,
        control_b_status=200,
        cross_status=200,
        owner_binding_match=True,
        scope_decision="authorized",
        identities=["identity_a", "identity_b"],
    )
    finding = AccessControlFinding(
        id=uuid4(),
        workspace_id=workspace.id,
        plan_id=plan.id,
        test_id=test_id,
        code="bola_confirmed",
        confidence="confirmed",
        status="finding",
        category="auth",
        target_endpoint_ref="endpoint:e1",
        source_evidence_refs=["evidence:v1"],
        observation_evidence_ref=evidence.ref,
        test_identity_roles=["identity_a", "identity_b"],
        scope_decision="authorized",
    )
    test = VerificationTest(
        id=test_id,
        workspace_id=workspace.id,
        plan_id=plan.id,
        catalog_id="bola_cross_owner_read",
        target_endpoint_ref="endpoint:e1",
        status="completed",
        outcome="bola_confirmed",
        confidence="confirmed",
        reason="cross_account_record_returned",
        evidence_refs=[evidence.ref],
        finding_ids=[finding.id],
    )
    store.save_test(test)
    store.save_evidence(evidence)
    store.save_finding(finding)
    report = store.report(workspace.id, plan.id)
    assert len(report.tests) == 1 and len(report.findings) == 1
    assert report.evidence[0].owner_binding_match is True
    assert report.raw_response_retained is False
