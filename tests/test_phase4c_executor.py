"""The deterministic executor drives three read-only requests through the guard.

Controls first (A->A, B->B), then the cross read (A->B). A finding is produced
only when both controls succeed and the owner-binding field proves B's record was
returned. Credentials never appear in any produced test, evidence or finding.
"""

import asyncio
import json

import httpx
from verification_helpers import verification_policy
from workspace_helpers import NOW, FakeResolver, seeded

from crimsonweb.api.verification.executor import VerificationExecutor
from crimsonweb.api.verification.models import (
    ExecuteRequest,
    PlanProposal,
    VerificationTarget,
)
from crimsonweb.api.workspaces.service import WorkspaceService

TOKEN_A = "Bearer tokA-secret"
TOKEN_B = "Bearer tokB-secret"


def lab(mode):
    def handler(request):
        obj = request.url.path.rsplit("/", 1)[-1]
        auth = request.headers.get("authorization")
        if mode == "blocked":
            return httpx.Response(403, json={})
        if mode == "secure":
            ok = (auth == TOKEN_A and obj == "111") or (auth == TOKEN_B and obj == "222")
            if not ok:
                return httpx.Response(401, json={})
            return httpx.Response(200, json={"owner_id": obj})
        if mode == "unverified":
            # Server always returns the requester's own record, ignoring the path id.
            own = "111" if auth == TOKEN_A else "222"
            return httpx.Response(200, json={"owner_id": own})
        # mode == "broken": object-level authz missing; anyone reads any record.
        return httpx.Response(200, json={"owner_id": obj})

    return httpx.MockTransport(handler)


def run(mode):
    repo, _, workspace, record = seeded(
        configuration=verification_policy(), resolver=FakeResolver()
    )
    guard = WorkspaceService(repo, FakeResolver(), lambda: NOW)
    executor = VerificationExecutor(guard, lab(mode))
    target = VerificationTarget(
        endpoint_ref="endpoint:e1",
        source="discovery",
        path="/api/objects/{object_id}",
        method="GET",
        object_identifier_parameter="object_id",
        evidence_refs=["evidence:v1"],
    )
    proposal = PlanProposal(
        catalog_id="bola_cross_owner_read",
        target_endpoint_ref="endpoint:e1",
        evidence_refs=["evidence:v1"],
    )
    request = ExecuteRequest.model_validate(
        {
            "base_url": "http://lab.test:8001",
            "owner_binding_field": "owner_id",
            "identities": [
                {"role": "identity_a", "header_name": "Authorization", "header_value": TOKEN_A, "owner_object_id": "111"},
                {"role": "identity_b", "header_name": "Authorization", "header_value": TOKEN_B, "owner_object_id": "222"},
            ],
        }
    )
    from uuid import uuid4

    return asyncio.run(
        executor.execute(
            workspace.id, record.id, uuid4(), proposal, target, request
        )
    )


def test_broken_access_control_is_a_confirmed_finding():
    result = run("broken")
    assert result.test.outcome == "bola_confirmed"
    assert result.test.confidence == "confirmed"
    assert result.finding is not None and result.finding.code == "bola_confirmed"
    evidence = result.evidence[0]
    assert (evidence.control_a_status, evidence.control_b_status, evidence.cross_status) == (200, 200, 200)
    assert evidence.owner_binding_match is True


def test_enforced_access_control_is_not_a_finding():
    result = run("secure")
    assert result.test.outcome == "access_control_enforced"
    assert result.finding is None
    assert result.evidence[0].cross_status == 401


def test_cross_read_without_owner_binding_is_unverified():
    result = run("unverified")
    assert result.test.outcome == "owner_binding_unverified"
    assert result.test.confidence == "unverified"
    assert result.finding is None
    assert result.evidence[0].owner_binding_match is False


def test_safe_stop_is_blocked_by_policy_and_inconclusive():
    result = run("blocked")
    assert result.test.status == "blocked_by_policy"
    assert result.test.confidence == "inconclusive"
    assert result.finding is None
    assert result.evidence[0].kind == "policy_stop"
    assert result.evidence[0].scope_decision == "http_403_access_denied"


def test_credentials_never_appear_in_outputs():
    for mode in ("broken", "secure", "unverified", "blocked"):
        result = run(mode)
        blob = json.dumps(
            {
                "test": result.test.model_dump(mode="json"),
                "evidence": [e.model_dump(mode="json") for e in result.evidence],
                "finding": result.finding.model_dump(mode="json") if result.finding else None,
            }
        )
        assert "tokA-secret" not in blob and "tokB-secret" not in blob
