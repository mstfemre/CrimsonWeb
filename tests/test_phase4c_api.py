"""End-to-end Phase 4C API: plan -> approve -> execute, with every safety gate."""

import json
from contextlib import contextmanager

import httpx
from fastapi.testclient import TestClient
from verification_helpers import verification_policy
from workspace_helpers import NOW, FakeResolver

from crimsonweb.api.app import create_app
from crimsonweb.api.database import Repository

PREFIX = "/api/v1/workspaces"
TOKEN_A = "Bearer tokA-secret"
TOKEN_B = "Bearer tokB-secret"
APPROVAL = {"base_url": "http://lab.test:8001", "owner_binding_field": "owner_id", "private_records_only": True}

IDENTITIES = [
    {"role": "identity_a", "header_name": "Authorization", "header_value": TOKEN_A, "owner_object_id": "111"},
    {"role": "identity_b", "header_name": "Authorization", "header_value": TOKEN_B, "owner_object_id": "222"},
]

OPENAPI = {
    "openapi": "3.1.0",
    "paths": {
        "/api/objects/{object_id}": {
            "get": {
                "parameters": [
                    {"name": "object_id", "in": "path", "schema": {"type": "integer"}}
                ],
                "responses": {"200": {}},
            }
        }
    },
}


def lab(mode="broken"):
    def handler(request):
        obj = request.url.path.rsplit("/", 1)[-1]
        if mode == "blocked":
            return httpx.Response(403, json={})
        return httpx.Response(200, json={"owner_id": obj})

    return httpx.MockTransport(handler)


@contextmanager
def client(mode="broken"):
    import os

    os.environ["CRIMSON_API_TOKEN"] = "synthetic-test-token"
    app = create_app(
        repository=Repository("sqlite://"), verification_transport=lab(mode)
    )
    with TestClient(app, headers={"Authorization": "Bearer synthetic-test-token"}) as c:
        app.state.workspace_service.clock = lambda: NOW
        app.state.workspace_service.resolver = FakeResolver()
        yield c


def workspace(c):
    return c.post(PREFIX, json={"name": "lab", "program_type": "lab"}).json()["id"]


def policy(c, ws, **changes):
    return c.post(
        f"{ws_base(ws)}/policies",
        json=verification_policy(**changes).model_dump(mode="json"),
    ).json()["id"]


def ws_base(ws):
    return f"{PREFIX}/{ws}"


def vbase(ws):
    return f"{PREFIX}/{ws}/verification"


def create_plan(c, ws, pid):
    return c.post(
        f"{vbase(ws)}/plans",
        json={"policy_id": pid, "source": "openapi", "openapi_document": OPENAPI},
    )


def test_full_operator_flow_confirms_broken_access_control():
    with client("broken") as c:
        ws = workspace(c)
        pid = policy(c, ws)
        plan = create_plan(c, ws, pid)
        assert plan.status_code == 202
        body = plan.json()
        assert body["status"] == "awaiting_approval"
        assert body["planner"] == "operator"
        assert len(body["proposals"]) == 1
        plan_id = body["id"]

        # Execution is refused until an operator approves.
        early = c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json={
            "base_url": "http://lab.test:8001", "owner_binding_field": "owner_id", "identities": IDENTITIES
        })
        assert early.status_code == 409

        approved = c.post(
            f"{vbase(ws)}/plans/{plan_id}/approve",
            json={"approved_by": "lab-operator", "scope_source": "owned lab", **APPROVAL},
        )
        assert approved.status_code == 200 and approved.json()["status"] == "approved"

        executed = c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json={
            "base_url": "http://lab.test:8001", "owner_binding_field": "owner_id", "identities": IDENTITIES
        })
        assert executed.status_code == 200 and executed.json()["status"] == "completed"

        findings = c.get(f"{vbase(ws)}/plans/{plan_id}/findings").json()
        assert findings["total"] == 1
        assert findings["items"][0]["code"] == "bola_confirmed"
        assert findings["items"][0]["confidence"] == "confirmed"

        report = c.get(f"{vbase(ws)}/plans/{plan_id}/report").json()
        assert report["raw_response_retained"] is False
        assert report["credentials_retained"] is False
        assert report["tests"][0]["confidence"] == "confirmed"
        evidence = report["evidence"][0]
        assert evidence["owner_binding_match"] is True
        assert evidence["scope_decision"] == "authorized"
        assert evidence["identities"] == ["identity_a", "identity_b"]
        assert findings["items"][0]["source_evidence_refs"]

        # No credential value appears anywhere in the served flow.
        blob = json.dumps([body, approved.json(), executed.json(), findings, report])
        assert "tokA-secret" not in blob and "tokB-secret" not in blob


def test_safe_stop_halts_plan_without_classifying_cause():
    with client("blocked") as c:
        ws = workspace(c)
        pid = policy(c, ws)
        plan_id = create_plan(c, ws, pid).json()["id"]
        c.post(
            f"{vbase(ws)}/plans/{plan_id}/approve",
            json={"approved_by": "op", "scope_source": "lab", **APPROVAL},
        )
        executed = c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json={
            "base_url": "http://lab.test:8001", "owner_binding_field": "owner_id", "identities": IDENTITIES
        }).json()
        assert executed["status"] == "halted"
        tests = c.get(f"{vbase(ws)}/plans/{plan_id}/tests").json()["items"]
        assert tests[0]["status"] == "blocked_by_policy"
        assert tests[0]["reason"] == "http_403_access_denied"
        assert c.get(f"{vbase(ws)}/plans/{plan_id}/findings").json()["total"] == 0


def test_request_budget_is_shared_and_halts_execution():
    with client("broken") as c:
        ws = workspace(c)
        pid = policy(c, ws, maximum_request_budget=2)
        plan_id = create_plan(c, ws, pid).json()["id"]
        c.post(
            f"{vbase(ws)}/plans/{plan_id}/approve",
            json={"approved_by": "op", "scope_source": "lab", **APPROVAL},
        )
        executed = c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json={
            "base_url": "http://lab.test:8001", "owner_binding_field": "owner_id", "identities": IDENTITIES
        }).json()
        assert executed["status"] == "halted"
        tests = c.get(f"{vbase(ws)}/plans/{plan_id}/tests").json()["items"]
        assert tests[0]["status"] == "blocked_by_policy"
        assert tests[0]["reason"] == "budget_exhausted"


def test_execute_denied_when_policy_category_forbids_auth_tests():
    with client("broken") as c:
        ws = workspace(c)
        pid = policy(c, ws, target_scope=verification_policy().target_scope.model_copy(
            update={"allowed_categories": ["web_observation"]}
        ).model_dump())
        plan_id = create_plan(c, ws, pid).json()["id"]
        c.post(
            f"{vbase(ws)}/plans/{plan_id}/approve",
            json={"approved_by": "op", "scope_source": "lab", **APPROVAL},
        )
        executed = c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json={
            "base_url": "http://lab.test:8001", "owner_binding_field": "owner_id", "identities": IDENTITIES
        })
        assert executed.status_code == 200 and executed.json()["status"] == "halted"
        # The auth-category request is denied by the shared scope guard.
        tests = c.get(f"{vbase(ws)}/plans/{plan_id}/tests").json()["items"]
        assert tests[0]["status"] == "blocked_by_policy"
        assert tests[0]["reason"] == "category_denied"


def test_plans_are_isolated_per_workspace():
    with client("broken") as c:
        ws = workspace(c)
        pid = policy(c, ws)
        plan_id = create_plan(c, ws, pid).json()["id"]
        other = workspace(c)
        assert c.get(f"{vbase(other)}/plans/{plan_id}").status_code == 404
        assert c.get(f"{vbase(ws)}/plans/{plan_id}").status_code == 200


def test_completed_plan_cannot_be_re_executed():
    with client("broken") as c:
        ws = workspace(c)
        pid = policy(c, ws)
        plan_id = create_plan(c, ws, pid).json()["id"]
        c.post(
            f"{vbase(ws)}/plans/{plan_id}/approve",
            json={"approved_by": "op", "scope_source": "lab", **APPROVAL},
        )
        body = {"base_url": "http://lab.test:8001", "owner_binding_field": "owner_id", "identities": IDENTITIES}
        assert c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json=body).json()["status"] == "completed"
        assert c.post(f"{vbase(ws)}/plans/{plan_id}/execute", json=body).status_code == 409
