from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from workspace_helpers import NOW, FakeResolver, policy

from crimsonweb.api.app import create_app
from crimsonweb.api.database import Repository
from crimsonweb.api.workspaces.store import NotFound

PREFIX = "/api/v1/workspaces"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("CRIMSON_API_TOKEN", "synthetic-test-token")
    repo = Repository("sqlite://")
    app = create_app(repository=repo)
    with TestClient(
        app, headers={"Authorization": "Bearer synthetic-test-token"}
    ) as result:
        app.state.workspace_service.clock = lambda: NOW
        app.state.workspace_service.resolver = FakeResolver()
        yield result


def workspace(client, name="lab"):
    response = client.post(PREFIX, json={"name": name, "program_type": "lab"})
    assert response.status_code == 201
    return response.json()["id"]


def create_policy(client, ws):
    response = client.post(
        f"{PREFIX}/{ws}/policies", json=policy().model_dump(mode="json")
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_workspace_crud_pagination_validation_and_openapi(client):
    first = workspace(client)
    workspace(client, "second")
    assert client.get(PREFIX, params={"limit": 1, "offset": 1}).json()["total"] == 2
    assert len(client.get(PREFIX, params={"limit": 1}).json()["items"]) == 1
    updated = client.patch(
        f"{PREFIX}/{first}",
        json={"name": "renamed", "description": "owned lab", "active": False},
    )
    assert updated.status_code == 200 and not updated.json()["active"]
    assert client.get(f"{PREFIX}/{first}").json()["name"] == "renamed"
    assert client.get(PREFIX, params={"limit": 101}).status_code == 422
    assert client.get(PREFIX, params={"offset": -1}).status_code == 422
    assert client.get(f"{PREFIX}/invalid-uuid").status_code == 422
    assert (
        client.post(PREFIX, json={"name": " ", "program_type": "lab"}).status_code
        == 422
    )
    assert client.patch(f"{PREFIX}/{first}", json={"active": None}).status_code == 422
    assert (
        client.patch(f"{PREFIX}/{first}", json={"program_type": "owned"}).status_code
        == 422
    )
    schema = client.get("/openapi.json").json()
    assert (
        f"{PREFIX}/{{workspace_id}}/policies/{{policy_id}}/preflight" in schema["paths"]
    )
    assert (
        schema["components"]["schemas"]["TargetScope"]["additionalProperties"] is False
    )


def test_policy_crud_preflight_and_revision_conflict(client):
    ws = workspace(client)
    pid = create_policy(client, ws)
    endpoint = f"{PREFIX}/{ws}/policies/{pid}"
    assert client.get(endpoint).json()["revision"] == 1
    assert client.post(endpoint + "/validate").json() == {"valid": True, "reasons": []}
    assert client.post(
        endpoint + "/preflight", json={"url": "http://lab.test/"}
    ).json()["allowed"]
    denied = client.post(endpoint + "/preflight", json={"url": "http://outside.test/"})
    assert denied.status_code == 200 and not denied.json()["allowed"]
    assert client.post(f"{PREFIX}/{ws}/policies", json={}).status_code == 409
    assert (
        client.put(
            endpoint,
            params={"expected_revision": 1},
            json=policy().model_dump(mode="json"),
        ).json()["revision"]
        == 2
    )
    assert (
        client.put(
            endpoint,
            params={"expected_revision": 1},
            json=policy().model_dump(mode="json"),
        ).status_code
        == 409
    )
    assert client.put(endpoint, json={}).status_code == 422
    assert client.get(endpoint).json()["used_requests"] == 0
    assert client.get(endpoint + "/revisions/1").json()[
        "policy"
    ] == policy().model_dump(mode="json")
    assert client.get(endpoint + "/revisions/2").json()["revision"] == 2
    assert client.get(endpoint + "/revisions/3").status_code == 404


@pytest.mark.parametrize("operation", ["read", "write", "validate", "preflight"])
def test_cross_workspace_policy_access_denied_at_api_and_service(client, operation):
    first, second = workspace(client, "A"), workspace(client, "B")
    policy_a = create_policy(client, first)
    create_policy(client, second)
    path = f"{PREFIX}/{second}/policies/{policy_a}"
    if operation == "read":
        response = client.get(path)
    elif operation == "write":
        response = client.put(
            path, params={"expected_revision": 1}, json=policy().model_dump(mode="json")
        )
    elif operation == "validate":
        response = client.post(path + "/validate")
    else:
        response = client.post(path + "/preflight", json={"url": "http://lab.test/"})
    assert response.status_code == 404
    service = client.app.state.workspace_service
    with pytest.raises(NotFound):
        service.store.snapshot(second, policy_a)
    assert client.get(path + "/revisions/1").status_code == 404
    with pytest.raises(NotFound):
        service.store.policy_revision(second, policy_a, 1)
    audit_a = client.get(f"{PREFIX}/{first}/audit").json()
    audit_b = client.get(f"{PREFIX}/{second}/audit").json()
    assert all(item["workspace_id"] == first for item in audit_a["items"])
    assert all(item["workspace_id"] == second for item in audit_b["items"])
    assert {item["id"] for item in audit_a["items"]}.isdisjoint(
        item["id"] for item in audit_b["items"]
    )


def test_deny_default_inactive_and_safe_audit(client):
    ws = workspace(client)
    pid = client.post(f"{PREFIX}/{ws}/policies", json={}).json()["id"]
    endpoint = f"{PREFIX}/{ws}/policies/{pid}"
    assert not client.post(endpoint + "/validate").json()["valid"]
    assert (
        client.post(endpoint + "/preflight", json={"url": "http://lab.test/"}).json()[
            "reason"
        ]
        == "approval_required"
    )
    client.put(
        endpoint, params={"expected_revision": 1}, json=policy().model_dump(mode="json")
    )
    client.post(
        endpoint + "/preflight", json={"url": "http://lab.test/?token=never-log-secret"}
    )
    audit = client.get(f"{PREFIX}/{ws}/audit").text
    assert "never-log-secret" not in audit and "lab.test" not in audit
    assert "request_fingerprint" in audit and "invalid_url" in audit
    client.patch(f"{PREFIX}/{ws}", json={"active": False})
    assert (
        client.post(endpoint + "/preflight", json={"url": "http://lab.test/"}).json()[
            "reason"
        ]
        == "workspace_inactive"
    )
    assert client.get(f"{PREFIX}/{uuid4()}/audit").status_code == 404


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", PREFIX, None),
        ("POST", PREFIX, {"name": "lab", "program_type": "lab"}),
        ("GET", PREFIX + "/00000000-0000-0000-0000-000000000001/audit", None),
        (
            "POST",
            PREFIX
            + "/00000000-0000-0000-0000-000000000001/policies/00000000-0000-0000-0000-000000000002/preflight",
            {"url": "http://lab.test/"},
        ),
    ],
)
def test_existing_bearer_auth_covers_workspace_routes(client, method, path, body):
    response = client.request(
        method, path, json=body, headers={"Authorization": "Bearer wrong"}
    )
    assert response.status_code == 401


def test_no_token_remote_client_denied(dev_tokenless):
    with TestClient(create_app(repository=Repository("sqlite://"))) as client:
        assert client.get(PREFIX).status_code == 403


def test_database_errors_do_not_expose_details(client, monkeypatch):
    def unavailable(*args):
        raise OperationalError("private db statement", {}, Exception("secret-db-token"))

    monkeypatch.setattr(
        client.app.state.workspace_service.store, "list_workspaces", unavailable
    )
    response = client.get(PREFIX)
    assert response.status_code == 503
    assert "secret" not in response.text and "private" not in response.text
