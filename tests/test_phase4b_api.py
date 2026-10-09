import json
import time
from uuid import uuid4

import httpx
import pytest
from discovery_helpers import crawl_policy, spec
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from workspace_helpers import NOW, FakeResolver

from crimsonweb.api.app import create_app
from crimsonweb.api.database import Repository

PREFIX = "/api/v1/workspaces"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("CRIMSON_API_TOKEN", "synthetic-test-token")
    app = create_app(
        repository=Repository("sqlite://"),
        discovery_transport=httpx.MockTransport(
            lambda r: httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=b'<a href="/next">Next</a>',
            )
        ),
    )
    with TestClient(
        app, headers={"Authorization": "Bearer synthetic-test-token"}
    ) as result:
        app.state.workspace_service.clock = lambda: NOW
        app.state.workspace_service.resolver = FakeResolver()
        yield result


def workspace(client):
    return client.post(PREFIX, json={"name": "lab", "program_type": "lab"}).json()["id"]


def policy_id(client, ws, **changes):
    return client.post(
        f"{PREFIX}/{ws}/policies", json=crawl_policy(**changes).model_dump(mode="json")
    ).json()["id"]


def wait(client, base, job):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get(f"{base}/jobs/{job}")
        assert response.status_code == 200
        if response.json()["status"] not in {"queued", "running"}:
            return response.json()
        time.sleep(0.01)
    pytest.fail("Discovery job did not finish")


def test_discovery_api_crawl_inventory_graph_summary_paging_and_schema(client):
    ws = workspace(client)
    pid = policy_id(client, ws)
    base = f"{PREFIX}/{ws}/discovery"
    response = client.post(
        base + "/jobs", json={"policy_id": pid, "seeds": ["http://lab.test/"]}
    )
    assert response.status_code == 202
    job = response.json()["id"]
    result = wait(client, base, job)
    assert result["status"] == "completed" and result["requests_made"] == 2
    assert "worker_id" not in result and "lab.test" not in json.dumps(result)
    endpoints = client.get(
        f"{base}/jobs/{job}/endpoints", params={"limit": 1, "offset": 1}
    ).json()
    assert endpoints["total"] == 2 and len(endpoints["items"]) == 1
    evidence = client.get(f"{base}/jobs/{job}/evidence").json()
    assert evidence["total"] == 2
    graph = client.get(f"{base}/jobs/{job}/graph").json()
    assert len(graph["endpoint_nodes"]) == 2 and graph["relations"]
    summary = client.get(f"{base}/jobs/{job}/summary").json()
    assert (
        summary["untrusted_discovery_data"]
        and not summary["network_execution_permitted"]
    )
    assert set(summary["evidence_refs"]) <= {e["ref"] for e in evidence["items"]}
    assert (
        client.get(base + "/jobs", params={"status": "completed"}).json()["total"] == 1
    )
    assert client.get(base + "/jobs", params={"status": "failed"}).json()["total"] == 0
    assert client.post(f"{base}/jobs/{job}/cancel").json()["status"] == "completed"
    schema = client.get("/openapi.json").json()["paths"][
        f"{PREFIX}/{{workspace_id}}/discovery/jobs"
    ]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert schema["additionalProperties"] is False
    assert schema["properties"]["limits"]["properties"]["max_pages"]["maximum"] == 200
    assert "#/$defs/" not in json.dumps(schema)


@pytest.mark.parametrize(
    "suffix,method",
    [
        ("/jobs", "GET"),
        ("/jobs", "POST"),
        ("/openapi", "POST"),
        ("/jobs/{job}", "GET"),
        ("/jobs/{job}/cancel", "POST"),
        ("/jobs/{job}/endpoints", "GET"),
        ("/jobs/{job}/evidence", "GET"),
        ("/jobs/{job}/graph", "GET"),
        ("/jobs/{job}/summary", "GET"),
    ],
)
def test_all_discovery_routes_require_api_token(client, suffix, method):
    path = f"{PREFIX}/{uuid4()}/discovery" + suffix.format(job=uuid4())
    assert (
        client.request(
            method, path, headers={"Authorization": "Bearer wrong"}, json={}
        ).status_code
        == 401
    )
    client.headers.pop("Authorization")
    assert client.request(method, path, json={}).status_code == 401


@pytest.mark.parametrize(
    "suffix,method",
    [
        ("", "GET"),
        ("/cancel", "POST"),
        ("/endpoints", "GET"),
        ("/evidence", "GET"),
        ("/graph", "GET"),
        ("/summary", "GET"),
    ],
)
def test_cross_workspace_jobs_cannot_be_accessed(client, suffix, method):
    first, second = workspace(client), workspace(client)
    response = client.post(
        f"{PREFIX}/{first}/discovery/openapi", json={"document": spec()}
    )
    assert response.status_code == 202
    job = response.json()["id"]
    wait(client, f"{PREFIX}/{first}/discovery", job)
    assert (
        client.request(
            method, f"{PREFIX}/{second}/discovery/jobs/{job}{suffix}"
        ).status_code
        == 404
    )
    assert client.get(f"{PREFIX}/{second}/discovery/jobs").json()["total"] == 0


def test_offline_openapi_needs_no_crawl_permission_and_never_resolves_servers(client):
    ws = workspace(client)
    pid = policy_id(client, ws, operator_approved=False)
    resolver = client.app.state.workspace_service.resolver
    base = f"{PREFIX}/{ws}/discovery"
    result = client.post(base + "/openapi", json={"document": spec(), "policy_id": pid})
    assert result.status_code == 202
    done = wait(client, base, result.json()["id"])
    assert (
        done["status"] == "completed"
        and done["requests_made"] == 0
        and not resolver.calls
    )
    data = client.get(f"{base}/jobs/{done['id']}/summary").text
    assert (
        "SYNTHETIC_TOKEN_NOT_RETAINED" not in data and "never-fetch.invalid" not in data
    )


@pytest.mark.parametrize(
    "seed", ["http://lab.test/?token=SYNTHETIC_SECRET", "http://lab.test/%2fadmin"]
)
def test_invalid_seed_is_rejected_without_dns_or_sensitive_error_echo(client, seed):
    ws = workspace(client)
    pid = policy_id(client, ws)
    response = client.post(
        f"{PREFIX}/{ws}/discovery/jobs", json={"policy_id": pid, "seeds": [seed]}
    )
    assert response.status_code == 422 and "SYNTHETIC_SECRET" not in response.text
    assert not client.app.state.workspace_service.resolver.calls


def test_crawl_permission_denied_before_any_dns(client):
    ws = workspace(client)
    pid = policy_id(client, ws, operator_approved=False)
    response = client.post(
        f"{PREFIX}/{ws}/discovery/jobs",
        json={"policy_id": pid, "seeds": ["http://lab.test/"]},
    )
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "approval_required"
    assert not client.app.state.workspace_service.resolver.calls


def test_bounded_non_echoing_validation_database_failure_and_worker_conflict(
    client, monkeypatch
):
    ws = workspace(client)
    base = f"{PREFIX}/{ws}/discovery"
    assert (
        client.post(
            base + "/openapi", content=b"{}", headers={"Content-Type": "text/plain"}
        ).status_code
        == 415
    )
    assert (
        client.post(
            base + "/openapi",
            content=b"x" * 1048577,
            headers={"Content-Type": "application/json"},
        ).status_code
        == 413
    )
    invalid = client.post(
        base + "/openapi",
        json={
            "document": {"secret": "SYNTHETIC_SECRET"},
            "unknown": "SYNTHETIC_SECRET",
        },
    )
    assert invalid.status_code == 422 and "SYNTHETIC_SECRET" not in invalid.text
    assert client.post(base + "/openapi", json={"document": {}}).status_code == 422
    for query in ({"limit": 101}, {"offset": -1}, {"status": "unknown"}):
        assert client.get(base + "/jobs", params=query).status_code == 422
    assert client.get(base + "/jobs/invalid-uuid").status_code == 422
    manager = client.app.state.discovery_manager
    manager.worker_lock.release()
    assert client.post(base + "/openapi", json={"document": spec()}).status_code == 409

    def broken(*args):
        raise OperationalError("synthetic", {}, RuntimeError("SYNTHETIC_SECRET"))

    monkeypatch.setattr(manager.store, "jobs", broken)
    response = client.get(base + "/jobs")
    assert response.status_code == 503 and "SYNTHETIC_SECRET" not in response.text
