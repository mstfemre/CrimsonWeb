import json
import time
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from workspace_helpers import NOW, FakeResolver, policy

from crimsonweb.api.app import create_app
from crimsonweb.api.database import Repository

PREFIX = "/api/v1/workspaces"
ROUTES = [
    ("POST", "/profiles"),
    ("GET", "/profiles"),
    ("GET", "/profiles/{profile}"),
    ("PUT", "/profiles/{profile}"),
    ("DELETE", "/profiles/{profile}"),
    ("GET", "/profiles/{profile}/policy"),
    ("PUT", "/profiles/{profile}/policy"),
    ("POST", "/profiles/{profile}/preflight"),
    ("POST", "/profiles/{profile}/observations"),
    ("GET", "/assessments"),
    ("GET", "/assessments/{job}"),
    ("POST", "/assessments/{job}/cancel"),
    ("GET", "/assessments/{job}/findings"),
    ("GET", "/evidence/{evidence}"),
    ("GET", "/audit"),
]


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("CRIMSON_API_TOKEN", "synthetic-test-token")
    app = create_app(
        repository=Repository("sqlite://"),
        privacy_transport=httpx.MockTransport(
            lambda r: httpx.Response(
                200,
                headers={
                    "content-type": "application/json",
                    "set-cookie": "SECRET_SESSION",
                },
                json={"ip": "203.0.113.7"},
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
    response = client.post(PREFIX, json={"name": "lab", "program_type": "lab"})
    assert response.status_code == 201
    return response.json()["id"]


def context(client, approved=True, expected="203.0.113.7"):
    ws = workspace(client)
    pid = client.post(
        f"{PREFIX}/{ws}/policies", json=policy().model_dump(mode="json")
    ).json()["id"]
    base = f"{PREFIX}/{ws}/privacy"
    response = client.post(
        base + "/profiles",
        json={"name": "privacy_lab", "approved_egress_identity": [expected]},
    )
    assert response.status_code == 201
    profile = response.json()
    if approved:
        response = client.put(
            base + f"/profiles/{profile['id']}/policy?expected_revision=1",
            json={
                "verification_urls": ["http://lab.test/echo"],
                "allowed_tests": ["egress", "dns", "ipv6"],
                "operator_approved": True,
                "valid_until": (NOW + timedelta(days=1)).isoformat(),
                "maximum_observations": 10,
                "rate_limit_per_minute": 60,
            },
        )
        assert response.status_code == 200
    return (
        ws,
        base,
        profile,
        {
            "kind": "egress",
            "program_policy_id": pid,
            "verification_url": "http://lab.test/echo",
        },
    )


def wait(client, base, job):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        response = client.get(f"{base}/assessments/{job}")
        assert response.status_code == 200
        record = response.json()
        if record["execution_status"] not in {"queued", "running"}:
            return record
        time.sleep(0.005)
    pytest.fail("Privacy job did not finish")


@pytest.mark.parametrize("method,suffix", ROUTES)
def test_all_privacy_routes_require_the_existing_api_token(client, method, suffix):
    path = f"{PREFIX}/{uuid4()}/privacy" + suffix.format(
        profile=uuid4(), job=uuid4(), evidence=uuid4()
    )
    assert (
        client.request(
            method, path, headers={"Authorization": "Bearer invalid"}, json={}
        ).status_code
        == 401
    )
    client.headers.pop("Authorization")
    assert client.request(method, path, json={}).status_code == 401


def test_profile_policy_preflight_observation_evidence_audit_and_paging(client):
    _, base, profile, payload = context(client)
    profile_path = base + f"/profiles/{profile['id']}"
    assert "203.0.113.7" not in json.dumps(profile) and "identity_key" not in profile
    preflight = client.post(profile_path + "/preflight", json=payload)
    assert preflight.status_code == 200 and preflight.json()["allowed"]
    assert (
        preflight.json()["advisory_only"] and not preflight.json()["network_performed"]
    )
    assert not client.app.state.workspace_service.resolver.calls
    response = client.post(profile_path + "/observations", json=payload)
    assert response.status_code == 202
    result = wait(client, base, response.json()["id"])
    assert result["status"] == "secure_observed" and result["requests_made"] == 1
    assert not result["anonymity_guaranteed"] and not result["retention_enforced"]
    evidence_id = result["evidence_refs"][0].split(":")[1]
    evidence = client.get(base + f"/evidence/{evidence_id}").json()
    assert (
        evidence["ref"] == result["evidence_refs"][0] and evidence["kind"] == "egress"
    )
    assert "203.0.113.7" not in json.dumps(
        evidence
    ) and "SECRET_SESSION" not in json.dumps(evidence)
    assert client.get(base + f"/assessments/{result['id']}/findings").json() == []
    assert (
        client.post(base + f"/assessments/{result['id']}/cancel").json()["status"]
        == "secure_observed"
    )
    assert client.get(base + "/assessments?limit=1&offset=1").json()["items"] == []
    assert client.get(base + "/assessments?limit=1&offset=0").json()["total"] == 1
    audit = client.get(base + "/audit?limit=100").json()
    assert any(item["evidence_ref"] == evidence["ref"] for item in audit["items"])
    assert "203.0.113.7" not in json.dumps(audit) and "lab.test" not in json.dumps(
        audit
    )
    schema = client.get("/openapi.json").json()["paths"][
        f"{PREFIX}/{{workspace_id}}/privacy/profiles"
    ]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert not schema["additionalProperties"] and "#/$defs/" not in json.dumps(schema)
    assert (
        schema["properties"]["logging"]["properties"]["store_raw_payloads"]["const"]
        is False
    )


def test_profile_and_policy_revision_conflicts_and_soft_delete_keep_history(client):
    _, base, profile, payload = context(client)
    profile_path = base + f"/profiles/{profile['id']}"
    job = client.post(profile_path + "/observations", json=payload).json()["id"]
    result = wait(client, base, job)
    response = client.put(
        profile_path + "?expected_revision=1", json={"name": "updated"}
    )
    assert response.status_code == 200 and response.json()["revision"] == 2
    assert (
        client.put(
            profile_path + "?expected_revision=1", json={"name": "stale"}
        ).status_code
        == 409
    )
    assert (
        client.put(profile_path + "/policy?expected_revision=1", json={}).status_code
        == 409
    )
    assert client.delete(profile_path).status_code == 204
    assert client.get(profile_path).status_code == 404
    assert client.get(base + "/profiles").json()["total"] == 0
    assert client.get(base + f"/assessments/{job}").json() == result
    assert (
        client.get(
            base + f"/evidence/{result['evidence_refs'][0].split(':')[1]}"
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "method,suffix",
    [
        ("GET", "/profiles/{profile}"),
        ("PUT", "/profiles/{profile}?expected_revision=1"),
        ("DELETE", "/profiles/{profile}"),
        ("GET", "/profiles/{profile}/policy"),
        ("PUT", "/profiles/{profile}/policy?expected_revision=2"),
        ("POST", "/profiles/{profile}/preflight"),
        ("POST", "/profiles/{profile}/observations"),
        ("GET", "/assessments/{job}"),
        ("POST", "/assessments/{job}/cancel"),
        ("GET", "/assessments/{job}/findings"),
        ("GET", "/evidence/{evidence}"),
    ],
)
def test_foreign_workspace_objects_are_unreachable_through_privacy_api(
    client, method, suffix
):
    _, base, profile, payload = context(client)
    job = client.post(
        base + f"/profiles/{profile['id']}/observations", json=payload
    ).json()["id"]
    result = wait(client, base, job)
    other = workspace(client)
    path = f"{PREFIX}/{other}/privacy" + suffix.format(
        profile=profile["id"],
        job=job,
        evidence=result["evidence_refs"][0].split(":")[1],
    )
    body = (
        {"name": "foreign"}
        if method == "PUT" and "/policy" not in path
        else {}
        if "/policy" in path
        else payload
    )
    assert client.request(method, path, json=body).status_code == 404
    assert client.get(f"{PREFIX}/{other}/privacy/audit").json()["total"] == 0


def test_foreign_program_policy_is_rejected_even_when_privacy_policy_denies(client):
    _, base, profile, payload = context(client, approved=False)
    other = workspace(client)
    payload["program_policy_id"] = client.post(
        f"{PREFIX}/{other}/policies", json=policy().model_dump(mode="json")
    ).json()["id"]
    assert (
        client.post(
            base + f"/profiles/{profile['id']}/preflight", json=payload
        ).status_code
        == 404
    )
    assert not client.app.state.workspace_service.resolver.calls


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "x", "approved_egress_identity": ["SECRET_INVALID_IP"]},
        {"name": "x", "mode": "SECRET_MODE"},
        {"name": "x", "logging": {"store_raw_payloads": True}},
        {"name": "x", "secret_token": "SECRET_TOKEN"},
    ],
)
def test_validation_rejects_inputs_without_echoing_sensitive_values(client, payload):
    ws = workspace(client)
    response = client.post(f"{PREFIX}/{ws}/privacy/profiles", json=payload)
    assert response.status_code == 422 and "SECRET" not in response.text
    assert "input" not in response.text


def test_bounded_body_media_type_pagination_and_fixed_database_errors(
    client, monkeypatch
):
    _, base, profile, _ = context(client)
    assert (
        client.post(
            base + "/profiles",
            content=b"x" * 1048577,
            headers={"Content-Type": "application/json"},
        ).status_code
        == 413
    )
    assert (
        client.post(
            base + "/profiles", content="secret", headers={"Content-Type": "text/plain"}
        ).status_code
        == 415
    )
    assert (
        client.post(
            base + "/profiles",
            content=b"{",
            headers={"Content-Type": "application/json"},
        ).status_code
        == 422
    )
    assert client.get(base + "/audit?limit=101").status_code == 422
    assert client.get(base + "/profiles?offset=-1").status_code == 422
    assert (
        client.put(base + f"/profiles/{profile['id']}", json={"name": "x"}).status_code
        == 422
    )

    def unavailable(*args):
        raise OperationalError("SECRET_SQL", {}, RuntimeError("SECRET_DATABASE"))

    monkeypatch.setattr(client.app.state.privacy_service.store, "snapshot", unavailable)
    response = client.get(base + f"/profiles/{profile['id']}")
    assert response.status_code == 503 and "SECRET" not in response.text


def test_mismatched_echo_produces_linked_suspicion_without_validated_leak(client):
    _, base, profile, payload = context(client, expected="203.0.113.8")
    job = client.post(
        base + f"/profiles/{profile['id']}/observations", json=payload
    ).json()["id"]
    result = wait(client, base, job)
    findings = client.get(base + f"/assessments/{job}/findings").json()
    assert result["status"] == "leak_suspected" and len(findings) == 1
    assert findings[0]["evidence_refs"] == result["evidence_refs"]
    assert findings[0]["status"] != "leak_validated"


def test_api_start_without_lifetime_worker_lock_is_unavailable_and_passive_read_works(
    client,
):
    _, base, profile, payload = context(client)
    client.app.state.privacy_service.worker_lock.release()
    path = base + f"/profiles/{profile['id']}"
    assert client.post(path + "/observations", json=payload).status_code == 409
    assert client.post(path + "/preflight", json=payload).status_code == 200
    assert client.get(path).status_code == 200
    assert not client.app.state.workspace_service.resolver.calls
