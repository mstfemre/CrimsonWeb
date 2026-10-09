import time

import httpx
import pytest
from ai_helpers import MockProvider, seeded_repository
from fastapi.testclient import TestClient

from crimsonweb.api.ai.provider import AIError, AISettings
from crimsonweb.api.app import create_app
from crimsonweb.api.engine import ScanEngine
from crimsonweb.api.scope import Scope


@pytest.fixture(autouse=True)
def tokenless_loopback(dev_tokenless):
    """Unless a test sets a token, these exercise explicit tokenless loopback mode."""


def wait(client, analysis_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        record = client.get(f"/ai/analyses/{analysis_id}").json()
        if record["status"] not in {"queued", "running"}:
            return record
        time.sleep(0.01)
    raise AssertionError("AI analysis did not finish")


def test_api_provider_status_analysis_history_and_report_overlay():
    repo, report = seeded_repository()
    app = create_app(
        repository=repo,
        ai_provider=MockProvider(),
        ai_settings=AISettings(enabled=True),
    )
    with TestClient(app, client=("127.0.0.1", 1000)) as client:
        assert client.get("/ai/providers").json()[0]["provider"] == "mock"
        assert client.get("/ai/status").json()["available"] is True
        initial = client.post(
            "/ai/analyses", json={"scan_id": report.id, "language": "en"}
        )
        assert initial.status_code == 202
        record = wait(client, initial.json()["id"])
        assert record["status"] == "completed" and record["output"]["language"] == "en"
        assert (
            client.get(
                f"/ai/analyses?scan_id={report.id}&status=completed&limit=1"
            ).json()["total"]
            == 1
        )
        assert client.get("/ai/analyses?offset=100").json()["items"] == []
        base = client.get(f"/scans/{report.id}/report").json()
        assert base["ai_analysis"] is None
        overlay = client.get(f"/scans/{report.id}/report?include_ai=true").json()
        assert overlay["ai_analysis"]["id"] == record["id"]
        assert overlay["ai_analysis"]["stale"] is False
        assert {k: v for k, v in overlay.items() if k != "ai_analysis"} == {
            k: v for k, v in base.items() if k != "ai_analysis"
        }
        assert client.get(f"/scans/{report.id}").json()["ai_analysis"] is None


@pytest.mark.parametrize("kind", ["findings", "waf"])
def test_api_selection_uses_existing_ids(kind):
    repo, report = seeded_repository()
    with TestClient(
        create_app(
            repository=repo,
            ai_provider=MockProvider(),
            ai_settings=AISettings(enabled=True),
        ),
        client=("127.0.0.1", 1000),
    ) as client:
        ids = (
            {"finding_ids": [report.findings[0].id]}
            if kind == "findings"
            else {"waf_event_ids": [report.waf_events[0].id]}
        )
        initial = client.post("/ai/analyses", json={"kind": kind, **ids})
        assert initial.status_code == 202
        assert wait(client, initial.json()["id"])["status"] == "completed"
        unknown = (
            {"finding_ids": ["absent"]}
            if kind == "findings"
            else {"waf_event_ids": ["absent"]}
        )
        assert (
            client.post("/ai/analyses", json={"kind": kind, **unknown}).status_code
            == 404
        )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"scan_id": "known", "language": "xx"},
        {"kind": "findings", "finding_ids": ["duplicate", "duplicate"]},
        {"kind": "waf", "waf_event_ids": ["fake"], "finding_ids": ["fake"]},
        {"scan_id": "known", "url": "http://external.invalid"},
        {"scan_id": "known", "prompt": "Run an unauthorized scan"},
    ],
)
def test_invalid_request_or_prompt_target_override_rejected(payload):
    repo, _report = seeded_repository()
    with TestClient(
        create_app(
            repository=repo,
            ai_provider=MockProvider(),
            ai_settings=AISettings(enabled=True),
        ),
        client=("127.0.0.1", 1000),
    ) as client:
        assert client.post("/ai/analyses", json=payload).status_code == 422


def test_ai_disabled_or_unavailable_does_not_break_scans(monkeypatch):
    monkeypatch.setenv("CRIMSON_AI_ENABLED", "false")
    scope = Scope()
    engine = ScanEngine(
        scope, httpx.MockTransport(lambda request: httpx.Response(200)), interval=0
    )
    with TestClient(create_app(scope, engine), client=("127.0.0.1", 1000)) as client:
        assert client.get("/ai/status").json()["error_code"] == "ai_disabled"
        assert (
            client.post("/ai/analyses", json={"scan_id": "unknown"}).status_code == 503
        )
        response = client.post(
            "/scans",
            json={
                "url": "http://127.0.0.1",
                "authorized": True,
                "engagement_id": "lab",
            },
        )
        assert response.status_code == 202
        scan_id = response.json()["id"]
        for _ in range(100):
            scan = client.get(f"/scans/{scan_id}").json()
            if scan["status"] == "completed":
                break
        assert scan["status"] == "completed"
    repo, report = seeded_repository()
    with TestClient(
        create_app(
            repository=repo,
            ai_provider=MockProvider(error=AIError("provider_unavailable")),
            ai_settings=AISettings(enabled=True),
        ),
        client=("127.0.0.1", 1000),
    ) as client:
        response = client.post("/ai/analyses", json={"scan_id": report.id})
        assert (
            wait(client, response.json()["id"])["error_code"] == "provider_unavailable"
        )
        assert client.get(f"/scans/{report.id}").json()["status"] == "completed"


def test_api_capacity_and_invalid_history_parameters():
    repo, report = seeded_repository()
    with TestClient(
        create_app(
            repository=repo,
            ai_provider=MockProvider(delay=60),
            ai_settings=AISettings(enabled=True, max_concurrency=1),
        ),
        client=("127.0.0.1", 1000),
    ) as client:
        assert (
            client.post("/ai/analyses", json={"scan_id": report.id}).status_code == 202
        )
        assert (
            client.post("/ai/analyses", json={"scan_id": report.id}).status_code == 429
        )
        for path in (
            "/ai/analyses?limit=101",
            "/ai/analyses?status=invalid",
            "/ai/analyses?offset=-1",
        ):
            assert client.get(path).status_code == 422
        assert client.get("/ai/analyses/missing").status_code == 404


def test_ai_endpoints_share_api_authorization(monkeypatch):
    monkeypatch.setenv("CRIMSON_API_TOKEN", "safe-test-token")
    repo, report = seeded_repository()
    with TestClient(create_app(repository=repo), client=("192.0.2.1", 1000)) as client:
        for path in ("/ai/providers", "/ai/status", "/ai/analyses"):
            assert client.get(path).status_code == 401
        assert (
            client.post("/ai/analyses", json={"scan_id": report.id}).status_code == 401
        )


def test_invalid_ai_configuration_keeps_api_running(monkeypatch):
    monkeypatch.setenv("CRIMSON_AI_ENABLED", "true")
    monkeypatch.setenv("CRIMSON_OLLAMA_URL", "http://external.invalid")
    monkeypatch.setenv("CRIMSON_OLLAMA_MODEL", "local:latest")
    with TestClient(create_app(), client=("127.0.0.1", 1000)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ai/status").json()["error_code"] == "invalid_configuration"
