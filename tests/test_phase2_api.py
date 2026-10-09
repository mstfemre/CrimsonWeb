import asyncio
import json
import time
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from crimsonweb.api.app import create_app
from crimsonweb.api.database import Repository
from crimsonweb.api.engine import ScanEngine
from crimsonweb.api.scope import Scope


@pytest.fixture(autouse=True)
def tokenless_loopback(dev_tokenless):
    """Unless a test sets a token, these exercise explicit tokenless loopback mode."""


def make_app(handler=None, repository=None):
    scope = Scope()
    return create_app(
        scope,
        ScanEngine(
            scope,
            httpx.MockTransport(
                handler
                or (lambda request: httpx.Response(429, headers={"Retry-After": "120"}))
            ),
            interval=0,
        ),
        repository,
    )


def start(client):
    response = client.post(
        "/scans",
        json={
            "url": "http://127.0.0.1/",
            "engagement_id": "phase2",
            "authorized": True,
        },
    )
    assert response.status_code == 202
    return response.json()["id"]


def wait(client, scan_id):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        report = client.get(f"/scans/{scan_id}").json()
        if report["status"] not in {"queued", "running"}:
            return report
        time.sleep(0.01)
    raise AssertionError("Scan did not finish")


def test_api_history_persists_across_app_restart_and_filters(monkeypatch):
    monkeypatch.delenv("CRIMSON_API_TOKEN", raising=False)
    with TestClient(make_app(), client=("127.0.0.1", 1000)) as client:
        scan_id = start(client)
        report = wait(client, scan_id)
        assert report["status"] == "blocked"
        assert report["waf_events"][0]["retry_after_seconds"] == 120
        target_id = client.get("/targets").json()["items"][0]["id"]
    with TestClient(make_app(), client=("127.0.0.1", 1000)) as client:
        assert client.get(f"/scans/{scan_id}").json() == report
        page = client.get(
            f"/history?status=blocked&target_id={target_id}&limit=1"
        ).json()
        assert page["total"] == 1 and page["items"][0]["id"] == scan_id
        assert client.get("/history?status=completed").json()["total"] == 0
        assert client.get("/history?offset=100").json()["items"] == []
        findings = client.get(
            f"/findings?scan_id={scan_id}&severity=low&limit=1"
        ).json()
        assert findings["total"] > 0 and len(findings["items"]) == 1
        assert findings["items"][0]["target_id"] == target_id
        events = client.get(
            f"/waf/events?event_type=rate_limited&scan_id={scan_id}"
        ).json()
        assert events["total"] == 1
        assert client.get(f"/scans/{scan_id}/report").json() == report


@pytest.mark.parametrize(
    "query",
    [
        "/history?limit=0",
        "/history?limit=101",
        "/history?offset=-1",
        "/history?status=unknown",
        "/findings?severity=unknown",
        "/waf/events?event_type=unknown",
    ],
)
def test_invalid_filters_are_422(query):
    with TestClient(make_app(), client=("127.0.0.1", 1000)) as client:
        assert client.get(query).status_code == 422


def test_waf_import_dedup_report_and_errors():
    with TestClient(make_app(), client=("127.0.0.1", 1000)) as client:
        scan_id = start(client)
        wait(client, scan_id)
        record = {
            "timestamp": "2026-10-08T09:00:00Z",
            "event_type": "waf_block",
            "rule_id": "949110",
        }
        payload = {
            "format": "normalized_json",
            "content": json.dumps(record),
            "scan_id": scan_id,
            "expected_benign": True,
        }
        assert client.post("/waf/import", json=payload).json() == {
            "imported": 1,
            "duplicates": 0,
        }
        assert client.post("/waf/import", json=payload).json() == {
            "imported": 0,
            "duplicates": 1,
        }
        event = client.get("/waf/events?rule_id=949110").json()["items"][0]
        assert event["assessment"] == "candidate_false_positive"
        assert len(client.get(f"/scans/{scan_id}/report").json()["waf_events"]) == 2
        assert (
            client.post(
                "/waf/import", json={**payload, "scan_id": "missing"}
            ).status_code
            == 404
        )
        assert (
            client.post("/waf/import", json={**payload, "content": "bad"}).status_code
            == 422
        )


@pytest.mark.parametrize("defense_log", [False, True])
def test_active_scan_stops_on_operator_or_defense_log(defense_log):
    calls = []

    async def handler(request):
        calls.append(request)
        await asyncio.sleep(60)
        return httpx.Response(200)

    with TestClient(make_app(handler), client=("127.0.0.1", 1000)) as client:
        scan_id = start(client)
        assert client.get(f"/scans/{scan_id}/report").status_code == 409
        if defense_log:
            response = client.post(
                "/waf/import",
                json={
                    "scan_id": scan_id,
                    "format": "normalized_json",
                    "content": json.dumps(
                        {
                            "timestamp": "2026-10-08T09:00:00Z",
                            "event_type": "ip_block",
                            "rule_id": "lab",
                        }
                    ),
                },
            )
            assert response.status_code == 200
        else:
            assert client.post(f"/scans/{scan_id}/stop").status_code == 200
        report = client.get(f"/scans/{scan_id}").json()
        assert report["status"] == ("blocked" if defense_log else "stopped")
        assert report["stop_reason"] == (
            "defense_log_block" if defense_log else "operator_stop"
        )
        assert len(calls) <= 1


def test_database_error_response_does_not_expose_details():
    repo = Repository("sqlite://")
    with TestClient(make_app(repository=repo), client=("127.0.0.1", 1000)) as client:
        with patch.object(
            repo,
            "history",
            side_effect=OperationalError("secret sql", {}, Exception("private")),
        ):
            response = client.get("/history")
        assert (
            response.status_code == 503
            and "secret" not in response.text
            and "private" not in response.text
        )


def test_waf_and_history_endpoints_require_authorization(monkeypatch):
    monkeypatch.setenv("CRIMSON_API_TOKEN", "test-token")
    with TestClient(make_app(), client=("192.0.2.1", 1000)) as client:
        for path in ("/history", "/targets", "/findings", "/waf/events"):
            assert client.get(path).status_code == 401
        assert (
            client.post(
                "/waf/import", json={"format": "normalized_json", "content": "{}"}
            ).status_code
            == 401
        )
