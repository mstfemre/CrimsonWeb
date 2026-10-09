import asyncio
import socket
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from crimsonweb.api.app import create_app
from crimsonweb.api.engine import ScanEngine
from crimsonweb.api.headers import analyze_headers
from crimsonweb.api.models import ScanReport
from crimsonweb.api.scope import Scope, ScopeError


def run_scan(handler, target="http://127.0.0.1:8001/", scope=None):
    policy = scope or Scope()
    report = ScanReport(
        id="test", engagement_id="lab", target=target, scope=policy.snapshot()
    )
    asyncio.run(
        ScanEngine(policy, httpx.MockTransport(handler), interval=0).run(report)
    )
    return report


@pytest.mark.parametrize(
    "url",
    [
        "ftp://localhost/",
        "http://example.com/",
        "http://localhost@evil.com/",
        "http://user:pass@localhost/",
        "http://localhost/?secret=x",
        "http://localhost/#fragment",
        "http://localhost:99999/",
        "http://localhost\\evil/",
    ],
)
def test_url_validation(url):
    with pytest.raises(ScopeError):
        Scope().validate_url(url)


def test_dns_mixed_addresses_rejected():
    async def check():
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 80))
            for ip in ("127.0.0.1", "192.0.2.1")
        ]
        with (
            patch.object(
                asyncio.get_running_loop(), "getaddrinfo", return_value=records
            ),
            pytest.raises(ScopeError),
        ):
            await Scope().resolve(httpx.URL("http://localhost/"))

    asyncio.run(check())


def test_pins_address_retains_host_and_sni():
    def handler(request):
        assert request.url.host in {"127.0.0.1", "::1"}
        assert request.headers["host"] == "localhost:8001"
        assert request.extensions["sni_hostname"] == "localhost"
        return httpx.Response(
            200, headers={"Set-Cookie": "secret=value", "Server": "private"}
        )

    report = run_scan(handler, "http://localhost:8001/")
    assert report.status == "completed"
    assert "secret" not in report.model_dump_json()
    assert "server" not in report.hops[0].headers
    assert all(f.classification == "configuration_observation" for f in report.findings)


@pytest.mark.parametrize(
    "code,reason", [(403, "http_403_access_denied"), (429, "http_429_rate_limited")]
)
def test_block_no_retry(code, reason):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(code, headers={"Location": "/next", "Retry-After": "1"})

    report = run_scan(handler)
    assert report.status == "blocked" and report.stop_reason == reason
    assert len(calls) == 1


def test_external_redirect_never_contacted():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "http://example.com/"})

    report = run_scan(handler)
    assert report.stop_reason == "scope_violation" and len(calls) == 1


def test_dns_rebinding_on_redirect_stops_before_second_request():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "/next"})

    with patch.object(
        Scope,
        "resolve",
        new=AsyncMock(
            side_effect=[["127.0.0.1"], ScopeError("DNS changed outside scope")]
        ),
    ):
        report = run_scan(handler, "http://localhost/")
    assert report.stop_reason == "scope_violation"
    assert len(calls) == 1


def test_redirect_request_budget():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": f"/next-{len(calls)}"})

    report = run_scan(handler)
    assert report.stop_reason == "redirect_limit"
    assert len(calls) == 6


def test_redirect_and_loop():
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(302, headers={"Location": "/ok"})
        return httpx.Response(200)

    assert len(run_scan(handler).hops) == 2
    report = run_scan(lambda request: httpx.Response(302, headers={"Location": "/"}))
    assert report.stop_reason == "redirect_loop"


def test_https_downgrade_stops():
    report = run_scan(
        lambda request: httpx.Response(302, headers={"Location": "http://127.0.0.1/"}),
        "https://127.0.0.1/",
    )
    assert report.stop_reason == "https_downgrade"


@pytest.mark.parametrize(
    "exception,category",
    [
        (httpx.ConnectError("failure"), "connection_or_tls_error"),
        (httpx.ReadTimeout("failure"), "timeout"),
    ],
)
def test_connection_failures(exception, category):
    def handler(request):
        raise exception

    report = run_scan(handler)
    assert report.status == "failed" and report.error_category == category


def test_headers_context():
    plain = analyze_headers(httpx.Headers(), False)
    assert not any(f.code == "missing_strict-transport-security" for f in plain)
    headers = httpx.Headers(
        {
            "Content-Security-Policy": "frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
    )
    assert analyze_headers(headers, False)[0].code == "plaintext_http"
    assert any(
        f.code == "missing_strict-transport-security"
        for f in analyze_headers(headers, True)
    )


def test_api_authorization_validation_report(dev_tokenless):
    policy = Scope()
    engine = ScanEngine(
        policy, httpx.MockTransport(lambda request: httpx.Response(200)), interval=0
    )
    with TestClient(create_app(policy, engine), client=("127.0.0.1", 50000)) as client:
        assert client.get("/health").status_code == 200
        assert (
            client.post(
                "/scans",
                json={
                    "url": "http://127.0.0.1",
                    "engagement_id": "lab",
                    "authorized": False,
                },
            ).status_code
            == 422
        )
        response = client.post(
            "/scans",
            json={
                "url": "http://127.0.0.1",
                "engagement_id": "lab",
                "authorized": True,
            },
        )
        assert response.status_code == 202
        scan_id = response.json()["id"]
        for _ in range(100):
            report = client.get(f"/scans/{scan_id}").json()
            if report["status"] == "completed":
                break
        assert report["status"] == "completed"
        download = client.get(f"/scans/{scan_id}/report")
        assert (
            download.status_code == 200
            and download.json()["scope"] == policy.snapshot()
        )
        assert client.get("/scans/missing").status_code == 404
    with TestClient(create_app(), client=("192.0.2.1", 1000)) as client:
        assert client.get("/health").status_code == 403


def test_api_token(monkeypatch):
    monkeypatch.setenv("CRIMSON_API_TOKEN", "test-token")
    with TestClient(create_app(), client=("192.0.2.1", 1000)) as client:
        assert client.get("/health").status_code == 401
        assert (
            client.get(
                "/health", headers={"Authorization": "Bearer test-token"}
            ).status_code
            == 200
        )
