import asyncio

import httpx
import pytest

from crimsonweb.api.engine import ScanEngine
from crimsonweb.api.models import ScanReport, TLSObservation
from crimsonweb.api.scope import Scope
from crimsonweb.api.tls import tls_findings
from crimsonweb.api.web_analysis import analyze_web
from crimsonweb.web_checks import CORS_TEST_ORIGIN


@pytest.mark.parametrize(
    "hsts,code",
    [
        ("max-age=0", "hsts_disabled"),
        ("max-age=100", "hsts_short_or_invalid"),
        ("max-age=oops", "hsts_invalid"),
        ("max-age=100; max-age=200", "hsts_invalid"),
    ],
)
def test_hsts(hsts, code):
    headers = httpx.Headers({"Strict-Transport-Security": hsts})
    assert code in {f.code for f in analyze_web(headers, True)}
    assert not any(f.code.startswith("hsts") for f in analyze_web(headers, False))


@pytest.mark.parametrize(
    "hsts", ["max-age=31536000; includeSubDomains", 'max-age = "31536000"']
)
def test_valid_hsts_no_false_positive(hsts):
    assert not analyze_web(httpx.Headers({"Strict-Transport-Security": hsts}), True)


def test_multi_cookie_privacy_and_context():
    headers = httpx.Headers(
        [
            ("set-cookie", "sid=top-secret; HttpOnly; Secure; SameSite=Lax"),
            ("set-cookie", "public=private-value; SameSite=None"),
            ("set-cookie", "extra=another-secret; Secure; SameSite=invalid"),
        ]
    )
    findings = analyze_web(headers, True)
    assert "cookie_none_without_secure" in {f.code for f in findings}
    assert "cookie_invalid_samesite" in {f.code for f in findings}
    assert all(f.severity == "low" for f in findings)
    assert "secret" not in str(findings) and "private-value" not in str(findings)
    assert not any("Cookie #1" in f.evidence for f in findings)


def test_public_cors_and_invalid_credentials_not_high_vulnerability():
    public = analyze_web(httpx.Headers({"Access-Control-Allow-Origin": "*"}), False)
    assert public[0].severity == "info"
    invalid = analyze_web(
        httpx.Headers(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        ),
        False,
    )
    assert (
        invalid[0].code == "cors_wildcard_credentials" and invalid[0].severity == "low"
    )


def test_cors_reflection_is_an_observation():
    reflected = analyze_web(
        httpx.Headers(
            {
                "Access-Control-Allow-Origin": CORS_TEST_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
        ),
        False,
    )
    assert len(reflected) == 1 and reflected[0].severity == "medium"
    assert reflected[0].classification == "configuration_observation"
    assert (
        analyze_web(
            httpx.Headers(
                {
                    "Access-Control-Allow-Origin": "https://trusted.example",
                    "Vary": "Origin",
                }
            ),
            False,
        )
        == []
    )


def test_tls_negotiated_protocol_is_not_supported_protocol_inventory():
    observed = TLSObservation(verified=True, protocol="TLSv1.3", days_remaining=100)
    assert tls_findings(observed) == []
    assert observed.supported_versions_tested is False
    assert (
        tls_findings(TLSObservation(verified=True, protocol="TLSv1.1"))[0].code
        == "tls_legacy_negotiated"
    )


def test_https_redirect_observation_and_origin_request():
    calls = []

    def handler(request):
        calls.append(request)
        assert request.headers["origin"] == CORS_TEST_ORIGIN
        if request.url.scheme == "http":
            return httpx.Response(301, headers={"Location": "https://127.0.0.1/"})
        return httpx.Response(200)

    scope = Scope()
    report = ScanReport(
        id="test",
        engagement_id="lab",
        target="http://127.0.0.1/",
        scope=scope.snapshot(),
    )
    asyncio.run(ScanEngine(scope, httpx.MockTransport(handler), interval=0).run(report))
    assert report.https_redirect == "observed" and len(calls) == 2
    assert (
        report.hops[-1].tls is None
    )  # Mock transport did not perform a real TLS handshake.
    assert not any(f.code == "plaintext_http" for f in report.findings)
