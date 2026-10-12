"""Live IPv4 sockets and TLS; no ASGITransport, MockTransport or fake resolver."""

import asyncio
import json
import socket
from urllib.parse import urlsplit

import httpx
import pytest

from crimsonweb.local_lab.bridge import LoopbackTransport, verify_laboratory
from crimsonweb.local_lab.server import LocalLaboratory


def test_real_detector_matches_vulnerable_and_secure_http_https(tmp_path):
    truth_path, output = tmp_path / "truth.json", tmp_path / "comparison.json"
    with LocalLaboratory(truth_path) as lab:
        result = asyncio.run(verify_laboratory(lab, output))
        ports = [urlsplit(origin).port for origin in (lab.http_origin, lab.https_origin)]
    assert result["all_matched"]
    assert len(result["comparisons"]) == 8
    assert len(result["lab_controls"]) == 16
    assert {r["scheme"] for r in result["comparisons"]} == {"http", "https"}
    for report in result["verification_reports"]:
        assert report["status"] == "completed"
        for finding in report["findings"]:
            assert finding["confidence"] == "unverified"
    assert json.loads(output.read_text(encoding="utf-8"))["run_id"] == result["run_id"]
    truth = json.loads(truth_path.read_text(encoding="utf-8"))
    assert len(truth["events"]) == 36
    assert not any(e["triggered"] for e in truth["events"] if e["mode"] == "secure")
    assert not any(e["browser_execution_observed"] for e in truth["events"])
    assert any(e["effect"] == "query_semantics_changed" for e in truth["events"])
    assert any(e["effect"] == "private_fixture_read" for e in truth["events"])
    for port in ports:
        with socket.socket() as client:
            client.settimeout(1)
            assert client.connect_ex(("127.0.0.1", port)) != 0


def test_tls_rejects_untrusted_certificate_and_validates_private_trust(tmp_path):
    with LocalLaboratory(tmp_path / "truth.json") as lab:
        with httpx.Client(trust_env=False) as client, pytest.raises(httpx.ConnectError):
            client.get(lab.https_origin + "/health")
        with httpx.Client(verify=lab.client_context, trust_env=False) as client:
            assert client.get(lab.https_origin + "/health").json()["lab"] is True


def test_traversal_cannot_read_real_files_outside_fixture_root(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("OUTSIDE_FIXTURE_SECRET", encoding="utf-8")
    with LocalLaboratory(tmp_path / "truth.json") as lab, httpx.Client(trust_env=False) as client:
        for mode in ("vulnerable", "secure"):
            response = client.get(lab.http_origin + f"/{mode}/files", params={"name": str(outside)})
            assert response.status_code == 404
            assert "OUTSIDE_FIXTURE_SECRET" not in response.text
            assert lab.truth.events[-1]["effect"] == "sandbox_escape_rejected"
        assert client.get(lab.http_origin + "/vulnerable/files", params={"name": "../private.txt"}).text == "LAB_PRIVATE_FIXTURE_ONLY"


def test_loopback_transport_and_host_boundary_reject_external_destinations(tmp_path):
    with LocalLaboratory(tmp_path / "truth.json") as lab:
        async def attempt():
            async with httpx.AsyncClient(transport=LoopbackTransport(lab), trust_env=False) as client:
                with pytest.raises(ValueError, match="outside this loopback lab"):
                    await client.get("https://example.invalid/")
        asyncio.run(attempt())
        with httpx.Client(trust_env=False) as client:
            response = client.get(lab.http_origin + "/health", headers={"Host": "example.invalid"})
            assert response.status_code == 403
        assert lab.truth.events == []


def test_xss_fixture_reflects_script_but_does_not_claim_browser_execution(tmp_path):
    payload = "<script>window.labProof=true</script>"
    with LocalLaboratory(tmp_path / "truth.json") as lab, httpx.Client(trust_env=False) as client:
        vulnerable = client.get(lab.http_origin + "/vulnerable/xss", params={"q": payload})
        secure = client.get(lab.http_origin + "/secure/xss", params={"q": payload})
        assert payload in vulnerable.text
        assert payload not in secure.text
        assert "&lt;script&gt;" in secure.text
        assert [e["triggered"] for e in lab.truth.events] == [True, False]
        assert not lab.truth.events[0]["browser_execution_observed"]
