"""Exercise the actual HTTPX/socket path against the shipped FastAPI lab."""

import socket
import threading
import time
from contextlib import contextmanager

import httpx
import uvicorn

from crimsonweb.api.app import create_app
from crimsonweb.api.lab import app as lab


@contextmanager
def live_server(app):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", proxy_headers=False))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, daemon=True
    )
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            assert thread.is_alive() and time.monotonic() < deadline, (
                "Server startup failed"
            )
            time.sleep(0.01)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "Server did not stop"


def test_live_api_and_lab(dev_tokenless):
    with (
        live_server(lab) as target,
        live_server(create_app()) as api,
        httpx.Client(base_url=api, trust_env=False, timeout=5) as client,
    ):
        for path, expected in [
            ("/redirect", "completed"),
            ("/blocked", "blocked"),
            ("/limited", "blocked"),
        ]:
            response = client.post(
                "/scans",
                json={
                    "url": target + path,
                    "engagement_id": "integration-lab",
                    "authorized": True,
                },
            )
            assert response.status_code == 202
            scan_id = response.json()["id"]
            deadline = time.monotonic() + 15
            while True:
                report = client.get(f"/scans/{scan_id}").json()
                if report["status"] not in {"queued", "running"}:
                    break
                assert time.monotonic() < deadline, "Scan did not finish"
                time.sleep(0.02)
            assert report["status"] == expected, report
            assert report["hops"][0]["connected_ip"] == "127.0.0.1"
            assert client.get(f"/scans/{scan_id}/report").json() == report
            if path == "/redirect":
                assert [h["status_code"] for h in report["hops"]] == [307, 200]
            else:
                assert len(report["hops"]) == 1
