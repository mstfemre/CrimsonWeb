"""Real HTTP only on an ephemeral, explicitly authorized loopback laboratory."""

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from discovery_helpers import crawl_policy, crawl_request, setup, wait


def test_real_loopback_discovery_pins_dns_preserves_host_and_closes_requests():
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(
                (self.path, self.headers["Host"], self.headers["Accept-Encoding"])
            )
            if self.path == "/":
                self.send_response(302)
                self.send_header("Location", "/index")
                body = b""
            else:
                self.send_response(200)
                body = b'<form action="/submit" method="POST"><input name="owner_id" value="SYNTHETIC_PRIVATE_VALUE"></form>'
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_port
    configuration = crawl_policy()
    configuration.target_scope.allowed_ports = [port]

    async def run():
        repo, service, ws, record, manager = setup(configuration=configuration)
        manager.transport = None  # Exercise the real pinned HTTPX transport.
        try:
            await manager.startup()
            job = await manager.start_crawl(
                ws.id, crawl_request(record.id, seeds=[f"http://lab.test:{port}/"])
            )
            result = await wait(manager, ws.id, job.id)
            assert result.status == "completed" and result.requests_made == 2
            assert calls == [
                ("/", f"lab.test:{port}", "identity"),
                ("/index", f"lab.test:{port}", "identity"),
            ]
            assert len(service.resolver.calls) == 3
            endpoints = manager.store.endpoints(ws.id, job.id).items
            assert any(
                e.path == "/submit"
                and e.method == "POST"
                and e.observation_status == "candidate_only"
                for e in endpoints
            )
            assert "SYNTHETIC_PRIVATE_VALUE" not in str(
                [e.model_dump() for e in endpoints]
            )
        finally:
            await manager.shutdown()
            repo.close()

    try:
        asyncio.run(run())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
