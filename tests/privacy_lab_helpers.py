"""Actual loopback DNS/HTTP peers. Never use an upstream DNS or external host."""

import ipaddress
import json
import socket
import socketserver
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dns.asyncresolver
import dns.exception
import dns.message
import dns.rdatatype
import dns.rrset

from crimsonweb.api.scope import ScopeError
from crimsonweb.api.workspaces.dns import Resolution, answer_chain


@contextmanager
def dns_lab(mode="normal"):
    receipts = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, peer = self.request
            query = dns.message.from_wire(packet)
            question = query.question[0]
            kind = dns.rdatatype.to_text(question.rdtype)
            receipts.append(kind)
            if mode == "timeout":
                return
            response = dns.message.make_response(query)
            name = question.name.to_text()
            if mode == "inconsistent":
                alias = "a.lab.test." if kind == "A" else "b.lab.test."
                response.answer.append(
                    dns.rrset.from_text(name, 1, "IN", "CNAME", alias)
                )
                name = alias
            response.answer.append(
                dns.rrset.from_text(
                    name, 1, "IN", kind, "127.0.0.1" if kind == "A" else "::1"
                )
            )
            peer.sendto(response.to_wire(), self.client_address)

    server = socketserver.ThreadingUDPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()

    class LabResolver:
        async def resolve(self, host):
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = ["127.0.0.1"]
            resolver.port = server.server_address[1]
            resolver.cache = None
            addresses, chains = set(), []
            try:
                for kind in ("A", "AAAA"):
                    answer = await resolver.resolve(
                        host + ".", kind, search=False, lifetime=0.15
                    )
                    chains.append(answer_chain(answer, host))
                    addresses.update(
                        str(ipaddress.ip_address(v.address)) for v in answer
                    )
            except (dns.exception.DNSException, OSError) as exc:
                raise ScopeError("dns_unavailable") from exc
            if not addresses or chains[0] != chains[1]:
                raise ScopeError("inconsistent_dns_answers")
            return Resolution(tuple(sorted(addresses)), chains[0])

        def privacy_diagnostics(self):
            # Trusted fixture instrumentation, not a field from DNS or echo data.
            return {
                "source": "controlled_packet_capture",
                "configured_resolvers": ["127.0.0.1"],
                "path_observed": bool(receipts),
                "observed_resolvers": ["127.0.0.1"] if receipts else [],
            }

    try:
        yield LabResolver(), receipts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def echo_lab(ipv6=False):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("Host")))
            payload = json.dumps({"ip": self.client_address[0]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", "PRIVATE_SESSION")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ipv6 else socket.AF_INET

    server = Server(("::1" if ipv6 else "127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    )
    thread.start()
    try:
        yield server.server_address[1], requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
