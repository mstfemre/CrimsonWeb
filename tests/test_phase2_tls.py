"""Real local TLS handshakes with generated certificates; no external targets."""

import asyncio
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from crimsonweb.api.engine import ScanEngine
from crimsonweb.api.models import ScanReport
from crimsonweb.api.scope import Scope


def certificate(tmp_path, days=10, hostname="localhost", future=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            now + timedelta(days=1) if future else now - timedelta(days=10)
        )
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@contextmanager
def tls_server(cert, key, status=200):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://localhost:{server.server_port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def scan(url, cert=None):
    scope = Scope()
    report = ScanReport(
        id="tls-test", engagement_id="local-tls", target=url, scope=scope.snapshot()
    )
    context = (
        ssl.create_default_context(cafile=str(cert))
        if cert
        else ssl.create_default_context()
    )

    async def run():
        await ScanEngine(
            scope, httpx.AsyncHTTPTransport(verify=context), interval=0
        ).run(report)

    asyncio.run(run())
    return report


def test_valid_trusted_certificate_expiry_and_negotiated_protocol(tmp_path):
    cert, key = certificate(tmp_path)
    with tls_server(cert, key) as url:
        report = scan(url, cert)
    assert report.status == "completed", report
    observed = report.hops[0].tls
    assert observed.verified and observed.protocol in {"TLSv1.2", "TLSv1.3"}
    assert observed.not_before < datetime.now(UTC) < observed.not_after
    assert 0 < observed.days_remaining <= 10
    assert any(f.code == "tls_expiry_soon" for f in report.findings)
    assert observed.supported_versions_tested is False


@pytest.mark.parametrize("mode", ["untrusted", "wrong-host", "expired", "future"])
def test_verification_rejects_invalid_certificates_without_insecure_retry(
    tmp_path, mode
):
    cert, key = certificate(
        tmp_path,
        days=-1 if mode == "expired" else 10,
        hostname="other.invalid" if mode == "wrong-host" else "localhost",
        future=mode == "future",
    )
    with tls_server(cert, key) as url:
        report = scan(url, None if mode == "untrusted" else cert)
    assert (
        report.status == "failed" and report.error_category == "tls_certificate_error"
    ), report
    assert len(report.tls_failures) == 1 and not report.hops
    assert report.tls_failures[0].verification_error


def test_https_block_preserves_tls_observation_and_stops(tmp_path):
    cert, key = certificate(tmp_path, days=90)
    with tls_server(cert, key, status=403) as url:
        report = scan(url, cert)
    assert report.status == "blocked" and len(report.hops) == 1
    assert (
        report.hops[0].tls.verified
        and report.waf_events[0].event_type == "access_denied"
    )
