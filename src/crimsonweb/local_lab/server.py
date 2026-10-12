"""Real ephemeral-port HTTP/HTTPS servers with a per-run self-signed certificate."""

import ipaddress
import socket
import ssl
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import uvicorn

from .app import GroundTruth, create_app


def generate_certificate(directory: Path):
    # Already in CrimsonWeb's dev extra; no subprocess, download or public CA.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CrimsonWeb loopback lab")])
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert, private_key = directory / "cert.pem", directory / "key.pem"
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private_key.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    return cert, private_key


class LocalLaboratory:
    """Own sockets, workers and disposable fixtures; persist only requested outputs."""

    def __init__(self, ground_truth: Path):
        self.ground_truth_path = Path(ground_truth)
        self.servers = []
        self.threads = []
        self.sockets = []
        self.temporary = None

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="crimsonweb-lab-")
        root = Path(self.temporary.name)
        try:
            cert, key = generate_certificate(root)
            self.cert_path = cert
            self.client_context = ssl.create_default_context(cafile=str(cert))
            self.truth = GroundTruth(self.ground_truth_path)
            self.app = create_app(root / "fixtures", self.truth)
            origins = []
            for scheme in ("http", "https"):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sockets.append(listener)
                listener.bind(("127.0.0.1", 0))
                origins.append(f"{scheme}://127.0.0.1:{listener.getsockname()[1]}")
                config = uvicorn.Config(
                    self.app, host="127.0.0.1", log_level="error", access_log=False,
                    proxy_headers=False, lifespan="off", loop="asyncio", http="h11",
                    ssl_certfile=str(cert) if scheme == "https" else None,
                    ssl_keyfile=str(key) if scheme == "https" else None,
                )
                server = uvicorn.Server(config)
                thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
                self.servers.append(server)
                self.threads.append(thread)
                thread.start()
                deadline = time.monotonic() + 10
                while not server.started:
                    if not thread.is_alive() or time.monotonic() >= deadline:
                        raise RuntimeError("Local laboratory startup failed")
                    time.sleep(0.01)
            self.http_origin, self.https_origin = origins
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        for server in self.servers:
            server.should_exit = True
        for thread in self.threads:
            thread.join(timeout=10)
        for listener in self.sockets:
            listener.close()
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("Local laboratory worker did not stop")
        if self.temporary:
            self.temporary.cleanup()
