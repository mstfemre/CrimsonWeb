import asyncio
import contextlib
import io
import socket
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.discovery.connect import AsyncConnectScanner  # noqa: E402
from crimsonweb.discovery.syn import estimate_os_from_ttl  # noqa: E402
from crimsonweb.discovery.udp import UDP_SYSLOG_PORT, UdpScanner, build_ikev2_sa_init_probe  # noqa: E402
from crimsonweb.formatting import format_banner_bytes  # noqa: E402
from crimsonweb.models import Target  # noqa: E402


class DiscoveryTests(unittest.TestCase):
    def test_format_banner_bytes_printable_and_binary(self):
        self.assertEqual(format_banner_bytes(b"hello\nworld"), "hello world")
        self.assertEqual(format_banner_bytes(b"\x00\x01\x02", max_hex=3), "<Binary Data: 000102>")

    def test_udp_scanner_syslog_port_is_optional(self):
        target = Target(original="localhost", address="127.0.0.1", family=socket.AF_INET)

        self.assertNotIn(UDP_SYSLOG_PORT, UdpScanner(target).ports)
        self.assertIn(UDP_SYSLOG_PORT, UdpScanner(target, include_syslog=True).ports)

    def test_udp_payload_for_static_and_dynamic_probe(self):
        dns_payload = UdpScanner._payload_for_port(53)
        ike_payload = build_ikev2_sa_init_probe()

        self.assertTrue(dns_payload.startswith(b"\x12\x34"))
        self.assertGreaterEqual(len(ike_payload), 28)
        self.assertEqual(int.from_bytes(ike_payload[24:28], "big"), len(ike_payload))

    def test_syn_os_ttl_estimator(self):
        linux_options = [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]
        windows_options = [("MSS", 1460), ("NOP", None), ("WScale", 8), ("NOP", None), ("NOP", None), ("SAckOK", b"")]

        self.assertEqual(estimate_os_from_ttl(64, 29200, linux_options), "Linux-like (high)")
        self.assertEqual(estimate_os_from_ttl(128, 64240, windows_options), "Windows-like (high)")

    def test_async_connect_scanner_finds_local_listener(self):
        async def run_scan() -> list[int]:
            async def handle(reader, writer):
                writer.close()
                await writer.wait_closed()

            server = await asyncio.start_server(handle, "127.0.0.1", 0)
            port = server.sockets[0].getsockname()[1]
            target = Target(original="localhost", address="127.0.0.1", family=socket.AF_INET)
            scanner = AsyncConnectScanner(target, concurrency=10, timeout=1.0)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    return await scanner.scan([port])
            finally:
                server.close()
                await server.wait_closed()

        open_ports = asyncio.run(run_scan())
        self.assertEqual(len(open_ports), 1)
        self.assertIsInstance(open_ports[0], int)


if __name__ == "__main__":
    unittest.main()
