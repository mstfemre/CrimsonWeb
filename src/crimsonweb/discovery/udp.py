"""UDP probe discovery."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable

from ..formatting import format_banner_bytes
from ..models import ServiceResult, Target

try:
    from colorama import Fore
except ImportError:
    class _NoColor:
        CYAN = GREEN = ""
    Fore = _NoColor()  # type: ignore[assignment]


DEFAULT_UDP_TIMEOUT = 2.0
UDP_SYSLOG_PORT = 514
UDP_SCAN_PORTS = (53, 69, 123, 161, 500, 1900, 5353)
UDP_OPTIONAL_PORTS = (UDP_SYSLOG_PORT,)
UDPProbeValue = bytes | Callable[[], bytes]


def _print_stage(title: str, detail: str = "") -> None:
    from ..ui import print_stage
    print_stage(title, detail)


def _ike_transform(last: int, transform_type: int, transform_id: int, attrs: bytes = b"") -> bytes:
    length = 8 + len(attrs)
    return (
        bytes([last, 0])
        + length.to_bytes(2, "big")
        + bytes([transform_type, 0])
        + transform_id.to_bytes(2, "big")
        + attrs
    )


def build_ikev2_sa_init_probe() -> bytes:
    """Build a syntactically valid IKEv2 SA_INIT probe with random SPI/nonce."""
    transforms = b"".join(
        (
            _ike_transform(0, 1, 12, b"\x80\x0e\x01\x00"),
            _ike_transform(0, 2, 5),
            _ike_transform(0, 3, 12),
            _ike_transform(3, 4, 14),
        )
    )
    proposal = (
        b"\x02\x00"
        + (8 + len(transforms)).to_bytes(2, "big")
        + b"\x01\x01\x00\x04"
        + transforms
    )
    sa_payload = b"\x22\x00" + (4 + len(proposal)).to_bytes(2, "big") + proposal
    ke_data = os.urandom(256)
    ke_payload = b"\x28\x00" + (8 + len(ke_data)).to_bytes(2, "big") + b"\x00\x0e\x00\x00" + ke_data
    nonce = os.urandom(32)
    nonce_payload = b"\x00\x00" + (4 + len(nonce)).to_bytes(2, "big") + nonce
    body = sa_payload + ke_payload + nonce_payload
    return (
        os.urandom(8)
        + (b"\x00" * 8)
        + b"\x21\x20\x22\x08"
        + (0).to_bytes(4, "big")
        + (28 + len(body)).to_bytes(4, "big")
        + body
    )


UDP_PROBES: dict[int, UDPProbeValue] = {
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    69: b"\x00\x01crimson-probe\x00octet\x00",
    123: b"\x1b" + (b"\x00" * 47),
    161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x70\x69\x6e\x67\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    500: build_ikev2_sa_init_probe,
    514: b"<14>crimsonweb udp assessment probe\n",
    1900: (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"MAN: \"ssdp:discover\"\r\n"
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    ),
    5353: (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        b"\x00\x0c\x00\x01"
    ),
}
UDP_SERVICE_HINTS = {
    53: "dns",
    69: "tftp",
    123: "ntp",
    161: "snmp",
    500: "ike",
    514: "syslog",
    1900: "ssdp",
    5353: "mdns",
}


class _UdpProbeProtocol(asyncio.DatagramProtocol):
    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.response: asyncio.Future[bytes] = loop.create_future()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, _addr) -> None:
        if not self.response.done():
            self.response.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.response.done():
            self.response.set_exception(exc)


class UdpScanner:
    def __init__(
        self,
        target: Target,
        timeout: float = DEFAULT_UDP_TIMEOUT,
        include_syslog: bool = False,
    ) -> None:
        self.target = target
        self.timeout = timeout
        self.ports = UDP_SCAN_PORTS + (UDP_OPTIONAL_PORTS if include_syslog else ())

    @staticmethod
    def _payload_for_port(port: int) -> bytes:
        payload = UDP_PROBES[port]
        return payload() if callable(payload) else payload

    async def _probe(self, port: int) -> ServiceResult | None:
        loop = asyncio.get_running_loop()
        transport = None
        try:
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: _UdpProbeProtocol(loop),
                remote_addr=(self.target.address, port),
                family=self.target.family,
            )
            transport.sendto(self._payload_for_port(port))
            raw = await asyncio.wait_for(protocol.response, timeout=self.timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            if transport is not None:
                transport.close()
        service = UDP_SERVICE_HINTS.get(port, "udp")
        return ServiceResult(
            port=port,
            service=service,
            version=format_banner_bytes(raw, max_text=80, max_hex=20),
            transport="udp",
            tls=False,
        )

    async def scan(self) -> dict[int, ServiceResult]:
        _print_stage(
            "UDP Scan",
            f"Ports: {', '.join(str(p) for p in self.ports)} | Timeout: {self.timeout:.2f}s",
        )
        results = await asyncio.gather(
            *(self._probe(port) for port in self.ports), return_exceptions=True
        )
        open_udp: dict[int, ServiceResult] = {}
        for item in results:
            if isinstance(item, ServiceResult):
                open_udp[item.port] = item
        from ..ui import print_success
        print_success(f"UDP responders found: {len(open_udp)}")
        return open_udp
