"""Scapy-backed TCP SYN port discovery."""

from __future__ import annotations

import random
import socket
import sys
import threading
import time
from importlib.util import find_spec

from ..models import Target

try:
    from colorama import Fore
except ImportError:
    class _NoColor:
        CYAN = GREEN = ""
    Fore = _NoColor()  # type: ignore[assignment]


TCP_SYN_ACK_FLAGS = 0x12
TCP_RST_FLAG = 0x04
SYN_MAX_BATCH_SIZE = 1024
SNIFFER_STARTUP_DELAY = 0.1


def _print_stage(title: str, detail: str = "") -> None:
    line = "=" * 78
    print(Fore.CYAN + line)
    print(f"[ {title} ]")
    if detail:
        print(detail)
    print(Fore.CYAN + line)


def _render_progress(prefix: str, done: int, total: int, width: int = 28) -> str:
    total = max(total, 1)
    ratio = min(max(done / total, 0.0), 1.0)
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    percent = int(ratio * 100)
    return f"{prefix} [{bar}] {percent:>3}% ({done}/{total})"


def load_scapy():
    try:
        from scapy.all import IP, IPv6, TCP, conf, AsyncSniffer
    except ImportError as exc:
        raise RuntimeError("Scapy required for --syn. Install: pip install scapy") from exc
    return IP, IPv6, TCP, conf, AsyncSniffer


def scapy_is_available() -> bool:
    return find_spec("scapy") is not None


def estimate_os_from_ttl(ttl: int, window: int, options: list) -> str:
    mss = 0
    wscale = 0
    for opt in options:
        if not isinstance(opt, tuple) or not opt:
            continue
        name = opt[0]
        value = opt[1] if len(opt) > 1 else None
        if name == "MSS" and isinstance(value, int):
            mss = value
        elif name == "WScale" and isinstance(value, int):
            wscale = value
    option_names = [item[0] for item in options if isinstance(item, tuple) and item]
    compact = [n for n in option_names if n != "EOL"]
    linux_order = ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"]
    windows_order = ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"]

    def has_order(expected: list[str]) -> bool:
        cursor = 0
        for name in compact:
            if cursor < len(expected) and name == expected[cursor]:
                cursor += 1
        return cursor == len(expected)

    if ttl <= 64:
        if has_order(linux_order):
            return "Linux-like (high)"
        if window == 65535 and wscale in {4, 5, 6}:
            return "macOS/FreeBSD-like (medium)"
        if mss == 1460 and wscale in {7, 8}:
            return "Linux-like (medium)"
        return "Unix-like (low)"
    if ttl <= 128:
        if has_order(windows_order):
            return "Windows-like (high)"
        if window in {8192, 16384, 64240, 65535}:
            return "Windows-like (medium)"
        return "Windows or embedded device (low)"
    if ttl <= 255:
        if window == 4128:
            return "Cisco IOS-like (medium)"
        return "network device or Unix-like (low)"
    return "unknown"


class SynScanner:
    """Split sender/receiver SYN scanner.

    A dedicated background sniffer (Scapy AsyncSniffer) with an aggressive BPF
    listens for replies while the main thread blasts SYN packets through a
    persistent L3 socket without waiting for individual answers. This decouples
    send from receive, avoiding the per-probe round-trip stalls of sr()/sr1().
    """

    def __init__(self, target: Target, timeout: float, retry: int, batch_size: int) -> None:
        self.IP, self.IPv6, self.TCP, self.conf, self.AsyncSniffer = load_scapy()
        self.target = target
        self.timeout = timeout
        self.retry = retry
        self.batch_size = max(1, min(int(batch_size), SYN_MAX_BATCH_SIZE))
        self.os_hints: dict[int, str] = {}
        self._sport = random.randint(1024, 65535)
        self._lock = threading.Lock()
        self._open_ports: set[int] = set()
        self._closed_ports: set[int] = set()
        self._synack_info: dict[int, tuple[int, int]] = {}

    def _is_ipv6(self) -> bool:
        return self.target.family == socket.AF_INET6

    def _layer(self):
        return (
            self.IPv6(dst=self.target.address)
            if self._is_ipv6()
            else self.IP(dst=self.target.address)
        )

    def _l3_socket(self):
        if self._is_ipv6():
            factory = getattr(self.conf, "L3socket6", None) or self.conf.L3socket
        else:
            factory = self.conf.L3socket
        return factory()

    # -- Receiver ---------------------------------------------------------
    def _handle_packet(self, pkt) -> None:
        """Sniffer-thread callback. BPF pre-filters; here we classify replies."""
        tcp = pkt.getlayer(self.TCP)
        if tcp is None:
            return
        try:
            if int(tcp.dport) != self._sport:
                return  # not a reply to one of our probes
            port = int(tcp.sport)
            flags = int(tcp.flags)
        except (TypeError, ValueError):
            return
        if flags == TCP_SYN_ACK_FLAGS:
            ttl = 0
            if pkt.haslayer(self.IP):
                ttl = int(pkt[self.IP].ttl)
            elif pkt.haslayer(self.IPv6):
                ttl = int(pkt[self.IPv6].hlim)
            with self._lock:
                if port in self._open_ports:
                    return
                self._open_ports.add(port)
                self.os_hints[port] = estimate_os_from_ttl(
                    ttl, int(tcp.window), list(tcp.options)
                )
                self._synack_info[port] = (int(tcp.ack), int(tcp.seq))
        elif flags & TCP_RST_FLAG:
            with self._lock:
                self._closed_ports.add(port)

    # -- Sender -----------------------------------------------------------
    def _send_syns(self, l3, ports: list[int]) -> None:
        sport = self._sport
        for index, port in enumerate(ports, start=1):
            l3.send(self._layer() / self.TCP(sport=sport, dport=port, flags="S"))
            if index % self.batch_size == 0:
                time.sleep(0.001)  # brief yield to relieve the local send buffer

    def _send_teardown_rsts(self, l3) -> None:
        with self._lock:
            info = dict(self._synack_info)
        sport = self._sport
        for port, (ack, seq) in info.items():
            try:
                l3.send(
                    self._layer()
                    / self.TCP(sport=sport, dport=port, flags="R", seq=ack, ack=seq + 1)
                )
            except OSError:
                continue

    # -- Orchestration ----------------------------------------------------
    def scan(self, ports: list[int]) -> list[int]:
        try:
            self.conf.verb = 0
            try:
                self.conf.use_pcap = True
            except Exception:
                pass
            return self._run_scan(ports)
        except PermissionError as exc:
            raise SystemExit(
                "SYN scan requires elevated privileges (root / CAP_NET_RAW on Linux, "
                f"Administrator + Npcap on Windows). Raw socket access denied: {exc}"
            ) from exc

    def _run_scan(self, ports: list[int]) -> list[int]:
        started = time.monotonic()
        bpf = f"tcp and src host {self.target.address}"
        _print_stage(
            "Port Scan",
            f"Mode: syn (split sender/receiver + BPF) | Timeout: {self.timeout:.2f}s | "
            f"Retry: {self.retry} | Batch size: {self.batch_size}",
        )
        try:
            sniffer = self.AsyncSniffer(filter=bpf, prn=self._handle_packet, store=False)
            sniffer.start()
        except PermissionError:
            raise
        except Exception as exc:
            raise SystemExit(
                f"Failed to start SYN receiver (privileges/interface/Npcap): {exc}"
            ) from exc
        l3 = None
        try:
            time.sleep(SNIFFER_STARTUP_DELAY)  # let the sniffer bind before blasting
            l3 = self._l3_socket()
            for attempt in range(self.retry + 1):
                with self._lock:
                    pending = [
                        port for port in ports
                        if port not in self._open_ports and port not in self._closed_ports
                    ]
                if not pending:
                    break
                self._send_syns(l3, pending)
                sys.stdout.write(
                    Fore.CYAN + "\r" + _render_progress("Blasting SYN", attempt + 1, self.retry + 1)
                )
                sys.stdout.flush()
                if attempt < self.retry:
                    time.sleep(min(self.timeout, 0.5))  # settle before retransmitting
            # Strict trailing window for late replies, then shut the receiver down.
            time.sleep(max(0.0, self.timeout))
        finally:
            try:
                sniffer.stop()
            except Exception:
                pass
            if l3 is not None:
                try:
                    self._send_teardown_rsts(l3)  # best-effort half-open cleanup
                except Exception:
                    pass
                try:
                    l3.close()
                except Exception:
                    pass
        with self._lock:
            open_ports = sorted(self._open_ports)
        elapsed = time.monotonic() - started
        print(Fore.GREEN + f"\nOpen ports found: {len(open_ports)} in {elapsed:.1f}s")
        return open_ports
