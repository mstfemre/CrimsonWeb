"""Scapy-backed TCP SYN port discovery."""

from __future__ import annotations

import logging
import random
import socket
import sys
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
SYN_MAX_BATCH_SIZE = 1024


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
        from scapy.all import IP, IPv6, TCP, conf, sr, sr1
    except ImportError as exc:
        raise RuntimeError("Scapy required for --syn. Install: pip install scapy") from exc
    return IP, IPv6, TCP, conf, sr, sr1


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
    def __init__(self, target: Target, timeout: float, retry: int, batch_size: int) -> None:
        self.IP, self.IPv6, self.TCP, self.conf, self.sr, self.sr1 = load_scapy()
        self.target = target
        self.timeout = timeout
        self.retry = retry
        self.batch_size = max(1, min(int(batch_size), SYN_MAX_BATCH_SIZE))
        self.os_hints: dict[int, str] = {}

    def _layer(self):
        return (
            self.IPv6(dst=self.target.address)
            if self.target.family == socket.AF_INET6
            else self.IP(dst=self.target.address)
        )

    def _scan_batch(self, ports: list[int]) -> list[int]:
        open_ports: list[int] = []
        pending = list(ports)
        ip_layer = self._layer()
        for _attempt in range(self.retry + 1):
            if not pending:
                break
            try:
                sport = random.randint(1024, 65535)
                packets = ip_layer / self.TCP(sport=sport, dport=pending, flags="S")
                answered, unanswered = self.sr(packets, timeout=self.timeout, verbose=0)
                for _sent, received in answered:
                    if not received.haslayer(self.TCP):
                        continue
                    tcp = received.getlayer(self.TCP)
                    if int(tcp.flags) != TCP_SYN_ACK_FLAGS:
                        continue
                    port = int(tcp.sport)
                    open_ports.append(port)
                    ttl = 0
                    if received.haslayer(self.IP):
                        ttl = int(received[self.IP].ttl)
                    elif received.haslayer(self.IPv6):
                        ttl = int(received[self.IPv6].hlim)
                    self.os_hints[port] = estimate_os_from_ttl(
                        ttl, int(tcp.window), list(tcp.options)
                    )
                    rst = ip_layer / self.TCP(
                        sport=sport,
                        dport=port,
                        flags="R",
                        seq=int(tcp.ack),
                        ack=int(tcp.seq) + 1,
                    )
                    self.sr1(rst, timeout=0.2, verbose=0)
                pending = [int(pkt.dport) for pkt in unanswered if pkt.haslayer(self.TCP)]
            except Exception as exc:
                logging.warning("SYN batch error on %s: %s", self.target.address, exc)
                break
        return open_ports

    def scan(self, ports: list[int]) -> list[int]:
        try:
            self.conf.verb = 0
            self.conf.use_pcap = True
        except Exception:
            pass
        started = time.monotonic()
        open_ports: set[int] = set()
        batches = [ports[i : i + self.batch_size] for i in range(0, len(ports), self.batch_size)]
        _print_stage(
            "Port Scan",
            f"Mode: syn | Timeout: {self.timeout:.2f}s | "
            f"Retry: {self.retry} | Batch size: {self.batch_size}",
        )
        for idx, batch in enumerate(batches, start=1):
            open_ports.update(self._scan_batch(batch))
            sys.stdout.write(Fore.CYAN + "\r" + _render_progress("Scanning batches", idx, len(batches)))
            sys.stdout.flush()
        elapsed = time.monotonic() - started
        print(Fore.GREEN + f"\nOpen ports found: {len(open_ports)} in {elapsed:.1f}s")
        return sorted(open_ports)
