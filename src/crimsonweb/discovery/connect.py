"""Async TCP connect port discovery."""

from __future__ import annotations

import asyncio
import sys
import time

from ..models import Target
from ..scheduling import bounded_results

try:
    from colorama import Fore
except ImportError:
    class _NoColor:
        CYAN = GREEN = ""
    Fore = _NoColor()  # type: ignore[assignment]


DEFAULT_CONNECT_TIMEOUT = 1.5
DEFAULT_PORT_CONCURRENCY = 500


def _print_stage(title: str, detail: str = "") -> None:
    from ..ui import print_stage
    print_stage(title, detail)


def _render_progress(prefix: str, done: int, total: int, width: int = 28) -> str:
    total = max(total, 1)
    ratio = min(max(done / total, 0.0), 1.0)
    filled = int(width * ratio)
    bar = "#" * filled + "-" * (width - filled)
    percent = int(ratio * 100)
    return f"{prefix} [{bar}] {percent:>3}% ({done}/{total})"


class AsyncConnectScanner:
    def __init__(self, target: Target, concurrency: int, timeout: float) -> None:
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout

    async def _scan_one(self, port: int, semaphore: asyncio.Semaphore) -> int | None:
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target.address, port),
                    timeout=self.timeout,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return port
            except (OSError, asyncio.TimeoutError):
                return None

    async def scan(self, ports: list[int]) -> list[int]:
        semaphore = asyncio.Semaphore(self.concurrency)
        open_ports: list[int] = []
        started = time.monotonic()
        _print_stage(
            "Port Scan",
            f"Mode: async-connect | Timeout: {self.timeout:.2f}s | Concurrency: {self.concurrency}",
        )
        idx = 0
        async for result in bounded_results(
            ports, lambda port: self._scan_one(port, semaphore), self.concurrency,
        ):
            idx += 1
            if result is not None:
                open_ports.append(result)
            if idx % 200 == 0 or idx == len(ports):
                from ..ui import write_progress
                write_progress("Scanning ports", idx, len(ports))
        elapsed = time.monotonic() - started
        from ..ui import print_success
        print_success(f"Open ports found: {len(open_ports)} in {elapsed:.1f}s")
        return sorted(open_ports)
