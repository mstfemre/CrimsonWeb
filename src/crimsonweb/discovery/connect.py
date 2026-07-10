"""Async TCP connect port discovery."""

from __future__ import annotations

import asyncio
import sys
import time

from ..models import Target

try:
    from colorama import Fore
except ImportError:
    class _NoColor:
        CYAN = GREEN = ""
    Fore = _NoColor()  # type: ignore[assignment]


DEFAULT_CONNECT_TIMEOUT = 1.5
DEFAULT_PORT_CONCURRENCY = 500


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
        tasks = [self._scan_one(port, semaphore) for port in ports]
        open_ports: list[int] = []
        started = time.monotonic()
        _print_stage(
            "Port Scan",
            f"Mode: async-connect | Timeout: {self.timeout:.2f}s | Concurrency: {self.concurrency}",
        )
        for idx, task in enumerate(asyncio.as_completed(tasks), start=1):
            result = await task
            if result is not None:
                open_ports.append(result)
            if idx % 200 == 0 or idx == len(tasks):
                sys.stdout.write(Fore.CYAN + "\r" + _render_progress("Scanning ports", idx, len(tasks)))
                sys.stdout.flush()
        elapsed = time.monotonic() - started
        print(Fore.GREEN + f"\nOpen ports found: {len(open_ports)} in {elapsed:.1f}s")
        return sorted(open_ports)
