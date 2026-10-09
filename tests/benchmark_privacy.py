"""Opt-in synthetic privacy overhead measurement; no AI or external connections."""

import argparse
import asyncio
import ctypes
import json
import os
import statistics
import time
import tracemalloc
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from ollama_benchmark import ProcessMemory
from workspace_helpers import NOW, seeded

from crimsonweb.api.privacy.models import (
    DiagnosticRequest,
    PrivacyPolicy,
    PrivacyProfileInput,
)
from crimsonweb.api.privacy.service import PrivacyService


def working_set():
    if os.name != "nt":
        return None
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemory),
        wintypes.DWORD,
    ]
    memory = ProcessMemory(size=ctypes.sizeof(ProcessMemory))
    if psapi.GetProcessMemoryInfo(
        kernel.GetCurrentProcess(), ctypes.byref(memory), memory.size
    ):
        return memory.working_set
    return None


async def measure():
    # Warm migration/import caches. Baseline and privacy additions use the same
    # current-head repository; this is not a comparison to pre-5A process RSS.
    warm = seeded()[0]
    warm.close()
    repo, shared, ws, program = seeded()
    memory_before = working_set()
    tracemalloc.start()
    service = None
    try:
        started = time.perf_counter()
        service = PrivacyService(
            repo,
            shared,
            httpx.MockTransport(
                lambda r: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    json={"ip": "203.0.113.7"},
                )
            ),
        )
        profile = service.store.create_profile(
            ws.id,
            PrivacyProfileInput(
                name="performance_lab", approved_egress_identity=["203.0.113.7"]
            ),
            NOW,
        )
        service.store.write_privacy_policy(
            ws.id,
            profile.id,
            PrivacyPolicy(
                verification_urls=["http://lab.test/echo"],
                allowed_tests=["egress", "dns", "ipv6"],
                operator_approved=True,
                valid_until=NOW + timedelta(days=1),
                maximum_observations=20,
                rate_limit_per_minute=60,
            ),
            1,
            NOW,
        )
        await service.startup()
        startup_s = time.perf_counter() - started
        startup_current, startup_peak = tracemalloc.get_traced_memory()
        tracemalloc.reset_peak()
        cases = []
        for kind in ["egress"] * 5 + ["dns", "ipv6"]:
            payload = (
                DiagnosticRequest(kind=kind)
                if kind == "ipv6"
                else DiagnosticRequest(
                    kind=kind,
                    program_policy_id=program.id,
                    verification_url="http://lab.test/echo",
                )
            )
            started = time.perf_counter()
            job = await service.start(ws.id, profile.id, payload)
            task = service.tasks.get((str(ws.id), str(job.id)))
            if task:
                await asyncio.wait_for(asyncio.shield(task), 10)
            result = service.store.get_assessment(ws.id, job.id)
            cases.append(
                {
                    "kind": kind,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                    "status": result.status,
                    "execution_status": result.execution_status,
                    "requests_made": result.requests_made,
                }
            )
        current, peak = tracemalloc.get_traced_memory()
        memory_after = working_set()
        return {
            "measured_at_utc": datetime.now(UTC).isoformat(),
            "method": "same_repository_incremental_tracemalloc_and_windows_working_set",
            "limitations": "7 serial synthetic jobs; tracemalloc adds overhead; MockTransport has no real network latency; process RSS includes allocator/cache effects; no GPU or loaded AI measurement",
            "startup_ms": round(startup_s * 1000, 3),
            "startup_python_current_bytes": startup_current,
            "startup_python_peak_bytes": startup_peak,
            "jobs_python_current_bytes": current,
            "jobs_python_peak_bytes": peak,
            "process_working_set_before_bytes": memory_before,
            "process_working_set_after_bytes": memory_after,
            "process_working_set_delta_bytes": memory_after - memory_before
            if memory_after is not None and memory_before is not None
            else None,
            "egress_median_ms": statistics.median(
                c["elapsed_ms"] for c in cases if c["kind"] == "egress"
            ),
            "ai_calls": 0,
            "maximum_pending_jobs": 8,
            "maximum_active_jobs": 1,
            "response_body_limit_bytes": 4096,
            "cases": cases,
        }
    finally:
        if service:
            await service.shutdown()
        tracemalloc.stop()
        repo.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    arguments = parser.parse_args()
    report = asyncio.run(measure())
    arguments.report.parent.mkdir(parents=True, exist_ok=True)
    arguments.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "startup_ms",
                    "egress_median_ms",
                    "jobs_python_peak_bytes",
                    "process_working_set_delta_bytes",
                )
            }
        )
    )
