"""Opt-in pytest observer for real local Ollama tests; never records raw input/output.

Load with -p ollama_benchmark and set CRIMSON_BENCHMARK_REPORT. Native Windows
memory counters, nvidia-smi and /api/ps are sampled without changing requests.
Only validated, masked synthetic-lab excerpts are retained for language review.
"""

import ctypes
import json
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.request
from ctypes import wintypes
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

REPORT = {"started_at_utc": datetime.now(UTC).isoformat(), "cases": []}


class MemoryStatus(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("load", wintypes.DWORD)] + [
        (name, ctypes.c_ulonglong)
        for name in (
            "total",
            "available",
            "page_total",
            "page_available",
            "virtual_total",
            "virtual_available",
            "extended_available",
        )
    ]


class ProcessEntry(ctypes.Structure):
    _fields_ = [
        ("size", wintypes.DWORD),
        ("usage", wintypes.DWORD),
        ("pid", wintypes.DWORD),
        ("heap", ctypes.c_size_t),
        ("module", wintypes.DWORD),
        ("threads", wintypes.DWORD),
        ("parent", wintypes.DWORD),
        ("priority", wintypes.LONG),
        ("flags", wintypes.DWORD),
        ("name", wintypes.WCHAR * 260),
    ]


class ProcessMemory(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
        (name, ctypes.c_size_t)
        for name in (
            "peak_ws",
            "working_set",
            "peak_paged",
            "paged",
            "peak_nonpaged",
            "nonpaged",
            "pagefile",
            "peak_pagefile",
            "private",
        )
    ]


def windows_memory():
    if os.name != "nt":
        return {"memory_available": False}
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    status = MemoryStatus(length=ctypes.sizeof(MemoryStatus))
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(status)):
        return {"memory_available": False}
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ProcessMemory),
        wintypes.DWORD,
    ]
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    working_set, private, count, unavailable = 0, 0, 0, 0
    try:
        entry = ProcessEntry(size=ctypes.sizeof(ProcessEntry))
        present = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while present:
            if entry.name.casefold().startswith(("ollama", "llama")):
                handle = kernel.OpenProcess(0x1000, False, entry.pid)
                if handle:
                    try:
                        memory = ProcessMemory(size=ctypes.sizeof(ProcessMemory))
                        if psapi.GetProcessMemoryInfo(
                            handle, ctypes.byref(memory), memory.size
                        ):
                            working_set += memory.working_set
                            private += memory.private
                            count += 1
                        else:
                            unavailable += 1
                    finally:
                        kernel.CloseHandle(handle)
                else:
                    unavailable += 1
            present = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return {
        "system_total_bytes": status.total,
        "system_used_bytes": status.total - status.available,
        "system_available_bytes": status.available,
        "ollama_working_set_bytes": working_set if count else None,
        "ollama_private_commit_bytes": private if count else None,
        "ollama_process_count": count,
        "unreadable_process_count": unavailable,
    }


def local_get(path):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://127.0.0.1:11434" + path, timeout=2) as response:
        return json.load(response)


def gpu_sample():
    binary = shutil.which("nvidia-smi")
    if not binary:
        return {"gpu_available": False}
    try:
        result = subprocess.run(
            [
                binary,
                "--query-gpu=name,memory.total,memory.used,utilization.gpu,power.draw,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=True,
        )
        values = result.stdout.splitlines()[0].split(",")
        names = (
            "gpu_total_mib",
            "gpu_used_mib",
            "gpu_util_percent",
            "gpu_power_w",
            "gpu_temperature_c",
        )
        metrics = {}
        for key, value in zip(names, values[1:], strict=True):
            try:
                metrics[key] = float(value.strip())
            except ValueError:
                metrics[key] = None
        return metrics
    except (OSError, subprocess.SubprocessError, IndexError, ValueError):
        return {"gpu_available": False}


class Sampler:
    interval = 2

    def __init__(self, model):
        self.model = model
        self.samples = []
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def sample(self):
        row = {
            "elapsed_s": round(time.perf_counter() - self.started, 3),
            **windows_memory(),
            **gpu_sample(),
        }
        try:
            residents = local_get("/api/ps").get("models", [])
            row["resident_model_count"] = len(residents)
            row["other_model_resident"] = any(
                m.get("name") != self.model for m in residents
            )
            models = [m for m in residents if m.get("name") == self.model]
            if models:
                selected = models[0]
                for key in ("size", "size_vram", "context_length"):
                    if isinstance(selected.get(key), int):
                        row["ps_" + key] = selected[key]
                digest = selected.get("digest", "")
                if re.fullmatch(r"[0-9a-f]{64}", digest):
                    row["model_digest"] = digest
        except (OSError, ValueError):
            row["ps_available"] = False
        self.samples.append(row)

    def loop(self):
        while not self.stop_event.wait(self.interval):
            self.sample()

    def start(self):
        self.started = time.perf_counter()
        self.sample()
        self.thread.start()

    def finish(self):
        self.stop_event.set()
        self.thread.join(timeout=8)
        self.sample()
        return self.samples


def flush():
    path = Path(os.environ["CRIMSON_BENCHMARK_REPORT"]).resolve()
    if not path.is_relative_to(Path.cwd().resolve()):
        raise ValueError("Benchmark report must be in the workspace")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(REPORT, ensure_ascii=False, indent=2), encoding="utf-8")


@pytest.fixture(autouse=True)
def observe_ollama(request, monkeypatch):
    if not os.getenv("CRIMSON_BENCHMARK_REPORT") or not request.node.get_closest_marker(
        "ollama"
    ):
        yield
        return
    module = request.module
    original = module.OllamaProvider
    validate = module.validate_provider_output
    case = {"scenario": request.node.callspec.params["kind"], "status": "running"}
    if os.getenv("CRIMSON_BENCHMARK_DATASET") == "paired-models-v1":
        from model_comparison_data import DATASET_VERSION, standard_repository

        case["dataset_version"] = DATASET_VERSION
        case["round"] = int(os.environ["CRIMSON_BENCHMARK_ROUND"])
        if hasattr(module, "seeded_repository"):
            monkeypatch.setattr(module, "seeded_repository", standard_repository)
    request.node.benchmark_case = case
    REPORT["cases"].append(case)

    class ObservedProvider(original):
        async def _request(self, method, path, payload=None):
            result = await super()._request(method, path, payload)
            if path == "/api/chat":
                message = result.get("message", {})
                thinking = message.get("thinking", "")
                content = message.get("content", "")
                case["thinking_chars"] = (
                    len(thinking) if isinstance(thinking, str) else None
                )
                case["content_chars"] = (
                    len(content) if isinstance(content, str) else None
                )
                case["thinking_separate"] = bool(thinking)
                for key in (
                    "total_duration",
                    "load_duration",
                    "prompt_eval_count",
                    "prompt_eval_duration",
                    "eval_count",
                    "eval_duration",
                ):
                    if isinstance(result.get(key), int):
                        case[key] = result[key]
                case["completed"] = result.get("done") is True
                case["length_stop"] = result.get("done_reason") == "length"
            return result

        async def generate(self, system, evidence, schema):
            case["settings"] = {
                "model": self.model,
                "context_tokens": self.settings.context_tokens,
                "max_output_tokens": self.settings.max_output_tokens,
                "timeout_seconds": self.settings.timeout_seconds,
                "max_concurrency": self.settings.max_concurrency,
            }
            case["system_digest"] = sha256(system.encode()).hexdigest()
            case["schema_digest"] = sha256(
                json.dumps(schema, sort_keys=True, ensure_ascii=False).encode()
            ).hexdigest()
            case["input_digest"] = sha256(
                json.dumps(
                    evidence, sort_keys=True, ensure_ascii=False, separators=(",", ":")
                ).encode()
            ).hexdigest()
            if hasattr(self.settings, "thinking"):
                case["settings"]["thinking"] = self.settings.thinking
            sampler = Sampler(self.model)
            sampler.start()
            started = time.perf_counter()
            try:
                return await super().generate(system, evidence, schema)
            except module.AIError as exc:
                case["error_code"] = exc.code
                case["safe_diagnostics"] = exc.diagnostics
                raise
            finally:
                case["wall_s"] = round(time.perf_counter() - started, 3)
                case["samples"] = sampler.finish()
                flush()

    def observed_validation(content, bundle, language):
        try:
            output = validate(content, bundle, language)
        except module.AIError as exc:
            case["error_code"] = exc.code
            case["safe_diagnostics"] = exc.diagnostics
            raise
        case["language_signals"] = module.language_signals(output)
        case["input_digest"] = bundle.digest
        case["validated_output_digest"] = sha256(
            output.model_dump_json().encode()
        ).hexdigest()
        case["reference_checks"] = {
            "expected_findings": sum(r.startswith("finding:") for r in bundle.refs),
            "actual_findings": len(output.technical_findings),
            "expected_waf": sum(r.startswith("waf:") for r in bundle.refs),
            "actual_waf": len(output.waf_assessment),
            "validation_passed": True,
            "primary_exact_match": (
                [c.evidence_ref for c in output.technical_findings]
                == sorted(r for r in bundle.refs if r.startswith("finding:"))
                and [c.evidence_ref for c in output.waf_assessment]
                == sorted(r for r in bundle.refs if r.startswith("waf:"))
            ),
        }
        # These are already validated/masked opinions from synthetic fixtures.
        # No reasoning trace, raw answer, prompt, credentials or evidence dump.
        case["validated_review"] = {
            "summary": output.executive_summary,
            "tls": output.tls_analysis.explanation,
            "tls_uncertainty": output.tls_analysis.uncertainty,
            "risk": output.risk_assessment.explanation,
            "risk_uncertainty": output.risk_assessment.uncertainty,
            "limitations": output.limitations,
            "priority_actions": [p.action for p in output.priority_improvements],
            "comments": [
                {
                    "evidence_ref": c.evidence_ref,
                    "explanation": c.explanation,
                    "uncertainty": c.uncertainty,
                    "confidence": c.confidence,
                    "false_positive": c.false_positive,
                    "impact": c.impact,
                    "remediations": c.remediations,
                }
                for c in [*output.technical_findings, *output.waf_assessment]
            ],
        }
        return output

    monkeypatch.setattr(module, "OllamaProvider", ObservedProvider)
    monkeypatch.setattr(module, "validate_provider_output", observed_validation)
    yield


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    result = yield
    report = result.get_result()
    if report.when == "call" and hasattr(item, "benchmark_case"):
        case = item.benchmark_case
        case["status"] = report.outcome
        if report.failed:
            # Extract a fixed code only; never retain exception/traceback text.
            from crimsonweb.api.ai.provider import AIError

            text = str(call.excinfo.value) if call.excinfo else ""
            token = text.split(";", 1)[0].strip()
            case["error_code"] = AIError(token).code
        flush()
