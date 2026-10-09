"""Serial, opt-in benchmark runner; unloads memory residency, never deletes models.

Run from the project root with the project virtualenv. All model calls are local,
all assessment evidence is synthetic. Each planned round remains a separate file.
"""

import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

MODELS = ("qwen3.5:9b", "gemma4:26b")
ROOT = Path(__file__).resolve().parents[1]
DESTINATION = (
    ROOT / os.getenv("CRIMSON_COMPARISON_DIRECTORY", "reports/qwen_vs_gemma")
).resolve()
JOURNAL = {"started_at_utc": datetime.now(UTC).isoformat(), "groups": []}
RUN_STARTED = False


def local_request(path, payload=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        "http://127.0.0.1:11434" + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
    )
    with opener.open(request, timeout=300 if payload is not None else 5) as response:
        return json.load(response)


def residents():
    return [item["name"] for item in local_request("/api/ps").get("models", [])]


def unload():
    before = residents()
    for model in before:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", model):
            raise RuntimeError("invalid_resident_model")
        local_request("/api/generate", {"model": model, "keep_alive": 0})
    if residents():
        raise RuntimeError("unload_not_complete")
    return before


def write(name, value):
    DESTINATION.mkdir(parents=True, exist_ok=True)
    (DESTINATION / name).write_text(
        json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def inventory():
    from ollama_benchmark import gpu_sample, windows_memory

    tags = local_request("/api/tags").get("models", [])
    result = {
        "ollama_version": local_request("/api/version").get("version"),
        "models": [],
        "initial_memory": windows_memory(),
        "initial_gpu": gpu_sample(),
    }
    for model in MODELS:
        matches = [m for m in tags if m.get("name") == model]
        if len(matches) != 1:
            raise RuntimeError("model_missing_or_ambiguous")
        tag = matches[0]
        show = local_request("/api/show", {"model": model})
        if False not in show.get("thinking", {}).get("values", []):
            raise RuntimeError("thinking_false_not_supported")
        result["models"].append(
            {
                "name": model,
                "digest": tag.get("digest"),
                "file_size_bytes": tag.get("size"),
                "details": show.get("details"),
                "capabilities": show.get("capabilities"),
                "thinking": show.get("thinking"),
                # Fixed model defaults, never template/prompt/system contents.
                "sampling_defaults": [
                    line
                    for line in show.get("parameters", "").splitlines()
                    if line.split()
                    and line.split()[0]
                    in {
                        "temperature",
                        "top_k",
                        "top_p",
                        "min_p",
                        "presence_penalty",
                        "repeat_penalty",
                    }
                ],
            }
        )
    return result


def main():
    global RUN_STARTED
    if Path.cwd().resolve() != ROOT:
        raise RuntimeError("run_from_project_root")
    if (
        not DESTINATION.is_relative_to(ROOT / "reports")
        or DESTINATION == ROOT / "reports"
    ):
        raise RuntimeError("report_directory_must_be_under_workspace_reports")
    if (DESTINATION / "run.json").exists():
        raise RuntimeError("report_already_exists_no_overwrite")
    RUN_STARTED = True
    write("environment.json", inventory())
    write("run.json", JOURNAL)
    failed = False
    for round_number in (1, 2, 3):
        order = MODELS if round_number != 2 else tuple(reversed(MODELS))
        for model in order:
            group = {"round": round_number, "model": model, "status": "preparing"}
            JOURNAL["groups"].append(group)
            write("run.json", JOURNAL)
            group["resident_before_unload"] = unload()
            label = "qwen" if model == MODELS[0] else "gemma"
            relative_report = (
                (DESTINATION / f"{label}_round{round_number}.json")
                .relative_to(ROOT)
                .as_posix()
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONPATH": "tests;src",
                    "CRIMSON_TEST_OLLAMA": "1",
                    "CRIMSON_AI_ENABLED": "true",
                    "CRIMSON_OLLAMA_URL": "http://127.0.0.1:11434",
                    "CRIMSON_OLLAMA_MODEL": model,
                    "CRIMSON_OLLAMA_THINK": "false",
                    "CRIMSON_AI_CONTEXT_TOKENS": "8192",
                    "CRIMSON_AI_MAX_OUTPUT_TOKENS": "4096",
                    "CRIMSON_AI_TIMEOUT": "300",
                    "CRIMSON_AI_MAX_CONCURRENCY": "1",
                    "CRIMSON_BENCHMARK_DATASET": "paired-models-v1",
                    "CRIMSON_BENCHMARK_ROUND": str(round_number),
                    "CRIMSON_BENCHMARK_REPORT": relative_report,
                }
            )
            group.update(status="running", report=relative_report)
            write("run.json", JOURNAL)
            print(
                f"Round {round_number}: {model}; cold start, four serial analysis cases",
                flush=True,
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-p",
                    "ollama_benchmark",
                    "tests/test_phase3_ollama_integration.py",
                    "tests/test_model_comparison_ollama.py",
                    "-q",
                    "--tb=short",
                ],
                cwd=ROOT,
                env=environment,
                check=False,
            )
            group.update(
                exit_code=result.returncode,
                status="passed" if result.returncode == 0 else "failed",
                resident_after=residents(),
            )
            if any(name != model for name in group["resident_after"]):
                group["status"] = "invalid_model_overlap"
                write("run.json", JOURNAL)
                raise RuntimeError("unexpected_model_residency")
            failed = failed or result.returncode != 0
            write("run.json", JOURNAL)
    JOURNAL["finished_at_utc"] = datetime.now(UTC).isoformat()
    JOURNAL["status"] = "failed_cases_present" if failed else "passed"
    JOURNAL["resident_before_final_unload"] = unload()
    write("run.json", JOURNAL)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, ValueError) as error:
        # No raw response, prompt, URL body, credential or traceback output.
        JOURNAL["status"] = "runner_failed"
        JOURNAL["error_type"] = type(error).__name__
        if RUN_STARTED:
            write("run.json", JOURNAL)
        print("Benchmark runner stopped; existing results preserved", flush=True)
        sys.exit(2)
