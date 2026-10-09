"""Aggregate preserved local benchmark records; no inference or network access."""

import json
import os
from collections import defaultdict
from pathlib import Path
from statistics import median

PROJECT = Path(__file__).resolve().parents[1]
ROOT = (
    PROJECT / os.getenv("CRIMSON_COMPARISON_DIRECTORY", "reports/qwen_vs_gemma")
).resolve()


def stats(values):
    values = [v for v in values if v is not None]
    return (
        {"median": median(values), "min": min(values), "max": max(values)}
        if values
        else None
    )


def summarize():
    if not ROOT.is_relative_to(PROJECT / "reports") or ROOT == PROJECT / "reports":
        raise ValueError("Report directory must be under workspace reports")
    journal = json.loads((ROOT / "run.json").read_text(encoding="utf-8"))
    if journal.get("status") not in {"passed", "failed_cases_present"}:
        raise ValueError("Benchmark is not complete")
    cases = defaultdict(list)
    signatures = defaultdict(set)
    for group in journal["groups"]:
        report = PROJECT / group["report"]
        data = json.loads(report.read_text(encoding="utf-8"))
        for case in data["cases"]:
            cases[group["model"], case["scenario"]].append(case)
            signatures[case["scenario"]].add(
                tuple(
                    case.get(k)
                    for k in ("input_digest", "schema_digest", "system_digest")
                )
            )
    result = {
        "same_inputs_schema_system": all(len(v) == 1 for v in signatures.values()),
        "case_count": sum(map(len, cases.values())),
        "scenarios": [],
        "models": [],
    }
    for (model, scenario), rows in sorted(cases.items()):
        loaded = [
            s for r in rows for s in r.get("samples", []) if s.get("model_digest")
        ]
        result["scenarios"].append(
            {
                "model": model,
                "scenario": scenario,
                "runs": len(rows),
                "passed": sum(r["status"] == "passed" for r in rows),
                "errors": [
                    r.get("error_code") for r in rows if r["status"] != "passed"
                ],
                "wall_s": stats([r.get("wall_s") for r in rows]),
                "load_s": stats(
                    [
                        r["load_duration"] / 1e9 if "load_duration" in r else None
                        for r in rows
                    ]
                ),
                "prompt_s": stats(
                    [
                        r["prompt_eval_duration"] / 1e9
                        if "prompt_eval_duration" in r
                        else None
                        for r in rows
                    ]
                ),
                "generation_s": stats(
                    [
                        r["eval_duration"] / 1e9 if "eval_duration" in r else None
                        for r in rows
                    ]
                ),
                "tokens_per_s": stats(
                    [
                        r["eval_count"] / (r["eval_duration"] / 1e9)
                        for r in rows
                        if r.get("eval_duration")
                    ]
                ),
                "output_tokens": [r.get("eval_count") for r in rows],
                "unique_validated_outputs": len(
                    {
                        r["validated_output_digest"]
                        for r in rows
                        if "validated_output_digest" in r
                    }
                ),
                "loaded_sample_peaks": {
                    key: max(
                        (s[key] for s in loaded if s.get(key) is not None), default=None
                    )
                    for key in (
                        "gpu_used_mib",
                        "system_used_bytes",
                        "ollama_working_set_bytes",
                        "ollama_private_commit_bytes",
                    )
                },
            }
        )
    for model in sorted({key[0] for key in cases}):
        rows = [r for (m, _), values in cases.items() if m == model for r in values]
        samples = [s for r in rows for s in r.get("samples", [])]
        loaded = [s for s in samples if s.get("model_digest")]
        result["models"].append(
            {
                "model": model,
                "passed": sum(r["status"] == "passed" for r in rows),
                "total": len(rows),
                "reference_exact_passed": sum(
                    r.get("reference_checks", {}).get("primary_exact_match") is True
                    for r in rows
                ),
                "thinking_chars": [r.get("thinking_chars") for r in rows],
                "length_stops": sum(r.get("length_stop") is True for r in rows),
                "settings": [r["settings"] for r in rows],
                "sampled_overlap": any(s.get("other_model_resident") for s in samples),
                "ps_unavailable_samples": sum(
                    s.get("ps_available") is False for s in samples
                ),
                "loaded_sample_count": len(loaded),
                "unreadable_process_peak": max(
                    (s.get("unreadable_process_count", 0) for s in samples), default=0
                ),
                "loaded_sample_stats": {
                    key: stats([s.get(key) for s in loaded])
                    for key in (
                        "gpu_used_mib",
                        "gpu_util_percent",
                        "gpu_power_w",
                        "gpu_temperature_c",
                        "system_used_bytes",
                        "system_available_bytes",
                        "ollama_working_set_bytes",
                        "ollama_private_commit_bytes",
                        "ps_size",
                        "ps_size_vram",
                        "ps_context_length",
                    )
                },
                "all_sample_peaks": {
                    key: max(
                        (s[key] for s in samples if s.get(key) is not None),
                        default=None,
                    )
                    for key in (
                        "gpu_used_mib",
                        "system_used_bytes",
                        "ollama_working_set_bytes",
                        "ollama_private_commit_bytes",
                    )
                },
                "cold_baselines": [
                    r["samples"][0] for r in rows if r["scenario"] == "findings"
                ],
            }
        )
    (ROOT / "summary.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in result.items() if k != "models"}, indent=2))


if __name__ == "__main__":
    summarize()
