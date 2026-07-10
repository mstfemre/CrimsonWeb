"""Subcommand dispatch helpers for the CrimsonWeb CLI."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import sys
from pathlib import Path
from typing import Iterable


SCAN_COMMANDS = {"scan", "web"}
UTILITY_COMMANDS = {"doctor", "config", "init"}
COMMANDS = SCAN_COMMANDS | UTILITY_COMMANDS
CONFIG_ENV_VAR = "CRIMSONWEB_CONFIG"

DEFAULT_CONFIG_TEXT = """# CrimsonWeb config
# Values here are intentionally conservative. CLI flags override config values.
scan:
  output_dir: .
  top_ports_count: 1000
  port_concurrency: 500
  service_concurrency: 50
  no_cve: false
web:
  request_delay: 3.0
  sensitive_delay: 5.0
  max_global_rate: 20
  tls_verify: true
"""


def default_config_path() -> Path:
    override = os.environ.get(CONFIG_ENV_VAR)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".crimsonweb" / "config.yaml"


def _has_option(argv: list[str], *names: str) -> bool:
    for arg in argv:
        if arg in names:
            return True
        for name in names:
            if arg.startswith(name + "="):
                return True
    return False


def _coerce_web_args(argv: list[str]) -> list[str]:
    rest = list(argv)
    if _has_option(rest, "-u", "--url", "-t", "--target"):
        return rest
    if rest and rest[0].startswith(("http://", "https://")):
        return ["-u", rest[0], *rest[1:]]
    return rest


def normalize_command_argv(argv: Iterable[str] | None) -> tuple[str, list[str]]:
    raw = list(argv or [])
    if not raw:
        return "scan", []
    first = raw[0]
    if first not in COMMANDS:
        return "scan", raw
    command = first
    rest = raw[1:]
    if command == "web":
        rest = _coerce_web_args(rest)
    return command, rest


def _dependency_status(module: str, required: bool = False) -> dict[str, object]:
    available = importlib.util.find_spec(module) is not None
    return {"name": module, "available": available, "required": required}


def _doctor_payload(version: str) -> dict[str, object]:
    dependencies = [
        _dependency_status("aiohttp", required=True),
        _dependency_status("httpx"),
        _dependency_status("asyncio_throttle"),
        _dependency_status("aiohttp_socks"),
        _dependency_status("yaml"),
        _dependency_status("curl_cffi"),
        _dependency_status("scapy"),
        _dependency_status("colorama"),
    ]
    python_ok = sys.version_info >= (3, 11)
    required_ok = python_ok and all(
        item["available"] for item in dependencies if item["required"]
    )
    config_path = default_config_path()
    return {
        "version": version,
        "python": {
            "version": platform.python_version(),
            "executable": sys.executable,
            "ok": python_ok,
        },
        "dependencies": dependencies,
        "config": {
            "path": str(config_path),
            "exists": config_path.exists(),
            "env_override": CONFIG_ENV_VAR in os.environ,
        },
        "ok": required_ok,
    }


def run_doctor(argv: list[str], *, version: str) -> int:
    parser = argparse.ArgumentParser(prog="crimsonweb doctor")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    args = parser.parse_args(argv)
    payload = _doctor_payload(version)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        status = "OK" if payload["ok"] else "ISSUES"
        print(f"CrimsonWeb {version} doctor: {status}")
        python_info = payload["python"]
        print(f"Python: {python_info['version']} ({python_info['executable']})")
        print(f"Config: {payload['config']['path']} exists={payload['config']['exists']}")
        print("Dependencies:")
        for dep in payload["dependencies"]:
            marker = "ok" if dep["available"] else ("missing required" if dep["required"] else "missing optional")
            print(f"  - {dep['name']}: {marker}")
    return 0 if payload["ok"] else 1


def run_config(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="crimsonweb config")
    sub = parser.add_subparsers(dest="action")
    sub.add_parser("path", help="Print config file path")
    sub.add_parser("show", help="Print current config or the default template")
    init_parser = sub.add_parser("init", help="Create a default config file")
    init_parser.add_argument("--force", action="store_true", help="Overwrite an existing non-symlink config file")
    args = parser.parse_args(argv)
    action = args.action or "show"
    path = default_config_path()
    if action == "path":
        print(path)
        return 0
    if action == "show":
        if path.exists() and path.is_file():
            print(path.read_text(encoding="utf-8"), end="")
        else:
            print(DEFAULT_CONFIG_TEXT, end="")
        return 0
    if action == "init":
        if path.exists() and path.is_symlink():
            raise SystemExit(f"Refusing to write config through symlink: {path}")
        if path.exists() and not args.force:
            print(f"Config already exists: {path}")
            return 0
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.parent.chmod(0o700)
        except OSError:
            pass
        path.write_text(DEFAULT_CONFIG_TEXT, encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        print(f"Config written: {path}")
        return 0
    raise SystemExit(f"Unknown config action: {action}")


def run_utility_command(command: str, argv: list[str], *, version: str) -> int:
    if command == "doctor":
        return run_doctor(argv, version=version)
    if command == "config":
        return run_config(argv)
    if command == "init":
        return run_config(["init", *argv])
    raise SystemExit(f"Unknown command: {command}")
