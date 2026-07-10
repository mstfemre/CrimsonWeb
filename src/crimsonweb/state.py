"""Checkpoint and resume state handling."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


DEFAULT_STATE_DIR = "~/.crimsonweb/state"


def target_hash(target: str) -> str:
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]


def default_state_path(target: str) -> Path:
    base = Path(os.path.expanduser(DEFAULT_STATE_DIR))
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{target_hash(target)}.json"


@dataclass(slots=True)
class ScanState:
    target: str
    target_hash: str
    started_at: float
    last_updated_at: float
    completed_ports: set[int] = field(default_factory=set)
    completed_paths: set[str] = field(default_factory=set)
    discovered_decoy_paths: set[str] = field(default_factory=set)
    egress_cooldowns: dict[str, float] = field(default_factory=dict)
    roe_ref: str | None = None
    version: int = 1

    @classmethod
    def new(cls, target: str, roe_ref: str | None = None) -> "ScanState":
        now = time.time()
        return cls(
            target=target,
            target_hash=target_hash(target),
            started_at=now,
            last_updated_at=now,
            roe_ref=roe_ref,
        )

    def mark_port_done(self, port: int) -> None:
        self.completed_ports.add(port)
        self.last_updated_at = time.time()

    def mark_path_done(self, path: str) -> None:
        self.completed_paths.add(path)
        self.last_updated_at = time.time()

    def add_decoy_paths(self, paths: list[str]) -> None:
        for path in paths:
            self.discovered_decoy_paths.add(path)
        self.last_updated_at = time.time()


def save_state(state: ScanState, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = asdict(state)
    payload["completed_ports"] = sorted(state.completed_ports)
    payload["completed_paths"] = sorted(state.completed_paths)
    payload["discovered_decoy_paths"] = sorted(state.discovered_decoy_paths)
    data = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".crimson_state_", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_name, path)
    except OSError as exc:
        logging.warning("save_state failed: %s", exc)
        try:
            os.unlink(tmp_name)
        except OSError:
            pass


def load_state(path: Path) -> ScanState | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logging.warning("load_state failed: %s", exc)
        return None
    return ScanState(
        target=payload.get("target", ""),
        target_hash=payload.get("target_hash", ""),
        started_at=payload.get("started_at", time.time()),
        last_updated_at=payload.get("last_updated_at", time.time()),
        completed_ports={int(port) for port in payload.get("completed_ports", [])},
        completed_paths=set(payload.get("completed_paths", [])),
        discovered_decoy_paths=set(payload.get("discovered_decoy_paths", [])),
        egress_cooldowns=dict(payload.get("egress_cooldowns", {})),
        roe_ref=payload.get("roe_ref"),
        version=int(payload.get("version", 1)),
    )
