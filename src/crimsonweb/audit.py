"""Audit logging and sensitive CLI redaction."""

from __future__ import annotations

import json
import logging
import os
import queue
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


LOG_FILE_TEXT = "crimsonweb_audit.log"
LOG_FILE_JSONL = "crimsonweb_audit.jsonl"
LOG_MAX_BYTES = 2_000_000
LOG_BACKUP_COUNT = 5
PRIVATE_LOG_MODE = 0o600
SENSITIVE_CLI_OPTIONS = {
    "--tor-control-password",
    "--nvd-api-key",
    "--web-proxy",
}

_JSONL_LOCK = threading.RLock()
_JSONL_PATH: Path | None = None
_JSONL_QUEUE: queue.Queue[str | None] | None = None
_JSONL_THREAD: threading.Thread | None = None


def _chmod_private(path: Path) -> None:
    try:
        os.chmod(path, PRIVATE_LOG_MODE)
    except OSError:
        pass


def _jsonl_writer(handle, items: queue.Queue[str | None]) -> None:
    try:
        while True:
            line = items.get()
            if line is None:
                break
            handle.write(line)
            handle.flush()
    except OSError as exc:
        logging.warning("audit writer failed: %s", exc)
    finally:
        try:
            handle.flush()
            handle.close()
        except OSError:
            pass


def _close_audit_log_locked() -> None:
    global _JSONL_QUEUE, _JSONL_THREAD
    queue_ref = _JSONL_QUEUE
    thread_ref = _JSONL_THREAD
    _JSONL_QUEUE = None
    _JSONL_THREAD = None
    if queue_ref is not None:
        queue_ref.put(None)
    if thread_ref is not None and thread_ref.is_alive():
        thread_ref.join(timeout=3.0)
        if thread_ref.is_alive():
            logging.warning("audit writer did not stop cleanly before timeout")


def _bind_jsonl_path(jsonl_path: Path) -> None:
    global _JSONL_PATH, _JSONL_QUEUE, _JSONL_THREAD
    with _JSONL_LOCK:
        if (
            _JSONL_PATH == jsonl_path
            and _JSONL_QUEUE is not None
            and _JSONL_THREAD is not None
            and _JSONL_THREAD.is_alive()
        ):
            return
        _close_audit_log_locked()
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(str(jsonl_path), flags, PRIVATE_LOG_MODE)
        handle = os.fdopen(fd, "a", encoding="utf-8", buffering=1)
        _JSONL_QUEUE = queue.Queue()
        _JSONL_THREAD = threading.Thread(
            target=_jsonl_writer,
            args=(handle, _JSONL_QUEUE),
            name="crimsonweb-audit-jsonl",
            daemon=False,
        )
        _JSONL_THREAD.start()
        _JSONL_PATH = jsonl_path
        _chmod_private(jsonl_path)


def close_audit_log() -> None:
    with _JSONL_LOCK:
        _close_audit_log_locked()


def setup_logging(output_dir: Path | str = ".") -> None:
    """Configure text logger and bind JSONL path. Idempotent."""
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    text_path = (out / LOG_FILE_TEXT).resolve()
    jsonl_path = (out / LOG_FILE_JSONL).resolve()
    _bind_jsonl_path(jsonl_path)
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    for handler in logger.handlers:
        if getattr(handler, "baseFilename", None) == str(text_path):
            return
    handler = RotatingFileHandler(
        str(text_path),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s - [%(levelname)s] - %(message)s"))
    logger.addHandler(handler)
    _chmod_private(text_path)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def audit_event(event: str, **fields: Any) -> None:
    """Write a structured JSONL audit event. Never crashes the scan."""
    if _JSONL_PATH is None:
        logging.info("AUDIT %s %s", event, fields)
        return
    record = {"ts": _utc_now_iso(), "event": event, **fields}
    line = json.dumps(record, ensure_ascii=False, default=str) + "\n"
    try:
        with _JSONL_LOCK:
            if _JSONL_QUEUE is None or _JSONL_THREAD is None or not _JSONL_THREAD.is_alive():
                _bind_jsonl_path(_JSONL_PATH)
            if _JSONL_QUEUE is not None:
                _JSONL_QUEUE.put(line)
    except OSError as exc:
        logging.warning("audit_event failed: %s", exc)


def redact_cli_args(argv: list[str]) -> str:
    """Return command-line text with sensitive option values masked."""
    redacted: list[str] = []
    redact_next = False
    for arg in argv:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        matched = False
        for option in SENSITIVE_CLI_OPTIONS:
            if arg == option:
                redacted.append(arg)
                redact_next = True
                matched = True
                break
            if arg.startswith(f"{option}="):
                redacted.append(f"{option}=<redacted>")
                matched = True
                break
        if not matched:
            redacted.append(arg)
    return " ".join(redacted)
