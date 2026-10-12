"""Intentionally vulnerable fixtures contained inside a disposable lab directory."""

import html
import json
import sqlite3
import threading
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse


def write_json(path: Path, value) -> None:
    """Atomic snapshot replacement; callers serialize concurrent updates."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


class GroundTruth:
    """Payloads here are lab input, deliberately separate from product evidence."""

    def __init__(self, path: Path):
        self.path = path
        self.run_id = str(uuid4())
        self.events = []
        self.lock = threading.Lock()
        write_json(path, self.snapshot())

    def snapshot(self):
        return {"schema_version": 1, "run_id": self.run_id, "events": list(self.events)}

    def record(self, request, family, mode, payload, triggered, effect, status):
        with self.lock:
            event = {
                "id": len(self.events) + 1,
                "timestamp": datetime.now(UTC).isoformat(),
                "scheme": request.url.scheme,
                "path": request.url.path,
                "family": family,
                "mode": mode,
                "payload": payload,
                "triggered": triggered,
                "effect": effect,
                "status": status,
                "browser_execution_observed": False,
            }
            self.events.append(event)
            write_json(self.path, self.snapshot())


class ElementDetector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.element = False

    def handle_starttag(self, tag, attrs):
        self.element = True


def create_app(root: Path, truth: GroundTruth) -> FastAPI:
    root = root.resolve()
    public = root / "public"
    public.mkdir(parents=True)
    (public / "hello.txt").write_text("LAB_PUBLIC_FILE", encoding="utf-8")
    (root / "private.txt").write_text("LAB_PRIVATE_FIXTURE_ONLY", encoding="utf-8")
    app = FastAPI(title="CrimsonWeb disposable vulnerability lab", docs_url=None, redoc_url=None)

    @app.middleware("http")
    async def loopback_only(request: Request, call_next):
        if (request.client is None or request.client.host not in {"127.0.0.1", "::1"}
                or request.url.hostname not in {"127.0.0.1", "localhost", "::1"}):
            return PlainTextResponse("Loopback only", status_code=403)
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"lab": True, "run_id": truth.run_id}

    @app.get("/{mode}/xss")
    async def xss(request: Request, mode: str, q: str = Query(default="", max_length=256)):
        if mode not in {"vulnerable", "secure"}:
            return PlainTextResponse("Unknown fixture", status_code=404)
        detector = ElementDetector()
        detector.feed(q)
        triggered = mode == "vulnerable" and detector.element
        truth.record(request, "xss", mode, q, triggered,
                     "unescaped_html_reflected" if triggered else "no_html_injection", 200)
        # Intentional reflection. Secure sibling encodes the same input.
        value = q if mode == "vulnerable" else html.escape(q)
        return HTMLResponse(f"<!doctype html><html><body><div>{value}</div></body></html>")

    @app.get("/{mode}/sqli")
    async def sqli(request: Request, mode: str, q: str = Query(default="1", max_length=256)):
        if mode not in {"vulnerable", "secure"}:
            return PlainTextResponse("Unknown fixture", status_code=404)
        # Each request gets its own in-memory database; no application/user data.
        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE records (id TEXT, label TEXT)")
        connection.executemany("INSERT INTO records VALUES (?, ?)", [("1", "lab-one"), ("2", "lab-two")])
        connection.set_progress_handler(lambda: 1, 10000)
        try:
            expected = connection.execute("SELECT id, label FROM records WHERE id = ?", (q,)).fetchall()
            if mode == "vulnerable":
                rows = connection.execute(f"SELECT id, label FROM records WHERE id = '{q}'").fetchall()
            else:
                rows = expected
            triggered = rows != expected
            effect = "query_semantics_changed" if triggered else "no_sql_injection"
            response = JSONResponse({"records": rows})
        except sqlite3.Error as exc:
            triggered = mode == "vulnerable"
            effect = "sql_parser_error" if triggered else "fixture_error"
            response = PlainTextResponse(f"sqlite3.{type(exc).__name__}: {exc}", status_code=500)
        finally:
            connection.close()
        truth.record(request, "sqli", mode, q, triggered, effect, response.status_code)
        return response

    @app.get("/{mode}/files")
    async def files(request: Request, mode: str, name: str = Query(default="hello.txt", max_length=256)):
        if mode not in {"vulnerable", "secure"}:
            return PlainTextResponse("Unknown fixture", status_code=404)
        target = (public / name).resolve()
        escaped_public = not target.is_relative_to(public)
        # The deliberate traversal may leave public/, but NEVER the fixture root.
        allowed = target.is_relative_to(root) and (mode == "vulnerable" or not escaped_public)
        if allowed and target.is_file():
            response = PlainTextResponse(target.read_text(encoding="utf-8"))
            triggered = escaped_public
            effect = "private_fixture_read" if triggered else "public_fixture_read"
        else:
            response = PlainTextResponse("File unavailable", status_code=404)
            triggered = False
            effect = "sandbox_escape_rejected" if not target.is_relative_to(root) else "file_rejected"
        truth.record(request, "path_traversal", mode, name, triggered, effect, response.status_code)
        return response

    return app
