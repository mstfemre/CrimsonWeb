"""Regression tests for terminal and redirected output."""

from io import StringIO
import os
import socket
import subprocess
import sys

from rich.console import Console

from crimsonweb import ui
from crimsonweb.models import ServiceResult


def test_narrow_banner_and_literal_stage(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, width=40, color_system=None))
    ui.print_banner("2.1.0")
    ui.print_stage("[target]", "[red]literal[/red]")
    text = output.getvalue()
    assert "CRIMSONWEB" in text
    assert "____" not in text
    assert "[red]literal[/red]" in text
    assert "\x1b" not in text
    assert all(len(line) <= 40 for line in text.splitlines())


def test_redirected_progress_only_emits_completion(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, color_system=None))
    ui.write_progress("Scanning ports", 1, 2)
    assert not output.getvalue()
    ui.write_progress("Scanning ports", 2, 2)
    assert "2/2" in output.getvalue()
    assert "\r" not in output.getvalue()


def test_results_render_on_narrow_terminal(monkeypatch):
    output = StringIO()
    monkeypatch.setattr(ui, "console", Console(file=output, width=60, color_system=None))
    ui.print_results({443: ServiceResult(port=443, state="open", service="https")})
    assert "443" in output.getvalue()
    assert "https" in output.getvalue()
    assert all(len(line) <= 60 for line in output.getvalue().splitlines())


def test_local_cli_scan_uses_ui_and_writes_report(tmp_path):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        run = subprocess.run(
            [sys.executable, "-m", "crimsonweb", "scan", "-t", "127.0.0.1",
             "-p", str(port), "--port-scan-only", "--no-cve", "--no-recon",
             "--state-file", str(tmp_path / "state.json"),
             "--output-dir", str(tmp_path / "reports")],
            capture_output=True, text=True, timeout=20,
            env={**os.environ, "NO_COLOR": "1"},
        )
    assert run.returncode == 0, run.stderr
    assert "CrimsonWeb" in run.stdout
    assert "[::] RESULTS" in run.stdout
    assert str(port) in run.stdout
    assert "\x1b" not in run.stdout
    assert list((tmp_path / "reports").glob("crimsonweb_*.json"))
