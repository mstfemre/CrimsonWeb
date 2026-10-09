"""Central terminal UI for CrimsonWeb.

Built on `rich` for a professional dashboard-style TUI (panels, tables, live
progress) that renders cleanly on Windows 11 (Windows Terminal) and Linux. If
`rich` is unavailable the module degrades to plain ASCII output so the scanner
still runs everywhere. All dynamic/user-derived text is rendered as literal
`Text` (never as markup) to avoid glitches on odd banners or Windows paths.
"""

from __future__ import annotations

from contextlib import contextmanager
import os
from typing import Any, Callable, Iterator

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeRemainingColumn,
    )
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only without rich installed
    RICH_AVAILABLE = False


BANNER_ART = r"""
  ____ ____  ___ __  __ ____   ___  _   ___        _______ ____
 / ___|  _ \|_ _|  \/  / ___| / _ \| \ | \ \      / / ____| __ )
| |   | |_) || || |\/| \___ \| | | |  \| |\ \ /\ / /|  _| |  _ \
| |___|  _ < | || |  | |___) | |_| | |\  | \ V  V / | |___| |_) |
 \____|_| \_\___|_|  |_|____/ \___/|_| \_|  \_/\_/  |_____|____/
"""


if RICH_AVAILABLE:
    # Crimson-themed palette. Structural elements (borders, bars, spinners,
    # indicators) are red; semantic result colors (success/warn/error) keep
    # their conventional meanings for readability. #DC143C is CSS "crimson".
    _THEME = Theme(
        {
            "crimson.title": "bold white",
            "crimson.stage": "bold red",
            "crimson.success": "bold green",
            "crimson.warn": "bold yellow",
            "crimson.error": "bold red",
            "crimson.info": "#DC143C",
            "crimson.dim": "dim",
            # Override Rich's default (blue/magenta) progress styles with red.
            "bar.complete": "red",
            "bar.finished": "bright_red",
            "bar.pulse": "red",
            "progress.description": "bold red",
            "progress.percentage": "bold red",
            "progress.remaining": "red",
            "progress.spinner": "red",
        }
    )
    # emoji/highlight disabled: keep output ASCII-stable and avoid number
    # auto-highlighting inside tables and paths.
    console: Any = Console(
        theme=_THEME, highlight=False, emoji=False,
        no_color=bool(os.environ.get("NO_COLOR")),
    )
else:  # pragma: no cover - plain fallback

    class _PlainConsole:
        def print(self, *args: Any, **_kwargs: Any) -> None:
            print(" ".join(str(arg) for arg in args))

    console = _PlainConsole()


def _trim(value: str | None, width: int) -> str:
    text = (value or "").replace("\r", " ").replace("\n", " ").strip()
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


# --------------------------------------------------------------------------
# Banner + section headers
# --------------------------------------------------------------------------
def print_banner(version: str) -> None:
    if RICH_AVAILABLE:
        if console.width >= 70:
            console.print(Text(BANNER_ART.rstrip(), style="bold red"))
        else:
            console.print(Text("CRIMSONWEB", style="bold red"))
        subtitle = Text.assemble(
            (f"CrimsonWeb v{version}", "bold white"),
            (" / Authorized assessment\n", "white"),
            ("DISCOVERY  /  SERVICES  /  WEB  /  REPORTS", "dim"),
        )
        console.print(subtitle)
        console.print()
    else:
        print(BANNER_ART)
        print(f"CrimsonWeb v{version} | Authorized Web & Service Scanner")
        print("multi-egress | ban-aware | adaptive pacing | audit logged\n")


def print_stage(title: str, detail: str = "") -> None:
    if RICH_AVAILABLE:
        console.print()
        console.print(Text.assemble(("[::] ", "bold red"), (title.upper(), "bold white")))
        if detail:
            console.print(Text(detail, style="dim"))
    else:
        print("\n" + "=" * 70)
        print(f"[ {title} ]")
        if detail:
            print(detail)
        print("=" * 70)


# --------------------------------------------------------------------------
# Status lines
# --------------------------------------------------------------------------
def _emit(prefix: str, message: str, style: str) -> None:
    if RICH_AVAILABLE:
        console.print(Text.assemble((f"{prefix} ", style), (message,)))
    else:
        print(f"{prefix} {message}")


def print_success(message: str) -> None:
    _emit("[+]", message, "bold green")


def print_warning(message: str) -> None:
    _emit("[!]", message, "bold yellow")


def print_error(message: str) -> None:
    _emit("[-]", message, "bold red")


def print_info(message: str) -> None:
    _emit("[*]", message, "#DC143C")


def print_discovered_subdomain(host: str, source_port: int, in_scope: bool = True) -> None:
    """Report a host found in a TLS SAN during dynamic scope discovery."""
    if in_scope:
        _emit("[+]", f"Discovered Subdomain: {host}  (via :{source_port})", "bold green")
    else:
        _emit("[~]", f"Out-of-scope SAN (not scanned): {host}  (via :{source_port})", "dim")


# --------------------------------------------------------------------------
# Progress
# --------------------------------------------------------------------------
def write_progress(description: str, done: int, total: int) -> None:
    """Redraw on terminals only; redirected output gets a final status line."""
    total = max(total, 1)
    if RICH_AVAILABLE and console.is_terminal:
        width = max(4, min(24, console.width - len(description) - 28))
        filled = int(width * min(max(done / total, 0), 1))
        bar = "#" * filled + "-" * (width - filled)
        console.print(
            Text(f"\r[*] {description} [{bar}] {done}/{total}", style="red"),
            end="\n" if done >= total else "",
            crop=True,
        )
    elif done >= total:
        print_info(f"{description}: {done}/{total}")


@contextmanager
def progress_bar(description: str, total: int) -> Iterator[Callable[..., None]]:
    """Yield an ``advance(n=1)`` callable backed by a live Rich progress bar.

    Replaces the legacy manual ``\\r`` redraws. Transient so it clears itself
    on completion, leaving the scroll-back clean.
    """
    if RICH_AVAILABLE and console.is_terminal:
        progress = Progress(
            # ASCII spinner (portable), driven red; bar completes/pulses in red.
            SpinnerColumn(spinner_name="line", style="bold red"),
            TextColumn("[bold red]{task.description}[/]"),
            BarColumn(complete_style="red", finished_style="bright_red", pulse_style="red"),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=False,
        )
        with progress:
            task_id = progress.add_task(description, total=max(total, 1))

            def advance(step: int = 1) -> None:
                progress.advance(task_id, step)

            yield advance
    else:  # pragma: no cover - plain fallback
        counter = {"done": 0}

        def advance(step: int = 1) -> None:
            counter["done"] += step

        print(f"{description} ... (0/{total})")
        try:
            yield advance
        finally:
            print(f"{description} ... done ({counter['done']}/{total})")


# --------------------------------------------------------------------------
# Results table
# --------------------------------------------------------------------------
def _result_style(result: Any) -> str:
    if result.service in {"http", "https"}:
        return "green"
    if result.service in {"ssh", "smtp", "ftp", "mysql", "pop3", "imap/pop"}:
        return "cyan"
    if (
        result.cves
        or result.sensitive_paths
        or result.api_paths
        or result.security_headers
        or result.cookie_findings
        or result.cors_findings
    ):
        return "yellow"
    return "white"


def _findings_summary(result: Any) -> str:
    parts: list[str] = []
    if result.waf:
        parts.append(f"WAF={result.waf}")
    if result.sensitive_paths:
        parts.append(f"files={len(result.sensitive_paths)}")
    if result.api_paths:
        parts.append(f"api={len(result.api_paths)}")
    if result.security_headers:
        parts.append(f"headers={len(result.security_headers)}")
    if result.cookie_findings:
        parts.append(f"cookies={len(result.cookie_findings)}")
    if result.cors_findings:
        parts.append(f"cors={len(result.cors_findings)}")
    if result.mitre_attack:
        parts.append(f"mitre={len(result.mitre_attack)}")
    if result.cves:
        parts.append(f"cves={len(result.cves)}")
    if result.tls_certificate:
        if result.tls_certificate.get("days_until_expiry") is not None:
            parts.append(f"cert={result.tls_certificate.get('days_until_expiry')}d")
        elif result.tls_certificate.get("skipped"):
            parts.append("cert=skipped")
    if result.os_hint:
        parts.append(f"os={result.os_hint}")
    if result.http_status is not None:
        parts.append(f"http={result.http_status}")
    if result.title:
        parts.append(f"title={_trim(result.title, 22)}")
    return ", ".join(parts) or "-"


def print_results(results: dict[int, Any]) -> None:
    from .reporting import web_finding_count  # local import avoids import cycle

    print_stage("Results", f"Open services discovered: {len(results)}")
    total_cves = total_sensitive = total_api = total_web = web_services = 0

    if RICH_AVAILABLE:
        table = Table(
            header_style="bold red",
            border_style="dark_red",
            expand=True,
            show_edge=False,
            box=None,
        )
        table.add_column("PORT", justify="right")
        table.add_column("SERVICE")
        table.add_column("TLS", justify="center")
        table.add_column("OS HINT")
        table.add_column("VERSION")
        table.add_column("FINDINGS")
        for port in sorted(results):
            result = results[port]
            style = _result_style(result)
            table.add_row(
                Text(str(port), style=style),
                Text(result.service, style=style),
                Text("yes" if result.tls else "no"),
                Text(_trim(result.os_hint or "-", 20)),
                Text(_trim(result.version, 40)),
                Text(_trim(_findings_summary(result), 60)),
            )
            total_cves += len(result.cves)
            total_sensitive += len(result.sensitive_paths)
            total_api += len(result.api_paths)
            total_web += web_finding_count(result)
            if result.service in {"http", "https"}:
                web_services += 1
        console.print(table)
    else:  # pragma: no cover - plain fallback
        print(f"{'PORT':<8}{'SERVICE':<10}{'TLS':<5}{'OS HINT':<20}{'VERSION':<34}FINDINGS")
        print("-" * 100)
        for port in sorted(results):
            result = results[port]
            print(
                f"{port:<8}{result.service:<10}{('yes' if result.tls else 'no'):<5}"
                f"{_trim(result.os_hint or '-', 20):<20}{_trim(result.version, 34):<34}"
                f"{_trim(_findings_summary(result), 40)}"
            )
            total_cves += len(result.cves)
            total_sensitive += len(result.sensitive_paths)
            total_api += len(result.api_paths)
            total_web += web_finding_count(result)
            if result.service in {"http", "https"}:
                web_services += 1

    print_success(
        f"{len(results)} open port(s) | {web_services} web service(s) | "
        f"{total_sensitive} sensitive path hit(s) | {total_api} API indicator(s) | "
        f"{total_web} web finding(s) | {total_cves} CVE match(es)"
    )


def print_web_blocks(events: list[Any]) -> None:
    if not events:
        return
    print_stage("Web Blocks", f"Blocked host/path targets observed: {len(events)}")
    for event in events:
        print_warning(f"{event.status} {event.url} | {event.reason} | egress={event.egress_id}")


def print_diff(messages: list[str]) -> None:
    if not messages:
        return
    print_stage("Diff Report")
    for message in messages:
        if RICH_AVAILABLE:
            console.print(Text.assemble(("  - ", "bold red"), (message,)))
        else:  # pragma: no cover - plain fallback
            print(f"  - {message}")
