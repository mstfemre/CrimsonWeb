# CrimsonWeb

CrimsonWeb is an authorized lab and assessment scanner. It does not call nmap,
masscan, nmap-service-probes, or external scanner binaries.


## Documentation

- Detailed user guide: `docs/USER_GUIDE.md`
- Refactor plan: `docs/REFRACTOR_PLAN.md`

## Current Layout

- `src/crimsonweb/core_engine.py`: current scanner orchestration and runtime engine.
- `src/crimsonweb/cli.py`: CLI entry point.
- `src/crimsonweb/cli_commands.py`: subcommand dispatch plus doctor/config/init helpers.
- `src/crimsonweb/models.py`: shared result and response models.
- `src/crimsonweb/audit.py`: text/JSONL audit logging and CLI redaction.
- `src/crimsonweb/state.py`: checkpoint/resume state handling.
- `src/crimsonweb/ports.py`: target resolution, port parsing, and top-port selection.
- `src/crimsonweb/reporting.py`: executive Markdown report helpers.
- `src/crimsonweb/web_checks.py`: security header, cookie, CORS, and web path check helpers.
- `src/crimsonweb/egress.py`: proxy/Tor routing, pacing, block-signal analysis, and decoy helpers.
- `src/crimsonweb/cve.py`: CPE extraction, NVD lookup, API throttling, and CVE cache handling.
- `src/crimsonweb/discovery/`: async TCP connect, SYN, and UDP discovery backends.
- `src/crimsonweb/probes/`: service probe registry and built-in fingerprint classifiers.
- `src/crimsonweb/service_detection.py`: service fingerprint orchestration, TLS certificate checks, and web-service follow-up checks.
- `src/crimsonweb/formatting.py`: shared banner/evidence formatting helpers.
- `core_engine.py`: backward-compatible launcher for older commands.
- `pyproject.toml`: package metadata and console scripts.

The engine is being split incrementally so behavior stays stable. The next
refactor should continue by boundary: profile loading, report commands, shell completion, and packaging polish.

## Local Usage

On Kali Linux, use an isolated virtual environment from the project root:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[full]"
crimson doctor
```

Normal TCP connect scans do not need root:

```bash
crimson scan -t 127.0.0.1 -p 80,443 --no-cve
crimson web -u http://localhost:8000 --no-cve
```

Privileged SYN scans require root/CAP_NET_RAW on Linux:

```bash
sudo .venv/bin/crimson scan -t 127.0.0.1 --top-ports --syn --no-cve
```

From the project root on Windows or an already configured Python environment:

```powershell
python -m pip install -e .
```

For all optional features:

```powershell
python -m pip install -e ".[full]"
```

Run commands directly from the project root:

```powershell
python core_engine.py scan -t 127.0.0.1 -p 80,443 --no-cve
python core_engine.py web http://localhost:8000 --no-cve
python core_engine.py doctor
python core_engine.py config init
```

Module invocation is also supported:

```powershell
$env:PYTHONPATH = "src"
python -m crimsonweb.cli --help
python -m crimsonweb --help
```

After editable install:

```powershell
crimson scan -t 127.0.0.1 --top-ports --no-cve
crimson web -u http://localhost:8000 --no-cve
crimson doctor
```

Legacy invocation still works:

```powershell
crimson -u http://localhost:8000 --no-cve
```

`--roe` is no longer required. Use `--engagement-id` when you want a project or
assessment identifier recorded in audit logs and reports.
