# CrimsonWeb

Local HTTP/HTTPS vulnerable and secure fixtures are available through
`python -m crimsonweb.local_lab verify`. The bridge uses real loopback sockets,
verified per-run TLS and a separate JSON ground truth log. See
[Local Vulnerability Laboratory](docs/LOCAL_VULNERABILITY_LAB.md).

Web/API verification is available through `crimsonweb web plan`, `approve`,
`execute`, `report` and `cancel`, without a port scan. See
[Phase 4C.1 web workflow and privacy hardening](docs/PHASE4C1.md).
The optional web catalog now includes inert HTML reflection, SQL error differential
and configuration observations, plus bounded model-guided follow-up plans. Use
`web plan --top10` for an honest OWASP 2025 coverage report; unsupported categories
remain `not_tested`. See [web catalog and Top10 workflow](docs/WEB_TOP10_ENGINE.md).
Optimized local `gemma-web` and `qwen-web` profiles are available. Use
`web plan --require-model` to reject operator fallback when model planning fails;
follow-up plans inherit this requirement. See [Gemma setup and real validation](docs/GEMMA_WEB_SETUP.md).

## HTTP assessment API — Phase 5A

Phase 4A adds workspace management, versioned scope policies, deterministic authorization,
durable request limits and scope audits. The existing HTTP scanner supports an optional
workspace guard; CLI and legacy API contracts remain available. See
[Phase 4A architecture, API and security boundaries](docs/PHASE4A.md).
Phase 4B adds guarded same-origin discovery, offline OpenAPI import, persistent jobs,
endpoint/resource relationships and bounded untrusted discovery summaries. See
[Phase 4B implementation, API and verified limits](docs/PHASE4B.md).
Phase 5A adds workspace privacy profiles, approved direct egress observations,
DNS/IPv6 diagnostics, deterministic assessments and minimal privacy audits. See
[Phase 5A implementation and verified limits](docs/PHASE5A.md),
[privacy threat model](docs/PRIVACY_THREAT_MODEL.md) and
[Phase 5 architecture and future plans](docs/PHASE5_ARCHITECTURE.md).
Observations do not certify anonymity or enforce an OS-level kill switch.
Phase 4C adds operator-approved, read-only API authorization comparison with two
researcher-supplied test identities. Its optional local model selects fixed catalog
tests; the deterministic executor reuses the scope guard and retains minimal evidence.
See [Phase 4C usage, security boundaries and validation](docs/PHASE4C.md).
The existing local AI production contract is unchanged; discovery does not invoke
models or execute AI instructions.

The FastAPI MVP is available alongside the existing CLI. It validates authorized
hosts and DNS addresses on every redirect, pins connections to validated IPs,
checks security headers, and exports JSON reports. Missing headers are configuration
observations, not confirmed vulnerabilities. Phase 2 adds SQLite persistence,
Alembic migrations, verified TLS observations, cookie/HSTS/CORS analysis and defense-event imports.
Phase 3 adds opt-in local Ollama analysis of persisted evidence, validated AI opinions,
independent technical priorities and separate analysis history. Existing scans work with AI disabled.
Phase 3.5 binds Ollama comments to exact evidence keys using a per-request schema,
restricts reference arrays, and checks clearly English prose in Turkish requests.

See [Phase 3 setup and AI API guide](docs/PHASE3.md) for the AI layer and
[Phase 2 setup, migrations and API guide](docs/PHASE2.md) for technical scans.
[Phase 3.5](docs/PHASE3.5.md) documents the gemma3:4b reference fix and real-model tests.
[Model benchmark](docs/MODEL_BENCHMARK.md) records Gemma 3/Gemma 4 compatibility and resource measurements.
[Phase 1](docs/PHASE1.md) records the original MVP and local lab setup.

```powershell
.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
# Existing DB: make a backup before a manual Alembic upgrade.
.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
$env:CRIMSON_API_TOKEN = "<strong random token>"   # required since Phase 5A.1
.venv\Scripts\python.exe -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --no-proxy-headers
```

The API refuses to start without `CRIMSON_API_TOKEN` (tokenless loopback use needs
`CRIMSON_API_DEV_ALLOW_NO_TOKEN=1`), rejects `Host` headers outside
`CRIMSON_API_ALLOWED_HOSTS`, and backs up an outdated SQLite database before
migrating it through application startup. Manual Alembic commands bypass that
automatic backup. See [Phase 5A.1](docs/PHASE5A1.md).

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
