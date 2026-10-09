# CrimsonWeb User Guide

Last updated: 2026-10-08

CrimsonWeb is an authorized lab and assessment scanner with native TCP/UDP discovery, service fingerprinting, web security checks, TLS inspection, CORS/cookie/header analysis, CVE correlation, audit logging, checkpoint/resume, and report generation. It does not call nmap, masscan, nmap-service-probes, or external scanner binaries.

This guide is the operational reference for the current codebase. When code changes affect commands, options, outputs, config, safety behavior, reports, dependencies, or module responsibilities, update this guide in the same change.

## Safety Scope

Use CrimsonWeb only on systems you own, administer, or are explicitly permitted to assess in a lab, school project, or authorized engagement.

CrimsonWeb includes features that can create network traffic, touch web paths, send UDP probes, query CVE APIs, and optionally use proxy/Tor egress. Keep scans scoped and rate-limited. Do not use the tool to evade IDS/IPS, bypass monitoring, hide unauthorized activity, or scan targets outside your approved scope.

`--roe` is no longer required. Use `--engagement-id` when you want a lab, project, ticket, or assessment identifier recorded in audit logs and reports. The legacy `--roe` alias still works for compatibility.

## Current Architecture

The project has been split from the original monolithic engine into smaller modules:

| Path | Purpose |
| --- | --- |
| `core_engine.py` | Backward-compatible root launcher. |
| `src/crimsonweb/core_engine.py` | Main CLI parser, orchestration, reporting flow, state lifecycle, and top-level scanner session. |
| `src/crimsonweb/cli.py` | Package console entrypoint. |
| `src/crimsonweb/cli_commands.py` | `scan`, `web`, `doctor`, `config`, and `init` dispatch/helpers. |
| `src/crimsonweb/models.py` | Shared dataclasses such as `Target`, `ServiceResult`, `WebFinding`, and `WebResponse`. |
| `src/crimsonweb/audit.py` | Audit logging, JSONL audit events, CLI secret redaction. |
| `src/crimsonweb/privacy.py` | Sanitization of persisted secrets and URL parameters. |
| `src/crimsonweb/scheduling.py` | Bounded task allocation and cancellation cleanup. |
| `src/crimsonweb/state.py` | Checkpoint/resume state file handling. |
| `src/crimsonweb/ports.py` | Target resolution, port parsing, and top-port selection. |
| `src/crimsonweb/discovery/` | Async TCP connect scanner, Scapy SYN scanner, UDP probe scanner. |
| `src/crimsonweb/probes/` | Active probe registry and built-in fingerprint classifiers. |
| `src/crimsonweb/service_detection.py` | Service fingerprint orchestration, HTTP/TLS probing, TLS certificate checks, and web-service follow-up checks. |
| `src/crimsonweb/web_checks.py` | Security header, cookie, CORS, sensitive path, and API path helper logic. |
| `src/crimsonweb/egress.py` | Direct/proxy/Tor routing, proxy validation, pacing, block detection, decoy helpers. |
| `src/crimsonweb/cve.py` | CPE extraction, NVD lookup, throttling, and CVE cache. |
| `src/crimsonweb/reporting.py` | Executive Markdown report helpers. |
| `src/crimsonweb/formatting.py` | Shared banner/evidence formatting helpers. |

## Installation

### Current Windows Installation

This computer uses `C:\Users\mstfc\OneDrive\Belgeler\CrimsonWeb` as the project
directory. The editable package is installed in `.venv`. The global launcher
`C:\Users\mstfc\bin\crimsonweb.cmd` points to that directory's
`.venv\Scripts\crimsonweb.exe`. Keep the directory in place; do not copy a
virtual environment when moving the project. Recreate it at the destination.

```powershell
crimsonweb --version
crimsonweb doctor
crimsonweb --help
```

To update package dependencies after editing this project:

```powershell
cd C:\Users\mstfc\OneDrive\Belgeler\CrimsonWeb
.\.venv\Scripts\python.exe -m pip install -e ".[full]"
```

Ordinary edits under `src\crimsonweb` take effect on the next invocation without
reinstallation. Use an explicit writable report path when launching from a
system directory:

```powershell
crimsonweb scan -t 127.0.0.1 -p 80,443 --no-cve --output-dir "$env:USERPROFILE\Documents\CrimsonWebReports"
```

### Terminal Appearance

Rich provides a crimson ASCII banner, compact `[::]` stage headings, progress
counters and a responsive results table. Narrow terminals show a compact
`CRIMSONWEB` title instead of wrapping the large banner. Progress redraws are
disabled when output is redirected; only the final counter is emitted.
Set `$env:NO_COLOR = '1'` to disable UI colors; remove it with
`Remove-Item Env:NO_COLOR` to restore terminal detection. On Kali use
`NO_COLOR=1 crimsonweb --help` for plain output. The UI changes do not modify
scan rates, probes, scope or proxy routing.

Known CPE products are checked against the detected service before CVE lookup
(for example, an nginx banner on a service classified as SSH is not correlated
with HTTP-server CVEs). Banner correlation still requires manual confirmation.

Terminal design references: https://clig.dev/ and
https://rich.readthedocs.io/en/stable/console.html.

### Privacy and Bounded Scheduling

TCP connect discovery and service detection now keep at most their configured
concurrency count of outstanding tasks, rather than scheduling the entire port
list at once. Pending work is cancelled and awaited on failure/cancellation.
Timeouts, scan scope, concurrency defaults and web rate limits are unchanged.
This reduces task-allocation memory; it is not a guarantee of faster network
responses or avoidance of blocks.

Structured audit fields and JSON reports mask credential/cookie headers, known
secret field names, URL userinfo and all URL query values; URL fragments are
omitted. Live responses are not modified, so cookie/header analysis continues
normally. The text audit handler also redacts URLs. CLI URL arguments are
sanitized before recording. Existing logs are not rewritten.

This is data minimization, not anonymity: target addresses and timestamps remain
in the audit trail. Arbitrary secrets in response bodies, paths or free-form
text are not comprehensively detected. CSV/Markdown evidence requires review
before sharing; protect the output directory with OS permissions. These changes
do not change Tor/proxy routing or bypass WAF/IDS blocks.

Reproduce the network-free scheduling benchmark on Windows:

```powershell
.\.venv\Scripts\python.exe tests\benchmark_scheduling.py
```

On this machine, 20,000 synthetic operations used 25.74 MiB peak traced Python
memory with eager allocation versus 0.95 MiB with a 100-task window. Runtime was
0.300s versus 0.219s in that run. These measurements are environment-dependent
and are not a network scanning throughput benchmark. No new CLI flags or
dependencies are needed for these changes.

CrimsonWeb requires Python 3.11 or newer.

### Kali Linux Recommended Setup

Use a virtual environment so CrimsonWeb dependencies do not modify the system Python environment:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd /path/to/CrimsonWeb
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[full]"
crimson doctor
```

Expected result after full install:

```text
doctor ok: true
aiohttp, httpx, asyncio_throttle, aiohttp_socks, yaml, curl_cffi, scapy, colorama available
```

Normal TCP connect scanning and web checks do not require root:

```bash
crimson scan -t 127.0.0.1 -p 80,443 --no-cve
crimson web -u http://localhost:8000 --no-cve
```

Linux SYN scanning uses raw packets and requires root/CAP_NET_RAW:

```bash
sudo .venv/bin/crimson scan -t 127.0.0.1 --top-ports --syn --no-cve
```

Use `--syn` only for authorized lab/assessment targets where privileged packet scanning is expected. The default async TCP connect scanner is the safer baseline for ordinary usage.

### Generic Python Setup

From the project root:

```powershell
python -m pip install -e .
```

For all optional capabilities:

```powershell
python -m pip install -e ".[full]"
```

Direct project-root usage:

```powershell
python core_engine.py doctor
python core_engine.py scan -t 127.0.0.1 -p 80 --no-cve
```

Module invocation for development:

```powershell
$env:PYTHONPATH = "src"
python -m crimsonweb.cli --help
python -m crimsonweb --help
```

Editable install with `pipx`:

```powershell
pipx install -e .
crimson doctor
crimson scan -t 127.0.0.1 -p 80 --no-cve
```

Package console scripts:

```text
crimson
crimsonweb
```

Both console scripts call the same entrypoint.

## Optional Dependencies

Base dependency:

```text
aiohttp
```

Optional groups from `pyproject.toml`:

| Extra | Purpose | Packages |
| --- | --- | --- |
| `cve` | NVD CVE lookup and throttling | `httpx`, `asyncio-throttle` |
| `egress` | SOCKS proxy/Tor and YAML egress config | `aiohttp-socks`, `PyYAML` |
| `fingerprint` | Optional curl_cffi TLS fingerprint profiles | `curl-cffi` |
| `syn` | Privileged SYN scanning | `scapy` |
| `full` | All optional capabilities | all optional packages plus `colorama` |

Examples:

```powershell
pipx install -e ".[full]"
pipx inject crimsonweb httpx asyncio-throttle aiohttp-socks PyYAML scapy colorama
```

Run `crimson doctor` after install to see which optional features are available.

## Command Overview

CrimsonWeb supports both modern subcommands and legacy direct invocation.

Modern commands:

```powershell
crimson scan -t 127.0.0.1 -p 80,443 --no-cve
crimson web -u http://localhost:8000 --no-cve
crimson doctor
crimson config init
crimson config path
crimson config show
```

Legacy style still works:

```powershell
crimson -u http://localhost:8000 --no-cve
crimson -t 127.0.0.1 -p 80
```

### `scan`

Use `scan` for TCP/UDP discovery plus service fingerprinting.

Common examples:

```powershell
crimson scan -t 127.0.0.1 -p 22,80,443 --no-cve
crimson scan -t example.test --top-ports --top-ports-count 100 --no-cve
crimson scan -t 10.10.10.10 -s 1 -e 1024 --fast --no-cve
crimson scan -t 127.0.0.1 -p 53 --udp --no-cve
```

Important options:

| Option | Meaning |
| --- | --- |
| `-t`, `--target` | Target host or IP. |
| positional target | Legacy target form, e.g. `crimson scan 127.0.0.1`. |
| `-u`, `--url` | HTTP/HTTPS URL; derives host and default port, and enables web-only mode. |
| `-p`, `--ports` | Comma-separated ports/ranges such as `22,80,443,8000-8010`. |
| `-s`, `--start` / `-e`, `--end` | Range scan bounds when `--ports` is not used. |
| `--top-ports` | Use ranked top TCP ports. |
| `--top-ports-count` | Number of ranked ports to use. |
| `--timeout` | TCP connect/SYN timeout. |
| `--banner-timeout` | Service fingerprint timeout. |
| `--port-concurrency` | TCP connect scan concurrency. |
| `--service-concurrency` | Service detection concurrency. |
| `--fast` | Faster profile: lower timeouts, higher concurrency, disables CVE/recon/web path checks. |
| `--port-scan-only` | Discover open TCP ports but skip fingerprinting and web checks. |
| `--udp` | Run UDP probe scanner after TCP/service phase. |
| `--udp-include-syslog` | Include UDP/514 syslog probe; may create entries in target logs/SIEM. |
| `--syn` | Use explicit privileged Scapy SYN scanner. Requires root/Administrator. |
| `--no-cve` | Disable NVD CVE lookup. Recommended for offline/lab speed. |
| `--no-web-checks` | Disable web hardening/sensitive path/API/CORS follow-up checks. |
| `--output-dir` | Directory for reports, logs, and audit output. |
| `--format` | Raw report format: `json`, `csv`, or `markdown`. |
| `--compare` | Compare current scan against a previous JSON report in output directory. |
| `--engagement-id` | Optional project/lab/assessment identifier in audit/report metadata. |

### `web`

Use `web` for web-only checks against known HTTP/HTTPS URLs or known web ports. This avoids direct port discovery when using proxy/Tor egress.

Examples:

```powershell
crimson web http://localhost:8000 --no-cve
crimson web -u https://example.test --no-cve
crimson web -u https://example.test --web-request-delay 2 --web-max-global-rate 30
```

`crimson web http://host:port` is automatically converted to `-u http://host:port` and forces `--web-only`.

Useful web options:

| Option | Meaning |
| --- | --- |
| `--web-request-delay` | Base delay between web requests. |
| `--web-sensitive-delay` | Higher delay for sensitive endpoints such as login/auth/payment/admin paths. |
| `--web-max-global-rate` | Global web request cap per minute. |
| `--web-max-retries` | Retry count for web requests. |
| `--web-stop-statuses` | HTTP status list treated as block/stop signals; default `403,429,503`. |
| `--tls-no-verify` | Disable TLS certificate verification. Use only when intentionally testing local/self-signed targets. |
| `--user-agent` | Fixed User-Agent string. |
| `--fingerprint` | Optional curl_cffi browser/TLS fingerprint profile when installed. |
| `--decoy-rate` | Probability of injecting decoy request. Default is `0.0`. |
| `--no-recon` | Disable passive recon for decoy path discovery. |
| `--recon-max-links` | Maximum passive recon links used for decoy pool. |

### `doctor`

Use `doctor` to inspect environment readiness.

```powershell
crimson doctor
crimson doctor --json
```

Doctor reports:

- Python version and executable.
- Required dependency status.
- Optional dependency status.
- Config path and whether it exists.
- Overall OK/ISSUES status.

Missing optional dependencies are not always errors. For example, CVE lookup needs `httpx`; SYN mode needs `scapy`; proxy/Tor SOCKS support needs `aiohttp-socks`.

### `config`

Current config support is intentionally minimal. It creates and shows a conservative template; automatic profile loading is still pending.

Commands:

```powershell
crimson config path
crimson config show
crimson config init
crimson config init --force
crimson init
```

Default config path:

```text
~/.crimsonweb/config.yaml
```

Override with environment variable:

```powershell
$env:CRIMSONWEB_CONFIG="C:\path\to\crimson.yaml"
crimson config init
```

Security behavior:

- `config init` refuses to write through a symlink.
- Config directory is created with restrictive permissions where the OS supports it.
- Config file is written with restrictive permissions where the OS supports it.

Automatic config/profile loading is not implemented yet. Keep CLI flags as the source of truth until that roadmap item is completed.

## Target Forms

Exactly one target form should be used:

```powershell
crimson scan 127.0.0.1 -p 80
crimson scan -t 127.0.0.1 -p 80
crimson web -u http://localhost:8000
```

If `--url` is used, CrimsonWeb extracts host and port from the URL and sets web-only mode. If the URL has no explicit port, HTTP uses 80 and HTTPS uses 443.

Invalid combinations are rejected, for example:

- Positional target plus `--target`.
- `--web-only` with `--syn`.
- `--web-only` with `--udp`.
- `--port-scan-only` with `--web-only`.
- Proxy/Tor egress without web-only mode.

## TCP Discovery

Default TCP discovery uses async connect scanning. It does not use nmap or masscan.

Typical flow:

1. Resolve target through `ports.py`.
2. Build port list from explicit ports, ranges, or top ports.
3. Run `AsyncConnectScanner` with configured concurrency and timeout.
4. Pass open ports to `ServiceDetector` unless `--port-scan-only` is set.

Use conservative concurrency on fragile lab targets. `--fast` is useful for quick local iteration, but it disables CVE/recon/web checks and raises concurrency.

## SYN Discovery

SYN scanning is explicit only:

```powershell
sudo crimson scan -t 10.10.10.10 --syn --top-ports --no-cve
```

Requirements:

- Optional `scapy` dependency.
- Root/Administrator privileges.
- Explicit `--syn` flag.

SYN mode records lightweight OS hints from TTL/window/options. It is not enabled automatically.

## UDP Discovery

UDP discovery is opt-in:

```powershell
crimson scan -t 127.0.0.1 --udp --no-cve
```

Default UDP probes cover:

| Port | Probe intent |
| --- | --- |
| 53 | DNS/version.bind style probe. |
| 69 | TFTP read probe. |
| 123 | NTP client probe. |
| 161 | SNMP public community probe. |
| 500 | IKEv2 SA_INIT probe. |
| 1900 | SSDP M-SEARCH. |
| 5353 | mDNS service discovery query. |

UDP/514 syslog is excluded by default because it can create target-side log/SIEM entries. Include it only when appropriate:

```powershell
crimson scan -t 127.0.0.1 --udp --udp-include-syslog --no-cve
```

## Service Fingerprinting

Service detection is handled by `service_detection.py` and `probes/`.

Current built-in classifiers include:

- SSH greeting.
- FTP greeting.
- SMTP greeting.
- POP3/IMAP-like greeting.
- MySQL handshake marker.
- TLS active response marker.
- RDP active response marker.
- SMB active response marker.
- Low-confidence port hints for selected uncommon ports.
- HTTP/HTTPS probing with title/header extraction.

Every service result includes evidence fields such as service name, version/banner, TLS flag, HTTP status, title, headers, notes, CVEs, and web findings where available.

## Web Security Checks

For HTTP/HTTPS services, CrimsonWeb can check:

- Security headers.
- Cookie flags.
- CORS behavior.
- Sensitive path exposure.
- API documentation/endpoint indicators.
- TLS certificate metadata.
- Passive WAF/header fingerprinting.

Disable this layer with:

```powershell
crimson scan -t example.test -p 80,443 --no-web-checks --no-cve
```

Security header findings are hardening indicators, not exploit proof. Treat them as review items and validate manually before remediation work.

## TLS Checks

For TLS services, CrimsonWeb records certificate information where direct probing is allowed:

- Subject CN.
- Issuer CN.
- Not before / not after.
- Days until expiry.
- Expired status.
- Subject alternative names.
- Cipher and TLS version.
- ALPN result.

Direct TLS certificate probing is skipped when proxy egress is active because the direct target connection would bypass the configured egress path.

## CVE Correlation

CVE lookup is disabled with `--no-cve` and otherwise uses the NVD API when `httpx` is installed.

The matching flow is intentionally conservative:

1. Parse service/version banner.
2. Convert recognized vendor/product/version into a CPE virtual match string.
3. Query NVD with bounded result count.
4. Cache CVE responses in memory.

False positives are still possible when banners are misleading or incomplete. Treat CVE matches as correlation candidates, not final vulnerability proof.

Set `NVD_API_KEY` in the environment to use a higher NVD rate limit:

```powershell
$env:NVD_API_KEY="..."
crimson scan -t example.test -p 80,443
```

## Egress, Proxy, and Tor

Direct mode is the default.

Proxy/Tor modes are restricted to web-only mode to avoid direct TCP discovery leaks. Use them only for authorized workflows where the target scope and egress path are approved.

Examples:

```powershell
crimson web -u https://example.test --web-tor --no-cve
crimson web -u https://example.test --web-proxy socks5h://127.0.0.1:9050 --no-cve
crimson web -u https://example.test --egress-config egress.yaml --no-cve
```

Important DNS leak guardrail:

- SOCKS proxies that require remote DNS must use `socks4a://` or `socks5h://`.
- Plain `socks5://` is rejected for Tor-style use because DNS may resolve locally.

Block-signal handling tracks HTTP status codes, body patterns, network errors, response-time anomalies, and response-size anomalies. Blocked egress nodes are placed into cooldown.

## Output Files

CrimsonWeb writes raw reports and an executive Markdown report.

Raw report formats:

```powershell
--format json
--format csv
--format markdown
```

Output directory:

```powershell
--output-dir reports
```

Typical files:

```text
crimsonweb_<target>_<timestamp>.json
crimsonweb_<target>_<timestamp>.executive.md
```

Raw JSON includes:

- Scanner name/version.
- Target metadata.
- Timestamp.
- Scan mode.
- Engagement ID.
- Web policy metadata.
- Port/service results.
- Web findings.
- CVE matches.
- MITRE mapping hints.

Executive Markdown summarizes results for review and remediation planning.

## Audit Logging

Audit logging records session-level events, authorization context, egress decisions, block events, scan start/finish, and other operational events.

Secret redaction covers common CLI secret forms and proxy credentials. Avoid placing long-lived secrets directly in command history where possible.

Examples of sensitive values to avoid exposing:

- API keys.
- Proxy usernames/passwords.
- Tor control password.
- Internal ticket/engagement data beyond the optional `--engagement-id` token.

## Checkpoint and Resume

State files support resume behavior:

```powershell
crimson scan -t example.test --top-ports --resume
crimson scan -t example.test --top-ports --state-file .\state\example.json --resume
```

Default state path is under the user CrimsonWeb state directory and is derived from the target. Use `--state-file` when you need a project-local state file.

## Common Workflows

Local web app quick check:

```powershell
crimson web http://localhost:8000 --no-cve
```

Fast local port pass:

```powershell
crimson scan -t 127.0.0.1 -p 1-1024 --fast
```

Top ports with service detection but no CVE calls:

```powershell
crimson scan -t example.test --top-ports --top-ports-count 100 --no-cve
```

Fuller authorized web/service check:

```powershell
crimson scan -t example.test -p 80,443,8080,8443 --engagement-id school-project
```

Generate JSON into a reports directory:

```powershell
crimson scan -t example.test --top-ports --format json --output-dir reports --no-cve
```

Compare against an earlier JSON report:

```powershell
crimson scan -t example.test --top-ports --compare crimsonweb_example_20260705_120000Z.json --output-dir reports --no-cve
```

## Troubleshooting

`aiohttp required`:
Install base dependency or use editable install from project metadata.

`httpx missing`:
Install CVE optional dependencies or pass `--no-cve`.

`--syn requires elevated privileges`:
Run as root/Administrator and install `scapy`, or use default async-connect mode.

`aiohttp_socks required for --web-tor`:
Install `aiohttp-socks` or avoid Tor/proxy mode.

`--web-tor requires --web-only`:
Use `crimson web -u ... --web-tor`. Direct TCP discovery is blocked in proxy/Tor mode to avoid egress leakage.

`--url must be an http:// or https:// URL`:
Use a full URL, for example `https://example.test`.

No open ports found:
Confirm target, port list, local firewall, timeout, and whether the service is listening. For localhost tests, start the service first.

CVE results look wrong:
Treat them as candidates. Verify exact product/version manually and review CPE matching assumptions.

## Testing and Quality Checks

Current project test command:

```powershell
python -m unittest discover -s tests -v
```

Syntax/import smoke check:

```powershell
python -m py_compile core_engine.py src\crimsonweb\core_engine.py
```

Expected current state at this guide update:

```text
53 unit tests passing
```

When adding a new module, add focused unit tests for pure helpers and at least one behavior test for the moved boundary.

## Documentation Update Rule

Update this file whenever any of the following changes:

- CLI command names, examples, or option behavior.
- Install instructions or optional dependencies.
- Output filenames, fields, or report formats.
- Config file path, schema, or loading behavior.
- Safety guardrails, proxy/Tor behavior, DNS behavior, or TLS verification behavior.
- Scanner capabilities, probes, fingerprint logic, CVE matching, or web checks.
- Module ownership/responsibility in `src/crimsonweb/`.
- Test commands or expected test count.

Suggested workflow for future code changes:

1. Implement the code change.
2. Add or update tests.
3. Run `python -m unittest discover -s tests -v`.
4. Update `docs/USER_GUIDE.md` if user-visible behavior or module ownership changed.
5. Update `README.md` if the quick-start path changed.

## Roadmap Notes

Implemented:

- Optional `--engagement-id`; legacy `--roe` alias retained.
- Package entrypoints `crimson` and `crimsonweb`.
- `scan`, `web`, `doctor`, `config`, and `init` subcommands.
- Modularized audit, state, ports, reporting, web checks, egress, CVE, discovery, probes, and service detection.

Pending:

- Automatic profile/config loading.
- Dedicated `report` subcommand.
- Shell completion.
- Man page generation.
- `.deb` packaging after pipx workflow is stable.
