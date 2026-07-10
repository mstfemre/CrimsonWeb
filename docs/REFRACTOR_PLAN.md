# CrimsonWeb Refactor Plan

This plan keeps scanner behavior stable while the monolithic engine is split
into maintainable modules.

## Phase 1: Packaging and CLI Safety

- Keep `src/crimsonweb/core_engine.py` as the working engine.
- Keep `core_engine.py` as a backward-compatible launcher.
- Make `--engagement-id` optional and keep `--roe` as a legacy alias.
- Add smoke tests around CLI parsing and report metadata.

## Phase 2: Low-Risk Module Split

Move pure helpers first because they are easiest to test:

- `crimsonweb/models.py`: `Target`, `ServiceResult`, `WebFinding`, response models. Done.
- `crimsonweb/audit.py`: log setup, redaction, JSONL audit writer. Done.
- `crimsonweb/state.py`: checkpoint/resume state handling. Done.
- `crimsonweb/ports.py`: port parsing, top-port table, target resolution. Done.
- `crimsonweb/reporting.py`: executive Markdown report. Done.
- `crimsonweb/web_checks.py`: header, cookie, CORS, sensitive path checks. Done.
- `crimsonweb/egress.py`: proxy/Tor routing, pacing, block backoff. Done.
- `crimsonweb/cve.py`: CPE extraction and NVD lookup/cache. Done.
- `crimsonweb/formatting.py`: shared banner/evidence formatting. Done.

Each move should include import-only tests and one behavior test.

## Phase 3: Engine Boundaries

Split active runtime components after helpers are covered:

- `crimsonweb/discovery/connect.py`: async TCP connect scanner. Done.
- `crimsonweb/discovery/syn.py`: privileged SYN scanner backend. Done.
- `crimsonweb/discovery/udp.py`: UDP probes and result classification. Done.
- `crimsonweb/probes/registry.py`: service probe registry. Done.
- `crimsonweb/probes/builtin.py`: SSH, FTP, SMTP, POP3, MySQL, TLS, SMB, RDP classifiers. Done.
- `crimsonweb/service_detection.py`: service fingerprint orchestration and web-service checks. Done.

## Phase 4: Professional CLI

- Add subcommands: `scan`, `web`, `doctor`, `init`, `config`. Done. `report` remains pending.
- Add profile loading from project/global config.
- Add shell completion and man page generation.
- Add `pipx` install workflow first, then `.deb` packaging.

## Guardrails

- Do not add IDS/IPS bypass or stealth behavior.
- Default behavior should be clear, rate-limited, and lab/authorized focused.
- External scanner binaries remain out of scope.
- Probe results must include confidence and evidence before CVE correlation is
  treated as actionable.
