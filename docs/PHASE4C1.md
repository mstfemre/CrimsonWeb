# Phase 4C.1 — Web/API workflow and privacy hardening

12 October 2026. CrimsonWeb now exposes a web verification workflow through the
CLI alongside the existing scanner. The new workflow does not perform a port scan.
It uses the existing workspace API, scope engine, optional local LLM planner and
deterministic three-read authorization verifier. This is the first web-focused
delivery; it is not a comprehensive automatic vulnerability scanner.

## What changed

- `crimsonweb web plan/approve/execute/report/cancel` uses the local authenticated
  API. Inputs come from Phase 4B discovery records or a bounded offline OpenAPI file.
  Target requests remain server-side behind scope, DNS, budget and safe-stop controls.
- CLI API origins accept only HTTP(S) loopback IP literals, without userinfo,
  query, fragment or path prefix. Environment proxies and redirects are disabled.
  Secrets and raw API error bodies are not printed. Responses are bounded to 1 MiB.
- Execute reads the approved plan before accepting test identities. It checks the
  approved origin/binding field, then requests private object IDs and credentials
  interactively without echo. There are no target credential command-line options.
  Noninteractive input and getpass echo fallback are rejected. No credential file
  or durable credential queue was added. The API token comes from `CRIMSON_API_TOKEN`.
- The shared sanitizer and AI secret-key rules now cover `X-API-Key`, `client_secret`,
  `id_token`, `session_id`, `header_value` and additional aliases. Common bearer and
  quoted/unquoted credential assignments are redacted in log text. Legacy proxy
  validation errors no longer interpolate unredacted URLs.
- Legacy HTTP request controllers stop the current HTTP engagement on defense
  signals. A stop prevents retry and subsequent paths, including when a fingerprinting
  caller inspects the blocked response. HTTP 403/429 always stop; the old flag no
  longer permits continued requests. Ban events no longer request a Tor identity change.
  Explicit legacy operator routing options remain; the new workflow is direct and
  has no evasion or stealth mechanism.
- Credential-bearing target requests require HTTPS. The central admission path
  allows HTTP only for `program_type=lab`, explicit private-network scope permission,
  and admitted private IPs. Public destinations never get plaintext credentials,
  even in a lab workspace. The transport independently rejects a public HTTP
  destination even if an internal caller sets the lab override flag.
- Verification scope audits retain neither observed IP lists nor request URL
  fingerprints. Authorization reason, policy revision and relational audit IDs
  remain available. Existing records and other legacy audit flows were not purged.
- Execute rejects overload before reading the credential body. There is one admitted
  API execution and no waiting credential queue. The execution payload cap is
  16 KiB; plan import remains 1 MiB. Direct service calls also fail immediately if busy.

## Web-first usage

Install API dependencies and start the existing authenticated local API as described
in `PHASE4C.md`. An existing disk database must be backed up before manual migration.
Application startup can apply existing migration `0006_phase4c`; this delivery adds
no migration and did not upgrade the real project database.

First create a workspace and a valid, operator-approved policy. Discovery records,
the target origin, GET methods, `auth` category, paths, ports, resolved networks,
time window and budget must all be authorized. For a private local lab, use a lab
workspace and explicit private network permission. Importing a schema is not authorization.

```powershell
# Inspect the workflow without running a scan.
.venv\Scripts\python.exe -m crimsonweb web --help

# Set the local API token through your existing environment configuration.
# Replace the UUID placeholders with records from your workspace.
.venv\Scripts\python.exe -m crimsonweb web plan --workspace <workspace-uuid> --policy <policy-uuid> --openapi docs/examples/web_lab_openapi.json

# Alternative: reuse Phase 4B discovery instead of importing a new schema.
.venv\Scripts\python.exe -m crimsonweb web plan --workspace <workspace-uuid> --policy <policy-uuid> --discovery-job <job-uuid>

# Review the plan and explicitly approve private test-record semantics.
.venv\Scripts\python.exe -m crimsonweb web approve --workspace <workspace-uuid> --plan <plan-uuid> --base-url https://your-authorized-host --binding-field owner_id --approved-by operator --scope-source "your authorization reference" --private-records-only

# Object IDs and authentication values are entered through hidden prompts.
.venv\Scripts\python.exe -m crimsonweb web execute --workspace <workspace-uuid> --plan <plan-uuid> --base-url https://your-authorized-host --binding-field owner_id

.venv\Scripts\python.exe -m crimsonweb web report --workspace <workspace-uuid> --plan <plan-uuid>
.venv\Scripts\python.exe -m crimsonweb web cancel --workspace <workspace-uuid> --plan <plan-uuid>
```

The example spec is synthetic; it is not a running target. The above commands do
not create a lab application or authorize a hostname. Port-scan options and legacy
`web http://localhost:8000` invocations remain available. Exit 2 signals a failed,
halted, cancelled or incomplete workflow; exit 130 indicates interruption. Findings
are represented in the report rather than encoded as process failure.

The AI planner uses existing Ollama settings only when enabled. No production model,
context, output-token or thinking defaults were changed. No Ollama/model download,
restart or target scan was performed in this delivery.

## Validation

- Baseline from the preceding delivery: 759 standard tests.
- Final suite: **785 passed, 0 failed, 5 deselected**, 66.21 seconds.
- **26 additional tests**: 18 privacy/safe-stop/admission checks and 8 web CLI checks.
  Existing 759 tests remain passing.
- End-to-end CLI test uses the real FastAPI contracts and a synthetic target
  transport. Plan, approval, execution and report confirm the deliberately vulnerable
  laboratory BOLA case without port discovery or third-party traffic.
- Tests cover secret aliases, error redaction, 403/429 stop across paths/retries,
  no identity change after ban, HTTPS/lab boundaries, scope audit minimization,
  busy-before-body admission, smaller execute payload, local-only CLI API origin,
  credential-free output and preserved legacy command dispatch.
- Ruff passes on the new CLI, shared sanitizer, verification package, touched
  workspace/API transport files and new tests. Full-repository Ruff still exits 1:
  **123 existing findings**, including legacy `core_engine.py`/`egress.py` findings.
  This is not reported as a clean whole-repository lint result.
- `compileall -q src tests` and `git diff --check` passed.
- Opt-in real-model suite: **5 skipped**. Live Gemma planning is not claimed tested.
- One existing Starlette/TestClient deprecation warning remains.

Artifacts: `reports/phase4c1/standard_tests.xml`, `reports/phase4c1/ruff_summary.json`.

```powershell
.venv\Scripts\python.exe -m pytest -m "not ollama" -q --junitxml=reports/phase4c1/standard_tests.xml
.venv\Scripts\python.exe -m pytest tests/test_phase4c1_privacy.py tests/test_web_workflow_cli.py -q
.venv\Scripts\python.exe -m pytest -m ollama -q
.venv\Scripts\python.exe -m compileall -q src tests
```

## Files and remaining work

New: `src/crimsonweb/web_cli.py`, `tests/test_web_workflow_cli.py`,
`tests/test_phase4c1_privacy.py`, `docs/examples/web_lab_openapi.json`, this document,
and validation artifacts.

Changed in this delivery: `cli.py`, `core_engine.py`, `egress.py`, `privacy.py`,
`api/engine.py`, `api/workspaces/service.py`, `api/workspaces/store.py`,
`api/verification/executor.py`, `service.py`, `routes.py`, the transport-header test
fixture, and documentation links. Earlier uncommitted Phase 4C work was preserved.

Still limited to one read-only BOLA/IDOR test family. Real-model planning, user/RBAC,
enforced retention, encrypted storage/backups, HAR/Burp/ZAP import, endpoint-specific
identity/object pairs and crash-attributed verification lease recovery remain open.
GET semantics and intended authorization still require correct operator declarations.
No generic secret detector can guarantee recognition of every arbitrary sensitive
string; schema minimization and storage boundaries remain essential. Old persisted
data has not been retrospectively cleaned. Privacy is not network anonymity.

Next delivery should bind object pairs and permission expectations per approved
endpoint, then add a redacting traffic importer and evaluate additional fixed
read-only catalog tests on vulnerable and secured local fixtures. Live-model
compatibility and privacy/deployment gates must remain explicit.
