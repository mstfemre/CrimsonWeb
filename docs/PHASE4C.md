# Phase 4C — Evidence-based API authorization verification

Follow-up delivery: [Phase 4C.1](PHASE4C1.md) adds a web workflow CLI, HTTPS
credential enforcement, audit minimization and bounded execution admission.
Its newer validation result is 785 standard tests; the results below describe
the preceding Phase 4C delivery.

Validation date: **12 October 2026**.

Phase 4C adds operator-approved, read-only BOLA/IDOR comparison on top of the
existing scope engine, Phase 4B discovery, Phase 5A privacy controls and local
Ollama provider. Phase 4D and subsequent modules have not been implemented.

## Architecture

The `src/crimsonweb/api/verification/` package contains:

| File | Responsibility |
|---|---|
| `catalog.py` | Fixed catalog: `bola_cross_owner_read`, GET, category `auth`. |
| `models.py` | Bounded contracts, approval, in-memory identities, evidence and reports. |
| `targets.py` | Candidates from persisted discovery or validated offline OpenAPI. |
| `planner.py` | Enum-constrained proposals; known endpoint and evidence references only. |
| `comparison.py` | Deterministic comparison outcomes, independent of the model. |
| `executor.py` | Three controlled GETs through `WorkspaceService.stream`. |
| `credentials.py` | One authentication header validated against the shared allowlist. |
| `store.py` | Atomic persistence and workspace isolation. |
| `service.py` | Planning, approval, serial execution, cancellation and shutdown. |
| `routes.py` | Authenticated workspace-qualified API and non-echoing validation errors. |
| `__init__.py` | Package boundary. |

The model receives masked endpoint metadata and a fixed test catalog. It may
select only known catalog IDs, endpoint references and each endpoint's own
source-evidence references. It cannot introduce a URL, credential, new reference,
request body, policy change or arbitrary test. Unknown/duplicated references,
extra fields and ineligible targets are rejected by deterministic validation.
Only GET candidates with exactly one resolvable object path parameter are eligible.

Verification shares the same `AIService.gate` as existing analysis jobs, including
concurrency, timeout and rolling call limits. Candidate metadata is bounded by
`max_input_bytes` before generation. Ineligible candidates are excluded from the
model input and permitted-reference schema. Ollama/Gemma settings and the existing
analysis contracts have not been changed.

When AI is disabled or planning fails, eligible catalog proposals are seeded
deterministically for operator review. A planner failure is visible in plan
`limitations` as `model_planner_unavailable_operator_seeded`; it is not reported as
successful model planning. The planner name is `operator` for that fallback.

## Comparison and false-positive controls

The operator supplies two distinct authorized test identities and two distinct
private test-object IDs. The fixed flow is:

1. A reads A's own object.
2. B reads B's own object.
3. A reads B's object.

A finding is classified as `bola_confirmed` only when all three return 200, the
controls contain distinct nonempty scalar binding values, and the cross response's
binding value exactly matches B's control value with the same Python type.
The field is a single **top-level JSON property**, not JSONPath. Missing/null,
boolean, array, identical-control, duplicate-key or oversized data cannot confirm
a finding. Response data is bounded to 65,536 bytes during consumption.

Approval requires `private_records_only: true`. This is an operator declaration
that these are private test records and A is not entitled to read B's record;
it is persisted with the plan and reported. A response comparison cannot establish
the intended permission model independently. Public/shared records must not be
submitted as private objects. Confirmation is conditional on correct operator
supplied ownership and permission expectations.

| Observation | Outcome |
|---|---|
| Successful controls, distinct values, cross 200 matching B | Confirmed finding, subject to declared private-record expectations. |
| Cross 401 after successful controls | Access denied for this observation; no finding. |
| Cross 200 without unambiguous binding | Unverified; no finding. |
| Other cross status | Inconclusive; no finding. |
| Failed control or network/response transport failure | Stop; plan `failed`; no success claim. |
| 403, 429 or redirect | Safe-stop; plan `halted`; neutral reason; no automatic WAF attribution. |

## Scope and credential boundaries

Every request goes through the existing central `WorkspaceService.stream` admission
path. It repeats domain/IP/CNAME/path/method/category/port, SSRF, policy validity,
shared budget/concurrency/rate-limit and DNS checks. The connection is pinned to an
admitted address. Redirects are not followed. No retries, IP rotation, proxying or
bypass behavior was added. Existing defense notifications halt the shared policy.

The catalog issues GET only and rejects candidates flagged as sensitive operations.
GET is not a guarantee that an incorrectly designed server cannot change state;
the operator must approve only genuinely read-only application operations.

Approval records the operator, scope source, hashed target origin, exact binding
field and private-record declaration. Execution cannot change the approved origin
or binding field. Candidates with discovery/OpenAPI origin provenance cannot be
rebound to another origin at approval. An explicitly offline candidate requires
an operator-assigned origin, which still undergoes scope admission per request.

Credentials are supplied only in the execute request, after approval. They remain
in process memory and are never deliberately persisted, logged, fingerprinted or
sent to the model. Header injection permits only `Authorization`, `Cookie` or
`X-API-Key`, with value/injection validation repeated at `pinned_response`.
Structural headers cannot be supplied by the operator through this interface.

No raw response body, binding value or derived binding hash is retained. Evidence
contains status codes, boolean comparison signals, fixed reasons, identity role
labels and source references. Persisted report/evidence contracts forbid additional
raw-body/credential fields. Invalid API payloads receive a fixed non-echoing 422.
Python does not guarantee secure erasure of immutable strings; process dumps,
external HTTP debug loggers, reverse proxies and operator-provided metadata are
outside that in-memory secrecy guarantee. Do not put secrets in approval metadata.

## Persistence and lifecycle

Migration `0006_phase4c`, following `0005_phase5a`, creates:

- `verification_plans`
- `verification_tests`
- `verification_evidence`
- `verification_findings`

Composite foreign keys enforce workspace/plan ownership. Result persistence is
atomic per test and verifies matching evidence/finding relationships. The downgrade
refuses while any plan is executing and otherwise removes only these tables.

The existing lease table is unchanged. Shared budgets and concurrency already
count ownerless leases. Graceful cancellation releases admitted slots; shutdown
cancels/drains inline execution tasks before repository closure. Cancellation is
checked before each next request and cannot retract a request already sent.

A hard process crash may leave an executing plan and ownerless lease unresolved.
There is no automatic restart/resume or lease release after an unknown in-flight
request. Operator reconciliation is required; budget is never reset automatically.

## API and usage

Base path: `/api/v1/workspaces/{workspace_id}/verification`.
Existing API authentication, exact Host allowlist and exception handling apply.
The local API token is separate from the two target-application credentials.

| Method/path | Purpose |
|---|---|
| `POST /plans` | Create candidates from a discovery job or offline OpenAPI. |
| `POST /plans/{id}/approve` | Approve origin, binding field and private test records. |
| `POST /plans/{id}/execute` | Supply in-memory credentials and execute; 409 without matching approval. |
| `POST /plans/{id}/cancel` | Cancel pending/approved plans or request cancellation while executing. |
| `GET /plans` | Paginated list, optional status filter. |
| `GET /plans/{id}` | Plan detail. |
| `GET /plans/{id}/tests` | Paginated test results. |
| `GET /plans/{id}/evidence` | Paginated minimized evidence. |
| `GET /plans/{id}/findings` | Paginated confirmed findings. |
| `GET /plans/{id}/report` | Plan/report including declared permission expectations. |

First create a workspace and an explicitly approved scope policy using the existing
workspace API. For the synthetic lab below, the policy must allow GET, category
`auth`, `lab.test:8001`, the resolved lab address and `/api/objects/*`.
Private network access is supported only for an explicitly configured owned/lab
workspace, never implicitly by importing an endpoint.

Create body (replace the policy UUID):

```json
{
  "policy_id": "<workspace-policy UUID>",
  "source": "openapi",
  "openapi_document": {
    "openapi": "3.1.0",
    "paths": {
      "/api/objects/{object_id}": {
        "get": {
          "parameters": [{"name": "object_id", "in": "path", "schema": {"type": "string"}}],
          "responses": {"200": {"description": "Synthetic test record"}}
        }
      }
    }
  }
}
```

For discovery reuse, use `source: "discovery"` with `discovery_job_id` from the same
workspace. OpenAPI parsing reuses the existing importer and fetches no servers or
external references; imported examples/descriptions are discarded. Candidates
never grant execution authority.

Approval body:

```json
{
  "approved_by": "lab-operator",
  "scope_source": "owned synthetic laboratory",
  "base_url": "http://lab.test:8001",
  "owner_binding_field": "owner_id",
  "private_records_only": true
}
```

Execute body, supplied after approval (placeholder credentials):

```json
{
  "base_url": "http://lab.test:8001",
  "owner_binding_field": "owner_id",
  "identities": [
    {"role": "identity_a", "header_name": "Authorization", "header_value": "<A token>", "owner_object_id": "111"},
    {"role": "identity_b", "header_name": "Authorization", "header_value": "<B token>", "owner_object_id": "222"}
  ]
}
```

Only role labels and comparison outcomes appear in the report. No ready-to-replay
credential-bearing request or raw response is exported. Reproduction requires the
operator to re-supply test identities/objects in a newly approved plan.

## Installation and migrations

```powershell
.venv\Scripts\python.exe -m pip install -e ".[api,dev]"
.venv\Scripts\python.exe -m alembic -c alembic.ini heads
# Back up an existing SQLite DB before a manual Alembic upgrade.
.venv\Scripts\python.exe -m alembic -c alembic.ini upgrade head
$env:CRIMSON_API_TOKEN = "<strong random token>"
.venv\Scripts\python.exe -m uvicorn crimsonweb.api.app:app --app-dir src --host 127.0.0.1 --port 8000 --no-proxy-headers
```

Application startup via `Repository.initialize()` automatically backs up an existing
behind-head SQLite DB before upgrading it. Manual Alembic commands bypass that
automatic backup. The working project's actual database was not migrated during
this verification; migrations were exercised on isolated test databases.

## Verified results — 12 October 2026

- Incoming implementation: **729 passed, 4 deselected** in 62.22 seconds.
- Final standard suite: **759 passed, 5 deselected, 0 failed**, 77.27 seconds.
  This includes the original 677 tests and **82 Phase 4C tests** (52 incoming,
  30 additional hardening checks). One existing Starlette TestClient deprecation warning.
- Phase 4C-only standard suite: **82 passed**, 682 deselected.
- Changed/new Python files: **Ruff passed**.
- Whole-repository Ruff: **124 findings**, all in unchanged files. Whole-repository
  lint is not clean; see `reports/phase4c/ruff_summary.json`.
- Compilation: `compileall -q src tests` passed.
- Real-model opt-in suite: **5 skipped**, 759 deselected. The local Ollama tags
  endpoint was unreachable. No real Gemma/verification-planner result is claimed.
- Migration metadata equivalence, guarded downgrade/upgrade, workspace API
  isolation, file-backed SQLite reopen, secret non-retention, approval binding,
  invalid payload redaction, shared concurrency/budget, DNS/IP/CNAME changes,
  forbidden path/method, private-network rejection, expiry, cancellation, shutdown,
  ambiguous response handling and 403/429/redirect stop are covered by automated tests.

Saved standard-suite artifact: `reports/phase4c/standard_tests.xml`.

```powershell
.venv\Scripts\python.exe -m pytest -m "not ollama" -q --junitxml=reports/phase4c/standard_tests.xml
.venv\Scripts\python.exe -m pytest -k phase4c -m "not ollama" -q
.venv\Scripts\python.exe -m pytest -m ollama -q
.venv\Scripts\python.exe -m compileall -q src tests
.venv\Scripts\ruff.exe check src/crimsonweb/api/verification src/crimsonweb/api/migrations/versions/0006_phase4c.py src/crimsonweb/api/app.py src/crimsonweb/api/database.py src/crimsonweb/api/engine.py src/crimsonweb/api/workspaces/service.py tests/test_phase4c* tests/verification_helpers.py tests/test_phase2_database.py tests/test_phase5a_database.py
```

For a future explicit local Gemma check, keep the existing optimized configuration:

```powershell
$env:CRIMSON_TEST_OLLAMA = "1"
$env:CRIMSON_AI_ENABLED = "true"
$env:CRIMSON_OLLAMA_MODEL = "gemma4:26b"
$env:CRIMSON_OLLAMA_THINK = "false"
$env:CRIMSON_AI_CONTEXT_TOKENS = "8192"
$env:CRIMSON_AI_MAX_OUTPUT_TOKENS = "4096"
$env:CRIMSON_AI_TIMEOUT = "300"
$env:CRIMSON_AI_MAX_CONCURRENCY = "1"
.venv\Scripts\python.exe -m pytest -m ollama -q
```

This includes the new opt-in `test_phase4c_ollama_integration.py` planner check and
existing analysis/privacy checks. All planning input is synthetic; no third-party
targets are contacted by verification tests. Do not interpret skips as passes.

## Files and limits

New: the eleven verification package files above, migration `0006_phase4c.py`,
`tests/verification_helpers.py`, fifteen `tests/test_phase4c_*.py` modules,
this document and test/lint report artifacts.
Changed: `api/app.py`, `api/database.py`, `api/engine.py`,
`api/workspaces/service.py`, migration-head assertions in `test_phase2_database.py`
and `test_phase5a_database.py`, and `README.md`.

The feature has one catalog test and serial inline execution. It does not support
HAR/Burp/ZAP import, login workflows, nested response selectors, per-endpoint object
pairs, stored credentials or state-changing tests. Status-based stop does not detect
every possible WAF block/challenge returned with HTTP 200. Matching evidence remains
conditional on operator-supplied private-record semantics. Graceful shutdown does
not provide crash recovery or guaranteed physical memory erasure. Existing API
bearer authentication is reused; per-user tenant RBAC is not newly implemented.

## Concrete Phase 4D preparation plan

1. Introduce background run/worker ownership only with atomic claiming and
   crash-recovery tests; extend lease ownership at that point if needed.
2. Bind object pairs and declared authorization expectations to each approved
   endpoint/test, with explicit plan revision checks.
3. Add a redacting, bounded HAR/Burp/ZAP importer; use imported traffic as
   candidates only and never as execution permission.
4. Extend the fixed read-only catalog and expected-permission matrix, validating
   each test with vulnerable and correctly secured local lab variants.
5. Complete real Gemma planning and existing analysis regression before claiming
   model compatibility for the new subsystem.

These are preparation notes only. No Phase 4D implementation was started.
