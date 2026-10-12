"""Production guard/planner/executor with real HTTPX sockets, not MockTransport."""

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

import httpx

from crimsonweb.api.database import Repository
from crimsonweb.api.verification.models import (
    ExecuteRequest,
    PlanApproval,
    VerificationPlanCreate,
)
from crimsonweb.api.verification.service import VerificationService
from crimsonweb.api.workspaces.models import (
    AuthorizationRequest,
    ProgramPolicy,
    WorkspaceCreate,
)
from crimsonweb.api.workspaces.service import WorkspaceService

from .app import write_json


class LoopbackTransport(httpx.AsyncBaseTransport):
    """Real transport with per-lab trust and an independent destination boundary."""

    def __init__(self, lab):
        self.context = lab.client_context
        self.origins = {lab.http_origin, lab.https_origin}
        self.active = []

    async def handle_async_request(self, request):
        origin = f"{request.url.scheme}://{request.url.host}:{request.url.port}"
        if origin not in self.origins:
            raise ValueError("Transport destination outside this loopback lab")
        transport = httpx.AsyncHTTPTransport(verify=self.context, retries=0, trust_env=False)
        self.active.append(transport)
        return await transport.handle_async_request(request)

    async def aclose(self):
        for transport in self.active:
            await transport.aclose()
        self.active.clear()


def openapi(origin, mode, family):
    return {
        "openapi": "3.0.3", "info": {"title": "Owned lab", "version": "1"},
        "servers": [{"url": origin}],
        "paths": {
            f"/{mode}/{family}": {"get": {
                "parameters": [{"name": "q", "in": "query", "schema": {"type": "string"}}],
                "responses": {"200": {"description": "Local fixture"}},
            }}
        },
    }


async def verify_laboratory(lab, output_path):
    """Create isolated DB/scope; compare detector signals against server events."""
    repository = Repository("sqlite://")
    manager = None
    transport = LoopbackTransport(lab)
    try:
        repository.initialize()
        # IP literals use SystemResolver's literal path: no OS/public DNS lookup.
        guard = WorkspaceService(repository)
        now = datetime.now(UTC)
        workspace = guard.store.create_workspace(
            WorkspaceCreate(name="Disposable socket laboratory", program_type="lab"), now,
        )
        policy = guard.store.write_policy(workspace.id, ProgramPolicy(
            target_scope={
                "allowed_networks": ["127.0.0.1/32"],
                "allowed_paths": ["/vulnerable/*", "/secure/*"],
                "allowed_methods": ["GET"],
                "allowed_ports": [urlsplit(lab.http_origin).port, urlsplit(lab.https_origin).port],
                "allowed_categories": ["xss", "sqli", "web_observation"],
                "allowed_query_parameters": ["q", "name"], "allow_private_networks": True,
            },
            rate_limit_per_minute=120, maximum_concurrency=1, maximum_request_budget=100,
            valid_from=now - timedelta(minutes=1), valid_until=now + timedelta(minutes=10),
            operator_approved=True, approved_by="owned-lab-runner",
            scope_source="This process owns both loopback servers and all fixtures",
        ), now)
        manager = VerificationService(repository, guard, transport=transport)
        reports, comparisons, checks = [], [], []
        for origin in (lab.http_origin, lab.https_origin):
            for mode in ("vulnerable", "secure"):
                for family, catalog, signal in (
                    ("xss", "xss_reflection_probe", "html_injection_suspected"),
                    ("sqli", "sql_error_probe", "sql_injection_suspected"),
                ):
                    start = len(lab.truth.events)
                    plan = await manager.create_plan(workspace.id, VerificationPlanCreate(
                        policy_id=policy.id, source="openapi", openapi_document=openapi(origin, mode, family),
                        catalog_ids=[catalog],
                    ))
                    manager.approve_plan(workspace.id, plan.id, PlanApproval(
                        base_url=origin, owner_binding_field="owner_id", approved_by="owned-lab-runner",
                        scope_source="Disposable fixtures created by this process",
                    ))
                    await manager.execute_plan(workspace.id, plan.id, ExecuteRequest(
                        base_url=origin, owner_binding_field="owner_id",
                    ))
                    report = manager.store.report(workspace.id, plan.id)
                    reports.append(report.model_dump(mode="json"))
                    selected = lab.truth.events[start:]
                    test = report.tests[0]
                    truth_signal = any(e["triggered"] for e in selected)
                    observed = test.outcome == signal
                    expected_count = 2 if family == "xss" else 3
                    matched = (report.status == "completed" and test.status == "completed"
                               and len(selected) == expected_count and truth_signal == (mode == "vulnerable")
                               and observed == truth_signal
                               and (observed or test.outcome == "no_signal_observed"))
                    comparisons.append({
                        "scheme": urlsplit(origin).scheme, "mode": mode, "family": family,
                        "test_id": str(test.id), "outcome": test.outcome,
                        "ground_truth_event_ids": [e["id"] for e in selected],
                        "ground_truth_triggered": truth_signal, "matched": matched,
                    })

                # Traversal is NOT a production catalog test. Exercise the real
                # guard + pinned transport only, confined to fixture files.
                for payload, expected in (("hello.txt", "LAB_PUBLIC_FILE"),
                                          ("../private.txt", "LAB_PRIVATE_FIXTURE_ONLY"),
                                          ("../../outside.txt", None)):
                    async with guard.stream(workspace.id, policy.id, AuthorizationRequest(
                        url=origin + f"/{mode}/files", category="web_observation",
                        query_parameters={"name": payload},
                    ), transport, observation_only=True, minimize_audit=True) as response:
                        body = (await response.aread()).decode()
                        should_read = expected is not None and (payload == "hello.txt" or mode == "vulnerable")
                        event = lab.truth.events[-1]
                        checks.append({"scheme": urlsplit(origin).scheme, "mode": mode,
                                       "family": "path_traversal", "source": "lab_guarded_check_not_catalog",
                                       "ground_truth_event_id": event["id"], "status": response.status_code,
                                       "matched": ((response.status_code == 200 and body == expected) if should_read
                                                   else response.status_code == 404)
                                                  and event["triggered"] == (should_read and payload != "hello.txt")})

                # Independently demonstrate changed SQL semantics on dummy rows.
                async with guard.stream(workspace.id, policy.id, AuthorizationRequest(
                    url=origin + f"/{mode}/sqli", category="sqli",
                    query_parameters={"q": "1' OR '1'='1"},
                ), transport, observation_only=True, minimize_audit=True) as response:
                    rows = json.loads(await response.aread())["records"]
                    event = lab.truth.events[-1]
                    checks.append({"scheme": urlsplit(origin).scheme, "mode": mode, "family": "sqli",
                                   "source": "lab_sql_semantics_control", "ground_truth_event_id": event["id"],
                                   "matched": response.status_code == 200
                                              and len(rows) == (2 if mode == "vulnerable" else 0)
                                              and event["triggered"] == (mode == "vulnerable")})
        result = {
            "schema_version": "local-lab.v1", "run_id": lab.truth.run_id,
            "transport": "real_loopback_http_and_verified_tls",
            "all_matched": all(c["matched"] for c in comparisons + checks),
            "comparisons": comparisons, "lab_controls": checks, "verification_reports": reports,
            "limitations": ["browser_script_execution_not_measured", "traversal_not_in_production_catalog",
                            "LLM_disabled_operator_planning", "raw_payloads_only_in_separate_lab_ground_truth"],
        }
        write_json(output_path, result)
        return result
    finally:
        if manager:
            await manager.shutdown()
        await transport.aclose()
        repository.engine.dispose()
