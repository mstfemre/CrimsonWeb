"""Web verification workflow client. Target traffic stays behind the API guard."""

import argparse
import getpass
import ipaddress
import json
import os
import sys
import warnings
from pathlib import Path
from uuid import UUID

import httpx

from .api.verification.catalog import catalog_ids
from .api.verification.models import (
    ExecuteRequest,
    PlanApproval,
    VerificationPlan,
    VerificationReport,
)
from .api.verification.targets import approved_origin

ACTIONS = frozenset({"plan", "approve", "execute", "report", "cancel", "next"})
MAX_BYTES = 1048576


def parser():
    root = argparse.ArgumentParser(prog="crimsonweb web", description=(
        "Authorized web/API discovery-to-verification workflow; no port scan."
    ))
    actions = root.add_subparsers(dest="action", required=True)
    for name in sorted(ACTIONS):
        action = actions.add_parser(name)
        action.add_argument("--api", default="http://127.0.0.1:8000",
                            help="Local CrimsonWeb API origin; loopback IP only")
        action.add_argument("--workspace", type=UUID, required=True)
        if name == "plan":
            action.add_argument("--policy", type=UUID, required=True)
            source = action.add_mutually_exclusive_group(required=True)
            source.add_argument("--openapi", type=Path)
            source.add_argument("--discovery-job", type=UUID)
            catalogs = action.add_mutually_exclusive_group()
            catalogs.add_argument("--catalog", action="append", choices=catalog_ids())
            catalogs.add_argument("--top10", action="store_true", help="Select implemented Top10-related tests; unsupported categories remain not_tested")
            action.add_argument("--max-tests", type=int, default=50)
            action.add_argument("--require-model", action="store_true",
                                help="Fail planning if the model cannot select tests; inherited by follow-ups")
        else:
            action.add_argument("--plan", type=UUID, required=True)
        if name in {"approve", "execute"}:
            action.add_argument("--base-url", required=True, help="Authorized target origin")
            action.add_argument("--binding-field", required=True)
        if name == "approve":
            action.add_argument("--approved-by", required=True)
            action.add_argument("--scope-source", required=True)
            action.add_argument("--private-records-only", action="store_true", help="Required for BOLA; declares private test-record expectations")
        if name == "execute":
            action.add_argument("--header-name", choices=["Authorization", "Cookie", "X-API-Key"],
                                default="Authorization")
            action.add_argument("--anonymous", action="store_true", help="No test credentials; unavailable for BOLA plans")
    return root


def local_api(value):
    url = httpx.URL(value)
    if (url.scheme not in {"http", "https"} or url.userinfo or url.query or url.fragment
        or url.path != "/" or not ipaddress.ip_address(url.host).is_loopback):
        raise ValueError("Local API origin required")
    return str(url).rstrip("/")


def exchange(client, method, path, payload=None):
    with client.stream(method, path, json=payload) as response:
        if response.status_code >= 300:
            raise ValueError("API rejected request")
        body = bytearray()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > MAX_BYTES:
                raise ValueError("API response too large")
            body.extend(chunk)
    return json.loads(body)


def main(argv=None, *, transport=None, secret_reader=None, interactive=None):
    args = parser().parse_args(argv)
    try:
        api = local_api(args.api)
        token = os.getenv("CRIMSON_API_TOKEN", "").strip()
        if not token:
            raise ValueError("Local API token required")
        base = f"/api/v1/workspaces/{args.workspace}/verification/plans"
        path = base if args.action == "plan" else f"{base}/{args.plan}"
        with httpx.Client(base_url=api, transport=transport, trust_env=False,
                          follow_redirects=False, timeout=300,
                          headers={"Authorization": f"Bearer {token}"}) as client:
            if args.action == "plan":
                payload = {"policy_id": str(args.policy), "max_tests": args.max_tests,
                           "catalog_ids": catalog_ids() if args.top10 else args.catalog or ["bola_cross_owner_read"],
                           "require_model": args.require_model}
                if args.openapi:
                    with args.openapi.open("rb") as handle:
                        document = handle.read(MAX_BYTES + 1)
                    if len(document) > MAX_BYTES:
                        raise ValueError("OpenAPI document too large")
                    payload.update(source="openapi", openapi_document=json.loads(document))
                else:
                    payload.update(source="discovery", discovery_job_id=str(args.discovery_job))
                result = exchange(client, "POST", path, payload)
            elif args.action == "approve":
                payload = PlanApproval(
                    approved_by=args.approved_by, scope_source=args.scope_source,
                    base_url=args.base_url, owner_binding_field=args.binding_field,
                    private_records_only=args.private_records_only,
                ).model_dump(mode="json")
                result = exchange(client, "POST", path + "/approve", payload)
            elif args.action == "execute":
                plan = VerificationPlan.model_validate(exchange(client, "GET", path))
                if plan.status != "approved":
                    raise ValueError("Approve the plan before supplying test credentials")
                if (approved_origin(args.base_url) != plan.approved_origin_ref
                    or args.binding_field != plan.approved_binding_field):
                    raise ValueError("Execution parameters must match approval")
                if args.anonymous and any(p.catalog_id == "bola_cross_owner_read" for p in plan.proposals):
                    raise ValueError("BOLA requires test identities")
                if not args.anonymous and not (sys.stdin.isatty() if interactive is None else interactive):
                    raise ValueError("Interactive credential entry required")
                read = secret_reader or getpass.getpass
                identities = []
                for role in (() if args.anonymous else ("identity_a", "identity_b")):
                    with warnings.catch_warnings():
                        warnings.simplefilter("error", getpass.GetPassWarning)
                        object_id = read(f"{role} own private test-object ID (hidden): ")
                        credential = read(f"{role} {args.header_name} value (hidden): ")
                    identities.append({"role": role, "header_name": args.header_name,
                                       "header_value": credential, "owner_object_id": object_id})
                request = ExecuteRequest(base_url=args.base_url,
                                         owner_binding_field=args.binding_field,
                                         identities=identities)
                result = exchange(client, "POST", path + "/execute", request.model_dump(mode="json"))
            elif args.action == "cancel":
                result = exchange(client, "POST", path + "/cancel")
            elif args.action == "next":
                result = exchange(client, "POST", path + "/next")
            else:
                report = VerificationReport.model_validate(exchange(client, "GET", path + "/report"))
                print(json.dumps({"plan_id": str(report.plan_id), "status": report.status,
                                  "findings": len(report.findings),
                                  "owasp_edition": report.owasp_edition,
                                  "coverage": [{"category": row.category, "status": row.status} for row in report.top10_coverage],
                                  "results": [{"outcome": test.outcome, "confidence": test.confidence,
                                               "reason": test.reason} for test in report.tests]}))
                return 0 if report.status == "completed" else 2
        plan = VerificationPlan.model_validate(result)
        print(json.dumps({"plan_id": str(plan.id), "status": plan.status,
                          "planner": plan.planner, "proposed_tests": len(plan.proposals)}))
        return 2 if plan.status in {"failed", "halted", "cancelled"} else 0
    except (ValueError, OSError, httpx.HTTPError, httpx.InvalidURL, RecursionError,
            getpass.GetPassWarning):
        # Never echo requests, validation inputs, credentials or transport errors.
        print("Web workflow failed: check API availability, authorization, approval and input.", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("Web workflow interrupted; check plan status before retrying.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
