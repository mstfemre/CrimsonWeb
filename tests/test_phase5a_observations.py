import asyncio
import json
from datetime import timedelta

import httpx
import pytest
from privacy_helpers import request, setup, wait
from sqlalchemy import select
from sqlalchemy.orm import Session
from workspace_helpers import NOW, FakeResolver
from workspace_helpers import policy as program_policy

from crimsonweb.api.database import PrivacyEvidenceRow, ScopeAuditRow, ScopeLeaseRow
from crimsonweb.api.privacy.models import (
    DiagnosticRequest,
    PrivacyPolicy,
    PrivacyProfileInput,
)
from crimsonweb.api.workspaces.dns import Resolution


def test_approved_echo_observation_is_masked_and_not_a_route_guarantee():
    calls = []

    def handler(r):
        calls.append(r)
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "set-cookie": "SECRET_COOKIE"},
            json={"ip": "203.0.113.7"},
        )

    async def run():
        repo, shared, ws, program, profile, service = setup(handler)
        try:
            await service.startup()
            preflight = await service.preflight(ws.id, profile.id, request(program.id))
            assert preflight.allowed and not shared.resolver.calls and not calls
            job = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, job.id)
            assert (
                result.execution_status == "completed"
                and result.status == "secure_observed"
            )
            evidence = service.store.evidence(
                ws.id, result.evidence_refs[0].split(":")[1]
            )
            assert (
                evidence.identity_matches
                and not evidence.route_verified
                and evidence.connection_family is None
            )
            assert len(calls) == 1 and len(shared.resolver.calls) == 1
            assert (
                calls[0].url.host == "127.0.0.1"
                and calls[0].headers["host"] == "lab.test"
            )
            assert (
                "authorization" not in calls[0].headers
                and "cookie" not in calls[0].headers
            )
            assert shared.store.snapshot(ws.id, program.id)[1].used_requests == 1
            with Session(repo.engine) as session:
                assert session.scalar(select(ScopeLeaseRow)).released
                assert all(
                    not row.resolved_ips
                    for row in session.scalars(select(ScopeAuditRow))
                )
                assert "203.0.113.7" not in str(
                    [r.data for r in session.scalars(select(PrivacyEvidenceRow))]
                )
            assert "SECRET_COOKIE" not in json.dumps(
                service.audits(ws.id).model_dump(mode="json")
            )
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "body,expected",
    [
        ({"ip": "203.0.113.8"}, "leak_suspected"),
        ({"ip": "203.0.113.7", "token": "DO_NOT_STORE"}, "inconclusive"),
        ({"ip": "invalid"}, "inconclusive"),
    ],
)
def test_untrusted_echo_mismatch_or_invalid_payload_never_validates_leak(
    body, expected
):
    async def run():
        repo, _, ws, program, profile, service = setup(
            lambda r: httpx.Response(
                200, headers={"content-type": "application/json"}, json=body
            )
        )
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, job.id)
            assert result.status == expected and result.evidence_refs
            assert "DO_NOT_STORE" not in str(
                service.store.evidence(ws.id, result.evidence_refs[0].split(":")[1])
            )
            assert bool(service.store.findings(ws.id, job.id)) == (
                expected == "leak_suspected"
            )
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "profile_changes,policy_changes,expected",
    [
        ({"mode": "managed_egress"}, {}, "managed_egress_not_implemented"),
        (
            {"allowed_network_interfaces": ["Wi-Fi"]},
            {},
            "interface_enforcement_unavailable",
        ),
        (
            {"dns_expectations": {"path": "proxy"}},
            {},
            "dns_path_enforcement_unavailable",
        ),
        ({"active": False}, {}, "privacy_profile_inactive"),
        ({}, {"operator_approved": False}, "privacy_approval_required"),
        ({}, {"maximum_observations": 0}, "privacy_budget_exhausted"),
        ({}, {"valid_until": NOW - timedelta(seconds=1)}, "privacy_permission_expired"),
        ({}, {"allowed_tests": ["dns"]}, "privacy_test_not_allowed"),
        ({}, {"verification_urls": []}, "verifier_not_allowlisted"),
    ],
)
def test_privacy_constraints_block_before_dns_or_http(
    profile_changes, policy_changes, expected
):
    calls = []

    async def run():
        repo, shared, ws, program, profile, service = setup(
            lambda r: calls.append(r) or httpx.Response(500),
            profile_changes=profile_changes,
            privacy_changes=policy_changes,
        )
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, job.id)
            assert result.status == "blocked_by_policy" and result.reason == expected
            assert not calls and not shared.resolver.calls and not result.requests_made
            assert shared.store.snapshot(ws.id, program.id)[1].used_requests == 0
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_privacy_allowlist_cannot_expand_program_scope():
    async def run():
        repo, shared, ws, program, profile, service = setup(
            privacy_changes={"verification_urls": ["http://outside.invalid/echo"]}
        )
        try:
            await service.startup()
            job = await service.start(
                ws.id,
                profile.id,
                request(program.id, verification_url="http://outside.invalid/echo"),
            )
            assert (await wait(service, ws.id, job.id)).status == "blocked_by_policy"
            assert not shared.resolver.calls
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize("status", [403, 429])
def test_defense_status_persists_stop_and_does_not_attribute_waf_or_retry(status):
    calls = []

    async def run():
        repo, shared, ws, program, profile, service = setup(
            lambda r: (
                calls.append(r)
                or httpx.Response(
                    status, headers={"retry-after": "1", "set-cookie": "SECRET"}
                )
            )
        )
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, job.id)
            assert result.status == "blocked_by_policy" and result.reason.startswith(
                f"http_{status}"
            )
            second = await service.start(ws.id, profile.id, request(program.id))
            assert (await wait(service, ws.id, second.id)).status == "blocked_by_policy"
            assert (
                len(calls) == 1
                and shared.store.snapshot(ws.id, program.id)[1].halted_reason
            )
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "location", ["http://outside.invalid/", "http://lab.test/?token=SECRET", "/safe"]
)
def test_redirect_is_not_followed_even_when_same_origin(location):
    calls = []

    async def run():
        repo, _, ws, program, profile, service = setup(
            lambda r: (
                calls.append(r) or httpx.Response(302, headers={"location": location})
            )
        )
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, job.id)
            assert (
                result.status == "blocked_by_policy"
                and result.reason == "privacy_redirect_not_followed"
            )
            assert len(calls) == 1 and "SECRET" not in str(
                service.store.evidence(ws.id, result.evidence_refs[0].split(":")[1])
            )
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize("failure", ["connection", "body", "compressed", "oversize"])
def test_network_and_body_failures_are_inconclusive_without_direct_fallback(failure):
    closed = []

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            if failure == "body":
                raise httpx.ReadTimeout("SYNTHETIC_SECRET")
            yield b"X" * 4097

        async def aclose(self):
            closed.append(True)

    calls = []

    def handler(r):
        calls.append(r)
        if failure == "connection":
            raise httpx.ConnectTimeout("SYNTHETIC_SECRET")
        headers = {"content-type": "application/json"}
        if failure == "compressed":
            headers["content-encoding"] = "gzip"
        return httpx.Response(200, headers=headers, stream=Body())

    async def run():
        repo, _, ws, program, profile, service = setup(handler)
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, job.id)
            assert result.status == "inconclusive" and len(calls) == 1
            with Session(repo.engine) as session:
                assert all(r.released for r in session.scalars(select(ScopeLeaseRow)))
            assert failure == "connection" or closed
            assert "SYNTHETIC_SECRET" not in str(result)
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "responses",
    [
        (Resolution(("127.0.0.1",)),),
        (TimeoutError("secret"),),
        (Resolution(("169.254.169.254",)),),
        (Resolution(("127.0.0.1",), ("outside.invalid",)),),
    ],
)
def test_dns_answers_and_errors_never_alone_prove_egress_or_dns_leak(responses):
    async def run():
        repo, _, ws, program, profile, service = setup(
            resolver=FakeResolver(*responses)
        )
        try:
            await service.startup()
            job = await service.start(
                ws.id, profile.id, request(program.id, kind="dns")
            )
            result = await wait(service, ws.id, job.id)
            assert result.status in {"inconclusive", "blocked_by_policy"}
            assert result.status != "leak_validated"
            if result.status == "inconclusive":
                evidence = service.store.evidence(
                    ws.id, result.evidence_refs[0].split(":")[1]
                )
                assert (
                    evidence.kind == "dns"
                    and not evidence.path_observed
                    and not evidence.system_resolution_tested
                )
            with Session(repo.engine) as session:
                assert all(r.released for r in session.scalars(select(ScopeLeaseRow)))
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_privacy_profile_and_program_revision_changes_fence_positive_publication():
    async def run(change):
        holder = {}

        def handler(r):
            service, shared, ws, program, profile = holder["context"]
            if change == "privacy":
                _, policy, _ = service.store.snapshot(ws.id, profile.id)
                service.store.write_privacy_policy(
                    ws.id,
                    profile.id,
                    PrivacyPolicy.model_validate(
                        policy.model_dump(
                            exclude={
                                "id",
                                "workspace_id",
                                "profile_id",
                                "revision",
                                "used_observations",
                                "updated_at",
                            }
                        )
                    ),
                    policy.revision,
                    NOW,
                )
            elif change == "profile":
                service.store.update_profile(
                    ws.id,
                    profile.id,
                    PrivacyProfileInput(name="updated"),
                    profile.revision,
                    NOW,
                )
            else:
                shared.store.write_policy(
                    ws.id,
                    program_policy(),
                    NOW,
                    program.id,
                    program.revision,
                )
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                json={"ip": "203.0.113.7"},
            )

        repo, shared, ws, program, profile, service = setup(handler)
        holder["context"] = service, shared, ws, program, profile
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, job.id)
            assert result.status == "blocked_by_policy" and result.requests_made == 1
            assert not shared.store.snapshot(ws.id, program.id)[1].halted_reason
        finally:
            await service.shutdown()
            repo.close()

    for change in ("privacy", "profile", "program"):
        asyncio.run(run(change))


def test_local_ipv6_diagnostic_does_not_claim_actual_egress(monkeypatch):
    monkeypatch.setattr(
        "crimsonweb.api.privacy.service.ipv6_capability", lambda: (True, True)
    )

    async def run():
        repo, shared, ws, _, profile, service = setup(
            profile_changes={"ipv6_expectation": "forbidden"}
        )
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, DiagnosticRequest(kind="ipv6"))
            result = await wait(service, ws.id, job.id)
            assert (
                result.status == "leak_suspected"
                and not shared.resolver.calls
                and not result.requests_made
            )
            evidence = service.store.evidence(
                ws.id, result.evidence_refs[0].split(":")[1]
            )
            assert not evidence.egress_tested
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_rebinding_between_privacy_observations_halts_before_second_http_request():
    async def run():
        calls = []
        resolver = FakeResolver(Resolution(("127.0.0.1",)), Resolution(("10.0.0.1",)))
        repo, shared, ws, program, profile, service = setup(
            lambda r: (
                calls.append(r)
                or httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    json={"ip": "203.0.113.7"},
                )
            ),
            resolver=resolver,
        )
        try:
            await service.startup()
            first = await service.start(ws.id, profile.id, request(program.id))
            assert (await wait(service, ws.id, first.id)).status == "secure_observed"
            second = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, second.id)
            assert (
                result.status == "blocked_by_policy"
                and result.reason == "ip_out_of_scope"
            )
            third = await service.start(ws.id, profile.id, request(program.id))
            assert (await wait(service, ws.id, third.id)).reason == "policy_halted"
            assert len(calls) == 1 and resolver.calls == ["lab.test", "lab.test"]
            assert shared.store.snapshot(ws.id, program.id)[1].used_requests == 1
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())
