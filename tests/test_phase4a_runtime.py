import asyncio
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from workspace_helpers import NOW, FakeResolver, policy, seeded

from crimsonweb.api.engine import ScanEngine
from crimsonweb.api.models import ScanReport
from crimsonweb.api.scope import Scope, ScopeError
from crimsonweb.api.workspaces.dns import Resolution
from crimsonweb.api.workspaces.models import AuthorizationRequest, WorkspaceUpdate
from crimsonweb.api.workspaces.service import AuthorizationDenied

REQUEST = AuthorizationRequest(url="http://lab.test/")


def run_scan(service, ws, record, handler, url="http://lab.test/"):
    item = ScanReport(id=str(uuid4()), engagement_id="synthetic", target=url, scope={})
    engine = ScanEngine(
        Scope(),
        interval=0,
        authorization=service.scan_guard(
            ws.id, record.id, httpx.MockTransport(handler)
        ),
    )
    asyncio.run(engine.run(item))
    return item


@pytest.mark.parametrize(
    "resolution,reason",
    [
        (Resolution(("127.0.0.1", "10.0.0.1")), "ip_out_of_scope"),
        (Resolution(("169.254.169.254",)), "ssrf_address_denied"),
        (Resolution(("127.0.0.1",), ("outside.test",)), "cname_out_of_scope"),
        (Resolution(()), "dns_unknown"),
        (ScopeError("untrusted raw DNS exception"), "dns_unavailable"),
    ],
)
def test_dns_fail_closed_without_http(resolution, reason):
    repo, service, ws, record = seeded(resolver=FakeResolver(resolution))
    calls = []
    try:
        item = run_scan(service, ws, record, lambda request: calls.append(request))
        assert item.status == "blocked" and not calls
        admission = [
            a
            for a in service.store.audits(ws.id, 100, 0).items
            if a.action == "request_admitted"
        ]
        assert len(admission) == 1 and admission[0].reason == reason
        assert service.store.snapshot(ws.id, record.id)[1].halted_reason == reason
    finally:
        repo.close()


def test_preflight_is_advisory_and_rebinding_rechecked_before_http():
    resolver = FakeResolver(Resolution(("127.0.0.1",)), Resolution(("10.0.0.1",)))
    repo, service, ws, record = seeded(resolver=resolver)
    calls = []
    try:
        assert asyncio.run(service.preflight(ws.id, record.id, REQUEST)).allowed
        item = run_scan(service, ws, record, lambda request: calls.append(request))
        assert item.status == "blocked" and not calls and len(resolver.calls) == 2
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 0
    finally:
        repo.close()


def test_redirect_rebinding_cannot_use_old_dns_result():
    resolver = FakeResolver(Resolution(("127.0.0.1",)), Resolution(("10.0.0.1",)))
    repo, service, ws, record = seeded(resolver=resolver)
    calls = []
    try:

        def handler(request):
            calls.append(request)
            return httpx.Response(302, headers={"Location": "/next"})

        item = run_scan(service, ws, record, handler)
        assert item.status == "blocked" and len(calls) == 1
        assert len(resolver.calls) == 2
    finally:
        repo.close()


@pytest.mark.parametrize(
    "destination",
    [
        "http://outside.test/",
        "http://10.0.0.1/",
        "/admin/secret",
        "http://169.254.169.254/",
    ],
)
def test_redirect_destination_reauthorized(destination):
    repo, service, ws, record = seeded()
    calls = []
    try:

        def handler(request):
            calls.append(request)
            return httpx.Response(302, headers={"Location": destination})

        item = run_scan(service, ws, record, handler)
        assert item.status == "blocked" and len(calls) == 1
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
    finally:
        repo.close()


def test_authorized_redirect_pin_host_sni_and_existing_findings():
    repo, service, ws, record = seeded(
        resolver=FakeResolver(Resolution(("127.0.0.1",), ("cdn.lab.test",)))
    )
    calls = []
    try:

        def handler(request):
            calls.append(request)
            assert request.url.host == "127.0.0.1"
            assert request.headers["host"] == "lab.test"
            assert request.extensions["sni_hostname"] == "lab.test"
            return (
                httpx.Response(302, headers={"Location": "/next"})
                if len(calls) == 1
                else httpx.Response(200)
            )

        item = run_scan(service, ws, record, handler)
        assert item.status == "completed" and len(item.hops) == 2 and item.findings
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 2
    finally:
        repo.close()


@pytest.mark.parametrize("status", [403, 429])
def test_defense_halts_policy_and_retains_waf_event(status):
    repo, service, ws, record = seeded()
    try:
        item = run_scan(
            service,
            ws,
            record,
            lambda request: httpx.Response(
                status, headers={"Retry-After": "60", "Location": "/next"}
            ),
        )
        assert item.status == "blocked" and len(item.hops) == 1
        assert item.waf_events[0].status_code == status
        after = asyncio.run(service.preflight(ws.id, record.id, REQUEST))
        assert not after.allowed and after.reason == "policy_halted"
        assert len(service.resolver.calls) == 1
    finally:
        repo.close()


@pytest.mark.parametrize("reason", ["waf_block", "ip_block", "authorization_violation"])
def test_trusted_defense_notification_halts(reason):
    repo, service, ws, record = seeded()
    try:
        asyncio.run(service.notify_defense(ws.id, record.id, reason))
        assert not asyncio.run(service.preflight(ws.id, record.id, REQUEST)).allowed
        assert service.store.snapshot(ws.id, record.id)[1].halted_reason == reason
    finally:
        repo.close()


def test_concurrency_and_release_on_consumer_failure():
    repo, service, ws, record = seeded(configuration=policy(maximum_concurrency=1))
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    try:

        async def run():
            with pytest.raises(RuntimeError, match="consumer failed"):
                async with service.stream(ws.id, record.id, REQUEST, transport):
                    with pytest.raises(
                        AuthorizationDenied, match="concurrency_exceeded"
                    ):
                        async with service.stream(ws.id, record.id, REQUEST, transport):
                            pytest.fail("Second active request admitted")
                    raise RuntimeError("consumer failed")
            async with service.stream(ws.id, record.id, REQUEST, transport):
                pass

        asyncio.run(run())
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 2
    finally:
        repo.close()


def test_cancelled_request_releases_slot_without_budget_refund():
    repo, service, ws, record = seeded(configuration=policy(maximum_concurrency=1))
    try:

        async def run():
            entered = asyncio.Event()

            async def worker():
                async with service.stream(
                    ws.id,
                    record.id,
                    REQUEST,
                    httpx.MockTransport(lambda request: httpx.Response(200)),
                ):
                    entered.set()
                    await asyncio.Event().wait()

            task = asyncio.create_task(worker())
            await entered.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert (await service.preflight(ws.id, record.id, REQUEST)).allowed

        asyncio.run(run())
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
    finally:
        repo.close()


def test_budget_counts_redirects_and_policy_update_cannot_refund():
    repo, service, ws, record = seeded(configuration=policy(maximum_request_budget=1))
    calls = []
    try:

        def handler(request):
            calls.append(request)
            return httpx.Response(302, headers={"Location": "/next"})

        item = run_scan(service, ws, record, handler)
        assert item.status == "blocked" and len(calls) == 1
        updated = service.store.write_policy(
            ws.id, policy(maximum_request_budget=1), NOW, record.id, 1
        )
        assert updated.used_requests == 1
        assert (
            asyncio.run(service.preflight(ws.id, record.id, REQUEST)).reason
            == "budget_exhausted"
        )
    finally:
        repo.close()


def test_sliding_rate_window_includes_failed_connections():
    now = [NOW]
    repo, service, ws, record = seeded(
        configuration=policy(rate_limit_per_minute=1), clock=lambda: now[0]
    )
    try:

        def handler(request):
            raise httpx.ConnectError("synthetic connection error", request=request)

        item = run_scan(service, ws, record, handler)
        assert item.status == "failed"
        assert (
            asyncio.run(service.preflight(ws.id, record.id, REQUEST)).reason
            == "rate_limit_exceeded"
        )
        now[0] += timedelta(seconds=60)
        assert asyncio.run(service.preflight(ws.id, record.id, REQUEST)).allowed
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
    finally:
        repo.close()


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("expired", "policy_expired"),
        ("changed", "policy_changed"),
        ("inactive", "workspace_inactive"),
    ],
)
def test_policy_rechecked_atomically_after_slow_dns(mutation, reason):
    now = [NOW]
    repo, service, ws, record = seeded(clock=lambda: now[0])
    try:

        class MutatingResolver:
            async def resolve(self, host):
                if mutation == "expired":
                    now[0] += timedelta(days=2)
                elif mutation == "changed":
                    service.store.write_policy(ws.id, policy(), NOW, record.id, 1)
                else:
                    service.store.update_workspace(
                        ws.id, WorkspaceUpdate(active=False), NOW
                    )
                return Resolution(("127.0.0.1",))

        service.resolver = MutatingResolver()
        result = asyncio.run(service.preflight(ws.id, record.id, REQUEST))
        assert not result.allowed and result.reason == reason
    finally:
        repo.close()
