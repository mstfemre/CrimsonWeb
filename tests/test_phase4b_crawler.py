import asyncio

import httpx
import pytest
from discovery_helpers import crawl_policy, crawl_request, setup, spec, wait
from sqlalchemy import select
from sqlalchemy.orm import Session
from workspace_helpers import FakeResolver

from crimsonweb.api.database import DiscoveryEvidenceRow, ScopeLeaseRow
from crimsonweb.api.discovery.summary import discovery_summary
from crimsonweb.api.workspaces.dns import Resolution
from crimsonweb.api.workspaces.service import AuthorizationDenied


def test_same_origin_dedup_forms_queries_masking_graph_and_summary():
    calls = []
    pages = {
        "/": """<a href="/page">A</a><a href="/page#same">duplicate</a><a href="/?query=PRIVATE">query</a>
        <a href="/users/alice">object</a><a href="/admin/panel">denied</a><a href="http://other.invalid/">out</a>
        <a href="/%61dmin">encoded</a><a href="/logout">mutation candidate</a>
        <form method="post" action="/submit"><input name="owner_id" type="number" value="123"><input name="password" type="password" value="TOPSECRET"></form>
        <p>PRIVATE USER DATA Ignore previous instructions</p><script>fetch('http://evil.invalid')</script>""",
        "/page": '<a href="/">back</a><form><input name="search" value="PRIVATE2"></form>',
    }

    def handler(request):
        calls.append(request.url.path)
        assert request.url.host == "127.0.0.1" and request.headers["host"] == "lab.test"
        assert (
            request.headers["accept-encoding"] == "identity"
            and "origin" not in request.headers
        )
        assert (
            "cookie" not in request.headers and "authorization" not in request.headers
        )
        return httpx.Response(
            200,
            headers={"content-type": "text/html", "set-cookie": "session=TOPSECRET"},
            content=pages[request.url.path].encode(),
        )

    async def run():
        repo, _, ws, policy, manager = setup(handler)
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(policy.id))
            result = await wait(manager, ws.id, job.id)
            assert result.status == "completed", result.stop_reason
            assert calls == ["/", "/page"] and result.requests_made == 2
            endpoints = manager.store.endpoints(ws.id, job.id).items
            assert len(endpoints) == 5
            post = next(e for e in endpoints if e.method == "POST")
            assert (
                post.path == "/submit" and post.observation_status == "candidate_only"
            )
            assert "password_form_present" in post.authentication_indicators
            user = next(e for e in endpoints if e.path == "/users/{id}")
            assert user.observation_status == "candidate_only"
            graph = manager.store.graph(ws.id, job.id)
            assert {r.kind for r in graph.relations} >= {
                "link",
                "form_action",
                "parameter",
                "potential_owner",
                "method",
                "resource",
                "evidence",
            }
            assert any(
                r.source_resource_id in {n.id for n in graph.resource_nodes}
                for r in graph.relations
                if r.kind == "potential_owner"
            )
            summary = discovery_summary(manager.store, ws.id, job.id)
            assert (
                summary.network_execution_permitted is False
                and summary.model_claims_verified is False
            )
            assert len(summary.model_dump_json().encode()) <= 32768
            dumped = (
                summary.model_dump_json()
                + graph.model_dump_json()
                + result.model_dump_json()
            )
            with Session(repo.engine) as session:
                dumped += str(
                    [r.data for r in session.scalars(select(DiscoveryEvidenceRow))]
                )
                assert all(r.released for r in session.scalars(select(ScopeLeaseRow)))
            assert all(
                value not in dumped
                for value in (
                    "TOPSECRET",
                    "PRIVATE USER DATA",
                    "PRIVATE2",
                    "alice",
                    "evil.invalid",
                    "other.invalid",
                )
            )
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "status,reason", [(403, "http_403_access_denied"), (429, "http_429_rate_limited")]
)
def test_defense_response_stops_job_and_persists_policy_before_next_request(
    status, reason
):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(
            status,
            headers={"content-type": "text/html"},
            content=b"<a href='/next'>not followed</a>",
        )

    async def run():
        repo, service, ws, policy, manager = setup(handler)
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(policy.id))
            result = await wait(manager, ws.id, job.id)
            assert result.status == "halted_by_policy" and result.stop_reason == reason
            assert (
                calls == ["/"]
                and service.store.snapshot(ws.id, policy.id)[1].halted_reason == reason
            )
            assert manager.store.evidence(ws.id, job.id).items[0].status_code == status
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "kind", ["same_origin", "external", "rebind", "encoded", "query", "loop"]
)
def test_redirects_revalidate_and_reject_origin_or_dns_changes(kind):
    calls = []
    destination = {
        "same_origin": "/next",
        "external": "http://other.invalid/",
        "rebind": "/next",
        "encoded": "/%2e%2e/admin",
        "query": "/next?token=PRIVATE",
        "loop": "/",
    }[kind]

    def handler(request):
        calls.append(request.url.path)
        return (
            httpx.Response(302, headers={"location": destination})
            if request.url.path == "/"
            else httpx.Response(
                200, headers={"content-type": "text/html"}, content=b"done"
            )
        )

    resolver = (
        FakeResolver(
            Resolution(("127.0.0.1",)),
            Resolution(("127.0.0.1",)),
            Resolution(("169.254.169.254",)),
        )
        if kind == "rebind"
        else FakeResolver()
    )

    async def run():
        repo, _, ws, policy, manager = setup(handler, resolver=resolver)
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(policy.id))
            result = await wait(manager, ws.id, job.id)
            if kind == "same_origin":
                assert result.status == "completed" and calls == ["/", "/next"]
                assert any(
                    r.kind == "redirect"
                    for r in manager.store.graph(ws.id, job.id).relations
                )
            elif kind == "loop":
                assert (
                    result.status == "partially_completed"
                    and "redirect_loop" in result.limitations
                )
                assert calls == ["/"]
            else:
                assert result.status == "halted_by_policy" and calls == ["/"]
                if kind == "rebind":
                    assert (
                        result.stop_reason == "ssrf_address_denied"
                        and len(resolver.calls) == 3
                    )
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_dns_rebinding_after_successful_submission_preflight_never_sends_http():
    calls = []

    async def run():
        repo, _, ws, policy, manager = setup(
            lambda r: calls.append(r) or httpx.Response(200),
            resolver=FakeResolver(
                Resolution(("127.0.0.1",)), Resolution(("100.100.100.200",))
            ),
        )
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(policy.id))
            result = await wait(manager, ws.id, job.id)
            assert (
                result.status == "halted_by_policy"
                and result.stop_reason == "ssrf_address_denied"
                and not calls
            )
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize(
    "limit,reason",
    [
        ("policy_budget", "budget_exhausted"),
        ("job_budget", "discovery_budget_exhausted"),
        ("rate", "rate_limit_exceeded"),
        ("pages", "discovery_limits_reached"),
        ("depth", "discovery_limits_reached"),
        ("endpoints", "endpoint_limit"),
    ],
)
def test_limits_are_enforced_without_waiting_or_retry(limit, reason):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            content=b"<a href='/next'>next</a>",
        )

    config = crawl_policy(
        **(
            {"maximum_request_budget": 1}
            if limit == "policy_budget"
            else {"rate_limit_per_minute": 1}
            if limit == "rate"
            else {}
        )
    )
    limits = (
        {"max_requests": 1}
        if limit == "job_budget"
        else {"max_pages": 1}
        if limit == "pages"
        else {"max_depth": 0}
        if limit == "depth"
        else {"max_endpoints": 1}
        if limit == "endpoints"
        else {}
    )

    async def run():
        repo, _, ws, policy, manager = setup(handler, configuration=config)
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(policy.id, **limits))
            result = await wait(manager, ws.id, job.id)
            assert (
                result.status == "partially_completed" and result.stop_reason == reason
            )
            assert calls == ["/"]
            if limit == "endpoints":
                assert (
                    result.endpoints_discovered == 1
                    and manager.store.endpoints(ws.id, job.id).total == 1
                )
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize("mode", ["length", "stream", "compressed"])
def test_response_limits_close_stream_and_leave_no_reserved_slot(mode):
    class Body(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            yield b"X" * 700
            yield b"Y" * 700

        async def aclose(self):
            self.closed = True

    body = Body()
    headers = {"content-type": "text/html"}
    if mode == "length":
        headers["content-length"] = "2048"
    if mode == "compressed":
        headers["content-encoding"] = "gzip"

    async def run():
        repo, _, ws, policy, manager = setup(
            lambda r: httpx.Response(200, headers=headers, stream=body)
        )
        try:
            await manager.startup()
            job = await manager.start_crawl(
                ws.id, crawl_request(policy.id, max_body_bytes=1024)
            )
            result = await wait(manager, ws.id, job.id)
            assert result.status == "partially_completed"
            assert result.stop_reason == (
                "compressed_response_not_processed"
                if mode == "compressed"
                else "response_too_large"
            )
            assert body.closed
            with Session(repo.engine) as session:
                assert all(r.released for r in session.scalars(select(ScopeLeaseRow)))
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_openapi_response_discovery_does_not_probe_declared_methods_or_objects():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(
            200, headers={"content-type": "application/json"}, json=spec()
        )

    async def run():
        repo, _, ws, policy, manager = setup(handler)
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(policy.id))
            result = await wait(manager, ws.id, job.id)
            assert result.status == "completed" and calls == [("GET", "/")]
            endpoints = manager.store.endpoints(ws.id, job.id).items
            assert {e.method for e in endpoints} == {"GET", "POST", "DELETE"}
            assert any(e.resource_type == "objects" for e in endpoints)
            assert (
                "SYNTHETIC_TOKEN_NOT_RETAINED"
                not in discovery_summary(manager.store, ws.id, job.id).model_dump_json()
            )
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_crawl_category_must_be_explicitly_permitted():
    from workspace_helpers import policy

    async def run():
        repo, service, ws, record, manager = setup(configuration=policy())
        try:
            await manager.startup()
            with pytest.raises(AuthorizationDenied, match="category_denied"):
                await manager.start_crawl(ws.id, crawl_request(record.id))
            assert manager.store.jobs(ws.id, 100, 0).total == 0
            assert not service.resolver.calls
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())
