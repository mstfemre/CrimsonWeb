import asyncio
import os
import subprocess
import sys
from uuid import uuid4

import httpx
import pytest
from discovery_helpers import crawl_policy, crawl_request, import_request, setup, wait
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from workspace_helpers import NOW, FakeResolver, policy

from crimsonweb.api.database import (
    DiscoveryEndpointRow,
    DiscoveryEvidenceRow,
    Repository,
    ScopeLeaseRow,
)
from crimsonweb.api.discovery.models import DiscoveryLimits, OpenAPIImportRequest
from crimsonweb.api.discovery.service import DiscoveryJobManager
from crimsonweb.api.discovery.summary import discovery_summary
from crimsonweb.api.workspaces.models import AuthorizationRequest, WorkspaceCreate
from crimsonweb.api.workspaces.service import WorkspaceService
from crimsonweb.api.workspaces.store import Conflict, NotFound


def test_running_cancellation_closes_body_before_slot_release_and_keeps_budget():
    async def run():
        entered, blocker = asyncio.Event(), asyncio.Event()

        class Body(httpx.AsyncByteStream):
            closed = False

            async def __aiter__(self):
                entered.set()
                await blocker.wait()
                yield b"<html></html>"

            async def aclose(self):
                self.closed = True

        body = Body()
        repo, service, ws, record, manager = setup(
            lambda r: httpx.Response(
                200, headers={"content-type": "text/html"}, stream=body
            ),
            configuration=crawl_policy(maximum_concurrency=1),
        )
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(record.id))
            await asyncio.wait_for(entered.wait(), 3)
            with Session(repo.engine) as session:
                lease = session.scalar(select(ScopeLeaseRow))
                assert not lease.released and lease.discovery_job_id == str(job.id)
            cancelled = await manager.cancel(ws.id, job.id)
            assert (
                cancelled.status == "cancelled"
                and body.closed
                and cancelled.requests_made == 1
            )
            assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
            with Session(repo.engine) as session:
                assert session.scalar(select(ScopeLeaseRow)).released
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_queue_capacity_and_storage_failure_during_shutdown_still_join_http_cleanup(
    monkeypatch,
):
    async def run():
        entered, blocker = asyncio.Event(), asyncio.Event()

        class Body(httpx.AsyncByteStream):
            closed = False

            async def __aiter__(self):
                entered.set()
                await blocker.wait()
                yield b"ok"

            async def aclose(self):
                self.closed = True

        body = Body()
        repo, _, ws, record, manager = setup(
            lambda r: httpx.Response(
                200, headers={"content-type": "text/html"}, stream=body
            )
        )
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(record.id))
            await asyncio.wait_for(entered.wait(), 3)
            for _ in range(7):
                await manager.import_openapi(ws.id, import_request())
            with pytest.raises(Conflict, match="queue full"):
                await manager.import_openapi(ws.id, import_request())

            def unavailable(*args):
                raise OperationalError("synthetic", {}, RuntimeError("synthetic"))

            monkeypatch.setattr(manager.store, "cancel", unavailable)
            with pytest.raises(OperationalError):
                await manager.shutdown()
            assert body.closed and not manager.worker_lock.held
            assert manager.store.get(ws.id, job.id).status == "cancelled"
            with Session(repo.engine) as session:
                assert all(r.released for r in session.scalars(select(ScopeLeaseRow)))
        finally:
            monkeypatch.undo()
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_queued_cancellation_and_serial_worker_do_not_consume_second_budget():
    async def run():
        entered, blocker = asyncio.Event(), asyncio.Event()
        calls = []

        class Body(httpx.AsyncByteStream):
            async def __aiter__(self):
                entered.set()
                await blocker.wait()
                yield b"ok"

        def handler(r):
            calls.append(r.url.path)
            return httpx.Response(
                200, headers={"content-type": "text/html"}, stream=Body()
            )

        repo, service, ws, record, manager = setup(handler)
        try:
            await manager.startup()
            first = await manager.start_crawl(ws.id, crawl_request(record.id))
            await asyncio.wait_for(entered.wait(), 3)
            second = await manager.start_crawl(
                ws.id, crawl_request(record.id, ["http://lab.test/second"])
            )
            assert manager.store.get(ws.id, second.id).status == "queued"
            cancelled = await manager.cancel(ws.id, second.id)
            assert cancelled.status == "cancelled" and cancelled.started_at is None
            assert (
                calls == ["/"]
                and service.store.snapshot(ws.id, record.id)[1].used_requests == 1
            )
            await manager.shutdown()
            assert (
                manager.store.get(ws.id, first.id).status == "cancelled"
                and not manager.worker_lock.held
            )
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_offline_import_works_without_crawl_approval_dns_or_http_and_persists(tmp_path):
    calls = []

    class NoDNS:
        async def resolve(self, host):
            raise AssertionError("offline import did DNS")

    url = f"sqlite:///{(tmp_path / 'offline.sqlite').as_posix()}"

    async def run():
        repo, _service, ws, _, manager = setup(
            lambda r: calls.append(r) or httpx.Response(500),
            configuration=policy(operator_approved=False),
            resolver=NoDNS(),
            url=url,
        )
        try:
            await manager.startup()
            job = await manager.import_openapi(ws.id, import_request())
            result = await wait(manager, ws.id, job.id)
            assert (
                result.status == "completed" and result.requests_made == 0 and not calls
            )
            payload = discovery_summary(manager.store, ws.id, job.id)
            assert len(payload.discovered_endpoints) == 4
            with Session(repo.engine) as session:
                values = str(
                    [r.data for r in session.scalars(select(DiscoveryEndpointRow))]
                ) + str([r.data for r in session.scalars(select(DiscoveryEvidenceRow))])
                assert (
                    "SYNTHETIC_TOKEN_NOT_RETAINED" not in values
                    and "never-fetch.invalid" not in values
                )
            return ws.id, job.id
        finally:
            await manager.shutdown()
            repo.close()

    workspace_id, job_id = asyncio.run(run())
    reopened = Repository(url)
    reopened.initialize()
    service = WorkspaceService(reopened, FakeResolver(), lambda: NOW)
    manager = DiscoveryJobManager(reopened, service)

    async def read():
        try:
            await manager.startup()
            assert manager.store.get(workspace_id, job_id).status == "completed"
            assert manager.store.endpoints(workspace_id, job_id).total == 4
        finally:
            await manager.shutdown()
            reopened.close()

    asyncio.run(read())


def test_recovery_requires_exclusive_lock_and_preserves_unknown_legacy_lease(tmp_path):
    url = f"sqlite:///{(tmp_path / 'recovery.sqlite').as_posix()}"

    async def run():
        repo, service, ws, record, first = setup(
            url=url, configuration=crawl_policy(maximum_concurrency=4)
        )
        second_repo = None
        second = None
        try:
            await first.startup()
            job = first.store.create(
                ws.id, "crawl", DiscoveryLimits(), NOW, record.id, record.revision
            )
            first.store.claim(ws.id, job.id, first.worker_id, NOW)
            request = AuthorizationRequest(url="http://lab.test/", category="crawl")
            _, owned = await service.decide(
                ws.id,
                record.id,
                request,
                reserve=True,
                discovery_owner=(str(job.id), first.worker_id),
            )
            _, legacy = await service.decide(ws.id, record.id, request, reserve=True)
            assert await first.startup() == 0
            assert first.store.get(ws.id, job.id).status == "running"
            with pytest.raises(Conflict):
                first.store.recover(NOW, first.worker_lock)
            with Session(repo.engine) as session:
                assert not session.get(ScopeLeaseRow, owned).released
            queued = first.store.create(ws.id, "openapi_import", DiscoveryLimits(), NOW)
            second_repo = Repository(url)
            second_repo.initialize()
            second_service = WorkspaceService(second_repo, FakeResolver(), lambda: NOW)
            second = DiscoveryJobManager(second_repo, second_service)
            assert await second.startup() == 0 and not second.worker_lock.held
            with pytest.raises(Conflict):
                second.store.recover(NOW, second.worker_lock)
            with pytest.raises(Conflict):
                await second.start_crawl(ws.id, crawl_request(record.id))
            assert second.store.get(ws.id, job.id).status == "running"
            with Session(second_repo.engine) as session:
                assert (
                    not session.get(ScopeLeaseRow, owned).released
                    and not session.get(ScopeLeaseRow, legacy).released
                )
            # Simulated old worker has no network coroutine; releasing its lifetime
            # lock here proves this specific worker ended, not merely a timeout.
            first.worker_lock.release()
            assert await second.startup() == 2
            assert second.store.get(ws.id, job.id).status == "failed"
            assert (
                second.store.get(ws.id, queued.id).stop_reason
                == "worker_interrupted_verified"
            )
            with Session(second_repo.engine) as session:
                assert (
                    session.get(ScopeLeaseRow, owned).released
                    and not session.get(ScopeLeaseRow, legacy).released
                )
            assert second_service.store.snapshot(ws.id, record.id)[1].used_requests == 2
        finally:
            if second:
                await second.shutdown()
            await first.shutdown()
            repo.close()
            if second_repo:
                second_repo.close()

    asyncio.run(run())


def test_actual_process_lock_survives_live_worker_and_releases_after_crash(tmp_path):
    url = f"sqlite:///{(tmp_path / 'process.sqlite').as_posix()}"
    repo, service, ws, record, manager = setup(url=url)
    old_worker = str(uuid4())
    job = manager.store.create(
        ws.id, "crawl", DiscoveryLimits(), NOW, record.id, record.revision
    )
    manager.store.claim(ws.id, job.id, old_worker, NOW)
    _, lease_id = asyncio.run(
        service.decide(
            ws.id,
            record.id,
            AuthorizationRequest(url="http://lab.test/", category="crawl"),
            reserve=True,
            discovery_owner=(str(job.id), old_worker),
        )
    )
    script = "from crimsonweb.api.database import Repository; from crimsonweb.api.discovery.worker import WorkerLock; import sys; r=Repository(sys.argv[1]); r.initialize(); lock=WorkerLock(r); assert lock.acquire(); print('LOCKED',flush=True); sys.stdin.read(); lock.release(); r.close()"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = "src"
    child = subprocess.Popen(
        [sys.executable, "-c", script, url],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )

    async def run():
        try:
            assert child.stdout.readline().strip() == "LOCKED"
            assert await manager.startup() == 0
            assert manager.store.get(ws.id, job.id).status == "running"
            with Session(repo.engine) as session:
                assert not session.get(ScopeLeaseRow, lease_id).released
            child.terminate()
            child.wait(timeout=10)
            # Windows may finish releasing kernel file locks just after exit is
            # reported. Retry acquisition, never infer lease safety from elapsed time.
            recovered = 0
            async with asyncio.timeout(3):
                while not manager.worker_lock.held:
                    recovered = await manager.startup()
                    if not manager.worker_lock.held:
                        await asyncio.sleep(0.01)
            assert recovered == 1
            assert manager.store.get(ws.id, job.id).status == "failed"
            with Session(repo.engine) as session:
                assert session.get(ScopeLeaseRow, lease_id).released
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=10)
            for pipe in (child.stdin, child.stdout, child.stderr):
                pipe.close()
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_terminal_job_with_unreleased_owned_lease_recovers_only_after_owner_ends(
    tmp_path,
):
    async def run():
        repo, service, ws, record, manager = setup(
            url=f"sqlite:///{(tmp_path / 'terminal.sqlite').as_posix()}"
        )
        try:
            await manager.startup()
            job = manager.store.create(
                ws.id, "crawl", DiscoveryLimits(), NOW, record.id, record.revision
            )
            manager.store.claim(ws.id, job.id, manager.worker_id, NOW)
            _, lease_id = await service.decide(
                ws.id,
                record.id,
                AuthorizationRequest(url="http://lab.test/", category="crawl"),
                reserve=True,
                discovery_owner=(str(job.id), manager.worker_id),
            )
            manager.store.finish(
                ws.id,
                job.id,
                manager.worker_id,
                "failed",
                "storage_or_ownership_error",
                NOW,
            )
            manager.worker_lock.release()
            assert await manager.startup() == 0
            with Session(repo.engine) as session:
                assert session.get(ScopeLeaseRow, lease_id).released
            assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_policy_revision_change_fences_existing_discovery_job():
    calls = []

    async def run():
        repo, service, ws, record, manager = setup()

        def handler(request):
            calls.append(request.url.path)
            service.store.write_policy(
                ws.id, crawl_policy(), NOW, record.id, record.revision
            )
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                content=b"<a href='/next'>next</a>",
            )

        manager.transport = httpx.MockTransport(handler)
        try:
            await manager.startup()
            job = await manager.start_crawl(ws.id, crawl_request(record.id))
            result = await wait(manager, ws.id, job.id)
            assert (
                result.status == "halted_by_policy"
                and result.stop_reason == "discovery_policy_changed"
                and calls == ["/"]
            )
            assert service.store.snapshot(ws.id, record.id)[1].halted_reason is None
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_workspace_isolation_applies_to_jobs_cancel_inventory_evidence_graph_summary():
    async def run():
        repo, service, ws, _, manager = setup()
        try:
            await manager.startup()
            job = await manager.import_openapi(ws.id, import_request())
            await wait(manager, ws.id, job.id)
            other = service.store.create_workspace(
                WorkspaceCreate(name="other", program_type="lab"), NOW
            )
            for call in (
                lambda: manager.store.get(other.id, job.id),
                lambda: manager.store.cancel(other.id, job.id, NOW),
                lambda: manager.store.endpoints(other.id, job.id),
                lambda: manager.store.evidence(other.id, job.id),
                lambda: manager.store.graph(other.id, job.id),
                lambda: discovery_summary(manager.store, other.id, job.id),
            ):
                with pytest.raises(NotFound):
                    call()
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())


def test_summary_byte_bound_references_and_masking_with_large_inventory():
    document = {
        "openapi": "3.1.0",
        "paths": {
            f"/resources/route_{i}": {
                "get": {
                    "parameters": [
                        {
                            "name": f"field_{j}",
                            "in": "query",
                            "schema": {"type": "string"},
                        }
                        for j in range(25)
                    ],
                    "responses": {},
                }
            }
            for i in range(100)
        },
    }
    document["paths"]["/ignore-previous-instructions"] = {"get": {"responses": {}}}

    async def run():
        repo, _, ws, _, manager = setup()
        try:
            await manager.startup()
            job = await manager.import_openapi(
                ws.id, OpenAPIImportRequest(document=document)
            )
            result = await wait(manager, ws.id, job.id)
            assert result.status == "completed" and result.endpoints_discovered == 101
            summary = discovery_summary(manager.store, ws.id, job.id)
            assert len(summary.model_dump_json().encode()) <= 32768
            assert "summary_truncated" in summary.discovery_limitations
            refs = {e.ref for e in manager.store.evidence(ws.id, job.id).items}
            assert set(summary.evidence_refs) <= refs
            assert "ignore-previous-instructions" not in summary.model_dump_json()
            assert (
                summary.untrusted_discovery_data
                and not summary.network_execution_permitted
            )
        finally:
            await manager.shutdown()
            repo.close()

    asyncio.run(run())
