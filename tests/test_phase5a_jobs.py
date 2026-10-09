import asyncio
import os
import subprocess
import sys
from datetime import timedelta
from uuid import uuid4

import httpx
import pytest
from privacy_helpers import request, setup, wait
from sqlalchemy import select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from workspace_helpers import NOW

from crimsonweb.api.database import ScopeLeaseRow
from crimsonweb.api.discovery.store import DiscoveryEvidenceStore
from crimsonweb.api.discovery.worker import WorkerLock
from crimsonweb.api.privacy.models import DiagnosticRequest, PrivacyProfileInput
from crimsonweb.api.privacy.service import PrivacyService
from crimsonweb.api.workspaces.models import AuthorizationRequest, WorkspaceUpdate
from crimsonweb.api.workspaces.store import Conflict


class BlockingBody(httpx.AsyncByteStream):
    def __init__(self):
        self.entered, self.release = asyncio.Event(), asyncio.Event()
        self.closed = False

    async def __aiter__(self):
        self.entered.set()
        await self.release.wait()
        yield b'{"ip":"203.0.113.7"}'

    async def aclose(self):
        self.closed = True


def test_cancel_closes_response_before_releasing_slot_and_keeps_both_budgets():
    async def run():
        body = BlockingBody()
        repo, shared, ws, program, profile, service = setup(
            lambda r: httpx.Response(
                200, headers={"content-type": "application/json"}, stream=body
            )
        )
        released_after_close = []
        release = service.guard.store.release

        def observe_release(*args):
            released_after_close.append(body.closed)
            return release(*args)

        service.guard.store.release = observe_release
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            await asyncio.wait_for(body.entered.wait(), 3)
            with Session(repo.engine) as session:
                lease = session.scalar(select(ScopeLeaseRow))
                assert not lease.released and lease.privacy_assessment_id == str(job.id)
            first, second = await asyncio.gather(
                service.cancel(ws.id, job.id), service.cancel(ws.id, job.id)
            )
            assert first.execution_status == second.execution_status == "cancelled"
            assert first.status == "not_tested" and first.evidence_refs
            assert body.closed and released_after_close == [True]
            assert (
                first.requests_made
                == shared.store.snapshot(ws.id, program.id)[1].used_requests
                == 1
            )
            assert service.store.snapshot(ws.id, profile.id)[1].used_observations == 1
            with Session(repo.engine) as session:
                assert session.scalar(select(ScopeLeaseRow)).released
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_queue_is_bounded_and_serial_and_queued_cancel_does_not_send_requests():
    async def run():
        body = BlockingBody()
        calls = []

        def handler(r):
            calls.append(r)
            return httpx.Response(
                200, headers={"content-type": "application/json"}, stream=body
            )

        repo, shared, ws, program, profile, service = setup(handler)
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            await asyncio.wait_for(body.entered.wait(), 3)
            queued = [
                await service.start(ws.id, profile.id, request(program.id))
                for _ in range(7)
            ]
            with pytest.raises(Conflict, match="queue unavailable"):
                await service.start(ws.id, profile.id, request(program.id))
            assert len(calls) == 1 and len(service.tasks) == 8
            result = await service.cancel(ws.id, queued[0].id)
            assert (
                result.requests_made == 0
                and result.evidence_refs
                and result.status == "not_tested"
            )
            assert service.store.snapshot(ws.id, profile.id)[1].used_observations == 8
            assert shared.store.snapshot(ws.id, program.id)[1].used_requests == 1
            await service.cancel(ws.id, job.id)
            await service.shutdown()
            assert body.closed
            assert all(
                service.store.get_assessment(ws.id, j.id).execution_status
                == "cancelled"
                for j in queued
            )
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_database_failure_in_shutdown_still_joins_network_cleanup(monkeypatch):
    async def run():
        body = BlockingBody()
        repo, _, ws, program, profile, service = setup(
            lambda r: httpx.Response(
                200, headers={"content-type": "application/json"}, stream=body
            )
        )
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            await asyncio.wait_for(body.entered.wait(), 3)

            def unavailable(*args):
                raise OperationalError(
                    "synthetic", {}, RuntimeError("SECRET_EXCEPTION")
                )

            monkeypatch.setattr(service.store, "cancel", unavailable)
            with pytest.raises(OperationalError):
                await service.shutdown()
            assert body.closed and not service.worker_lock.held
            assert (
                service.store.get_assessment(ws.id, job.id).execution_status
                == "cancelled"
            )
            with Session(repo.engine) as session:
                assert session.scalar(select(ScopeLeaseRow)).released
        finally:
            monkeypatch.undo()
            await service.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize("change", ["expiry", "workspace", "deleted"])
def test_positive_publication_is_fenced_by_expiry_workspace_or_profile_deletion(change):
    async def run():
        body = BlockingBody()
        repo, shared, ws, program, profile, service = setup(
            lambda r: httpx.Response(
                200, headers={"content-type": "application/json"}, stream=body
            )
        )
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            await asyncio.wait_for(body.entered.wait(), 3)
            if change == "expiry":
                shared.clock = lambda: NOW + timedelta(days=2)
            elif change == "workspace":
                shared.store.update_workspace(ws.id, WorkspaceUpdate(active=False), NOW)
            else:
                service.store.delete_profile(ws.id, profile.id, NOW)
            body.release.set()
            result = await wait(service, ws.id, job.id)
            assert (
                result.status == "blocked_by_policy"
                and result.evidence_refs
                and body.closed
            )
            assert not service.store.findings(ws.id, job.id)
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_unexpected_internal_error_fails_job_without_raw_exception_logging(caplog):
    async def run():
        def handler(r):
            raise RuntimeError("SECRET_INTERNAL_IP_203.0.113.7")

        repo, _, ws, program, profile, service = setup(handler)
        try:
            await service.startup()
            job = await service.start(ws.id, profile.id, request(program.id))
            result = await wait(service, ws.id, job.id)
            assert (
                result.execution_status == "failed" and result.reason == "worker_error"
            )
            assert result.status == "inconclusive" and result.evidence_refs
            assert "SECRET_INTERNAL_IP" not in caplog.text
            with Session(repo.engine) as session:
                assert session.scalar(select(ScopeLeaseRow)).released
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_privacy_rate_budget_and_passive_preflight_require_no_network():
    async def run():
        repo, shared, ws, program, profile, service = setup(
            privacy_changes={"rate_limit_per_minute": 1}
        )
        try:
            preflight = await service.preflight(ws.id, profile.id, request(program.id))
            assert (
                preflight.allowed
                and not preflight.network_performed
                and preflight.advisory_only
            )
            assert (
                not shared.resolver.calls
                and shared.store.snapshot(ws.id, program.id)[1].used_requests == 0
            )
            await service.startup()
            first = await service.start(
                ws.id, profile.id, DiagnosticRequest(kind="ipv6")
            )
            await wait(service, ws.id, first.id)
            second = await service.start(
                ws.id, profile.id, DiagnosticRequest(kind="ipv6")
            )
            result = await wait(service, ws.id, second.id)
            assert (
                result.reason == "privacy_rate_limit_exceeded"
                and result.status == "blocked_by_policy"
            )
            assert (
                not shared.resolver.calls
                and service.store.snapshot(ws.id, profile.id)[1].used_observations == 1
            )
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_default_profile_policy_denies_all_diagnostics():
    async def run():
        repo, shared, ws, _, _, service = setup()
        try:
            profile = service.store.create_profile(
                ws.id, PrivacyProfileInput(name="default"), NOW
            )
            await service.startup()
            job = await service.start(ws.id, profile.id, DiagnosticRequest(kind="ipv6"))
            result = await wait(service, ws.id, job.id)
            assert (
                result.status == "blocked_by_policy"
                and result.reason == "privacy_approval_required"
            )
            assert not shared.resolver.calls
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_worker_lock_namespaces_cannot_authorize_cross_engine_recovery():
    repo, _, _, _, _, service = setup()
    discovery_lock = WorkerLock(repo)
    privacy_lock = WorkerLock(repo, "privacy")
    try:
        assert discovery_lock.acquire() and privacy_lock.acquire()
        with pytest.raises(Conflict):
            service.store.recover(discovery_lock, NOW)
        with pytest.raises(Conflict):
            DiscoveryEvidenceStore(repo).recover(NOW, privacy_lock)
        assert service.store.recover(privacy_lock, NOW) == 0
        with pytest.raises(Conflict):
            service.store.recover(privacy_lock, NOW)
    finally:
        discovery_lock.release()
        privacy_lock.release()
        repo.close()


@pytest.mark.parametrize("terminal", [False, True])
def test_recovery_requires_ended_owner_and_preserves_unowned_lease_and_budgets(
    tmp_path, terminal
):
    async def run():
        repo, shared, ws, program, profile, service = setup(
            url=f"sqlite:///{(tmp_path / 'recovery.sqlite').as_posix()}"
        )
        contender = PrivacyService(repo, shared)
        try:
            await service.startup()
            payload = request(program.id)
            preflight = await service.preflight(ws.id, profile.id, payload)
            job = service.store.create_assessment(
                ws.id, profile.id, payload, preflight, NOW
            )
            service.store.claim(ws.id, job.id, service.worker_id)
            _, lease_id = await service.guard.decide(
                ws.id,
                program.id,
                AuthorizationRequest(url="http://lab.test/echo"),
                reserve=True,
                privacy_owner=(str(job.id), service.worker_id),
            )
            unowned_id = str(uuid4())
            with Session(repo.engine) as session:
                session.add(
                    ScopeLeaseRow(
                        id=unowned_id,
                        workspace_id=str(ws.id),
                        policy_id=str(program.id),
                        created_at=NOW.isoformat(),
                        released=False,
                    )
                )
                session.commit()
            if terminal:
                from crimsonweb.api.privacy.models import PolicyObservation

                service.store.complete(
                    ws.id,
                    job.id,
                    service.worker_id,
                    PolicyObservation(**service.base(job, "inconclusive", "synthetic")),
                    NOW,
                    "failed",
                )
            assert await contender.startup() == 0 and not contender.worker_lock.held
            assert (
                await service.startup() == 0
            )  # no second recovery while lifetime lock held
            with Session(repo.engine) as session:
                assert not session.get(ScopeLeaseRow, lease_id).released
            service.worker_lock.release()  # fixture has no live task or HTTP connection
            assert await contender.startup() == (0 if terminal else 1)
            result = contender.store.get_assessment(ws.id, job.id)
            assert result.execution_status == "failed" and result.evidence_refs
            with Session(repo.engine) as session:
                assert session.get(ScopeLeaseRow, lease_id).released
                assert not session.get(ScopeLeaseRow, unowned_id).released
            assert shared.store.snapshot(ws.id, program.id)[1].used_requests == 1
            assert contender.store.snapshot(ws.id, profile.id)[1].used_observations == 1
            assert not contender.tasks
        finally:
            await contender.shutdown()
            await service.shutdown()
            repo.close()

    asyncio.run(run())


def test_real_process_lifetime_lock_prevents_recovery_until_process_ends(tmp_path):
    async def run():
        repo, _, ws, program, profile, service = setup(
            url=f"sqlite:///{(tmp_path / 'process.sqlite').as_posix()}"
        )
        code = """import sys
from crimsonweb.api.database import Repository
from crimsonweb.api.discovery.worker import WorkerLock
repo = Repository(sys.argv[1])
lock = WorkerLock(repo, 'privacy')
assert lock.acquire()
print('ready', flush=True)
sys.stdin.read(1)
lock.release()
repo.close()
"""
        child = await asyncio.to_thread(
            subprocess.Popen,
            [sys.executable, "-c", code, str(repo.engine.url)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "PYTHONPATH": "src"},
        )
        try:
            ready = await asyncio.wait_for(asyncio.to_thread(child.stdout.readline), 10)
            assert ready.strip() == "ready"
            payload = request(program.id)
            preflight = await service.preflight(ws.id, profile.id, payload)
            job = service.store.create_assessment(
                ws.id, profile.id, payload, preflight, NOW
            )
            service.store.claim(ws.id, job.id, "child-worker")
            _, lease = await service.guard.decide(
                ws.id,
                program.id,
                AuthorizationRequest(url="http://lab.test/echo"),
                reserve=True,
                privacy_owner=(str(job.id), "child-worker"),
            )
            assert await service.startup() == 0 and not service.worker_lock.held
            with Session(repo.engine) as session:
                assert not session.get(ScopeLeaseRow, lease).released
            child.stdin.write("x")
            child.stdin.flush()
            await asyncio.to_thread(child.wait, 10)
            assert child.returncode == 0 and await service.startup() == 1
            result = service.store.get_assessment(ws.id, job.id)
            assert (
                result.reason == "worker_interrupted_verified"
                and result.execution_status == "failed"
                and result.evidence_refs
            )
            with Session(repo.engine) as session:
                assert session.get(ScopeLeaseRow, lease).released
        finally:
            if child.poll() is None:
                child.terminate()
                await asyncio.to_thread(child.wait, 10)
            for pipe in (child.stdin, child.stdout, child.stderr):
                pipe.close()
            await service.shutdown()
            repo.close()

    asyncio.run(run())
