import asyncio
from threading import Event

import httpx
import pytest
from workspace_helpers import NOW, policy, seeded

from crimsonweb.api.workspaces.models import AuthorizationRequest
from crimsonweb.api.workspaces.service import AuthorizationDenied

REQUEST = AuthorizationRequest(url="http://lab.test/")


def test_cancellation_during_database_admission_does_not_orphan_slot(monkeypatch):
    repo, service, ws, record = seeded(configuration=policy(maximum_concurrency=1))
    original = service.store.decide
    unblock = Event()
    try:

        async def run():
            started = asyncio.Event()
            loop = asyncio.get_running_loop()

            def controlled_admission(*args):
                loop.call_soon_threadsafe(started.set)
                if not unblock.wait(timeout=5):
                    raise AssertionError("Admission test stalled")
                return original(*args)

            monkeypatch.setattr(service.store, "decide", controlled_admission)
            task = asyncio.create_task(
                service.decide(ws.id, record.id, REQUEST, reserve=True)
            )
            await asyncio.wait_for(started.wait(), timeout=5)
            task.cancel()
            unblock.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=5)
            monkeypatch.setattr(service.store, "decide", original)
            assert (await service.preflight(ws.id, record.id, REQUEST)).allowed

        asyncio.run(run())
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
    finally:
        unblock.set()
        repo.close()


def test_defense_response_retains_slot_until_closed_even_after_operator_resume():
    repo, service, ws, record = seeded(configuration=policy(maximum_concurrency=1))
    try:

        async def run():
            async with service.stream(
                ws.id,
                record.id,
                REQUEST,
                httpx.MockTransport(lambda request: httpx.Response(403)),
            ):
                service.store.write_policy(
                    ws.id, policy(maximum_concurrency=1), NOW, record.id, 1
                )
                with pytest.raises(AuthorizationDenied, match="concurrency_exceeded"):
                    async with service.stream(
                        ws.id,
                        record.id,
                        REQUEST,
                        httpx.MockTransport(lambda request: httpx.Response(200)),
                    ):
                        pytest.fail("Defense response still occupies its slot")
            assert (
                await service.preflight(ws.id, record.id, REQUEST)
            ).reason == "policy_halted"

        asyncio.run(run())
    finally:
        repo.close()


def test_policy_revisions_preserve_old_scope_and_audit_proof():
    repo, service, ws, record = seeded()
    try:
        assert asyncio.run(service.preflight(ws.id, record.id, REQUEST)).allowed
        replacement = policy().model_dump()
        replacement["target_scope"]["forbidden_paths"] = ["/*"]
        from crimsonweb.api.workspaces.models import ProgramPolicy

        service.store.write_policy(
            ws.id, ProgramPolicy.model_validate(replacement), NOW, record.id, 1
        )
        assert service.store.policy_revision(
            ws.id, record.id, 1
        ).policy.target_scope.forbidden_paths == ["/admin/*"]
        assert service.store.policy_revision(
            ws.id, record.id, 2
        ).policy.target_scope.forbidden_paths == ["/*"]
        decision = next(
            a
            for a in service.store.audits(ws.id, 100, 0).items
            if a.action == "preflight"
        )
        assert decision.policy_revision == 1 and decision.resolved_ips == ["127.0.0.1"]
        assert not asyncio.run(service.preflight(ws.id, record.id, REQUEST)).allowed
    finally:
        repo.close()
