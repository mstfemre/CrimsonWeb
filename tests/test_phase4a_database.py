import asyncio
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from workspace_helpers import NOW, FakeResolver, policy, seeded

from crimsonweb.api.database import (
    Base,
    Repository,
    ScopeAuditRow,
    ScopeLeaseRow,
    TargetScopeRow,
    migration_config,
)
from crimsonweb.api.models import ScanReport
from crimsonweb.api.workspaces.models import AuthorizationRequest, WorkspaceCreate
from crimsonweb.api.workspaces.service import WorkspaceService
from crimsonweb.api.workspaces.store import NotFound

REQUEST = AuthorizationRequest(url="http://lab.test/")


def test_durable_budget_and_outstanding_slot_after_restart(tmp_path):
    url = f"sqlite:///{(tmp_path / 'scope.sqlite').as_posix()}"
    repo, service, ws, record = seeded(url, configuration=policy(maximum_concurrency=1))
    decision, lease_id = asyncio.run(
        service.decide(ws.id, record.id, REQUEST, reserve=True)
    )
    assert decision.allowed and lease_id
    repo.close()
    reopened = Repository(url)
    reopened.initialize()
    try:
        service = WorkspaceService(reopened, FakeResolver(), lambda: NOW)
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
        assert (
            asyncio.run(service.preflight(ws.id, record.id, REQUEST)).reason
            == "concurrency_exceeded"
        )
        assert service.store.audits(ws.id, 100, 0).total == 4
        service.store.release(ws.id, record.id, lease_id, None, NOW)
        service.store.release(ws.id, record.id, lease_id, None, NOW)
        assert asyncio.run(service.preflight(ws.id, record.id, REQUEST)).allowed
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
    finally:
        reopened.close()


def test_workspace_isolation_for_lease_release_and_database_fks():
    repo, service, ws, record = seeded()
    other = service.store.create_workspace(
        WorkspaceCreate(name="B", program_type="lab"), NOW
    )
    other_policy = service.store.write_policy(other.id, policy(), NOW)
    _, lease_id = asyncio.run(service.decide(ws.id, record.id, REQUEST, reserve=True))
    try:
        with pytest.raises(NotFound):
            service.store.release(other.id, record.id, lease_id, None, NOW)
        with pytest.raises(NotFound):
            service.store.release(other.id, other_policy.id, lease_id, None, NOW)
        with Session(repo.engine) as session:
            assert not session.get(ScopeLeaseRow, lease_id).released
        for row in (
            TargetScopeRow(
                id=str(uuid4()),
                workspace_id=str(other.id),
                policy_id=str(record.id),
                data={},
            ),
            ScopeAuditRow(
                id=str(uuid4()),
                workspace_id=str(other.id),
                policy_id=str(record.id),
                timestamp=NOW.isoformat(),
                action="test",
                allowed=False,
                reason="test",
            ),
            ScopeLeaseRow(
                id=str(uuid4()),
                workspace_id=str(other.id),
                policy_id=str(record.id),
                created_at=NOW.isoformat(),
                released=False,
            ),
        ):
            with Session(repo.engine) as session, pytest.raises(IntegrityError):
                session.add(row)
                session.commit()
    finally:
        repo.close()


@pytest.mark.parametrize("limit", ["budget", "concurrency"])
def test_atomic_admission_across_independent_repository_connections(tmp_path, limit):
    url = f"sqlite:///{(tmp_path / 'races.sqlite').as_posix()}"
    config = (
        policy(maximum_request_budget=1)
        if limit == "budget"
        else policy(maximum_concurrency=1)
    )
    repo, service, ws, record = seeded(url, configuration=config)
    second = Repository(url)
    second.initialize()
    other_service = WorkspaceService(second, FakeResolver(), lambda: NOW)
    barrier = Barrier(2)
    try:

        def admit(svc):
            barrier.wait(timeout=5)
            return asyncio.run(svc.decide(ws.id, record.id, REQUEST, reserve=True))[0]

        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(admit, svc) for svc in (service, other_service)]
            decisions = [future.result(timeout=10) for future in futures]
        assert sum(d.allowed for d in decisions) == 1
        assert [d.reason for d in decisions if not d.allowed] == [
            "budget_exhausted" if limit == "budget" else "concurrency_exceeded"
        ]
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
    finally:
        repo.close()
        second.close()


def test_migration_preserves_legacy_reports_through_upgrade_and_downgrade(tmp_path):
    repo = Repository(f"sqlite:///{(tmp_path / 'upgrade.sqlite').as_posix()}")
    item = ScanReport(
        id=str(uuid4()),
        engagement_id="legacy",
        target="http://127.0.0.1/",
        scope={},
        status="completed",
    )
    try:
        with repo.engine.begin() as connection:
            config = migration_config()
            config.attributes["connection"] = connection
            command.upgrade(config, "0002_phase3")
        repo.save(item)
        repo.initialize()
        service = WorkspaceService(repo)
        workspace = service.store.create_workspace(
            WorkspaceCreate(name="new", program_type="lab"), NOW
        )
        service.store.write_policy(workspace.id, policy(), NOW)
        assert repo.get(item.id).model_dump() == item.model_dump()
        with repo.engine.begin() as connection:
            assert (
                compare_metadata(MigrationContext.configure(connection), Base.metadata)
                == []
            )
            config.attributes["connection"] = connection
            command.downgrade(config, "0002_phase3")
            assert connection.scalar(text("SELECT COUNT(*) FROM scans")) == 1
            command.upgrade(config, "head")
            assert (
                compare_metadata(MigrationContext.configure(connection), Base.metadata)
                == []
            )
        assert repo.get(item.id).model_dump() == item.model_dump()
        with Session(repo.engine) as session:
            assert not session.scalars(select(TargetScopeRow)).all()
    finally:
        repo.close()
