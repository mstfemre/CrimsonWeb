import asyncio
from uuid import uuid4

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from discovery_helpers import crawl_policy, setup
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from workspace_helpers import NOW

from crimsonweb.api.database import (
    Base,
    DiscoveryEndpointRow,
    DiscoveryEvidenceRow,
    DiscoveryRelationRow,
    Repository,
    ScopeLeaseRow,
    migration_config,
)
from crimsonweb.api.discovery.crawler import AuthorizedCrawler
from crimsonweb.api.discovery.inventory import (
    ApplicationSurfaceGraph,
    EndpointInventory,
)
from crimsonweb.api.discovery.models import DiscoveryLimits
from crimsonweb.api.workspaces.models import AuthorizationRequest, WorkspaceCreate
from crimsonweb.api.workspaces.store import Conflict


def migrate(repo, direction, revision):
    with repo.engine.begin() as connection:
        config = migration_config()
        config.attributes["connection"] = connection
        getattr(command, direction)(config, revision)


def test_endpoint_reference_cap_preserves_latest_observation_provenance():
    repo, service, ws, _, manager = setup()
    try:
        job = manager.store.create(ws.id, "openapi_import", DiscoveryLimits(), NOW)
        manager.store.claim(ws.id, job.id, manager.worker_id, NOW)
        crawler = AuthorizedCrawler(service, manager.store, manager.worker_id)
        for _ in range(21):
            evidence = crawler.evidence("http_metadata", "a" * 64, status=200)
            endpoint = EndpointInventory.make(
                job.id,
                "offline",
                "/shared",
                "GET",
                "http_response",
                evidence.ref,
                observation_status="request_guarded",
                status_code=200,
            )
            manager.store.save_batch(
                ws.id, job.id, manager.worker_id, evidence, [endpoint], []
            )
        stored = manager.store.endpoints(ws.id, job.id).items[0]
        assert (
            len(stored.evidence_refs) == 20 and stored.evidence_refs[0] == evidence.ref
        )
        assert manager.store.evidence(ws.id, job.id).total == 21
    finally:
        repo.close()


@pytest.mark.parametrize("field", ["evidence", "endpoint", "relation"])
def test_discovery_store_rejects_forged_evidence_references_atomically(field):
    repo, service, ws, _, manager = setup()
    try:
        job = manager.store.create(ws.id, "openapi_import", DiscoveryLimits(), NOW)
        manager.store.claim(ws.id, job.id, manager.worker_id, NOW)
        crawler = AuthorizedCrawler(service, manager.store, manager.worker_id)
        evidence = crawler.evidence("openapi_structure", "a" * 64)
        endpoint = EndpointInventory.make(
            job.id, "offline", "/objects", "GET", "openapi", evidence.ref
        )
        relation = ApplicationSurfaceGraph.relation(
            job.id, endpoint.id, "method", "GET", evidence.ref
        )
        forged = f"discovery_evidence:{uuid4()}"
        if field == "evidence":
            evidence.ref = forged
        elif field == "endpoint":
            endpoint.evidence_refs.append(forged)
        else:
            relation.evidence_ref = forged
        with pytest.raises(Conflict, match="evidence contract"):
            manager.store.save_batch(
                ws.id, job.id, manager.worker_id, evidence, [endpoint], [relation]
            )
        assert manager.store.endpoints(ws.id, job.id).total == 0
        assert manager.store.evidence(ws.id, job.id).total == 0
    finally:
        repo.close()


def test_phase4b_upgrade_downgrade_preserves_policy_budget_audit_and_legacy_lease(
    tmp_path,
):
    repo = Repository(f"sqlite:///{(tmp_path / 'migration.sqlite').as_posix()}")
    try:
        migrate(repo, "upgrade", "0003_phase4a")
        from workspace_helpers import FakeResolver

        from crimsonweb.api.workspaces.service import WorkspaceService

        service = WorkspaceService(repo, FakeResolver(), lambda: NOW)
        ws = service.store.create_workspace(
            WorkspaceCreate(name="existing", program_type="lab"), NOW
        )
        record = service.store.write_policy(ws.id, crawl_policy(), NOW)
        # Create a historical reservation in the pre-4B schema without new ORM columns.
        lease_id = str(uuid4())
        with repo.engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO scope_request_leases (id,workspace_id,policy_id,created_at,released) VALUES (:id,:ws,:policy,:time,0)"
                ),
                {
                    "id": lease_id,
                    "ws": str(ws.id),
                    "policy": str(record.id),
                    "time": NOW.isoformat(),
                },
            )
            connection.execute(
                text("UPDATE program_policies SET used_requests=1 WHERE id=:id"),
                {"id": str(record.id)},
            )
        before = service.store.audits(ws.id, 100, 0).model_dump()
        migrate(repo, "upgrade", "head")
        with Session(repo.engine) as session:
            lease = session.get(ScopeLeaseRow, lease_id)
            assert not lease.released and lease.discovery_job_id is None
        with repo.engine.connect() as connection:
            assert (
                compare_metadata(MigrationContext.configure(connection), Base.metadata)
                == []
            )
        migrate(repo, "downgrade", "0003_phase4a")
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
        assert service.store.audits(ws.id, 100, 0).model_dump() == before
        with repo.engine.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT released FROM scope_request_leases WHERE id=:id"),
                    {"id": lease_id},
                )
                == 0
            )
        migrate(repo, "upgrade", "head")
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 1
    finally:
        repo.close()


def test_downgrade_refuses_active_jobs_and_outstanding_owned_reservations():
    repo, service, ws, policy, manager = setup()
    try:
        job = manager.store.create(
            ws.id, "crawl", DiscoveryLimits(), NOW, policy.id, policy.revision
        )
        with pytest.raises(RuntimeError, match="Stop discovery workers"):
            migrate(repo, "downgrade", "0003_phase4a")
        manager.store.claim(ws.id, job.id, manager.worker_id, NOW)
        decision, lease_id = asyncio.run(
            service.decide(
                ws.id,
                policy.id,
                AuthorizationRequest(url="http://lab.test/", category="crawl"),
                reserve=True,
                discovery_owner=(str(job.id), manager.worker_id),
            )
        )
        assert decision.allowed
        manager.store.finish(
            ws.id, job.id, manager.worker_id, "failed", "storage_error", NOW
        )
        with pytest.raises(RuntimeError, match="Stop discovery workers"):
            migrate(repo, "downgrade", "0003_phase4a")
        service.store.release(ws.id, policy.id, lease_id, None, NOW)
        migrate(repo, "downgrade", "0003_phase4a")
        assert service.store.snapshot(ws.id, policy.id)[1].used_requests == 1
    finally:
        repo.close()


def test_composite_database_constraints_reject_cross_workspace_and_cross_job_records():
    repo, service, ws, _, manager = setup()
    try:
        other = service.store.create_workspace(
            WorkspaceCreate(name="B", program_type="lab"), NOW
        )
        first = manager.store.create(ws.id, "openapi_import", DiscoveryLimits(), NOW)
        second = manager.store.create(ws.id, "openapi_import", DiscoveryLimits(), NOW)
        endpoint_id, evidence_id = str(uuid4()), str(uuid4())
        with Session(repo.engine) as session:
            session.add(
                DiscoveryEndpointRow(
                    id=endpoint_id,
                    workspace_id=str(ws.id),
                    job_id=str(first.id),
                    fingerprint="a" * 64,
                    data={},
                )
            )
            session.add(
                DiscoveryEvidenceRow(
                    id=evidence_id,
                    workspace_id=str(ws.id),
                    job_id=str(first.id),
                    data={},
                )
            )
            session.commit()
        for row in (
            DiscoveryEndpointRow(
                id=str(uuid4()),
                workspace_id=str(other.id),
                job_id=str(first.id),
                fingerprint="b" * 64,
                data={},
            ),
            DiscoveryEvidenceRow(
                id=str(uuid4()),
                workspace_id=str(other.id),
                job_id=str(first.id),
                data={},
            ),
            DiscoveryRelationRow(
                id=str(uuid4()),
                workspace_id=str(ws.id),
                job_id=str(second.id),
                source_endpoint_id=endpoint_id,
                evidence_id=evidence_id,
                data={},
            ),
            DiscoveryRelationRow(
                id=str(uuid4()),
                workspace_id=str(other.id),
                job_id=str(first.id),
                source_endpoint_id=endpoint_id,
                evidence_id=evidence_id,
                data={},
            ),
        ):
            with Session(repo.engine) as session, pytest.raises(IntegrityError):
                session.add(row)
                session.commit()
    finally:
        repo.close()


@pytest.mark.parametrize(
    "change,expected",
    [
        ("worker", "discovery_worker_inactive"),
        ("cancel", "discovery_cancelled"),
        ("terminal", "discovery_worker_inactive"),
        ("budget", "discovery_budget_exhausted"),
    ],
)
def test_atomic_discovery_admission_fences_worker_cancellation_state_and_budget(
    change, expected
):
    repo, service, ws, record, manager = setup()
    try:
        job = manager.store.create(
            ws.id,
            "crawl",
            DiscoveryLimits(max_requests=1),
            NOW,
            record.id,
            record.revision,
        )
        manager.store.claim(ws.id, job.id, manager.worker_id, NOW)
        worker = manager.worker_id
        request = AuthorizationRequest(url="http://lab.test/", category="crawl")
        if change == "worker":
            worker = str(uuid4())
        elif change == "cancel":
            manager.store.cancel(ws.id, job.id, NOW)
        elif change == "terminal":
            manager.store.finish(ws.id, job.id, worker, "completed", None, NOW)
        else:
            _, admitted = asyncio.run(
                service.decide(
                    ws.id,
                    record.id,
                    request,
                    reserve=True,
                    discovery_owner=(str(job.id), worker),
                )
            )
            service.store.release(ws.id, record.id, admitted, None, NOW)
        decision, lease = asyncio.run(
            service.decide(
                ws.id,
                record.id,
                request,
                reserve=True,
                discovery_owner=(str(job.id), worker),
            )
        )
        assert not decision.allowed and decision.reason == expected and lease is None
        policy = service.store.snapshot(ws.id, record.id)[1]
        assert policy.used_requests == (1 if change == "budget" else 0)
        assert not policy.halted_reason
    finally:
        repo.close()
