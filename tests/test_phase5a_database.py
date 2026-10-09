import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from privacy_helpers import request, setup
from sqlalchemy import inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from workspace_helpers import NOW, policy

from crimsonweb.api.database import (
    Base,
    PrivacyAssessmentRow,
    PrivacyEvidenceRow,
    PrivacyFindingRow,
    Repository,
    ScopeLeaseRow,
    migration_config,
)
from crimsonweb.api.discovery.models import DiscoveryLimits
from crimsonweb.api.discovery.store import DiscoveryEvidenceStore
from crimsonweb.api.privacy.models import PrivacyPolicy, PrivacyProfileInput
from crimsonweb.api.privacy.store import PrivacyStore
from crimsonweb.api.workspaces.models import AuthorizationRequest, WorkspaceCreate
from crimsonweb.api.workspaces.service import WorkspaceService
from crimsonweb.api.workspaces.store import Conflict, NotFound


def queued(service, ws, profile, program):
    payload = request(program.id)
    preflight = asyncio.run(service.preflight(ws.id, profile.id, payload))
    return service.store.create_assessment(ws.id, profile.id, payload, preflight, NOW)


def migrate(repo, direction, revision):
    with repo.engine.begin() as connection:
        config = migration_config()
        config.attributes["connection"] = connection
        getattr(command, direction)(config, revision)


@pytest.mark.parametrize(
    "field", ["ref", "workspace_id", "profile_id", "assessment_id"]
)
def test_wrong_privacy_evidence_contract_is_rejected_atomically(field):
    repo, _, ws, program, profile, service = setup()
    try:
        job = queued(service, ws, profile, program)
        service.store.claim(ws.id, job.id, service.worker_id)
        from crimsonweb.api.privacy.models import PolicyObservation

        evidence = PolicyObservation(**service.base(job, "inconclusive", "synthetic"))
        setattr(
            evidence,
            field,
            f"privacy_evidence:{uuid4()}" if field == "ref" else uuid4(),
        )
        with pytest.raises(Conflict, match="evidence contract"):
            service.store.complete(ws.id, job.id, service.worker_id, evidence, NOW)
        with Session(repo.engine) as session:
            assert not list(session.scalars(select(PrivacyEvidenceRow)))
        assert service.store.get_assessment(ws.id, job.id).execution_status == "running"
    finally:
        repo.close()


def test_cleanup_bypass_cannot_publish_a_positive_privacy_verdict():
    from crimsonweb.api.privacy.models import PolicyObservation

    repo, _, ws, program, profile, service = setup()
    try:
        job = queued(service, ws, profile, program)
        service.store.claim(ws.id, job.id, service.worker_id)
        evidence = PolicyObservation(
            **service.base(job, "secure_observed", "synthetic")
        )
        with pytest.raises(Conflict, match="requires current permission"):
            service.store.complete(
                ws.id, job.id, service.worker_id, evidence, NOW, bypass_revision=True
            )
    finally:
        repo.close()


def test_database_foreign_keys_reject_cross_workspace_profile_and_evidence_links():
    repo, shared, ws, program, profile, service = setup()
    try:
        other = shared.store.create_workspace(
            WorkspaceCreate(name="other", program_type="lab"), NOW
        )
        other_profile = service.store.create_profile(
            ws.id, PrivacyProfileInput(name="second"), NOW
        )
        job = queued(service, ws, profile, program)
        evidence_id = str(uuid4())
        with Session(repo.engine) as session:
            session.add(
                PrivacyEvidenceRow(
                    id=evidence_id,
                    workspace_id=str(ws.id),
                    profile_id=str(profile.id),
                    assessment_id=str(job.id),
                    data={},
                )
            )
            session.commit()
        for row in (
            PrivacyEvidenceRow(
                id=str(uuid4()),
                workspace_id=str(other.id),
                profile_id=str(profile.id),
                assessment_id=str(job.id),
                data={},
            ),
            PrivacyEvidenceRow(
                id=str(uuid4()),
                workspace_id=str(ws.id),
                profile_id=str(other_profile.id),
                assessment_id=str(job.id),
                data={},
            ),
            PrivacyFindingRow(
                id=str(uuid4()),
                workspace_id=str(ws.id),
                profile_id=str(other_profile.id),
                assessment_id=str(job.id),
                evidence_id=evidence_id,
                data={},
            ),
            PrivacyFindingRow(
                id=str(uuid4()),
                workspace_id=str(ws.id),
                profile_id=str(profile.id),
                assessment_id=str(job.id),
                evidence_id=str(uuid4()),
                data={},
            ),
            ScopeLeaseRow(
                id=str(uuid4()),
                workspace_id=str(ws.id),
                policy_id=str(program.id),
                created_at=NOW.isoformat(),
                released=False,
                privacy_assessment_id=str(uuid4()),
                privacy_worker_id=service.worker_id,
            ),
        ):
            with Session(repo.engine) as session, pytest.raises(IntegrityError):
                session.add(row)
                session.commit()
    finally:
        repo.close()


def test_workspace_and_same_workspace_profile_isolation_in_store():
    repo, shared, ws, program, profile, service = setup()
    try:
        other = shared.store.create_workspace(
            WorkspaceCreate(name="other", program_type="lab"), NOW
        )
        second = service.store.create_profile(
            ws.id, PrivacyProfileInput(name="second"), NOW
        )
        job = queued(service, ws, profile, program)
        for call in (
            lambda: service.store.snapshot(other.id, profile.id),
            lambda: service.store.update_profile(
                other.id, profile.id, PrivacyProfileInput(name="x"), 1, NOW
            ),
            lambda: service.store.delete_profile(other.id, profile.id, NOW),
            lambda: service.store.write_privacy_policy(
                other.id, profile.id, PrivacyPolicy(), 2, NOW
            ),
            lambda: service.store.get_assessment(other.id, job.id),
            lambda: service.store.cancel(other.id, job.id, NOW),
            lambda: service.store.findings(other.id, job.id),
            lambda: service.store.evidence(other.id, uuid4()),
        ):
            with pytest.raises(NotFound):
                call()
        assert (
            service.profiles(other.id).total
            == service.assessments(other.id).total
            == service.audits(other.id).total
            == 0
        )
        assert service.store.snapshot(ws.id, second.id)[1].used_observations == 0
        assert service.store.snapshot(ws.id, profile.id)[1].used_observations == 1
        assert (
            service.store.snapshot(ws.id, second.id)[0].approved_egress_identity
            != profile.approved_egress_identity
        )
    finally:
        repo.close()


@pytest.mark.parametrize(
    "change,reason",
    [
        ("worker", "privacy_worker_inactive"),
        ("cancel", "privacy_cancelled"),
        ("profile", "privacy_revision_changed"),
        ("request", "privacy_request_contract_changed"),
        ("budget", "privacy_observation_budget_exhausted"),
    ],
)
def test_atomic_privacy_admission_fences_owner_revision_fingerprint_and_budget(
    change, reason
):
    repo, shared, ws, program, profile, service = setup()
    try:
        job = queued(service, ws, profile, program)
        service.store.claim(ws.id, job.id, service.worker_id)
        worker = service.worker_id
        target = AuthorizationRequest(url="http://lab.test/echo")
        if change == "worker":
            worker = str(uuid4())
        elif change == "cancel":
            service.store.cancel(ws.id, job.id, NOW)
        elif change == "profile":
            service.store.update_profile(
                ws.id, profile.id, PrivacyProfileInput(name="changed"), 1, NOW
            )
        elif change == "request":
            target = AuthorizationRequest(url="http://lab.test/changed")
        else:
            decision, lease = asyncio.run(
                service.guard.decide(
                    ws.id,
                    program.id,
                    target,
                    reserve=True,
                    privacy_owner=(str(job.id), worker),
                )
            )
            assert decision.allowed
            shared.store.release(ws.id, program.id, lease, None, NOW)
        decision, lease = asyncio.run(
            service.guard.decide(
                ws.id,
                program.id,
                target,
                reserve=True,
                privacy_owner=(str(job.id), worker),
            )
        )
        assert not decision.allowed and decision.reason == reason and lease is None
        record = shared.store.snapshot(ws.id, program.id)[1]
        assert (
            record.used_requests == (1 if change == "budget" else 0)
            and not record.halted_reason
        )
    finally:
        repo.close()


def test_privacy_budget_is_atomic_across_connections_persistent_and_not_reset_by_update(
    tmp_path,
):
    url = f"sqlite:///{(tmp_path / 'budget.sqlite').as_posix()}"
    repo, _, ws, program, profile, service = setup(
        url=url, privacy_changes={"maximum_observations": 1}
    )
    second_repo = Repository(url)
    try:
        second_store = PrivacyStore(second_repo)
        payload = request(program.id)
        preflight = asyncio.run(service.preflight(ws.id, profile.id, payload))
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = list(
                pool.map(
                    lambda store: store.create_assessment(
                        ws.id, profile.id, payload, preflight, NOW
                    ),
                    [service.store, second_store],
                )
            )
        with Session(repo.engine) as session:
            rows = list(session.scalars(select(PrivacyAssessmentRow)))
            assert sum(row.data["diagnostic_admitted"] for row in rows) == 1
        assert (
            len(jobs) == 2
            and second_store.snapshot(ws.id, profile.id)[1].used_observations == 1
        )
        record = service.store.snapshot(ws.id, profile.id)[1]
        service.store.write_privacy_policy(
            ws.id,
            profile.id,
            PrivacyPolicy(maximum_observations=100),
            record.revision,
            NOW,
        )
        assert service.store.snapshot(ws.id, profile.id)[1].used_observations == 1
    finally:
        second_repo.close()
        repo.close()
    reopened = Repository(url)
    try:
        assert (
            PrivacyStore(reopened).snapshot(ws.id, profile.id)[1].used_observations == 1
        )
    finally:
        reopened.close()


def test_migration_roundtrip_preserves_preexisting_scope_discovery_audits_and_leases(
    tmp_path,
):
    repo = Repository(f"sqlite:///{(tmp_path / 'migration.sqlite').as_posix()}")
    try:
        migrate(repo, "upgrade", "0004_phase4b")
        from workspace_helpers import FakeResolver

        shared = WorkspaceService(repo, FakeResolver(), lambda: NOW)
        ws = shared.store.create_workspace(
            WorkspaceCreate(name="existing", program_type="lab"), NOW
        )
        program = shared.store.write_policy(ws.id, policy(), NOW)
        discovery = DiscoveryEvidenceStore(repo)
        job = discovery.create(ws.id, "openapi_import", DiscoveryLimits(), NOW)
        discovery.claim(ws.id, job.id, "prior-worker", NOW)
        discovery.finish(ws.id, job.id, "prior-worker", "completed", None, NOW)
        lease_id = str(uuid4())
        with repo.engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO scope_request_leases (id,workspace_id,policy_id,created_at,released) VALUES (:id,:ws,:pid,:time,0)"
                ),
                {
                    "id": lease_id,
                    "ws": str(ws.id),
                    "pid": str(program.id),
                    "time": NOW.isoformat(),
                },
            )
            connection.execute(
                text("UPDATE program_policies SET used_requests=1 WHERE id=:pid"),
                {"pid": str(program.id)},
            )
        before_audit = shared.store.audits(ws.id, 100, 0).model_dump()
        before_job = discovery.get(ws.id, job.id).model_dump()
        migrate(repo, "upgrade", "head")
        with repo.engine.connect() as connection:
            assert (
                compare_metadata(MigrationContext.configure(connection), Base.metadata)
                == []
            )
        migrate(repo, "downgrade", "0004_phase4b")
        assert discovery.get(ws.id, job.id).model_dump() == before_job
        assert shared.store.audits(ws.id, 100, 0).model_dump() == before_audit
        assert shared.store.snapshot(ws.id, program.id)[1].used_requests == 1
        with repo.engine.connect() as connection:
            assert (
                connection.scalar(
                    text("SELECT released FROM scope_request_leases WHERE id=:id"),
                    {"id": lease_id},
                )
                == 0
            )
        assert "privacy_profiles" not in inspect(repo.engine).get_table_names()
        migrate(repo, "upgrade", "head")
        assert shared.store.snapshot(ws.id, program.id)[1].used_requests == 1
    finally:
        repo.close()


def test_repeated_downgrade_refusals_leave_head_schema_and_jobs_intact():
    repo, shared, ws, program, profile, service = setup()
    try:
        job = queued(service, ws, profile, program)
        before = service.store.get_assessment(ws.id, job.id).model_dump()
        for _ in range(2):
            with pytest.raises(RuntimeError, match="Stop privacy workers"):
                migrate(repo, "downgrade", "0004_phase4b")
            with repo.engine.connect() as connection:
                assert (
                    connection.scalar(text("SELECT version_num FROM alembic_version"))
                    == "0005_phase5a"
                )
                assert (
                    compare_metadata(
                        MigrationContext.configure(connection), Base.metadata
                    )
                    == []
                )
            assert not any(
                name.startswith("_alembic_tmp")
                for name in inspect(repo.engine).get_table_names()
            )
            assert service.store.get_assessment(ws.id, job.id).model_dump() == before
        service.store.claim(ws.id, job.id, service.worker_id)
        decision, lease = asyncio.run(
            service.guard.decide(
                ws.id,
                program.id,
                AuthorizationRequest(url="http://lab.test/echo"),
                reserve=True,
                privacy_owner=(str(job.id), service.worker_id),
            )
        )
        assert decision.allowed
        # Even a terminal record cannot free a still-live HTTP reservation for rollback.
        with Session(repo.engine) as session:
            row = session.get(PrivacyAssessmentRow, str(job.id))
            row.execution_status = "failed"
            session.commit()
        with pytest.raises(RuntimeError, match="Stop privacy workers"):
            migrate(repo, "downgrade", "0004_phase4b")
        shared.store.release(ws.id, program.id, lease, None, NOW)
        migrate(repo, "downgrade", "0004_phase4b")
        assert shared.store.snapshot(ws.id, program.id)[1].used_requests == 1
    finally:
        repo.close()


def test_privacy_minimization_applies_to_durable_records_and_audit_summaries():
    repo, _, ws, program, profile, service = setup()
    try:
        job = queued(service, ws, profile, program)
        service.store.cancel(ws.id, job.id, NOW)
        with Session(repo.engine) as session:
            from crimsonweb.api.database import PrivacyAuditRow, PrivacyProfileRow

            encoded = json.dumps(
                [
                    row.data
                    for table in (
                        PrivacyAuditRow,
                        PrivacyProfileRow,
                        PrivacyAssessmentRow,
                        PrivacyEvidenceRow,
                    )
                    for row in session.scalars(select(table))
                ]
            )
        assert "203.0.113.7" not in encoded and "http://lab.test/echo" not in encoded
        assert "identity_key" not in encoded and "SECRET_COOKIE" not in encoded
        cancelled = service.store.get_assessment(ws.id, job.id)
        assert cancelled.evidence_refs and not cancelled.retention_enforced
    finally:
        repo.close()


@pytest.mark.parametrize(
    "ownership", ["mixed_engines", "missing_worker", "orphan_worker"]
)
def test_database_check_constraint_rejects_ambiguous_reservation_ownership(ownership):
    repo, _, ws, program, profile, service = setup()
    try:
        job = queued(service, ws, profile, program)
        discovery = DiscoveryEvidenceStore(repo).create(
            ws.id, "openapi_import", DiscoveryLimits(), NOW
        )
        row = ScopeLeaseRow(
            id=str(uuid4()),
            workspace_id=str(ws.id),
            policy_id=str(program.id),
            created_at=NOW.isoformat(),
            released=False,
            privacy_assessment_id=None if ownership == "orphan_worker" else str(job.id),
            privacy_worker_id=None
            if ownership == "missing_worker"
            else service.worker_id,
            discovery_job_id=str(discovery.id)
            if ownership == "mixed_engines"
            else None,
            discovery_worker_id="discovery-worker"
            if ownership == "mixed_engines"
            else None,
        )
        with (
            Session(repo.engine) as session,
            pytest.raises(IntegrityError, match="ck_scope_lease_privacy_ownership"),
        ):
            session.add(row)
            session.commit()
    finally:
        repo.close()
