"""SQLite repository. Sessions never cross threads; reports and child rows commit atomically."""

import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from uuid import uuid4

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    delete,
    event,
    func,
    inspect,
    select,
)
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship
from sqlalchemy.pool import StaticPool

from .ai.models import AnalysisRecord
from .models import FindingResult, Page, ScanReport, TargetResult, WAFEvent


class Base(DeclarativeBase):
    pass


class TargetRow(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    url: Mapped[str] = mapped_column(String(2048), unique=True)
    created_at: Mapped[str] = mapped_column(String(40))
    scans: Mapped[list["ScanRow"]] = relationship(back_populates="target")


class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    engagement_id: Mapped[str] = mapped_column(String(100), index=True)
    started_at: Mapped[str] = mapped_column(String(40), index=True)
    finished_at: Mapped[str | None] = mapped_column(String(40))
    report: Mapped[dict] = mapped_column(JSON)
    target: Mapped[TargetRow] = relationship(back_populates="scans")
    findings: Mapped[list["FindingRow"]] = relationship(back_populates="scan")
    events: Mapped[list["EventRow"]] = relationship(back_populates="scan")


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    data: Mapped[dict] = mapped_column(JSON)
    scan: Mapped[ScanRow] = relationship(back_populates="findings")


class EventRow(Base):
    __tablename__ = "waf_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), index=True)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    rule_id: Mapped[str | None] = mapped_column(String(64), index=True)
    data: Mapped[dict] = mapped_column(JSON)
    scan: Mapped[ScanRow | None] = relationship(back_populates="events")


class AnalysisRow(Base):
    __tablename__ = "ai_analyses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str | None] = mapped_column(ForeignKey("scans.id"), index=True)
    status: Mapped[str] = mapped_column(String(16), index=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)
    created_at: Mapped[str] = mapped_column(String(40), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class WorkspaceRow(Base):
    __tablename__ = "workspaces"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    data: Mapped[dict] = mapped_column(JSON)


class ProgramPolicyRow(Base):
    __tablename__ = "program_policies"
    __table_args__ = (UniqueConstraint("id", "workspace_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), unique=True)
    revision: Mapped[int] = mapped_column(Integer)
    used_requests: Mapped[int] = mapped_column(Integer)
    halted_reason: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[str] = mapped_column(String(40))
    updated_at: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)


class PolicyRevisionRow(Base):
    __tablename__ = "policy_revisions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    policy_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)


class TargetScopeRow(Base):
    __tablename__ = "target_scopes"
    __table_args__ = (
        ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(36), unique=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class ScopeAuditRow(Base):
    __tablename__ = "scope_audit_logs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    policy_id: Mapped[str | None] = mapped_column(String(36))
    policy_revision: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    action: Mapped[str] = mapped_column(String(32))
    allowed: Mapped[bool] = mapped_column(Boolean)
    reason: Mapped[str] = mapped_column(String(64))
    request_fingerprint: Mapped[str | None] = mapped_column(String(64))
    resolved_ips: Mapped[list] = mapped_column(JSON, default=list)


class ScopeLeaseRow(Base):
    __tablename__ = "scope_request_leases"
    __table_args__ = (
        CheckConstraint(
            "(privacy_assessment_id IS NULL AND privacy_worker_id IS NULL) OR "
            "(privacy_assessment_id IS NOT NULL AND privacy_worker_id IS NOT NULL "
            "AND discovery_job_id IS NULL AND discovery_worker_id IS NULL)",
            name="ck_scope_lease_privacy_ownership",
        ),
        ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
        ForeignKeyConstraint(
            ["discovery_job_id", "workspace_id"],
            ["discovery_jobs.id", "discovery_jobs.workspace_id"],
            name="fk_scope_lease_discovery_job",
        ),
        ForeignKeyConstraint(
            ["privacy_assessment_id", "workspace_id", "policy_id"],
            [
                "privacy_assessments.id",
                "privacy_assessments.workspace_id",
                "privacy_assessments.program_policy_id",
            ],
            name="fk_scope_lease_privacy_assessment",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    policy_id: Mapped[str] = mapped_column(String(36), index=True)
    created_at: Mapped[str] = mapped_column(String(40), index=True)
    released: Mapped[bool] = mapped_column(Boolean)
    discovery_job_id: Mapped[str | None] = mapped_column(String(36))
    discovery_worker_id: Mapped[str | None] = mapped_column(String(36))
    privacy_assessment_id: Mapped[str | None] = mapped_column(String(36))
    privacy_worker_id: Mapped[str | None] = mapped_column(String(36))


class DiscoveryJobRow(Base):
    __tablename__ = "discovery_jobs"
    __table_args__ = (
        UniqueConstraint("id", "workspace_id"),
        ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    policy_id: Mapped[str | None] = mapped_column(String(36))
    status: Mapped[str] = mapped_column(String(32), index=True)
    worker_id: Mapped[str | None] = mapped_column(String(36))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)


class DiscoveryEndpointRow(Base):
    __tablename__ = "discovery_endpoints"
    __table_args__ = (
        UniqueConstraint("id", "workspace_id", "job_id"),
        UniqueConstraint("workspace_id", "job_id", "fingerprint"),
        ForeignKeyConstraint(
            ["job_id", "workspace_id"],
            ["discovery_jobs.id", "discovery_jobs.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), index=True)
    job_id: Mapped[str] = mapped_column(String(36), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)


class DiscoveryEvidenceRow(Base):
    __tablename__ = "discovery_evidence"
    __table_args__ = (
        UniqueConstraint("id", "workspace_id", "job_id"),
        ForeignKeyConstraint(
            ["job_id", "workspace_id"],
            ["discovery_jobs.id", "discovery_jobs.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), index=True)
    job_id: Mapped[str] = mapped_column(String(36), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class DiscoveryRelationRow(Base):
    __tablename__ = "discovery_relations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["job_id", "workspace_id"],
            ["discovery_jobs.id", "discovery_jobs.workspace_id"],
        ),
        ForeignKeyConstraint(
            ["source_endpoint_id", "workspace_id", "job_id"],
            [
                "discovery_endpoints.id",
                "discovery_endpoints.workspace_id",
                "discovery_endpoints.job_id",
            ],
        ),
        ForeignKeyConstraint(
            ["related_endpoint_id", "workspace_id", "job_id"],
            [
                "discovery_endpoints.id",
                "discovery_endpoints.workspace_id",
                "discovery_endpoints.job_id",
            ],
        ),
        ForeignKeyConstraint(
            ["evidence_id", "workspace_id", "job_id"],
            [
                "discovery_evidence.id",
                "discovery_evidence.workspace_id",
                "discovery_evidence.job_id",
            ],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), index=True)
    job_id: Mapped[str] = mapped_column(String(36), index=True)
    source_endpoint_id: Mapped[str] = mapped_column(String(36))
    related_endpoint_id: Mapped[str | None] = mapped_column(String(36))
    evidence_id: Mapped[str] = mapped_column(String(36))
    data: Mapped[dict] = mapped_column(JSON)


class PrivacyProfileRow(Base):
    __tablename__ = "privacy_profiles"
    __table_args__ = (UniqueConstraint("id", "workspace_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    revision: Mapped[int] = mapped_column(Integer)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    identity_key: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)


class PrivacyPolicyRow(Base):
    __tablename__ = "privacy_policies"
    __table_args__ = (
        UniqueConstraint("profile_id", "workspace_id"),
        ForeignKeyConstraint(
            ["profile_id", "workspace_id"],
            ["privacy_profiles.id", "privacy_profiles.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36))
    profile_id: Mapped[str] = mapped_column(String(36))
    revision: Mapped[int] = mapped_column(Integer)
    used_observations: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(JSON)


class PrivacyAssessmentRow(Base):
    __tablename__ = "privacy_assessments"
    __table_args__ = (
        UniqueConstraint("id", "profile_id", "workspace_id"),
        UniqueConstraint("id", "workspace_id", "program_policy_id"),
        ForeignKeyConstraint(
            ["profile_id", "workspace_id"],
            ["privacy_profiles.id", "privacy_profiles.workspace_id"],
        ),
        ForeignKeyConstraint(
            ["program_policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), index=True)
    profile_id: Mapped[str] = mapped_column(String(36), index=True)
    program_policy_id: Mapped[str | None] = mapped_column(String(36))
    execution_status: Mapped[str] = mapped_column(String(16))
    worker_id: Mapped[str | None] = mapped_column(String(36))
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)


class PrivacyEvidenceRow(Base):
    __tablename__ = "privacy_evidence"
    __table_args__ = (
        UniqueConstraint("id", "assessment_id", "profile_id", "workspace_id"),
        ForeignKeyConstraint(
            ["assessment_id", "profile_id", "workspace_id"],
            [
                "privacy_assessments.id",
                "privacy_assessments.profile_id",
                "privacy_assessments.workspace_id",
            ],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36))
    profile_id: Mapped[str] = mapped_column(String(36))
    assessment_id: Mapped[str] = mapped_column(String(36), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class PrivacyFindingRow(Base):
    __tablename__ = "privacy_findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["assessment_id", "profile_id", "workspace_id"],
            [
                "privacy_assessments.id",
                "privacy_assessments.profile_id",
                "privacy_assessments.workspace_id",
            ],
        ),
        ForeignKeyConstraint(
            ["evidence_id", "assessment_id", "profile_id", "workspace_id"],
            [
                "privacy_evidence.id",
                "privacy_evidence.assessment_id",
                "privacy_evidence.profile_id",
                "privacy_evidence.workspace_id",
            ],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36))
    profile_id: Mapped[str] = mapped_column(String(36))
    assessment_id: Mapped[str] = mapped_column(String(36), index=True)
    evidence_id: Mapped[str] = mapped_column(String(36))
    data: Mapped[dict] = mapped_column(JSON)


class PrivacyAuditRow(Base):
    __tablename__ = "privacy_audit"
    __table_args__ = (
        ForeignKeyConstraint(
            ["profile_id", "workspace_id"],
            ["privacy_profiles.id", "privacy_profiles.workspace_id"],
        ),
        ForeignKeyConstraint(
            ["assessment_id", "profile_id", "workspace_id"],
            [
                "privacy_assessments.id",
                "privacy_assessments.profile_id",
                "privacy_assessments.workspace_id",
            ],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), index=True)
    profile_id: Mapped[str] = mapped_column(String(36))
    assessment_id: Mapped[str | None] = mapped_column(String(36))
    data: Mapped[dict] = mapped_column(JSON)


class VerificationPlanRow(Base):
    __tablename__ = "verification_plans"
    __table_args__ = (
        UniqueConstraint("id", "workspace_id"),
        ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id"), index=True)
    policy_id: Mapped[str] = mapped_column(String(36))
    status: Mapped[str] = mapped_column(String(24), index=True)
    created_at: Mapped[str] = mapped_column(String(40))
    data: Mapped[dict] = mapped_column(JSON)


class VerificationTestRow(Base):
    __tablename__ = "verification_tests"
    __table_args__ = (
        UniqueConstraint("id", "workspace_id", "plan_id"),
        ForeignKeyConstraint(
            ["plan_id", "workspace_id"],
            ["verification_plans.id", "verification_plans.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), index=True)
    plan_id: Mapped[str] = mapped_column(String(36), index=True)
    status: Mapped[str] = mapped_column(String(24), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class VerificationEvidenceRow(Base):
    __tablename__ = "verification_evidence"
    __table_args__ = (
        UniqueConstraint("id", "workspace_id", "plan_id"),
        ForeignKeyConstraint(
            ["plan_id", "workspace_id"],
            ["verification_plans.id", "verification_plans.workspace_id"],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), index=True)
    plan_id: Mapped[str] = mapped_column(String(36), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class VerificationFindingRow(Base):
    __tablename__ = "verification_findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["plan_id", "workspace_id"],
            ["verification_plans.id", "verification_plans.workspace_id"],
        ),
        ForeignKeyConstraint(
            ["test_id", "workspace_id", "plan_id"],
            [
                "verification_tests.id",
                "verification_tests.workspace_id",
                "verification_tests.plan_id",
            ],
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(36), index=True)
    plan_id: Mapped[str] = mapped_column(String(36), index=True)
    test_id: Mapped[str] = mapped_column(String(36))
    data: Mapped[dict] = mapped_column(JSON)


def database_url() -> str:
    return os.getenv("CRIMSON_DATABASE_URL", "sqlite:///data/crimsonweb.sqlite")


def migration_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    return config


class MigrationBackupError(RuntimeError):
    """An existing database was not upgraded because its backup did not complete."""


SQLITE_COMPANIONS = ("-wal", "-shm")


def backup_sqlite(path: Path, now: datetime | None = None) -> list[Path]:
    """Copy the database and any WAL/SHM companions to one timestamped backup set.

    The backup keeps SQLite's naming (``<backup>-wal``) so it opens as-is. Any
    failure removes the partial set and raises; callers must not migrate then.
    """
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%S%fZ")
    target = Path(f"{path}.{stamp}.bak")
    copied: list[Path] = []
    try:
        for suffix in ("", *SQLITE_COMPANIONS):
            source = Path(f"{path}{suffix}")
            if suffix and not source.exists():
                continue
            destination = Path(f"{target}{suffix}")
            if destination.exists():
                raise MigrationBackupError("backup_target_exists")
            shutil.copy2(source, destination)
            copied.append(destination)
            if destination.stat().st_size != source.stat().st_size:
                raise MigrationBackupError("backup_size_mismatch")
    except (OSError, MigrationBackupError) as exc:
        for item in copied:
            item.unlink(missing_ok=True)
        raise MigrationBackupError(
            "SQLite backup failed; database migration was not applied"
        ) from exc
    return copied


class Repository:
    def __init__(self, url: str | None = None) -> None:
        parsed = make_url(url or database_url())
        if parsed.drivername != "sqlite":
            raise ValueError("Phase 2 supports SQLite URLs only")
        self.database_path: Path | None = None
        if parsed.database and parsed.database != ":memory:":
            self.database_path = Path(parsed.database)
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_paths: list[Path] = []
        self._lock = RLock()
        options = (
            {"poolclass": StaticPool}
            if parsed.database in {None, "", ":memory:"}
            else {}
        )
        self.engine = create_engine(
            parsed, connect_args={"check_same_thread": False}, **options
        )

        @event.listens_for(self.engine, "connect")
        def configure_sqlite(connection, record) -> None:
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    def pending_upgrade(self) -> bool:
        """True when an existing schema is behind head; a new/empty DB is not."""
        with self.engine.connect() as connection:
            current = MigrationContext.configure(connection).get_current_revision()
            if current is None and not inspect(connection).get_table_names():
                return False
        head = ScriptDirectory.from_config(migration_config()).get_current_head()
        return current != head

    def initialize(self) -> None:
        with self._lock:
            path = self.database_path
            if path is not None and path.exists() and self.pending_upgrade():
                # Close pooled handles so the copy sees a quiescent file set.
                self.engine.dispose()
                self.backup_paths = backup_sqlite(path)
            with self.engine.begin() as connection:
                config = migration_config()
                config.attributes["connection"] = connection
                command.upgrade(config, "head")
        # A process cannot resume its vanished coroutine safely after restart.
        with self._lock, Session(self.engine) as session:
            rows = session.scalars(
                select(ScanRow).where(ScanRow.status.in_(["queued", "running"]))
            ).all()
            for row in rows:
                report = ScanReport.model_validate(row.report)
                report.status = "stopped"
                report.stop_reason = "process_interrupted"
                report.finished_at = datetime.now(UTC)
                row.status = report.status
                row.finished_at = report.finished_at.isoformat()
                row.report = report.model_dump(mode="json")
            for row in session.scalars(
                select(AnalysisRow).where(AnalysisRow.status.in_(["queued", "running"]))
            ):
                record = AnalysisRecord.model_validate(row.data)
                record.status, record.error_code = "stopped", "process_interrupted"
                record.finished_at = datetime.now(UTC)
                row.status, row.data = record.status, record.model_dump(mode="json")
            session.commit()

    def close(self) -> None:
        self.engine.dispose()

    def save(self, report: ScanReport) -> None:
        with self._lock, Session(self.engine) as session, session.begin():
            target = session.scalar(
                select(TargetRow).where(TargetRow.url == report.target)
            )
            if target is None:
                target = TargetRow(
                    id=str(uuid4()),
                    url=report.target,
                    created_at=datetime.now(UTC).isoformat(),
                )
                session.add(target)
                session.flush()
            row = session.get(ScanRow, report.id)
            if row is None:
                row = ScanRow(id=report.id, target_id=target.id)
                session.add(row)
            row.status = report.status
            row.engagement_id = report.engagement_id
            row.started_at = report.started_at.isoformat()
            row.finished_at = (
                report.finished_at.isoformat() if report.finished_at else None
            )
            row.report = report.model_dump(mode="json")
            row.report["ai_analysis"] = (
                None  # AI annotations never overwrite technical source reports.
            )
            session.flush()
            session.execute(delete(FindingRow).where(FindingRow.scan_id == report.id))
            session.add_all(
                [
                    FindingRow(
                        id=f.id,
                        scan_id=report.id,
                        severity=f.severity,
                        data=f.model_dump(mode="json"),
                    )
                    for f in report.findings
                ]
            )
            for item in report.waf_events:
                if session.get(EventRow, item.id) is None:
                    session.add(self._event_row(item))

    @staticmethod
    def _event_row(item: WAFEvent) -> EventRow:
        return EventRow(
            id=item.id,
            scan_id=item.scan_id,
            timestamp=item.timestamp.isoformat(),
            event_type=item.event_type,
            rule_id=item.rule_id,
            data=item.model_dump(mode="json"),
        )

    def get(self, scan_id: str) -> ScanReport | None:
        with self._lock, Session(self.engine) as session:
            row = session.get(ScanRow, scan_id)
            if row is None:
                return None
            report = ScanReport.model_validate(row.report)
            report.waf_events = [
                WAFEvent.model_validate(e.data)
                for e in session.scalars(
                    select(EventRow)
                    .where(EventRow.scan_id == scan_id)
                    .order_by(EventRow.timestamp, EventRow.id)
                )
            ]
            return report

    def history(
        self,
        limit: int,
        offset: int,
        status: str | None = None,
        target_id: str | None = None,
        engagement_id: str | None = None,
    ) -> Page[ScanReport]:
        with self._lock, Session(self.engine) as session:
            query = select(ScanRow)
            if status:
                query = query.where(ScanRow.status == status)
            if target_id:
                query = query.where(ScanRow.target_id == target_id)
            if engagement_id:
                query = query.where(ScanRow.engagement_id == engagement_id)
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(
                query.order_by(ScanRow.started_at.desc(), ScanRow.id)
                .limit(limit)
                .offset(offset)
            ).all()
            return Page(
                items=[self.get(row.id) for row in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def targets(self, limit: int, offset: int) -> Page[TargetResult]:
        with self._lock, Session(self.engine) as session:
            total = session.scalar(select(func.count()).select_from(TargetRow))
            rows = session.scalars(
                select(TargetRow)
                .order_by(TargetRow.created_at, TargetRow.id)
                .limit(limit)
                .offset(offset)
            )
            return Page(
                items=[
                    TargetResult(id=r.id, url=r.url, created_at=r.created_at)
                    for r in rows
                ],
                total=total,
                limit=limit,
                offset=offset,
            )

    def findings(
        self,
        limit: int,
        offset: int,
        severity: str | None = None,
        scan_id: str | None = None,
    ) -> Page[FindingResult]:
        with self._lock, Session(self.engine) as session:
            query = select(FindingRow, ScanRow.target_id).join(ScanRow)
            if severity:
                query = query.where(FindingRow.severity == severity)
            if scan_id:
                query = query.where(FindingRow.scan_id == scan_id)
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.execute(
                query.order_by(FindingRow.id).limit(limit).offset(offset)
            )
            return Page(
                items=[
                    FindingResult(**r.data, scan_id=r.scan_id, target_id=t)
                    for r, t in rows
                ],
                total=total,
                limit=limit,
                offset=offset,
            )

    def events(
        self,
        limit: int,
        offset: int,
        scan_id: str | None = None,
        event_type: str | None = None,
        rule_id: str | None = None,
    ) -> Page[WAFEvent]:
        with self._lock, Session(self.engine) as session:
            query = select(EventRow)
            for column, value in [
                (EventRow.scan_id, scan_id),
                (EventRow.event_type, event_type),
                (EventRow.rule_id, rule_id),
            ]:
                if value is not None:
                    query = query.where(column == value)
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(
                query.order_by(EventRow.timestamp.desc(), EventRow.id)
                .limit(limit)
                .offset(offset)
            )
            return Page(
                items=[WAFEvent.model_validate(row.data) for row in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def import_events(self, events: list[WAFEvent]) -> int:
        count = 0
        with self._lock, Session(self.engine) as session, session.begin():
            for item in events:
                if item.scan_id and session.get(ScanRow, item.scan_id) is None:
                    raise LookupError("Scan not found")
                if session.get(EventRow, item.id) is None:
                    session.add(self._event_row(item))
                    session.flush()
                    count += 1
        return count

    def finding_by_id(self, finding_id: str) -> FindingResult | None:
        with self._lock, Session(self.engine) as session:
            item = session.get(FindingRow, finding_id)
            if item is None:
                return None
            return FindingResult(
                **item.data, scan_id=item.scan_id, target_id=item.scan.target_id
            )

    def event_by_id(self, event_id: str) -> WAFEvent | None:
        with self._lock, Session(self.engine) as session:
            item = session.get(EventRow, event_id)
            return WAFEvent.model_validate(item.data) if item else None

    def save_analysis(self, record: AnalysisRecord) -> None:
        with self._lock, Session(self.engine) as session, session.begin():
            row = session.get(AnalysisRow, record.id)
            if row is None:
                row = AnalysisRow(
                    id=record.id,
                    scan_id=record.scan_id,
                    kind=record.kind,
                    created_at=record.created_at.isoformat(),
                )
                session.add(row)
            row.status, row.data = record.status, record.model_dump(mode="json")

    def get_analysis(self, analysis_id: str) -> AnalysisRecord | None:
        with self._lock, Session(self.engine) as session:
            row = session.get(AnalysisRow, analysis_id)
            return AnalysisRecord.model_validate(row.data) if row else None

    def analysis_history(
        self,
        limit: int,
        offset: int,
        scan_id: str | None = None,
        status: str | None = None,
        kind: str | None = None,
    ) -> Page[AnalysisRecord]:
        with self._lock, Session(self.engine) as session:
            query = select(AnalysisRow)
            for column, value in [
                (AnalysisRow.scan_id, scan_id),
                (AnalysisRow.status, status),
                (AnalysisRow.kind, kind),
            ]:
                if value is not None:
                    query = query.where(column == value)
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(
                query.order_by(AnalysisRow.created_at.desc(), AnalysisRow.id)
                .limit(limit)
                .offset(offset)
            )
            return Page(
                items=[AnalysisRecord.model_validate(row.data) for row in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def latest_scan_analysis(self, scan_id: str) -> AnalysisRecord | None:
        page = self.analysis_history(
            1, 0, scan_id=scan_id, status="completed", kind="scan"
        )
        return page.items[0] if page.items else None
