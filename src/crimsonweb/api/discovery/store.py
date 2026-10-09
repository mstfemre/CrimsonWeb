"""Workspace/job qualified discovery transactions on the existing SQLite engine."""

from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import (
    DiscoveryEndpointRow,
    DiscoveryEvidenceRow,
    DiscoveryJobRow,
    DiscoveryRelationRow,
    ScopeLeaseRow,
)
from ..models import Page
from ..workspaces.store import Conflict, NotFound, WorkspaceStore
from .models import (
    DiscoveryJob,
    Endpoint,
    Evidence,
    Relation,
    ResourceNode,
    SurfaceGraph,
)
from .urls import fingerprint


class DiscoveryLimit(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class DiscoveryEvidenceStore(WorkspaceStore):
    @staticmethod
    def job_row(session, workspace_id, job_id):
        row = session.scalar(
            select(DiscoveryJobRow).where(
                DiscoveryJobRow.id == str(job_id),
                DiscoveryJobRow.workspace_id == str(workspace_id),
            )
        )
        if row is None:
            raise NotFound("Discovery job not found")
        return row

    @staticmethod
    def record(row):
        return DiscoveryJob(
            **row.data,
            id=row.id,
            workspace_id=row.workspace_id,
            policy_id=row.policy_id,
            status=row.status,
            created_at=row.created_at,
            cancel_requested=row.cancel_requested,
            requests_made=row.requests_made,
        )

    def create(
        self,
        workspace_id,
        mode,
        limits,
        now,
        policy_id=None,
        policy_revision=None,
        seeds=(),
    ):
        with self.transaction() as session:
            self.workspace(session, workspace_id)
            if policy_id:
                row = self.policy_row(session, workspace_id, policy_id)
                if row.revision != policy_revision:
                    raise Conflict("Policy changed")
            row = DiscoveryJobRow(
                id=str(uuid4()),
                workspace_id=str(workspace_id),
                policy_id=str(policy_id) if policy_id else None,
                status="queued",
                worker_id=None,
                cancel_requested=False,
                requests_made=0,
                created_at=now.isoformat(),
                data={
                    "mode": mode,
                    "limits": limits.model_dump(mode="json"),
                    "policy_revision": policy_revision,
                    "seed_fingerprints": [fingerprint(s) for s in seeds],
                    "pages_processed": 0,
                    "endpoints_discovered": 0,
                    "limitations": [
                        "observations_not_vulnerabilities",
                        "no_credentials_or_response_bodies_stored",
                        "no_form_submission",
                        "no_javascript_execution",
                        "query_encoded_path_requests_disabled",
                    ],
                },
            )
            session.add(row)
            self.audit(
                session,
                workspace_id,
                policy_id,
                "discovery_queued",
                True,
                "operator_action",
                now,
            )
            session.flush()
            return self.record(row)

    def get(self, workspace_id, job_id):
        with self.repository._lock, Session(self.repository.engine) as session:
            return self.record(self.job_row(session, workspace_id, job_id))

    def jobs(self, workspace_id, limit, offset, status=None):
        with self.repository._lock, Session(self.repository.engine) as session:
            self.workspace(session, workspace_id)
            query = select(DiscoveryJobRow).where(
                DiscoveryJobRow.workspace_id == str(workspace_id)
            )
            if status:
                query = query.where(DiscoveryJobRow.status == status)
            total = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(
                query.order_by(DiscoveryJobRow.created_at.desc(), DiscoveryJobRow.id)
                .limit(limit)
                .offset(offset)
            )
            return Page(
                items=[self.record(r) for r in rows],
                total=total,
                limit=limit,
                offset=offset,
            )

    def claim(self, workspace_id, job_id, worker_id, now):
        with self.transaction() as session:
            row = self.job_row(session, workspace_id, job_id)
            if row.status != "queued" or row.cancel_requested:
                return None
            row.status, row.worker_id = "running", str(worker_id)
            row.data = {**row.data, "started_at": now.isoformat()}
            self.audit(
                session,
                workspace_id,
                row.policy_id,
                "discovery_started",
                True,
                "worker_claimed",
                now,
            )
            return self.record(row)

    def check_worker(self, session, workspace_id, job_id, worker_id):
        row = self.job_row(session, workspace_id, job_id)
        if row.status != "running" or row.worker_id != str(worker_id):
            raise Conflict("Discovery ownership changed")
        if row.cancel_requested:
            raise DiscoveryLimit("operator_cancelled")
        return row

    def update(self, workspace_id, job_id, worker_id, pages=None, limitations=()):
        with self.transaction() as session:
            row = self.check_worker(session, workspace_id, job_id, worker_id)
            data = dict(row.data)
            if pages is not None:
                data["pages_processed"] = pages
            data["limitations"] = sorted(set(data["limitations"]) | set(limitations))[
                :30
            ]
            row.data = data

    def finish(self, workspace_id, job_id, worker_id, status, reason, now):
        if status not in {
            "completed",
            "partially_completed",
            "cancelled",
            "failed",
            "halted_by_policy",
        }:
            raise ValueError("Invalid terminal status")
        with self.transaction() as session:
            row = self.job_row(session, workspace_id, job_id)
            if row.worker_id != str(worker_id) or row.status != "running":
                return self.record(row)
            # Cancellation wins a race with normal completion.
            if row.cancel_requested:
                status, reason = "cancelled", "operator_cancelled"
            row.status = status
            row.data = {
                **row.data,
                "finished_at": now.isoformat(),
                "stop_reason": reason,
            }
            self.audit(
                session,
                workspace_id,
                row.policy_id,
                "discovery_finished",
                status == "completed",
                reason or status,
                now,
            )
            return self.record(row)

    def cancel(self, workspace_id, job_id, now):
        with self.transaction() as session:
            row = self.job_row(session, workspace_id, job_id)
            if row.status in {"queued", "running"}:
                row.cancel_requested = True
                if row.status == "queued":
                    row.status = "cancelled"
                    row.data = {
                        **row.data,
                        "finished_at": now.isoformat(),
                        "stop_reason": "operator_cancelled",
                    }
                self.audit(
                    session,
                    workspace_id,
                    row.policy_id,
                    "discovery_cancel",
                    True,
                    "operator_action",
                    now,
                )
            return self.record(row)

    def recover(self, now, worker_lock):
        """An exclusive lifetime lock proves all previous cooperating workers ended."""
        from .worker import WorkerLock

        if (
            not isinstance(worker_lock, WorkerLock)
            or not worker_lock.held
            or not worker_lock.recovery_pending
            or worker_lock.namespace != "discovery"
            or worker_lock.repository is not self.repository
        ):
            raise Conflict("Exclusive worker lock required for recovery")
        recovered = 0
        with self.transaction() as session:
            # Also recover terminal jobs whose response cleanup lost the DB.
            for lease in session.scalars(
                select(ScopeLeaseRow).where(
                    ScopeLeaseRow.discovery_job_id.is_not(None),
                    ScopeLeaseRow.released.is_(False),
                )
            ):
                owner = session.get(DiscoveryJobRow, lease.discovery_job_id)
                if (
                    owner
                    and owner.worker_id
                    and owner.worker_id == lease.discovery_worker_id
                    and owner.workspace_id == lease.workspace_id
                    and owner.policy_id == lease.policy_id
                ):
                    lease.released = True
                    self.audit(
                        session,
                        lease.workspace_id,
                        lease.policy_id,
                        "discovery_lease_recovery",
                        False,
                        "worker_lock_recovered",
                        now,
                    )
            rows = session.scalars(
                select(DiscoveryJobRow).where(
                    DiscoveryJobRow.status.in_(["queued", "running"])
                )
            ).all()
            for row in rows:
                # Legacy/unknown-worker reservations were intentionally left alone.
                row.status = "failed"
                row.data = {
                    **row.data,
                    "finished_at": now.isoformat(),
                    "stop_reason": "worker_interrupted_verified",
                }
                self.audit(
                    session,
                    row.workspace_id,
                    row.policy_id,
                    "discovery_recovery",
                    False,
                    "worker_lock_recovered",
                    now,
                )
                recovered += 1
        worker_lock.recovery_pending = False
        return recovered

    def save_batch(
        self, workspace_id, job_id, worker_id, evidence, endpoints, relations
    ):
        with self.transaction() as session:
            limited = None
            skipped = set()
            job = self.check_worker(session, workspace_id, job_id, worker_id)
            known_refs = {
                f"discovery_evidence:{identifier}"
                for identifier in session.scalars(
                    select(DiscoveryEvidenceRow.id).where(
                        DiscoveryEvidenceRow.workspace_id == str(workspace_id),
                        DiscoveryEvidenceRow.job_id == str(job_id),
                    )
                )
            } | {f"discovery_evidence:{evidence.id}"}
            if (
                evidence.ref != f"discovery_evidence:{evidence.id}"
                or any(r.evidence_ref != evidence.ref for r in relations)
                or any(
                    evidence.ref not in e.evidence_refs
                    or not set(e.evidence_refs) <= known_refs
                    for e in endpoints
                )
            ):
                raise Conflict("Discovery evidence contract violation")
            evidence_count = session.scalar(
                select(func.count())
                .select_from(DiscoveryEvidenceRow)
                .where(
                    DiscoveryEvidenceRow.job_id == str(job_id),
                    DiscoveryEvidenceRow.workspace_id == str(workspace_id),
                )
            )
            if evidence_count >= 1000:
                raise DiscoveryLimit("evidence_limit")
            session.add(
                DiscoveryEvidenceRow(
                    id=str(evidence.id),
                    workspace_id=str(workspace_id),
                    job_id=str(job_id),
                    data=evidence.model_dump(mode="json"),
                )
            )
            for item in endpoints:
                existing = session.scalar(
                    select(DiscoveryEndpointRow).where(
                        DiscoveryEndpointRow.id == str(item.id),
                        DiscoveryEndpointRow.job_id == str(job_id),
                        DiscoveryEndpointRow.workspace_id == str(workspace_id),
                    )
                )
                if existing:
                    old = Endpoint.model_validate(existing.data)
                    data = old.model_dump()
                    for field, cap in (
                        ("sources", 4),
                        ("parameters", 100),
                        ("forms", 10),
                        ("authentication_indicators", 10),
                        ("evidence_refs", 20),
                    ):
                        # Keep current observation provenance when the bounded
                        # reference list fills; status/content-type may be updated.
                        values = (
                            [*getattr(item, field), *getattr(old, field)]
                            if field == "evidence_refs"
                            else [*getattr(old, field), *getattr(item, field)]
                        )
                        merged = []
                        for value in values:
                            if value not in merged:
                                merged.append(value)
                        data[field] = merged[:cap]
                    if item.observation_status == "request_guarded":
                        data.update(
                            observation_status="request_guarded",
                            status_code=item.status_code,
                            content_type=item.content_type,
                        )
                    existing.data = Endpoint.model_validate(data).model_dump(
                        mode="json"
                    )
                else:
                    if (
                        job.data["endpoints_discovered"]
                        >= job.data["limits"]["max_endpoints"]
                    ):
                        limited = "endpoint_limit"
                        skipped.add(item.id)
                        continue
                    session.add(
                        DiscoveryEndpointRow(
                            id=str(item.id),
                            workspace_id=str(workspace_id),
                            job_id=str(job_id),
                            fingerprint=fingerprint(
                                f"{item.origin_ref}\n{item.path}\n{item.method}"
                            ),
                            data=item.model_dump(mode="json"),
                        )
                    )
                    job.data = {
                        **job.data,
                        "endpoints_discovered": job.data["endpoints_discovered"] + 1,
                    }
                session.flush()
            # Composite FKs prevent cross-workspace/job endpoint/evidence edges.
            count = session.scalar(
                select(func.count())
                .select_from(DiscoveryRelationRow)
                .where(
                    DiscoveryRelationRow.job_id == str(job_id),
                    DiscoveryRelationRow.workspace_id == str(workspace_id),
                )
            )
            for relation in relations:
                if (
                    relation.source_endpoint_id in skipped
                    or relation.related_endpoint_id in skipped
                ):
                    continue
                if session.get(DiscoveryRelationRow, str(relation.id)):
                    continue
                if count >= 4000:
                    limited = limited or "graph_relation_limit"
                    continue
                session.add(
                    DiscoveryRelationRow(
                        id=str(relation.id),
                        workspace_id=str(workspace_id),
                        job_id=str(job_id),
                        source_endpoint_id=str(relation.source_endpoint_id),
                        related_endpoint_id=str(relation.related_endpoint_id)
                        if relation.related_endpoint_id
                        else None,
                        evidence_id=str(evidence.id),
                        data=relation.model_dump(mode="json"),
                    )
                )
                count += 1
            if limited:
                job.data = {
                    **job.data,
                    "limitations": sorted(set(job.data["limitations"]) | {limited})[
                        :30
                    ],
                }
            return limited

    def page(self, workspace_id, job_id, table, model, limit, offset):
        if table not in {
            DiscoveryEndpointRow,
            DiscoveryEvidenceRow,
            DiscoveryRelationRow,
        }:
            raise ValueError("Unsupported table")
        with self.repository._lock, Session(self.repository.engine) as session:
            self.job_row(session, workspace_id, job_id)
            query = select(table).where(
                table.workspace_id == str(workspace_id), table.job_id == str(job_id)
            )
            count = session.scalar(select(func.count()).select_from(query.subquery()))
            rows = session.scalars(query.order_by(table.id).limit(limit).offset(offset))
            return Page(
                items=[model.model_validate(r.data) for r in rows],
                total=count,
                limit=limit,
                offset=offset,
            )

    def endpoints(self, workspace_id, job_id, limit=100, offset=0):
        return self.page(
            workspace_id, job_id, DiscoveryEndpointRow, Endpoint, limit, offset
        )

    def evidence(self, workspace_id, job_id, limit=100, offset=0):
        return self.page(
            workspace_id, job_id, DiscoveryEvidenceRow, Evidence, limit, offset
        )

    def graph(self, workspace_id, job_id):
        from .inventory import ApplicationSurfaceGraph

        endpoints = self.endpoints(workspace_id, job_id, 500, 0)
        relations = self.page(
            workspace_id, job_id, DiscoveryRelationRow, Relation, 4000, 0
        )
        resources = {}
        for endpoint in endpoints.items:
            resource_id = ApplicationSurfaceGraph.resource_id(job_id, endpoint)
            if resource_id is None:
                continue
            node = resources.setdefault(
                resource_id,
                ResourceNode(
                    id=resource_id,
                    origin_ref=endpoint.origin_ref,
                    name=endpoint.resource_type,
                ),
            )
            node.endpoint_ids.append(endpoint.id)
            node.potential_owner_identifiers = sorted(
                set(node.potential_owner_identifiers)
                | {p.name for p in endpoint.parameters if p.owner_identifier_candidate}
            )[:100]
        return SurfaceGraph(
            workspace_id=UUID(str(workspace_id)),
            job_id=UUID(str(job_id)),
            endpoint_nodes=endpoints.items,
            resource_nodes=list(resources.values()),
            relations=relations.items,
            truncated=endpoints.total > 500 or relations.total > 4000,
        )
