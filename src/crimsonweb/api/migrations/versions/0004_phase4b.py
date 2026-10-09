"""Durable discovery inventory and explicitly owned request reservations."""

import sqlalchemy as sa
from alembic import op

revision = "0004_phase4b"
down_revision = "0003_phase4a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "discovery_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workspace_id",
            sa.String(36),
            sa.ForeignKey("workspaces.id"),
            nullable=False,
        ),
        sa.Column("policy_id", sa.String(36)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("worker_id", sa.String(36)),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("requests_made", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("id", "workspace_id"),
        sa.ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    for name in ("discovery_endpoints", "discovery_evidence", "discovery_relations"):
        columns = [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("workspace_id", sa.String(36), nullable=False),
            sa.Column("job_id", sa.String(36), nullable=False),
            sa.Column("data", sa.JSON(), nullable=False),
            sa.ForeignKeyConstraint(
                ["job_id", "workspace_id"],
                ["discovery_jobs.id", "discovery_jobs.workspace_id"],
            ),
        ]
        if name == "discovery_endpoints":
            columns += [
                sa.Column("fingerprint", sa.String(64), nullable=False),
                sa.UniqueConstraint("workspace_id", "job_id", "fingerprint"),
            ]
        if name != "discovery_relations":
            columns.append(sa.UniqueConstraint("id", "workspace_id", "job_id"))
        else:
            columns += [
                sa.Column("source_endpoint_id", sa.String(36), nullable=False),
                sa.Column("related_endpoint_id", sa.String(36)),
                sa.Column("evidence_id", sa.String(36), nullable=False),
            ]
            for field, parent in (
                ("source_endpoint_id", "discovery_endpoints"),
                ("related_endpoint_id", "discovery_endpoints"),
                ("evidence_id", "discovery_evidence"),
            ):
                columns.append(
                    sa.ForeignKeyConstraint(
                        [field, "workspace_id", "job_id"],
                        [f"{parent}.id", f"{parent}.workspace_id", f"{parent}.job_id"],
                    )
                )
        op.create_table(name, *columns)
        for field in ("workspace_id", "job_id"):
            op.create_index(f"ix_{name}_{field}", name, [field])
    for field in ("workspace_id", "status"):
        op.create_index(f"ix_discovery_jobs_{field}", "discovery_jobs", [field])
    with op.batch_alter_table("scope_request_leases") as batch:
        batch.add_column(sa.Column("discovery_job_id", sa.String(36)))
        batch.add_column(sa.Column("discovery_worker_id", sa.String(36)))
        batch.create_foreign_key(
            "fk_scope_lease_discovery_job",
            "discovery_jobs",
            ["discovery_job_id", "workspace_id"],
            ["id", "workspace_id"],
        )


def downgrade():
    connection = op.get_bind()
    if connection.scalar(
        sa.text(
            "SELECT COUNT(*) FROM scope_request_leases WHERE discovery_job_id IS NOT NULL AND released=0"
        )
    ) or connection.scalar(
        sa.text(
            "SELECT COUNT(*) FROM discovery_jobs WHERE status IN ('queued', 'running')"
        )
    ):
        raise RuntimeError(
            "Stop discovery workers and resolve owned reservations before downgrade"
        )
    with op.batch_alter_table("scope_request_leases") as batch:
        batch.drop_constraint("fk_scope_lease_discovery_job", type_="foreignkey")
        batch.drop_column("discovery_job_id")
        batch.drop_column("discovery_worker_id")
    for name in (
        "discovery_relations",
        "discovery_evidence",
        "discovery_endpoints",
        "discovery_jobs",
    ):
        op.drop_table(name)
