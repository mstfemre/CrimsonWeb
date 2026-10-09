"""Privacy profiles and minimal observations; no changes to legacy evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0005_phase5a"
down_revision = "0004_phase4b"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "privacy_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workspace_id",
            sa.String(36),
            sa.ForeignKey("workspaces.id"),
            nullable=False,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("deleted", sa.Boolean(), nullable=False),
        sa.Column("identity_key", sa.String(64), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("id", "workspace_id"),
    )
    op.create_index(
        "ix_privacy_profiles_workspace_id", "privacy_profiles", ["workspace_id"]
    )
    op.create_table(
        "privacy_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("profile_id", sa.String(36), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("used_observations", sa.Integer(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("profile_id", "workspace_id"),
        sa.ForeignKeyConstraint(
            ["profile_id", "workspace_id"],
            ["privacy_profiles.id", "privacy_profiles.workspace_id"],
        ),
    )
    op.create_table(
        "privacy_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("profile_id", sa.String(36), nullable=False),
        sa.Column("program_policy_id", sa.String(36)),
        sa.Column("execution_status", sa.String(16), nullable=False),
        sa.Column("worker_id", sa.String(36)),
        sa.Column("cancel_requested", sa.Boolean(), nullable=False),
        sa.Column("requests_made", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("id", "profile_id", "workspace_id"),
        sa.UniqueConstraint("id", "workspace_id", "program_policy_id"),
        sa.ForeignKeyConstraint(
            ["profile_id", "workspace_id"],
            ["privacy_profiles.id", "privacy_profiles.workspace_id"],
        ),
        sa.ForeignKeyConstraint(
            ["program_policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    for field in ("workspace_id", "profile_id"):
        op.create_index(
            f"ix_privacy_assessments_{field}", "privacy_assessments", [field]
        )
    for name in ("privacy_evidence", "privacy_findings", "privacy_audit"):
        columns = [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("workspace_id", sa.String(36), nullable=False),
            sa.Column("profile_id", sa.String(36), nullable=False),
            sa.Column("assessment_id", sa.String(36), nullable=name == "privacy_audit"),
            sa.Column("data", sa.JSON(), nullable=False),
            sa.ForeignKeyConstraint(
                ["assessment_id", "profile_id", "workspace_id"],
                [
                    "privacy_assessments.id",
                    "privacy_assessments.profile_id",
                    "privacy_assessments.workspace_id",
                ],
            ),
        ]
        if name == "privacy_evidence":
            columns.append(
                sa.UniqueConstraint("id", "assessment_id", "profile_id", "workspace_id")
            )
        elif name == "privacy_findings":
            columns += [
                sa.Column("evidence_id", sa.String(36), nullable=False),
                sa.ForeignKeyConstraint(
                    ["evidence_id", "assessment_id", "profile_id", "workspace_id"],
                    [
                        "privacy_evidence.id",
                        "privacy_evidence.assessment_id",
                        "privacy_evidence.profile_id",
                        "privacy_evidence.workspace_id",
                    ],
                ),
            ]
        else:
            columns.append(
                sa.ForeignKeyConstraint(
                    ["profile_id", "workspace_id"],
                    ["privacy_profiles.id", "privacy_profiles.workspace_id"],
                )
            )
        op.create_table(name, *columns)
        field = "workspace_id" if name == "privacy_audit" else "assessment_id"
        op.create_index(f"ix_{name}_{field}", name, [field])
    with op.batch_alter_table("scope_request_leases") as batch:
        batch.add_column(sa.Column("privacy_assessment_id", sa.String(36)))
        batch.add_column(sa.Column("privacy_worker_id", sa.String(36)))
        batch.create_check_constraint(
            "ck_scope_lease_privacy_ownership",
            "(privacy_assessment_id IS NULL AND privacy_worker_id IS NULL) OR "
            "(privacy_assessment_id IS NOT NULL AND privacy_worker_id IS NOT NULL "
            "AND discovery_job_id IS NULL AND discovery_worker_id IS NULL)",
        )
        batch.create_foreign_key(
            "fk_scope_lease_privacy_assessment",
            "privacy_assessments",
            ["privacy_assessment_id", "workspace_id", "policy_id"],
            ["id", "workspace_id", "program_policy_id"],
        )


def downgrade():
    connection = op.get_bind()
    if connection.scalar(
        sa.text(
            "SELECT COUNT(*) FROM privacy_assessments WHERE execution_status IN ('queued','running')"
        )
    ) or connection.scalar(
        sa.text(
            "SELECT COUNT(*) FROM scope_request_leases WHERE privacy_assessment_id IS NOT NULL AND released=0"
        )
    ):
        raise RuntimeError(
            "Stop privacy workers and resolve reservations before downgrade"
        )
    with op.batch_alter_table("scope_request_leases") as batch:
        batch.drop_constraint("ck_scope_lease_privacy_ownership", type_="check")
        batch.drop_constraint("fk_scope_lease_privacy_assessment", type_="foreignkey")
        batch.drop_column("privacy_assessment_id")
        batch.drop_column("privacy_worker_id")
    for name in (
        "privacy_audit",
        "privacy_findings",
        "privacy_evidence",
        "privacy_assessments",
        "privacy_policies",
        "privacy_profiles",
    ):
        op.drop_table(name)
