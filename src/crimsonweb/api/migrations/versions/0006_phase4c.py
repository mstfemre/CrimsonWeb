"""Phase 4C verification plans, tests, evidence and findings.

Reversible. No lease-table change: verification requests reserve shared budget and
concurrency through the existing ownerless lease path, so nothing in Phase 5A or
earlier is altered. Downgrade refuses while a plan is still executing.
"""

import sqlalchemy as sa
from alembic import op

revision = "0006_phase4c"
down_revision = "0005_phase5a"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "verification_plans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workspace_id",
            sa.String(36),
            sa.ForeignKey("workspaces.id"),
            nullable=False,
        ),
        sa.Column("policy_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("id", "workspace_id"),
        sa.ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    op.create_index(
        "ix_verification_plans_workspace_id", "verification_plans", ["workspace_id"]
    )
    op.create_index("ix_verification_plans_status", "verification_plans", ["status"])
    op.create_table(
        "verification_tests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("id", "workspace_id", "plan_id"),
        sa.ForeignKeyConstraint(
            ["plan_id", "workspace_id"],
            ["verification_plans.id", "verification_plans.workspace_id"],
        ),
    )
    for field in ("workspace_id", "plan_id", "status"):
        op.create_index(
            f"ix_verification_tests_{field}", "verification_tests", [field]
        )
    op.create_table(
        "verification_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("id", "workspace_id", "plan_id"),
        sa.ForeignKeyConstraint(
            ["plan_id", "workspace_id"],
            ["verification_plans.id", "verification_plans.workspace_id"],
        ),
    )
    for field in ("workspace_id", "plan_id"):
        op.create_index(
            f"ix_verification_evidence_{field}", "verification_evidence", [field]
        )
    op.create_table(
        "verification_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("workspace_id", sa.String(36), nullable=False),
        sa.Column("plan_id", sa.String(36), nullable=False),
        sa.Column("test_id", sa.String(36), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["plan_id", "workspace_id"],
            ["verification_plans.id", "verification_plans.workspace_id"],
        ),
        sa.ForeignKeyConstraint(
            ["test_id", "workspace_id", "plan_id"],
            [
                "verification_tests.id",
                "verification_tests.workspace_id",
                "verification_tests.plan_id",
            ],
        ),
    )
    for field in ("workspace_id", "plan_id"):
        op.create_index(
            f"ix_verification_findings_{field}", "verification_findings", [field]
        )


def downgrade():
    connection = op.get_bind()
    if connection.scalar(
        sa.text(
            "SELECT COUNT(*) FROM verification_plans WHERE status = 'executing'"
        )
    ):
        raise RuntimeError("Stop executing verification plans before downgrade")
    for name in (
        "verification_findings",
        "verification_evidence",
        "verification_tests",
        "verification_plans",
    ):
        op.drop_table(name)
