"""Workspace isolation, scope authorization, audits and durable request reservations."""

import sqlalchemy as sa
from alembic import op

revision = "0003_phase4a"
down_revision = "0002_phase3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_table(
        "program_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workspace_id",
            sa.String(36),
            sa.ForeignKey("workspaces.id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("used_requests", sa.Integer(), nullable=False),
        sa.Column("halted_reason", sa.String(64)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.UniqueConstraint("id", "workspace_id"),
    )
    op.create_table(
        "policy_revisions",
        sa.Column("policy_id", sa.String(36), primary_key=True),
        sa.Column("revision", sa.Integer(), primary_key=True),
        sa.Column(
            "workspace_id",
            sa.String(36),
            sa.ForeignKey("workspaces.id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["policy_id", "workspace_id"],
            ["program_policies.id", "program_policies.workspace_id"],
        ),
    )
    op.create_index(
        "ix_policy_revisions_workspace_id", "policy_revisions", ["workspace_id"]
    )
    for name in ("target_scopes", "scope_audit_logs", "scope_request_leases"):
        columns = [
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column(
                "workspace_id",
                sa.String(36),
                sa.ForeignKey("workspaces.id"),
                nullable=False,
            ),
            sa.Column(
                "policy_id",
                sa.String(36),
                nullable=name == "scope_audit_logs",
                unique=name == "target_scopes",
            ),
        ]
        if name == "target_scopes":
            columns.append(sa.Column("data", sa.JSON(), nullable=False))
        elif name == "scope_audit_logs":
            columns.extend(
                [
                    sa.Column("policy_revision", sa.Integer()),
                    sa.Column("resolved_ips", sa.JSON(), nullable=False),
                    sa.Column("timestamp", sa.String(40), nullable=False),
                    sa.Column("action", sa.String(32), nullable=False),
                    sa.Column("allowed", sa.Boolean(), nullable=False),
                    sa.Column("reason", sa.String(64), nullable=False),
                    sa.Column("request_fingerprint", sa.String(64)),
                ]
            )
        else:
            columns.extend(
                [
                    sa.Column("created_at", sa.String(40), nullable=False),
                    sa.Column("released", sa.Boolean(), nullable=False),
                ]
            )
        columns.append(
            sa.ForeignKeyConstraint(
                ["policy_id", "workspace_id"],
                ["program_policies.id", "program_policies.workspace_id"],
            )
        )
        op.create_table(name, *columns)
        indexes = ["workspace_id"]
        if name == "scope_audit_logs":
            indexes.append("timestamp")
        if name == "scope_request_leases":
            indexes.extend(["policy_id", "created_at"])
        for column in indexes:
            op.create_index(f"ix_{name}_{column}", name, [column])


def downgrade() -> None:
    for name in (
        "scope_request_leases",
        "scope_audit_logs",
        "target_scopes",
        "policy_revisions",
        "program_policies",
        "workspaces",
    ):
        op.drop_table(name)
