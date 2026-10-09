"""Persist targets, scans, findings and defense events."""

import sqlalchemy as sa
from alembic import op

revision = "0001_phase2"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("url", sa.String(2048), nullable=False, unique=True),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False
        ),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("engagement_id", sa.String(100), nullable=False),
        sa.Column("started_at", sa.String(40), nullable=False),
        sa.Column("finished_at", sa.String(40)),
        sa.Column("report", sa.JSON(), nullable=False),
    )
    for name in ("target_id", "status", "engagement_id", "started_at"):
        op.create_index(f"ix_scans_{name}", "scans", [name])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    for name in ("scan_id", "severity"):
        op.create_index(f"ix_findings_{name}", "findings", [name])
    op.create_table(
        "waf_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id")),
        sa.Column("timestamp", sa.String(40), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("rule_id", sa.String(64)),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    for name in ("scan_id", "timestamp", "event_type", "rule_id"):
        op.create_index(f"ix_waf_events_{name}", "waf_events", [name])


def downgrade() -> None:
    for table in ("waf_events", "findings", "scans", "targets"):
        op.drop_table(table)
