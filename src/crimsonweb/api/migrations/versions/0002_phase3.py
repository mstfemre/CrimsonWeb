"""Separate AI opinions from technical evidence."""

import sqlalchemy as sa
from alembic import op

revision = "0002_phase3"
down_revision = "0001_phase2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_analyses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("scans.id")),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    for name in ("scan_id", "status", "kind", "created_at"):
        op.create_index(f"ix_ai_analyses_{name}", "ai_analyses", [name])


def downgrade() -> None:
    op.drop_table("ai_analyses")
