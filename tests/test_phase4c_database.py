"""0006 is reversible, matches the ORM metadata, and refuses to drop live runs."""

from uuid import uuid4

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import inspect
from verification_helpers import verification_policy
from workspace_helpers import NOW, seeded

from crimsonweb.api.database import Base, migration_config
from crimsonweb.api.verification.models import VerificationPlan
from crimsonweb.api.verification.store import VerificationStore


def migrate(repo, direction, revision):
    with repo.engine.begin() as connection:
        config = migration_config()
        config.attributes["connection"] = connection
        getattr(command, direction)(config, revision)


def plan(workspace_id, policy_id, status):
    return VerificationPlan(
        id=uuid4(),
        workspace_id=workspace_id,
        policy_id=policy_id,
        source="discovery",
        status=status,
        planner="operator",
        created_at=NOW,
        updated_at=NOW,
    )


def test_head_schema_matches_orm_models():
    repo, _, _, _ = seeded(configuration=verification_policy())
    try:
        with repo.engine.connect() as connection:
            assert (
                compare_metadata(MigrationContext.configure(connection), Base.metadata)
                == []
            )
    finally:
        repo.close()


def test_downgrade_refuses_while_a_plan_is_executing_then_reverses_cleanly():
    repo, _, workspace, record = seeded(configuration=verification_policy())
    store = VerificationStore(repo)
    try:
        executing = store.create_plan(plan(workspace.id, record.id, "executing"))
        with pytest.raises(RuntimeError, match="executing verification plans"):
            migrate(repo, "downgrade", "0005_phase5a")
        assert "verification_plans" in inspect(repo.engine).get_table_names()

        store.set_status(workspace.id, executing.id, "completed", NOW)
        migrate(repo, "downgrade", "0005_phase5a")
        assert "verification_plans" not in inspect(repo.engine).get_table_names()
        assert "privacy_profiles" in inspect(repo.engine).get_table_names()

        migrate(repo, "upgrade", "head")
        assert "verification_plans" in inspect(repo.engine).get_table_names()
    finally:
        repo.close()
