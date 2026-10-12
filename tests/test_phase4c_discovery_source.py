"""A verification plan reuses existing Phase 4B discovery endpoints and evidence."""

import asyncio

from discovery_helpers import import_request, wait
from discovery_helpers import setup as discovery_setup

from crimsonweb.api.verification.models import VerificationPlanCreate
from crimsonweb.api.verification.service import VerificationService


def test_plan_targets_are_built_from_discovery_endpoints():
    repo, service, workspace, record, manager = discovery_setup()
    try:
        async def discover():
            await manager.startup()
            job = await manager.import_openapi(workspace.id, import_request())
            await wait(manager, workspace.id, job.id)
            return job

        job = asyncio.run(discover())
        verification = VerificationService(repo, service)
        plan = asyncio.run(
            verification.create_plan(
                workspace.id,
                VerificationPlanCreate(
                    policy_id=record.id,
                    source="discovery",
                    discovery_job_id=job.id,
                ),
            )
        )
        assert plan.source_discovery_job_id == job.id
        assert plan.targets  # endpoints were imported from Phase 4B
        proposals = [p for p in plan.proposals if p.catalog_id == "bola_cross_owner_read"]
        assert proposals
        target = next(
            t for t in plan.targets if t.endpoint_ref == proposals[0].target_endpoint_ref
        )
        assert target.source == "discovery"
        assert target.object_identifier_parameter is not None
        assert target.evidence_refs  # reused from discovery, not fabricated
        assert plan.status == "awaiting_approval"
    finally:
        asyncio.run(manager.shutdown())
        repo.close()
