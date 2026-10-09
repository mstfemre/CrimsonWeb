"""Synthetic policy/profile fixtures; no external HTTP or DNS."""

import asyncio
from datetime import timedelta

import httpx
from workspace_helpers import NOW, seeded

from crimsonweb.api.privacy.models import (
    DiagnosticRequest,
    PrivacyPolicy,
    PrivacyProfileInput,
)
from crimsonweb.api.privacy.service import PrivacyService


def setup(
    handler=None,
    profile_changes=None,
    privacy_changes=None,
    resolver=None,
    configuration=None,
    url="sqlite://",
):
    repo, workspace_service, workspace, program = seeded(
        url, resolver=resolver, configuration=configuration
    )
    service = PrivacyService(
        repo,
        workspace_service,
        httpx.MockTransport(
            handler
            or (
                lambda r: httpx.Response(
                    200,
                    headers={
                        "content-type": "application/json",
                        "set-cookie": "SECRET_COOKIE",
                    },
                    json={"ip": "203.0.113.7"},
                )
            )
        ),
    )
    payload = PrivacyProfileInput.model_validate(
        {
            "name": "lab_privacy",
            "approved_egress_identity": ["203.0.113.7"],
            **(profile_changes or {}),
        }
    )
    profile = service.store.create_profile(workspace.id, payload, NOW)
    policy = PrivacyPolicy(
        verification_urls=["http://lab.test/echo"],
        allowed_tests=["egress", "dns", "ipv6"],
        operator_approved=True,
        valid_until=NOW + timedelta(days=1),
        maximum_observations=20,
        rate_limit_per_minute=60,
    )
    if privacy_changes:
        policy = PrivacyPolicy.model_validate(
            {**policy.model_dump(), **privacy_changes}
        )
    service.store.write_privacy_policy(workspace.id, profile.id, policy, 1, NOW)
    return repo, workspace_service, workspace, program, profile, service


def request(program_id, kind="egress", **changes):
    return DiagnosticRequest.model_validate(
        {
            "kind": kind,
            "program_policy_id": program_id,
            "verification_url": "http://lab.test/echo",
            **changes,
        }
    )


async def wait(service, workspace_id, assessment_id):
    task = service.tasks.get((str(workspace_id), str(assessment_id)))
    if task:
        await asyncio.wait_for(asyncio.shield(task), 10)
    return service.store.get_assessment(workspace_id, assessment_id)
