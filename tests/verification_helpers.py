"""Synthetic Phase 4C fixtures; never any third-party HTTP or DNS."""

import httpx
from workspace_helpers import FakeResolver, policy, seeded


def verification_policy(**changes):
    data = policy().model_dump()
    data["target_scope"]["allowed_categories"] = ["web_observation", "auth"]
    data["target_scope"]["allowed_methods"] = ["GET"]
    data.update(changes)
    return policy(**data)


def setup(handler=None, configuration=None, resolver=None, url="sqlite://"):
    from crimsonweb.api.verification.service import VerificationService

    repo, service, workspace, record = seeded(
        url,
        configuration=configuration or verification_policy(),
        resolver=resolver or FakeResolver(),
    )
    manager = VerificationService(
        repo,
        service,
        httpx.MockTransport(
            handler
            or (
                lambda request: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    json={"owner_id": "default"},
                )
            )
        ),
    )
    return repo, service, workspace, record, manager
