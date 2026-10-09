"""Synthetic scope fixtures; no third-party HTTP or DNS traffic."""

from datetime import UTC, datetime, timedelta

from crimsonweb.api.database import Repository
from crimsonweb.api.workspaces.dns import Resolution
from crimsonweb.api.workspaces.models import ProgramPolicy, WorkspaceCreate
from crimsonweb.api.workspaces.service import WorkspaceService

NOW = datetime(2026, 10, 9, 12, tzinfo=UTC)


def policy(**changes):
    data = {
        "target_scope": {
            "allowed_domains": ["lab.test", "*.lab.test"],
            "allowed_networks": ["127.0.0.0/8", "::1/128"],
            "allowed_paths": ["/*"],
            "forbidden_paths": ["/admin/*"],
            "allowed_methods": ["GET"],
            "allowed_ports": [80, 443, 8001],
            "allowed_categories": ["web_observation"],
            "allow_private_networks": True,
        },
        "rate_limit_per_minute": 100,
        "maximum_concurrency": 2,
        "maximum_request_budget": 20,
        "valid_from": NOW - timedelta(days=1),
        "valid_until": NOW + timedelta(days=1),
        "operator_approved": True,
        "approved_by": "lab-operator",
        "scope_source": "owned synthetic laboratory",
    }
    data.update(changes)
    return ProgramPolicy.model_validate(data)


class FakeResolver:
    def __init__(self, *responses):
        self.responses = responses or (Resolution(("127.0.0.1",)),)
        self.calls = []

    async def resolve(self, host):
        self.calls.append(host)
        value = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        if isinstance(value, Exception):
            raise value
        return value


def seeded(
    url="sqlite://", resolver=None, program_type="lab", configuration=None, clock=None
):
    repository = Repository(url)
    repository.initialize()
    service = WorkspaceService(
        repository, resolver or FakeResolver(), clock or (lambda: NOW)
    )
    workspace = service.store.create_workspace(
        WorkspaceCreate(name="Lab", program_type=program_type), NOW
    )
    record = service.store.write_policy(workspace.id, configuration or policy(), NOW)
    return repository, service, workspace, record
