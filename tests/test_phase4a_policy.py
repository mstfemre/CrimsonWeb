import asyncio
from datetime import timedelta

import pytest
from pydantic import ValidationError
from workspace_helpers import NOW, FakeResolver, policy, seeded

from crimsonweb.api.workspaces.dns import Resolution
from crimsonweb.api.workspaces.models import (
    AuthorizationRequest,
    ProgramPolicy,
    TargetScope,
)


@pytest.mark.parametrize(
    "scope",
    [
        {"allowed_domains": ["*"]},
        {"allowed_domains": ["*.com"]},
        {"allowed_domains": ["a.*.test"]},
        {"allowed_domains": ["lab.test."]},
        {"allowed_domains": ["https://lab.test"]},
        {"allowed_domains": ["127.0.0.1"]},
        {"allowed_domains": ["bad..test"]},
        {"allowed_domains": ["-lab.test"]},
        {"allowed_networks": ["127.0.0.1/8"]},
        {"allowed_networks": ["10.0.0.0/99"]},
        {"allowed_networks": ["not-a-cidr"]},
        {"allowed_paths": ["/admin*"]},
        {"allowed_paths": ["/a/../b"]},
        {"allowed_paths": ["/%61dmin"]},
        {"allowed_methods": ["CONNECT"]},
        {"allowed_ports": [0]},
        {"allowed_ports": [65536]},
        {"allow_private_networks": "true"},
        {"unrecognized": True},
    ],
)
def test_invalid_scope_contract(scope):
    with pytest.raises(ValidationError):
        TargetScope.model_validate(scope)


@pytest.mark.parametrize(
    "changes",
    [
        {"valid_until": "2026-10-10T00:00:00"},
        {"valid_from": NOW, "valid_until": NOW},
        {"test_window_start": NOW},
        {"test_window_start": NOW, "test_window_end": NOW - timedelta(seconds=1)},
        {"approved_by": ""},
        {"scope_source": ""},
        {"operator_approved": "true"},
        {"maximum_concurrency": 0},
        {"maximum_request_budget": -1},
        {"rate_limit_per_minute": 0},
    ],
)
def test_invalid_policy_contract(changes):
    with pytest.raises(ValidationError):
        policy(**changes)


@pytest.mark.parametrize(
    "url,method,category,reason",
    [
        ("http://outside.test/", "GET", "web_observation", "domain_out_of_scope"),
        ("http://evillab.test/", "GET", "web_observation", "domain_out_of_scope"),
        (
            "http://lab.test.attacker.test/",
            "GET",
            "web_observation",
            "domain_out_of_scope",
        ),
        ("http://10.2.3.4/", "GET", "web_observation", "ip_out_of_scope"),
        ("http://lab.test/admin", "GET", "web_observation", "path_denied"),
        ("http://lab.test/admin/secrets", "GET", "web_observation", "path_denied"),
        ("http://lab.test/", "POST", "web_observation", "method_denied"),
        ("http://lab.test/", "GET", "sqli", "category_denied"),
        ("http://lab.test:9999/", "GET", "web_observation", "port_denied"),
        ("http://user:password@lab.test/", "GET", "web_observation", "invalid_url"),
        ("http://lab.test/?token=secret", "GET", "web_observation", "invalid_url"),
        ("http://lab.test/a/../admin", "GET", "web_observation", "invalid_url"),
        ("http://lab.test/%2e%2e/admin", "GET", "web_observation", "invalid_url"),
        ("http://lab.test/%252fadmin", "GET", "web_observation", "invalid_url"),
        ("http://lab.test/a\\admin", "GET", "web_observation", "invalid_url"),
        ("ftp://lab.test/", "GET", "web_observation", "invalid_url"),
        ("http://169.254.169.254/", "GET", "web_observation", "ssrf_address_denied"),
        ("http://0.0.0.0/", "GET", "web_observation", "ssrf_address_denied"),
        ("http://224.0.0.1/", "GET", "web_observation", "ssrf_address_denied"),
        ("http://[::ffff:127.0.0.1]/", "GET", "web_observation", "ssrf_address_denied"),
    ],
)
def test_denied_before_dns(url, method, category, reason):
    repo, service, ws, record = seeded()
    try:
        result = asyncio.run(
            service.preflight(
                ws.id,
                record.id,
                AuthorizationRequest(url=url, method=method, category=category),
            )
        )
        assert not result.allowed and result.reason == reason
        assert service.resolver.calls == []
        assert service.store.snapshot(ws.id, record.id)[1].used_requests == 0
    finally:
        repo.close()


@pytest.mark.parametrize(
    "configuration,reason",
    [
        (ProgramPolicy(), "approval_required"),
        (policy(valid_until=None), "expiry_required"),
        (policy(valid_until=NOW), "policy_expired"),
        (policy(valid_from=NOW + timedelta(hours=1)), "policy_not_started"),
        (
            policy(
                test_window_start=NOW + timedelta(hours=1),
                test_window_end=NOW + timedelta(hours=2),
            ),
            "outside_test_window",
        ),
        (policy(maximum_request_budget=0), "budget_exhausted"),
        (policy(target_scope={}), "empty_allowlist"),
    ],
)
def test_deny_default_and_time_bounds(configuration, reason):
    repo, service, ws, record = seeded(configuration=configuration)
    try:
        assert reason in service.validate_policy(ws.id, record.id).reasons
        result = asyncio.run(
            service.preflight(
                ws.id, record.id, AuthorizationRequest(url="http://lab.test/")
            )
        )
        assert not result.allowed and result.reason == reason
        assert not service.resolver.calls
    finally:
        repo.close()


@pytest.mark.parametrize(
    "program_type,private",
    [
        ("bug_bounty", True),
        ("authorized_pentest", True),
        ("lab", False),
        ("owned", False),
    ],
)
def test_private_network_restrictions(program_type, private):
    config = policy().model_dump()
    config["target_scope"]["allow_private_networks"] = private
    repo, service, ws, record = seeded(
        program_type=program_type, configuration=ProgramPolicy.model_validate(config)
    )
    try:
        result = asyncio.run(
            service.preflight(
                ws.id, record.id, AuthorizationRequest(url="http://127.0.0.1/")
            )
        )
        expected = (
            "private_network_permission_invalid"
            if private
            else "private_network_denied"
        )
        assert not result.allowed and result.reason == expected
    finally:
        repo.close()


@pytest.mark.parametrize(
    "url",
    [
        "http://lab.test/",
        "http://a.lab.test/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://lab.test/administrator",
    ],
)
def test_explicit_lab_authorization(url):
    resolver = FakeResolver(
        Resolution(("::1",)) if "[::1]" in url else Resolution(("127.0.0.1",))
    )
    repo, service, ws, record = seeded(resolver=resolver)
    try:
        assert asyncio.run(
            service.preflight(ws.id, record.id, AuthorizationRequest(url=url))
        ).allowed
    finally:
        repo.close()


@pytest.mark.parametrize(
    "url",
    ["http://100.100.100.200/", "http://168.63.129.16/", "http://[fd00:ec2::254]/"],
)
def test_platform_endpoints_denied_even_with_explicit_broad_lab_cidr(url):
    config = policy().model_dump()
    config["target_scope"]["allowed_networks"] = ["0.0.0.0/0", "::/0"]
    repo, service, ws, record = seeded(
        configuration=ProgramPolicy.model_validate(config)
    )
    try:
        result = asyncio.run(
            service.preflight(ws.id, record.id, AuthorizationRequest(url=url))
        )
        assert not result.allowed and result.reason == "ssrf_address_denied"
        assert not service.resolver.calls
    finally:
        repo.close()


def test_forbidden_category_overrides_allowlist():
    config = policy().model_dump()
    config["target_scope"]["forbidden_categories"] = ["web_observation"]
    repo, service, ws, record = seeded(
        configuration=ProgramPolicy.model_validate(config)
    )
    try:
        result = asyncio.run(
            service.preflight(
                ws.id, record.id, AuthorizationRequest(url="http://lab.test/")
            )
        )
        assert not result.allowed and result.reason == "category_denied"
        assert not service.resolver.calls
    finally:
        repo.close()


def test_wildcard_excludes_apex_and_public_bounty_requires_both_domain_and_cidr():
    config = policy().model_dump()
    config["target_scope"].update(
        allowed_domains=["*.lab.test"],
        allowed_networks=["8.8.8.8/32"],
        allow_private_networks=False,
    )
    # The public address is synthetic resolver output; no target HTTP request occurs.
    repo, service, ws, record = seeded(
        program_type="bug_bounty",
        configuration=ProgramPolicy.model_validate(config),
        resolver=FakeResolver(Resolution(("8.8.8.8",))),
    )
    try:
        assert not asyncio.run(
            service.preflight(
                ws.id, record.id, AuthorizationRequest(url="http://lab.test/")
            )
        ).allowed
        assert asyncio.run(
            service.preflight(
                ws.id, record.id, AuthorizationRequest(url="http://a.lab.test/")
            )
        ).allowed
        service.resolver = FakeResolver(Resolution(("8.8.4.4",)))
        assert (
            asyncio.run(
                service.preflight(
                    ws.id, record.id, AuthorizationRequest(url="http://a.lab.test/")
                )
            ).reason
            == "ip_out_of_scope"
        )
    finally:
        repo.close()
