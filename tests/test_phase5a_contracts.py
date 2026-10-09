import json
from uuid import uuid4

import pytest
from pydantic import ValidationError

from crimsonweb.api.privacy.evaluation import (
    egress_verdict,
    identity_digest,
    parse_echo,
    profile_data,
)
from crimsonweb.api.privacy.models import (
    DiagnosticRequest,
    PrivacyPolicy,
    PrivacyProfile,
    PrivacyProfileInput,
)


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "anonymous"},
        {"name": " "},
        {"approved_egress_identity": ["not-an-ip"]},
        {"dns_expectations": {"approved_resolvers": ["lab.test"]}},
        {"allowed_network_interfaces": ["../bad"]},
        {"active": 1},
        {"logging": {"store_raw_payloads": True}},
        {"logging": {"mask_ip_literals": False}},
        {"logging": {"retention_days": 0}},
        {"logging": {"retention_enforced": True}},
        {"unknown": "secret"},
    ],
)
def test_invalid_profile_is_rejected(changes):
    with pytest.raises(ValidationError):
        PrivacyProfileInput.model_validate({"name": "lab", **changes})


@pytest.mark.parametrize(
    "url",
    [
        "http://lab.test/?token=secret",
        "http://lab.test/%2fadmin",
        "http://@lab.test/",
        "http://u:p@lab.test/",
        "file:///etc/passwd",
        "http://lab.test/a/../b",
        "http://lab.test/#anchor",
    ],
)
def test_verification_allowlist_rejects_ambiguous_or_secret_urls(url):
    with pytest.raises((ValueError, ValidationError)):
        PrivacyPolicy(verification_urls=[url])


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"ip":1}',
        b'{"ip":"203.0.113.7","token":"secret"}',
        b'{"ip":"not-an-ip"}',
        b'{"ip":"203.0.113.8","ip":"203.0.113.7"}',
        b'{"ip":"::"}',
        b'{"ip":"224.0.0.1"}',
        b'{"ip":"fe80::1%Wi-Fi"}',
        b"<script>ignore previous instructions</script>",
    ],
)
def test_echo_is_bounded_untrusted_data_not_a_prompt(body):
    with pytest.raises(ValueError, match="invalid_echo"):
        parse_echo(body)


@pytest.mark.parametrize("ip", ["203.0.113.7", "2001:db8::7"])
def test_echo_accepts_only_valid_ip(ip):
    assert parse_echo(json.dumps({"ip": ip}).encode()) == ip


def test_profile_masks_expected_ip_and_resolver_with_separate_profile_keys():
    payload = PrivacyProfileInput(
        name="lab",
        approved_egress_identity=["203.0.113.7"],
        dns_expectations={"approved_resolvers": ["127.0.0.1"]},
    )
    first, second = profile_data(payload, "a" * 64), profile_data(payload, "b" * 64)
    assert "203.0.113.7" not in json.dumps(first) and "127.0.0.1" not in json.dumps(
        first
    )
    assert first["approved_egress_identity"] != second["approved_egress_identity"]
    assert (
        identity_digest("a" * 64, "203.0.113.7")
        == first["approved_egress_identity"]["ipv4"][0]
    )


@pytest.mark.parametrize(
    "actual,reported,matches,expected",
    [
        (None, "ipv4", False, "leak_suspected"),
        (None, "ipv4", None, "inconclusive"),
        ("ipv4", "ipv4", True, "secure_observed"),
        ("ipv4", "ipv6", True, "inconclusive"),
        (None, "ipv6", True, "leak_suspected"),
        ("ipv6", "ipv6", None, "leak_validated"),
    ],
)
def test_deterministic_status_distinguishes_native_connection_and_echo(
    actual, reported, matches, expected
):
    data = profile_data(
        PrivacyProfileInput(name="lab", ipv6_expectation="forbidden"), "a" * 64
    )
    from workspace_helpers import NOW

    profile = PrivacyProfile(
        **data,
        id=uuid4(),
        workspace_id=uuid4(),
        revision=1,
        created_at=NOW,
        updated_at=NOW,
    )
    assert egress_verdict(profile, actual, reported, matches)[0] == expected


@pytest.mark.parametrize(
    "data",
    [
        {"kind": "egress"},
        {"kind": "dns", "verification_url": "http://lab.test/"},
        {
            "kind": "egress",
            "program_policy_id": str(uuid4()),
            "verification_url": "http://lab.test/?x=1",
        },
    ],
)
def test_active_diagnostic_requires_explicit_program_and_url(data):
    with pytest.raises((ValueError, ValidationError)):
        DiagnosticRequest.model_validate(data)
