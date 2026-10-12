"""Verification contracts enforce read-only, in-memory-credential, no-raw-storage rules."""

import pytest
from pydantic import ValidationError

from crimsonweb.api.verification.models import (
    AccessControlFinding,
    ComparativeAccessEvidence,
    ExecuteRequest,
    IdentityInput,
)

A = {"role": "identity_a", "header_name": "Authorization", "header_value": "Bearer a", "owner_object_id": "111"}
B = {"role": "identity_b", "header_name": "Authorization", "header_value": "Bearer b", "owner_object_id": "222"}


def execute(**changes):
    return ExecuteRequest.model_validate(
        {
            "base_url": "http://lab.test:8001",
            "owner_binding_field": "owner_id",
            "identities": [A, B],
            **changes,
        }
    )


def test_execute_request_requires_both_distinct_identities():
    request = execute()
    assert {i.role for i in request.identities} == {"identity_a", "identity_b"}
    with pytest.raises(ValidationError):
        execute(identities=[A])  # missing identity_b
    with pytest.raises(ValidationError):
        execute(identities=[A, A])  # duplicate role


def test_credential_value_is_not_shown_in_repr():
    identity = IdentityInput.model_validate(A)
    assert "Bearer a" not in repr(identity)


def test_execute_request_rejects_disallowed_header_name():
    with pytest.raises(ValidationError):
        execute(identities=[A, {**B, "header_name": "X-Forwarded-For"}])


def test_execute_request_rejects_unsafe_owner_object_id():
    with pytest.raises(ValidationError):
        execute(identities=[A, {**B, "owner_object_id": "../secret"}])


def test_comparative_evidence_never_stores_raw_response_or_credential():
    evidence = ComparativeAccessEvidence.model_validate(
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "ref": "verification_evidence:11111111-1111-1111-1111-111111111111",
            "workspace_id": "22222222-2222-2222-2222-222222222222",
            "plan_id": "33333333-3333-3333-3333-333333333333",
            "test_id": "44444444-4444-4444-4444-444444444444",
            "timestamp": "2026-10-12T00:00:00Z",
            "status": "owner_binding_unverified",
            "reason": "owner_binding_not_demonstrated",
            "catalog_id": "bola_cross_owner_read",
            "target_endpoint_ref": "endpoint:55555555-5555-5555-5555-555555555555",
            "method": "GET",
            "control_a_status": 200,
            "control_b_status": 200,
            "cross_status": 200,
            "owner_binding_match": False,
            "scope_decision": "authorized",
            "identities": ["identity_a", "identity_b"],
        }
    )
    assert evidence.raw_response_stored is False
    assert evidence.credential_stored is False
    # Extra fields (e.g. a smuggled raw body) are forbidden.
    with pytest.raises(ValidationError):
        ComparativeAccessEvidence.model_validate(
            {**evidence.model_dump(mode="json"), "response_body": "secret"}
        )


def test_finding_is_only_ever_a_confirmed_bola():
    with pytest.raises(ValidationError):
        AccessControlFinding.model_validate(
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "workspace_id": "22222222-2222-2222-2222-222222222222",
                "plan_id": "33333333-3333-3333-3333-333333333333",
                "test_id": "44444444-4444-4444-4444-444444444444",
                "code": "bola_confirmed",
                "confidence": "unverified",  # a finding must be confirmed
                "status": "finding",
                "category": "auth",
                "target_endpoint_ref": "endpoint:x",
                "source_evidence_refs": ["evidence:1"],
                "observation_evidence_ref": "verification_evidence:1",
                "test_identity_roles": ["identity_a", "identity_b"],
                "scope_decision": "authorized",
            }
        )
