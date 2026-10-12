"""The planner binds model output to known catalog ids, endpoint refs and evidence.

The model can never introduce a URL, a new endpoint/evidence id, a non-catalog
test, or a test against a sensitive/non-read-only endpoint.
"""

import json

import pytest

from crimsonweb.api.verification.models import VerificationTarget
from crimsonweb.api.verification.planner import PlannerError, validate_proposals


def target(ref="endpoint:e1", **changes):
    data = {
        "endpoint_ref": ref,
        "source": "discovery",
        "path": "/api/objects/{object_id}",
        "method": "GET",
        "object_identifier_parameter": "object_id",
        "potentially_sensitive_operation": False,
        "evidence_refs": ["evidence:v1"],
    }
    data.update(changes)
    return VerificationTarget.model_validate(data)


def content(proposals):
    return json.dumps({"proposals": proposals})


def test_accepts_valid_proposal_bound_to_known_ids():
    targets = [target()]
    result = validate_proposals(
        content(
            [
                {
                    "catalog_id": "bola_cross_owner_read",
                    "target_endpoint_ref": "endpoint:e1",
                    "evidence_refs": ["evidence:v1"],
                }
            ]
        ),
        targets,
    )
    assert len(result) == 1
    assert result[0].catalog_id == "bola_cross_owner_read"


def test_rejects_unknown_catalog_id():
    with pytest.raises(PlannerError) as exc:
        validate_proposals(
            content(
                [{"catalog_id": "sqli_dump", "target_endpoint_ref": "endpoint:e1", "evidence_refs": []}]
            ),
            [target()],
        )
    assert exc.value.code == "unknown_catalog_id"


def test_rejects_fabricated_endpoint_ref():
    with pytest.raises(PlannerError) as exc:
        validate_proposals(
            content(
                [{"catalog_id": "bola_cross_owner_read", "target_endpoint_ref": "endpoint:evil", "evidence_refs": []}]
            ),
            [target()],
        )
    assert exc.value.code == "unknown_target_ref"


def test_rejects_evidence_ref_outside_target():
    with pytest.raises(PlannerError) as exc:
        validate_proposals(
            content(
                [{"catalog_id": "bola_cross_owner_read", "target_endpoint_ref": "endpoint:e1", "evidence_refs": ["evidence:forged"]}]
            ),
            [target()],
        )
    assert exc.value.code == "unknown_evidence_ref"


def test_rejects_bola_on_target_without_object_identifier():
    with pytest.raises(PlannerError) as exc:
        validate_proposals(
            content(
                [{"catalog_id": "bola_cross_owner_read", "target_endpoint_ref": "endpoint:e1", "evidence_refs": []}]
            ),
            [target(object_identifier_parameter=None)],
        )
    assert exc.value.code == "target_missing_object_identifier"


def test_rejects_test_against_sensitive_or_write_endpoint():
    with pytest.raises(PlannerError):
        validate_proposals(
            content(
                [{"catalog_id": "bola_cross_owner_read", "target_endpoint_ref": "endpoint:e1", "evidence_refs": []}]
            ),
            [target(method="DELETE", potentially_sensitive_operation=True)],
        )


def test_rejects_malformed_or_non_object_model_output():
    with pytest.raises(PlannerError):
        validate_proposals("not json", [target()])
    with pytest.raises(PlannerError):
        validate_proposals(json.dumps([1, 2, 3]), [target()])


class FakeProvider:
    """A local provider stand-in; no network, no real Ollama call."""

    def __init__(self, content):
        self.content = content

    async def generate(self, system, evidence, schema):
        return type("Reply", (), {"content": self.content})()


def test_model_wiring_validates_and_binds_a_returned_proposal():
    import asyncio

    from crimsonweb.api.verification.planner import generate_proposals

    provider = FakeProvider(content(
        [{"catalog_id": "bola_cross_owner_read", "target_endpoint_ref": "endpoint:e1", "evidence_refs": ["evidence:v1"]}]
    ))
    result = asyncio.run(generate_proposals(provider, [target()]))
    assert len(result) == 1 and result[0].target_endpoint_ref == "endpoint:e1"


def test_model_cannot_smuggle_a_fabricated_target_through_the_boundary():
    import asyncio

    from crimsonweb.api.verification.planner import generate_proposals

    provider = FakeProvider(content(
        [{"catalog_id": "bola_cross_owner_read", "target_endpoint_ref": "endpoint:evil", "evidence_refs": []}]
    ))
    with pytest.raises(PlannerError):
        asyncio.run(generate_proposals(provider, [target()]))
