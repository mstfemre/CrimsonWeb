"""Target building reuses Phase 4B endpoints and offline OpenAPI parsing."""

from uuid import uuid4

from discovery_helpers import spec

from crimsonweb.api.discovery.models import Endpoint
from crimsonweb.api.verification.targets import (
    targets_from_endpoints,
    targets_from_openapi,
)


def discovery_endpoint():
    return Endpoint(
        id=uuid4(),
        origin_ref="origin:1",
        path="/api/objects/{object_id}",
        method="GET",
        sources=["openapi"],
        parameters=[
            {"name": "object_id", "location": "path", "object_identifier_candidate": True},
        ],
        evidence_refs=["evidence:v1"],
    )


def test_discovery_endpoint_becomes_a_target_preserving_evidence():
    endpoint = discovery_endpoint()
    [target] = targets_from_endpoints([endpoint])
    assert target.endpoint_ref == f"endpoint:{endpoint.id}"
    assert target.source == "discovery"
    assert target.object_identifier_parameter == "object_id"
    assert target.evidence_refs == ["evidence:v1"]
    assert target.potentially_sensitive_operation is False


def test_openapi_candidates_flag_read_only_and_sensitive_operations():
    targets = targets_from_openapi(spec(), base_url=None)
    by_key = {(t.path, t.method): t for t in targets}
    read = by_key[("/api/objects/{object_id}", "GET")]
    assert read.source == "openapi"
    assert read.object_identifier_parameter == "object_id"
    assert read.potentially_sensitive_operation is False
    assert read.evidence_refs  # a synthetic declared-evidence ref is attached
    # A write/delete operation is present but flagged sensitive (never testable here).
    assert by_key[("/api/objects/{object_id}", "DELETE")].potentially_sensitive_operation
    assert by_key[("/api/objects", "POST")].potentially_sensitive_operation
