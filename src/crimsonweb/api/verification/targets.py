"""Build verification targets from Phase 4B endpoints or offline OpenAPI parsing.

Targets are endpoint CANDIDATES only. Building a target never grants authority to
send a request; every request is still authorized by the shared scope guard at
execution time. OpenAPI candidates carry a synthetic declared-evidence ref.
"""

from ..discovery.models import Endpoint
from ..discovery.openapi import OpenAPIImporter
from ..discovery.urls import fingerprint, masked_path, origin, sensitive_operation
from ..scope import ScopeError
from ..workspaces.models import AuthorizationRequest
from ..workspaces.policy import parsed_target
from .models import VerificationTarget


def approved_origin(base_url: str) -> str:
    """Only a strict HTTP(S) origin, with no credentials, query or path prefix."""
    url = parsed_target(AuthorizationRequest(url=base_url, category="auth"))
    if url.path != "/" or url.query or url.fragment:
        raise ScopeError("verification_origin_required")
    return fingerprint(origin(url))


def _object_identifier(parameters) -> str | None:
    for parameter in parameters:
        location = (
            parameter.location
            if hasattr(parameter, "location")
            else parameter.get("location")
        )
        candidate = (
            parameter.object_identifier_candidate
            if hasattr(parameter, "object_identifier_candidate")
            else parameter.get("object_identifier_candidate")
        )
        name = parameter.name if hasattr(parameter, "name") else parameter.get("name")
        if location == "path" and candidate:
            return name
    return None


def _query_parameters(parameters):
    from ..workspaces.models import query_name

    names = []
    for parameter in parameters:
        if parameter.location == "query":
            try:
                names.append(query_name(parameter.name))
            except ValueError:
                continue
    return sorted(set(names))[:16]


def targets_from_endpoints(endpoints: list[Endpoint]) -> list[VerificationTarget]:
    return [
        VerificationTarget(
            endpoint_ref=f"endpoint:{endpoint.id}",
            source="discovery",
            origin_ref=endpoint.origin_ref,
            path=masked_path(endpoint.path),
            method=endpoint.method,
            object_identifier_parameter=_object_identifier(endpoint.parameters),
            potentially_sensitive_operation=endpoint.potentially_sensitive_operation,
            evidence_refs=list(endpoint.evidence_refs),
            query_parameters=_query_parameters(endpoint.parameters),
        )
        for endpoint in endpoints
    ]


def targets_from_openapi(document: dict, base_url: str | None) -> list[VerificationTarget]:
    importer = OpenAPIImporter()
    entries = importer.parse(document, base_url)
    digest = importer.source_digest(document)
    targets = []
    for index, entry in enumerate(entries):
        targets.append(
            VerificationTarget(
                endpoint_ref=f"endpoint:openapi-{digest[:16]}-{index}",
                source="openapi",
                origin_ref=entry["origin_ref"],
                path=entry["path"],
                method=entry["method"],
                object_identifier_parameter=_object_identifier(entry["parameters"]),
                potentially_sensitive_operation=sensitive_operation(
                    entry["path"], entry["method"]
                ),
                evidence_refs=[f"openapi:{digest[:32]}"],
                query_parameters=_query_parameters(entry["parameters"]),
            )
        )
    return targets
