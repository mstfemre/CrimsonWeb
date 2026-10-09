"""Deterministic endpoint identity and candidate relations; no network calls."""

import re
from uuid import UUID, uuid5

from .models import Endpoint, Relation
from .urls import fingerprint, parameter, safe_name, sensitive_operation


class EndpointInventory:
    @staticmethod
    def make(job_id, origin_ref, path, method, source, evidence_ref, **fields):
        resource = next(
            (
                p
                for p in path.split("/")
                if p
                and not p.startswith("{")
                and p not in {"api", "rest"}
                and not re.fullmatch(r"v\d+", p)
            ),
            None,
        )
        resource = safe_name(resource)
        params = list(fields.pop("parameters", []))
        for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}", path):
            item = parameter(name, "path")
            if item and not any(
                p.name == name and p.location == "path" for p in params
            ):
                params.append(item)
        identity = fingerprint(f"{origin_ref}\n{path}\n{method}")
        return Endpoint(
            id=uuid5(UUID(str(job_id)), identity),
            origin_ref=origin_ref,
            path=path,
            method=method,
            sources=[source],
            resource_type=resource,
            potentially_sensitive_operation=sensitive_operation(path, method),
            evidence_refs=[evidence_ref],
            parameters=params[:100],
            **fields,
        )


class ApplicationSurfaceGraph:
    @staticmethod
    def resource_id(job_id, endpoint):
        return (
            uuid5(
                UUID(str(job_id)),
                f"resource:{endpoint.origin_ref}:{endpoint.resource_type}",
            )
            if endpoint.resource_type
            else None
        )

    @staticmethod
    def relation(job_id, source_id, kind, label, evidence_ref, target_id=None):
        identity = f"{source_id}\n{kind}\n{label}\n{target_id or ''}"
        return Relation(
            id=uuid5(UUID(str(job_id)), identity),
            source_endpoint_id=source_id,
            related_endpoint_id=target_id,
            kind=kind,
            target_label=label[:128],
            evidence_ref=evidence_ref,
        )

    @classmethod
    def endpoint_relations(cls, job_id, endpoint, evidence_ref):
        pairs = [("method", endpoint.method), ("evidence", evidence_ref)]
        pairs += [
            ("authentication", value) for value in endpoint.authentication_indicators
        ]
        pairs += [("parameter", f"{p.location}:{p.name}") for p in endpoint.parameters]
        pairs += [
            ("potential_owner", p.name)
            for p in endpoint.parameters
            if p.owner_identifier_candidate
        ]
        if endpoint.resource_type:
            pairs.append(("resource", endpoint.resource_type))
        return [
            cls.relation(job_id, endpoint.id, kind, label, evidence_ref).model_copy(
                update={
                    "source_resource_id": cls.resource_id(job_id, endpoint)
                    if kind == "potential_owner"
                    else None
                }
            )
            for kind, label in pairs
        ]
