"""Bounded, masked, untrusted JSON inventory; never wired to AI or network tools."""

from ..ai.security import mask_data
from .models import DiscoverySummary


def discovery_summary(store, workspace_id, job_id):
    job = store.get(workspace_id, job_id)
    graph = store.graph(workspace_id, job_id)
    # Keep references, remove free-text payloads (none are retained by extraction).
    endpoints = []
    for item in graph.endpoint_nodes[:32]:
        forms = [
            f.model_copy(
                update={"fields": f.fields[:10], "action_path": f.action_path[:512]}
            )
            for f in item.forms[:3]
        ]
        endpoints.append(
            item.model_copy(
                update={
                    "parameters": item.parameters[:12],
                    "forms": forms,
                    "evidence_refs": item.evidence_refs[:4],
                    "path": item.path[:512],
                }
            )
        )
    limitations = set(job.limitations) | {
        "untrusted_inventory_not_execution_plan",
        "authentication_indicators_not_verified",
        "object_owner_candidates_are_heuristics",
    }
    if (
        len(graph.endpoint_nodes) > len(endpoints)
        or graph.truncated
        or len(graph.relations) > 64
        or any(
            len(e.parameters) > 12
            or len(e.forms) > 3
            or len(e.evidence_refs) > 4
            or len(e.path) > 512
            or any(len(f.fields) > 10 or len(f.action_path) > 512 for f in e.forms)
            for e in graph.endpoint_nodes
        )
        or any(len(r.potential_owner_identifiers) > 12 for r in graph.resource_nodes)
    ):
        limitations.add("summary_truncated")
    while True:
        ids = {e.id for e in endpoints}
        relations = [
            r
            for r in graph.relations
            if r.source_endpoint_id in ids
            and (r.related_endpoint_id is None or r.related_endpoint_id in ids)
        ][:64]
        refs = sorted(
            {ref for e in endpoints for ref in e.evidence_refs}
            | {r.evidence_ref for r in relations}
        )
        resources = [
            r.model_copy(
                update={
                    "endpoint_ids": [i for i in r.endpoint_ids if i in ids],
                    "potential_owner_identifiers": r.potential_owner_identifiers[:12],
                }
            )
            for r in graph.resource_nodes
            if any(i in ids for i in r.endpoint_ids)
        ]
        payload = DiscoverySummary(
            workspace_id=workspace_id,
            job_id=job_id,
            discovered_endpoints=endpoints,
            discovered_resources=resources,
            authentication_indicators=[
                {"endpoint_id": str(e.id), "indicators": e.authentication_indicators}
                for e in endpoints
                if e.authentication_indicators
            ],
            resource_relationships=relations,
            potentially_sensitive_operations=[
                e.id for e in endpoints if e.potentially_sensitive_operation
            ],
            evidence_refs=refs,
            discovery_limitations=sorted(limitations),
        )
        notes = set()
        masked = DiscoverySummary.model_validate(
            mask_data(payload.model_dump(mode="json"), notes)
        )
        if notes:
            masked.discovery_limitations = sorted(
                set(masked.discovery_limitations) | notes
            )
        if len(masked.model_dump_json().encode()) <= 32768:
            return masked
        endpoints = endpoints[:-1]
        limitations.add("summary_truncated")
