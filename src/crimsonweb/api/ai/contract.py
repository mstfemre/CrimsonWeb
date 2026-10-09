"""Per-request provider schema. Exact object keys bind opinions to trusted IDs.

The wire format is internal; persisted/API output remains AnalystOutput.
No positional, fuzzy, truncated-ID or prose-based matching is permitted.
"""

from typing import Literal

from pydantic import Field, create_model

from .models import (
    AnalystOutput,
    CommentBody,
    Improvement,
    Language,
    Relationship,
    Section,
    StrictModel,
)


def output_contract(refs: list[str], language: Language) -> type[StrictModel]:
    allowed = sorted(set(refs))
    tls_refs = [r for r in allowed if r.startswith(("tls:", "tls_failure:"))]

    def bound_section(name, base, choices, minimum=0):
        # An empty registry must produce an empty array, never an empty enum.
        ref_type = Literal[tuple(choices)] if choices else str
        return create_model(
            name,
            __base__=base,
            evidence_refs=(
                list[ref_type],
                Field(
                    min_length=minimum,
                    max_length=min(100, len(choices)),
                    json_schema_extra={"uniqueItems": True},
                ),
            ),
        )

    body = create_model(
        "ConciseComment",
        __base__=CommentBody,
        remediations=(list[str], Field(min_length=1, max_length=3)),
    )

    def comments(name, prefix):
        return create_model(
            name,
            __base__=StrictModel,
            **{
                f"entry_{index}": (body, Field(alias=ref))
                for index, ref in enumerate(allowed)
                if ref.startswith(prefix)
            },
        )

    risk = bound_section("BoundRisk", Section, allowed, int(bool(allowed)))
    tls = bound_section("BoundTLS", Section, tls_refs, int(bool(tls_refs)))
    improvement = bound_section("BoundImprovement", Improvement, allowed, 1)
    relationship = bound_section("BoundRelationship", Relationship, allowed, 2)
    # No improvement/relationship can reference evidence when not enough exists.
    # Their items are unreachable when maxItems=0; retain a valid item schema.
    if not allowed:
        improvement = Improvement
    if len(allowed) < 2:
        relationship = Relationship
    return create_model(
        "EvidenceBoundOutput",
        __base__=AnalystOutput,
        language=(Literal[language], Field()),
        technical_findings=(comments("FindingComments", "finding:"), Field()),
        waf_assessment=(comments("WAFComments", "waf:"), Field()),
        risk_assessment=(risk, Field()),
        tls_analysis=(tls, Field()),
        priority_improvements=(
            list[improvement],
            Field(max_length=min(3, len(allowed))),
        ),
        relationships=(
            list[relationship],
            Field(max_length=2 if len(allowed) >= 2 else 0),
        ),
        limitations=(list[str], Field(min_length=1, max_length=3)),
    )


def output_schema(refs: list[str], language: Language) -> dict:
    schema = output_contract(refs, language).model_json_schema()
    schema["description"] = (
        "Tüm açıklama, özet, etki, belirsizlik, öneri ve sınırlamaları Türkçe yaz. "
        "Kanıt anahtarlarını ve enum değerlerini değiştirme."
        if language == "tr"
        else "Write every summary, explanation, impact, uncertainty, remedy and "
        "limitation in English. Preserve evidence keys and enum values exactly."
    )
    return schema
