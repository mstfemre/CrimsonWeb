import asyncio
import json
from uuid import uuid4

import pytest
from ai_helpers import MockProvider, seeded_repository, valid_output

from crimsonweb.api.ai.contract import output_schema
from crimsonweb.api.ai.models import AnalysisRequest
from crimsonweb.api.ai.provider import AIError, AISettings
from crimsonweb.api.ai.security import (
    build_bundle,
    language_signals,
    validate_output,
    validate_provider_output,
)
from crimsonweb.api.ai.service import AIService
from crimsonweb.api.database import Repository


@pytest.fixture
def evidence():
    repo, report = seeded_repository()
    bundle = build_bundle(repo, AnalysisRequest(scan_id=report.id), 32768)
    try:
        yield repo, report, bundle
    finally:
        repo.close()


def wire_output(bundle):
    output = valid_output(bundle.data)
    for name in ("technical_findings", "waf_assessment"):
        output[name] = {
            comment["evidence_ref"]: {
                key: value
                for key, value in comment.items()
                if key not in {"evidence_ref", "evidence_refs"}
            }
            for comment in output[name]
        }
    return output


def validate(data, bundle):
    return validate_provider_output(json.dumps(data, ensure_ascii=False), bundle, "tr")


def test_reproduced_context_records_must_not_become_findings(evidence):
    _, _, bundle = evidence
    output = valid_output(bundle.data)
    comment = output["technical_findings"][0]
    extras = [ref for ref in bundle.refs if ref.startswith(("scan:", "tls:"))]
    output["technical_findings"].extend(
        {**comment, "evidence_ref": ref, "evidence_refs": [ref]} for ref in extras
    )
    with pytest.raises(AIError, match="invalid_evidence_reference") as failure:
        validate_output(json.dumps(output), bundle, "tr")
    diagnostic = failure.value.diagnostics
    assert diagnostic["missing"] == [] and diagnostic["duplicates"] == []
    assert diagnostic["unexpected"] == sorted(extras)


def test_schema_binds_categories_refs_and_requested_language(evidence):
    _, _, bundle = evidence
    schema = output_schema(bundle.refs, "tr")
    assert schema == output_schema(list(reversed(bundle.refs)), "tr")
    assert schema["properties"]["language"]["const"] == "tr"
    for name, prefix in [("FindingComments", "finding:"), ("WAFComments", "waf:")]:
        definition = schema["$defs"][name]
        expected = sorted(ref for ref in bundle.refs if ref.startswith(prefix))
        assert sorted(definition["properties"]) == expected
        assert sorted(definition["required"]) == expected
        assert definition["additionalProperties"] is False
    body = schema["$defs"]["ConciseComment"]["properties"]
    assert "evidence_ref" not in body and "evidence_refs" not in body
    assert set(
        schema["$defs"]["BoundRisk"]["properties"]["evidence_refs"]["items"]["enum"]
    ) == set(bundle.refs)
    assert (
        schema["$defs"]["BoundTLS"]["properties"]["evidence_refs"]["items"]["const"]
        == "tls:0"
    )


def test_exact_key_binding_survives_reversed_order_and_preserves_api_shape(evidence):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    comments = wire["technical_findings"]
    expected = {}
    for index, (ref, body) in enumerate(comments.items()):
        body["explanation"] = f"Bu bulgu için yorum numarası {index}."
        expected[ref] = body["explanation"]
    wire["technical_findings"] = dict(reversed(list(comments.items())))
    output = validate(wire, bundle)
    assert isinstance(output.technical_findings, list)
    assert {
        c.evidence_ref: c.explanation for c in output.technical_findings
    } == expected
    assert {c.evidence_ref for c in output.waf_assessment} == {
        ref for ref in bundle.refs if ref.startswith("waf:")
    }


@pytest.mark.parametrize(
    "change", ["missing", "extra", "changed", "shortened", "context"]
)
def test_no_reference_repair_or_positional_mapping(evidence, change):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    comments = wire["technical_findings"]
    ref = next(iter(comments))
    body = comments[ref]
    if change == "missing":
        del comments[ref]
    elif change == "extra":
        comments[f"finding:{uuid4()}"] = body
    elif change == "changed":
        comments[f"finding:{uuid4()}"] = comments.pop(ref)
    elif change == "shortened":
        comments[ref[:20]] = comments.pop(ref)
    else:
        comments["tls:0"] = body
    with pytest.raises(AIError, match="invalid_evidence_reference"):
        validate(wire, bundle)


def test_comment_self_reference_is_server_owned(evidence):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    for body in wire["technical_findings"].values():
        assert "evidence_ref" not in body and "evidence_refs" not in body
    output = validate(wire, bundle)
    assert all(
        c.evidence_refs == [c.evidence_ref]
        for c in [*output.technical_findings, *output.waf_assessment]
    )


@pytest.mark.parametrize(
    "field",
    [
        "risk_assessment",
        "tls_analysis",
        "priority_improvements",
        "relationships",
    ],
)
def test_all_reference_arrays_reject_unknown_ids_without_leaking_prose(evidence, field):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    value = wire[field]
    section = value[0] if isinstance(value, list) else value
    section["evidence_refs"].append("password=private-secret; user@example.invalid")
    with pytest.raises(AIError, match="invalid_evidence_reference") as failure:
        validate(wire, bundle)
    assert failure.value.diagnostics["invalid_reference_count"] == 1
    assert "private-secret" not in json.dumps(failure.value.diagnostics)
    assert "example.invalid" not in json.dumps(failure.value.diagnostics)
    assert str(failure.value) == "invalid_evidence_reference"


@pytest.mark.parametrize("field", ["evidence_ref", "evidence_refs"])
def test_model_cannot_override_server_owned_comment_references(evidence, field):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    next(iter(wire["technical_findings"].values()))[field] = "password=private-secret"
    with pytest.raises(AIError, match="invalid_model_output") as failure:
        validate(wire, bundle)
    assert (
        str(failure.value) == "invalid_model_output"
        and failure.value.__suppress_context__
    )


def test_duplicate_refs_still_rejected(evidence):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    section = wire["risk_assessment"]
    section["evidence_refs"].append(section["evidence_refs"][0])
    with pytest.raises(AIError, match="invalid_evidence_reference") as failure:
        validate(wire, bundle)
    assert len(failure.value.diagnostics["duplicates"]) == 1


def test_duplicate_json_evidence_keys_not_silently_collapsed(evidence):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    ref = next(iter(wire["technical_findings"]))
    key = json.dumps(ref)
    content = json.dumps(wire).replace(key + ":", key + ": {}, " + key + ":", 1)
    with pytest.raises(AIError, match="invalid_evidence_reference") as failure:
        validate_provider_output(content, bundle, "tr")
    assert failure.value.diagnostics["duplicates"] == [ref]


@pytest.mark.parametrize(
    "change",
    [
        "prose_type",
        "extra_field",
        "duplicate_field",
        "array_instead_of_object",
        "wrong_language",
    ],
)
def test_wire_shape_errors_do_not_disclose_validation_inputs(evidence, change):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    if change == "prose_type":
        wire["executive_summary"] = {"password": "private-secret"}
    elif change == "extra_field":
        next(iter(wire["technical_findings"].values()))["evidence_ref"] = (
            "private-secret"
        )
    elif change == "array_instead_of_object":
        wire["technical_findings"] = list(wire["technical_findings"].values())
    elif change == "wrong_language":
        wire["language"] = "en"
    content = json.dumps(wire)
    if change == "duplicate_field":
        content = content.replace(
            '"language": "tr"', '"language": "en", "language": "tr"'
        )
    with pytest.raises(AIError, match="invalid_model_output") as failure:
        validate_provider_output(content, bundle, "tr")
    if change in {"prose_type", "extra_field", "wrong_language"}:
        assert failure.value.__suppress_context__
    assert "private-secret" not in str(failure.value)


def test_turkish_label_does_not_accept_clearly_english_summary(evidence):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    wire["executive_summary"] = (
        "The observed configuration is incomplete and should be reviewed with the application owner."
    )
    with pytest.raises(AIError, match="model_language_mismatch"):
        validate(wire, bundle)


def test_ascii_turkish_and_technical_english_terms_are_not_rejected(evidence):
    _, _, bundle = evidence
    wire = wire_output(bundle)
    wire["executive_summary"] = (
        "Bu bir TLS ve HTTP incelemesi olarak ele alinmali ve bu kanitlar icin kesin sonuc beklenmemeli."
    )
    output = validate(wire, bundle)
    assert output.language == "tr" and language_signals(output)["turkish_markers"] > 0


@pytest.mark.parametrize("selection", ["empty", "waf", "finding"])
def test_empty_categories_and_absent_tls_have_valid_contracts(selection):
    repo, report = seeded_repository()
    report.hops = []
    report.tls_failures = []
    if selection != "finding":
        report.findings = []
    if selection != "waf":
        report.waf_events = []
    # Events are append-only in normal persistence; seed an isolated database
    # rather than pretending report.save removes already recorded WAF events.
    repo.close()
    repo = Repository("sqlite://")
    repo.initialize()
    repo.save(report)
    try:
        bundle = build_bundle(repo, AnalysisRequest(scan_id=report.id), 32768)
        schema = output_schema(bundle.refs, "tr")
        output = validate(wire_output(bundle), bundle)
        assert output.tls_analysis.evidence_refs == []
        assert len(output.technical_findings) == (2 if selection == "finding" else 0)
        assert len(output.waf_assessment) == (1 if selection == "waf" else 0)
        assert (
            schema["$defs"]["BoundTLS"]["properties"]["evidence_refs"]["maxItems"] == 0
        )
    finally:
        repo.close()


def test_service_uses_bound_schema_and_preserves_failed_language_result(evidence):
    repo, report, _ = evidence
    provider = MockProvider(
        transform=lambda x: {
            **x,
            "executive_summary": "The observed configuration is incomplete and should be reviewed with the application owner.",
        }
    )
    service = AIService(repo, provider, AISettings(enabled=True))
    before = repo.get(report.id).model_dump_json()

    async def run():
        record = await service.start(AnalysisRequest(scan_id=report.id))
        await service.tasks[record.id]
        return repo.get_analysis(record.id)

    record = asyncio.run(run())
    assert record.status == "failed" and record.error_code == "model_language_mismatch"
    assert record.output is None and len(provider.calls) == 1
    schema = provider.calls[0][2]
    assert "FindingComments" in schema["$defs"]
    assert repo.get(report.id).model_dump_json() == before
