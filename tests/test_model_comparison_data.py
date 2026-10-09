import pytest
from model_comparison_data import API_CASES, api_repository, standard_repository

from crimsonweb.api.ai.contract import output_schema
from crimsonweb.api.ai.models import AnalysisRequest
from crimsonweb.api.ai.security import build_bundle


@pytest.mark.parametrize("kind", ["findings", "scan", "waf"])
def test_paired_standard_fixture_has_identical_masked_input_and_schema(kind):
    bundles = []
    for _ in range(2):
        repository, report = standard_repository()
        try:
            request = AnalysisRequest(
                kind=kind,
                scan_id=report.id if kind == "scan" else None,
                finding_ids=[report.findings[0].id] if kind == "findings" else [],
                waf_event_ids=[report.waf_events[0].id] if kind == "waf" else [],
            )
            bundles.append(build_bundle(repository, request, 32768))
        finally:
            repository.close()
    assert bundles[0].data == bundles[1].data and bundles[0].digest == bundles[1].digest
    assert output_schema(bundles[0].refs, "tr") == output_schema(bundles[1].refs, "tr")


def test_api_fixture_reproducible_and_has_all_four_controls_without_tls_waf():
    bundles = []
    for _ in range(2):
        repository, report = api_repository()
        try:
            assert [f.code for f in report.findings] == [row[0] for row in API_CASES]
            bundles.append(
                build_bundle(repository, AnalysisRequest(scan_id=report.id), 32768)
            )
        finally:
            repository.close()
    assert bundles[0].digest == bundles[1].digest
    assert sum(r.startswith("finding:") for r in bundles[0].refs) == 4
    assert not any(r.startswith(("tls:", "waf:")) for r in bundles[0].refs)
