"""Deterministic BOLA/IDOR verdicts: controls, cross-account read, owner binding.

No unauthenticated probe. The matrix only ever sees clean post-guard completions;
403/429/redirect are handled as safe-stops by the executor, never classified here.
"""

from crimsonweb.api.verification.comparison import Verdict, classify_bola


def test_confirmed_only_when_controls_pass_and_owner_binding_matches():
    verdict = classify_bola(
        control_a_status=200,
        control_b_status=200,
        cross_status=200,
        owner_binding_match=True,
    )
    assert verdict == Verdict("bola_confirmed", "cross_account_record_returned")


def test_cross_account_200_without_owner_binding_is_unverified_not_a_finding():
    verdict = classify_bola(
        control_a_status=200,
        control_b_status=200,
        cross_status=200,
        owner_binding_match=False,
    )
    assert verdict == Verdict("owner_binding_unverified", "owner_binding_not_demonstrated")


def test_cross_account_200_with_unevaluable_binding_is_unverified():
    verdict = classify_bola(
        control_a_status=200,
        control_b_status=200,
        cross_status=200,
        owner_binding_match=None,
    )
    assert verdict == Verdict("owner_binding_unverified", "owner_binding_not_evaluable")


def test_cross_account_401_is_access_control_enforced():
    verdict = classify_bola(
        control_a_status=200,
        control_b_status=200,
        cross_status=401,
        owner_binding_match=None,
    )
    assert verdict == Verdict("access_control_enforced", "cross_account_access_denied")


def test_failed_control_request_is_inconclusive_never_a_finding():
    for a, b in [(401, 200), (200, 404), (500, 500)]:
        verdict = classify_bola(
            control_a_status=a,
            control_b_status=b,
            cross_status=200,
            owner_binding_match=True,
        )
        assert verdict == Verdict("inconclusive", "control_requests_failed")


def test_other_cross_status_is_inconclusive():
    verdict = classify_bola(
        control_a_status=200,
        control_b_status=200,
        cross_status=404,
        owner_binding_match=None,
    )
    assert verdict == Verdict("inconclusive", "cross_account_response_inconclusive")
