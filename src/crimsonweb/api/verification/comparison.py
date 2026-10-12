"""Pure, deterministic BOLA/IDOR classification. No I/O, no model input.

The executor supplies only clean post-guard completions: a 403/429/redirect
never reaches this module, because the shared guard safe-stops on those first
(and their cause is reported as stopped-by-policy, never classified as WAF).

A finding is produced ONLY when both control reads succeed and the cross-account
read is confirmed, in memory, to have returned the second identity's record via a
pre-defined safe response field. Everything else is secure, unverified or
inconclusive -- never a finding.
"""

from dataclasses import dataclass

# Outcomes. Only ``bola_confirmed`` is a finding; the rest are recorded results.
BOLA_CONFIRMED = "bola_confirmed"
ACCESS_CONTROL_ENFORCED = "access_control_enforced"
OWNER_BINDING_UNVERIFIED = "owner_binding_unverified"
INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Verdict:
    outcome: str
    reason: str


def classify_bola(
    control_a_status: int,
    control_b_status: int,
    cross_status: int,
    owner_binding_match: bool | None,
) -> Verdict:
    """Classify a cross-owner read.

    control_a_status -- identity A reading A's own record (control)
    control_b_status -- identity B reading B's own record (control)
    cross_status     -- identity A reading B's record (the test)
    owner_binding_match -- in-memory equality of the pre-defined safe response
        field between the control-B read and the cross-account read; ``None``
        when it could not be evaluated.
    """
    if control_a_status != 200 or control_b_status != 200:
        return Verdict(INCONCLUSIVE, "control_requests_failed")
    if cross_status == 401:
        return Verdict(ACCESS_CONTROL_ENFORCED, "cross_account_access_denied")
    if cross_status == 200:
        if owner_binding_match is True:
            return Verdict(BOLA_CONFIRMED, "cross_account_record_returned")
        if owner_binding_match is False:
            return Verdict(OWNER_BINDING_UNVERIFIED, "owner_binding_not_demonstrated")
        return Verdict(OWNER_BINDING_UNVERIFIED, "owner_binding_not_evaluable")
    return Verdict(INCONCLUSIVE, "cross_account_response_inconclusive")
