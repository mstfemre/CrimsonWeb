"""Extra restrictions inside the existing atomic WorkspaceStore admission."""

import ipaddress

from .store import PrivacyStop, PrivacyStore


def privacy_admission(
    repository, session, workspace_id, policy_id, owner, decision, fingerprint, now
):
    store = PrivacyStore(repository)
    try:
        row = store.check_owner(session, workspace_id, owner[0], owner[1], now)
    except PrivacyStop as exc:
        return None, exc.reason
    if (
        row.program_policy_id != str(policy_id)
        or row.data["request_fingerprint"] != fingerprint
    ):
        return None, "privacy_request_contract_changed"
    if row.requests_made >= 1:
        return None, "privacy_observation_budget_exhausted"
    policy = store.policy_record(
        store.privacy_policy_row(session, workspace_id, row.profile_id)
    )
    if row.data["kind"] != "dns" and decision.resolved_ips:
        family = (
            "ipv4"
            if ipaddress.ip_address(decision.resolved_ips[0]).version == 4
            else "ipv6"
        )
        if family == "ipv6" and not policy.allow_ipv6_probe:
            return None, "privacy_ipv6_probe_not_approved"
        if row.data["requested_family"] not in {family, "any"}:
            return None, "privacy_address_family_mismatch"
    return row, None
