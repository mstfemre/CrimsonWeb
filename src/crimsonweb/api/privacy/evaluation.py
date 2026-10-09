"""Deterministic, bounded interpretations of untrusted observations."""

import hashlib
import hmac
import ipaddress
import json
import socket


def identity_digest(key, value):
    return hmac.new(
        bytes.fromhex(key), str(ipaddress.ip_address(value)).encode(), hashlib.sha256
    ).hexdigest()


def profile_data(payload, key):
    result = payload.model_dump(mode="json")
    result["approved_egress_identity"] = {
        family: [
            identity_digest(key, ip)
            for ip in payload.approved_egress_identity
            if (ipaddress.ip_address(ip).version == 4) == (family == "ipv4")
        ]
        for family in ("ipv4", "ipv6")
    }
    result["dns_expectations"]["approved_resolvers"] = [
        identity_digest(key, ip) for ip in payload.dns_expectations.approved_resolvers
    ]
    return result


def privacy_reason(profile, policy, request, now, check_budget=True):
    if not profile.active:
        return "privacy_profile_inactive"
    if not policy.operator_approved:
        return "privacy_approval_required"
    if policy.valid_until is None or now >= policy.valid_until:
        return "privacy_permission_expired"
    if request.kind not in policy.allowed_tests:
        return "privacy_test_not_allowed"
    if request.verification_url:
        if profile.dns_expectations["path"] in {"proxy", "system"}:
            return "dns_path_enforcement_unavailable"
        if profile.mode != "direct_observation":
            return "managed_egress_not_implemented"
        if profile.allowed_network_interfaces:
            return "interface_enforcement_unavailable"
        if request.verification_url not in policy.verification_urls:
            return "verifier_not_allowlisted"
        if request.family == "ipv6" and not policy.allow_ipv6_probe:
            return "ipv6_probe_not_approved"
    if check_budget and policy.used_observations >= policy.maximum_observations:
        return "privacy_budget_exhausted"
    return None


def connection_family(response):
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    try:
        peer = stream.get_extra_info("server_addr")
        if not isinstance(peer, tuple) or not peer:
            return None
        return "ipv4" if ipaddress.ip_address(peer[0]).version == 4 else "ipv6"
    except (ValueError, TypeError, OSError, AttributeError):
        return None


def parse_echo(body):
    def unique_fields(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("invalid_echo_response")
            result[name] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=unique_fields)
        if (
            not isinstance(value, dict)
            or set(value) != {"ip"}
            or not isinstance(value["ip"], str)
            or "%" in value["ip"]
        ):
            raise ValueError
        address = ipaddress.ip_address(value["ip"])
        if address.is_unspecified or address.is_multicast:
            raise ValueError
        return str(address)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid_echo_response") from exc


def egress_verdict(profile, actual_family, reported_family, matches):
    if (
        actual_family
        and getattr(profile, f"{actual_family}_expectation") == "forbidden"
    ):
        return "leak_validated", "unexpected_connection_family_observed"
    if actual_family and actual_family != reported_family:
        return "inconclusive", "echo_connection_family_inconsistent"
    if getattr(profile, f"{reported_family}_expectation") == "forbidden":
        return "leak_suspected", "unexpected_reported_ip_family"
    if matches is False:
        return "leak_suspected", "untrusted_echo_identity_mismatch"
    if matches is True:
        return "secure_observed", "approved_echo_identity_matched"
    return "inconclusive", "no_approved_identity_to_compare"


def ipv6_capability():
    available = None
    if socket.has_ipv6:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                probe.bind(("::1", 0))
                available = True
        except OSError:
            available = False
    return socket.has_ipv6, available
