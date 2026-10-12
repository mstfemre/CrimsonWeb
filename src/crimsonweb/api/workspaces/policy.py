"""Pure Python decisions shared by preview and atomic request admission."""

import ipaddress
from datetime import datetime
from urllib.parse import urlsplit

from ..scope import Scope, ScopeError
from .dns import Resolution
from .models import AuthorizationRequest, Decision, ProgramPolicy, Workspace

# Platform control/metadata addresses are never active HTTP assessment targets,
# including when an owned lab explicitly allows its private network.
PROTECTED_PLATFORM_IPS = frozenset(
    {"100.100.100.200", "168.63.129.16", "fd00:ec2::254"}
)


def readiness(policy: ProgramPolicy, now: datetime) -> list[str]:
    reasons = []
    if (
        not policy.operator_approved
        or not policy.approved_by.strip()
        or not policy.scope_source.strip()
    ):
        reasons.append("approval_required")
    if policy.valid_until is None:
        reasons.append("expiry_required")
    elif now >= policy.valid_until:
        reasons.append("policy_expired")
    if policy.valid_from and now < policy.valid_from:
        reasons.append("policy_not_started")
    if (
        policy.test_window_start
        and not policy.test_window_start <= now < policy.test_window_end
    ):
        reasons.append("outside_test_window")
    scope = policy.target_scope
    if (
        not scope.allowed_networks
        or not scope.allowed_paths
        or not scope.allowed_methods
        or not scope.allowed_ports
        or not scope.allowed_categories
    ):
        reasons.append("empty_allowlist")
    if not policy.maximum_request_budget:
        reasons.append("budget_exhausted")
    return reasons


def host_allowed(host: str, rules: list[str]) -> bool:
    return any(
        host == rule if not rule.startswith("*.") else host.endswith("." + rule[2:])
        for rule in rules
    )


def matches_path(path: str, rule: str) -> bool:
    if rule == "/*":
        return True
    if rule.endswith("/*"):
        return path == rule[:-2] or path.startswith(rule[:-1])
    return path == rule


def parsed_target(request: AuthorizationRequest):
    # Check original spelling BEFORE httpx normalizes dot segments.
    path = urlsplit(request.url).path or "/"
    if "%" in path or "//" in path or any(p in {".", ".."} for p in path.split("/")):
        raise ScopeError("ambiguous_path")
    return Scope.parse_url(request.url)


def ip_allowed(address: str, workspace: Workspace, policy: ProgramPolicy) -> str | None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "invalid_dns_address"
    if (
        str(ip) in PROTECTED_PLATFORM_IPS
        or "%" in address
        or ip.is_unspecified
        or ip.is_multicast
        or ip.is_link_local
        or (ip.is_reserved and not ip.is_loopback)
        or (
            isinstance(ip, ipaddress.IPv6Address)
            and (ip.ipv4_mapped or ip.sixtofour or ip.teredo)
        )
    ):
        return "ssrf_address_denied"
    scope = policy.target_scope
    if not ip.is_global and not (
        workspace.program_type in {"owned", "lab"} and scope.allow_private_networks
    ):
        return "private_network_denied"
    if not any(ip in ipaddress.ip_network(n) for n in scope.allowed_networks):
        return "ip_out_of_scope"
    return None


def evaluate(
    workspace: Workspace,
    policy: ProgramPolicy,
    request: AuthorizationRequest,
    now: datetime,
    resolution: Resolution | None = None,
) -> Decision:
    def deny(reason):
        return Decision(allowed=False, reason=reason)

    if not workspace.active:
        return deny("workspace_inactive")
    reasons = readiness(policy, now)
    if reasons:
        return deny(reasons[0])
    try:
        url = parsed_target(request)
    except (ScopeError, ValueError):
        return deny("invalid_url")
    scope = policy.target_scope
    if set(request.query_parameters) - set(scope.allowed_query_parameters):
        return deny("query_parameter_denied")
    if request.method not in scope.allowed_methods:
        return deny("method_denied")
    if scope.allow_private_networks and workspace.program_type not in {"owned", "lab"}:
        return deny("private_network_permission_invalid")
    if (
        request.category in scope.forbidden_categories
        or request.category not in scope.allowed_categories
    ):
        return deny("category_denied")
    if (url.port or (443 if url.scheme == "https" else 80)) not in scope.allowed_ports:
        return deny("port_denied")
    if any(matches_path(url.path, r) for r in scope.forbidden_paths) or not any(
        matches_path(url.path, r) for r in scope.allowed_paths
    ):
        return deny("path_denied")
    try:
        literal = ipaddress.ip_address(url.host)
    except ValueError:
        if not host_allowed(url.host, scope.allowed_domains):
            return deny("domain_out_of_scope")
    else:
        reason = ip_allowed(str(literal), workspace, policy)
        if reason:
            return deny(reason)
    if resolution is not None:
        if not resolution.addresses:
            return deny("dns_unknown")
        if any(
            not host_allowed(name, scope.allowed_domains) for name in resolution.cnames
        ):
            return deny("cname_out_of_scope")
        for address in resolution.addresses:
            reason = ip_allowed(address, workspace, policy)
            if reason:
                return deny(reason)
        return Decision(
            allowed=True,
            reason="authorized",
            resolved_ips=list(resolution.addresses),
            cnames=list(resolution.cnames),
        )
    return Decision(allowed=True, reason="dns_check_required")
