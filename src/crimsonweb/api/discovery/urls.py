"""Strict link handling without normalizing forbidden paths into allowed ones."""

import hashlib
import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from ..scope import ScopeError
from ..workspaces.models import AuthorizationRequest
from ..workspaces.policy import parsed_target
from .models import Parameter


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()


def safe_name(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_.-]{0,63}", value
    ):
        return None
    if re.search(r"[a-fA-F0-9]{24,}", value) or len(value) > 48:
        return None
    return value


def parameter(name, location, data_type="unknown"):
    name = safe_name(name)
    if name is None:
        return None
    lowered = name.lower().replace("-", "_")
    owner = lowered in {
        "owner",
        "owner_id",
        "user_id",
        "tenant_id",
        "account_id",
        "organization_id",
        "org_id",
    }
    if isinstance(data_type, list):
        data_type = next(
            (t for t in data_type if isinstance(t, str) and t != "null"), "unknown"
        )
    return Parameter(
        name=name,
        location=location,
        data_type=data_type
        if isinstance(data_type, str)
        and data_type in {"string", "integer", "number", "boolean", "array", "object"}
        else "unknown",
        object_identifier_candidate=owner or lowered == "id" or lowered.endswith("_id"),
        owner_identifier_candidate=owner,
    )


def masked_path(path):
    result = []
    resource_parents = {
        "users",
        "user",
        "accounts",
        "tenants",
        "organizations",
        "orgs",
        "projects",
        "orders",
        "items",
        "documents",
        "files",
        "profiles",
        "customers",
    }
    secret_parents = {"token", "tokens", "secret", "session", "password", "reset"}
    previous = ""
    for part in path.split("/"):
        if not part:
            result.append("")
        elif re.fullmatch(r"\{[A-Za-z_][A-Za-z0-9_]{0,63}\}", part):
            result.append(part)
        elif (
            part.isdigit()
            or re.fullmatch(r"[a-fA-F0-9-]{24,}", part)
            or (
                previous in resource_parents
                and part not in {"me", "new", "create", "list", "search"}
            )
        ):
            result.append("{id}")
        elif (
            previous in secret_parents
            or len(part) > 48
            or "@" in part
            or part.startswith("eyJ")
            or (
                len(part) >= 24
                and re.search(r"[A-Z]", part)
                and re.search(r"[a-z]", part)
                and re.search(r"\d", part)
            )
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
        ):
            result.append("{redacted}")
        else:
            result.append(part)
        previous = part.lower()
    return "/".join(result) or "/"


def origin(url):
    return str(url.copy_with(path="/", query=None, fragment=None))


def metadata_route(value):
    """Drop query/fragment values for inventory ONLY; this never authorizes HTTP."""
    parts = urlsplit(value)
    if parts.username is not None or parts.password is not None or len(value) > 2048:
        raise ScopeError("invalid_discovery_url")
    query_parameters = []
    if parts.query:
        for name, sample in parse_qsl(
            parts.query, keep_blank_values=True, max_num_fields=50
        ):
            kind = (
                "integer"
                if re.fullmatch(r"-?\d+", sample)
                else "number"
                if re.fullmatch(r"-?\d+\.\d+", sample)
                else "boolean"
                if sample.lower() in {"true", "false"}
                else "string"
            )
            item = parameter(name, "query", kind)
            if item:
                query_parameters.append(item)
    without_values = value.split("#", 1)[0].split("?", 1)[0]
    # Templates are permitted only in offline inventory, not in active requests.
    checked = re.sub(r"\{[A-Za-z_][A-Za-z0-9_]{0,63}\}", "placeholder", without_values)
    parsed_target(AuthorizationRequest(url=checked, category="crawl"))
    return (
        fingerprint(origin(parsed_target(AuthorizationRequest(url=checked)))),
        masked_path(parts.path or "/"),
        query_parameters,
    )


def active_url(value, base=None):
    if not isinstance(value, str) or len(value) > 2048 or not value.strip():
        raise ScopeError("invalid_discovery_url")
    # Validate the spelling BEFORE urljoin/httpx remove dot segments.
    raw = urlsplit(value)
    if (
        raw.query
        or "?" in value
        or raw.username is not None
        or raw.password is not None
        or "\\" in value
    ):
        raise ScopeError("query_or_credentials_not_supported")
    path = raw.path
    if (
        not re.fullmatch(r"[A-Za-z0-9/_.~-]*", path)
        or "//" in path
        or any(p in {".", ".."} for p in path.split("/"))
        or any(ord(c) < 33 or ord(c) > 126 for c in value)
    ):
        raise ScopeError("encoded_or_ambiguous_path_not_supported")
    # HTML anchors have no HTTP meaning, so strip fragment before guard admission.
    value = value.split("#", 1)[0]
    joined = urljoin(base, value) if base else value
    url = parsed_target(AuthorizationRequest(url=joined, category="crawl"))
    return url


def same_origin(first, second):
    return origin(first) == origin(second)


def metadata_link(base, value):
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(ord(c) < 32 for c in value)
        or "\\" in value
    ):
        raise ScopeError("invalid_discovery_url")
    path = urlsplit(value).path
    if "%" in path or "//" in path or any(p in {".", ".."} for p in path.split("/")):
        raise ScopeError("ambiguous_path")
    combined = urljoin(base, value)
    metadata_route(combined)
    return combined


def sensitive_operation(path, method):
    return method in {"POST", "PUT", "PATCH", "DELETE"} or bool(
        set(path.lower().split("/"))
        & {
            "logout",
            "signout",
            "delete",
            "remove",
            "destroy",
            "reset",
            "transfer",
            "checkout",
            "purchase",
            "pay",
        }
    )
