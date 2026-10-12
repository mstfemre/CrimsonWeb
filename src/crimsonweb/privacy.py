"""Data minimization for persisted audit and report values."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "<redacted>"
SECRET_FIELDS = {
    "password", "passwd", "secret", "token", "accesstoken", "refreshtoken",
    "apikey", "authorization", "proxyauthorization", "cookie", "setcookie",
    "setcookielist", "torcontrolpassword",
    "xapikey", "clientsecret", "idtoken", "sessiontoken", "sessionid",
    "headervalue", "privatekey", "credential", "credentials",
}
URL_PATTERN = re.compile(r"(?:https?|socks4a?|socks5h?)://[^\s<>\"']+", re.IGNORECASE)
BEARER_PATTERN = re.compile(r"\bBearer\s+[^\s,;]+", re.IGNORECASE)
SECRET_ASSIGNMENT = re.compile(
    r"(\b(?:password|passwd|secret|token|api[_-]?key|x-api-key|client[_-]?secret|"
    r"id[_-]?token|access[_-]?token|refresh[_-]?token|authorization|cookie|set-cookie)"
    r"\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)", re.IGNORECASE,
)


def redact_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        netloc = parts.netloc.rsplit("@", 1)[-1]
        query = urlencode([(key, REDACTED) for key, _ in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, netloc, parts.path, query, ""))
    except ValueError:
        return REDACTED


def sanitize(value: Any) -> Any:
    """Return a sanitized copy; leave live response objects unchanged."""
    if isinstance(value, dict):
        return {
            key: REDACTED if re.sub(r"[-_]", "", str(key)).lower() in SECRET_FIELDS
            else sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        clean = URL_PATTERN.sub(lambda match: redact_url(match.group()), value)
        clean = BEARER_PATTERN.sub("Bearer " + REDACTED, clean)
        return SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + REDACTED, clean)
    return value
