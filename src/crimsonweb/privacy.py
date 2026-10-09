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
}
URL_PATTERN = re.compile(r"(?:https?|socks4a?|socks5h?)://[^\s<>\"']+", re.IGNORECASE)


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
        return URL_PATTERN.sub(lambda match: redact_url(match.group()), value)
    return value
