"""Validate a single test-identity auth header before it reaches the guard.

Credential VALUES are held only in memory for the duration of a run. They are
never persisted, logged, placed in a request fingerprint, sent to the model, or
included in any exception message. This validator refuses anything outside a
small auth-header allowlist and rejects header-injection, and it raises errors
that carry a fixed code plus the header NAME only -- never the value.
"""

from ..engine import checked_auth_header
from ..scope import ScopeError

MAX_VALUE_LENGTH = 4096


class CredentialError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_auth_header(name: str, value: str) -> tuple[str, str]:
    """Return the validated (name, value) or raise CredentialError.

    The returned value is the credential and must never be logged or stored.
    """
    try:
        return checked_auth_header(name, value)
    except ScopeError as exc:
        code = "header_not_allowed" if str(exc) == "auth_header_not_allowed" else "invalid_header_value"
        raise CredentialError(code) from None
