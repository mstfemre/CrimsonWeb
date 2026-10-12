"""Credential injection is restricted to an auth-header allowlist and never leaks."""

import pytest

from crimsonweb.api.verification.credentials import (
    CredentialError,
    validate_auth_header,
)

SECRET = "Bearer s3cr3t-value-should-never-appear"


def test_allows_known_auth_headers_case_insensitively():
    assert validate_auth_header("Authorization", SECRET) == ("Authorization", SECRET)
    assert validate_auth_header("cookie", "session=abc")[0] == "cookie"
    assert validate_auth_header("X-API-Key", "k")[0] == "X-API-Key"


def test_rejects_non_auth_and_structural_headers():
    for name in ["Host", "Content-Length", "User-Agent", "Origin", "X-Forwarded-For"]:
        with pytest.raises(CredentialError) as exc:
            validate_auth_header(name, SECRET)
        assert exc.value.code == "header_not_allowed"
        # The rejection names the header but never the secret value.
        assert SECRET not in str(exc.value)


def test_rejects_header_injection_in_value_without_echoing_it():
    for value in ["a\r\nHost: evil", "x\nSet-Cookie: y", "ctrl\x00byte"]:
        with pytest.raises(CredentialError) as exc:
            validate_auth_header("Authorization", value)
        assert exc.value.code == "invalid_header_value"
        assert value not in str(exc.value)
        assert "evil" not in str(exc.value)


def test_rejects_empty_or_oversized_value():
    with pytest.raises(CredentialError):
        validate_auth_header("Authorization", "")
    with pytest.raises(CredentialError):
        validate_auth_header("Authorization", "x" * 4097)
