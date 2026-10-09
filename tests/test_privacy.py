import json

from crimsonweb import audit
from crimsonweb.core_engine import BlueScanner
from crimsonweb.models import ServiceResult
from crimsonweb.privacy import sanitize


def test_url_and_nested_secrets_are_redacted_without_mutating_input():
    original = {"url": "https://user:password@example.test/api?token=abc&name=alice#secret",
                "headers": {"Authorization": "Bearer abc", "Set-Cookie": "sid=secret; Secure"}}
    clean = sanitize(original)
    assert "password" not in clean["url"]
    assert "alice" not in clean["url"]
    assert "abc" not in json.dumps(clean)
    assert "example.test/api" in clean["url"]
    assert original["headers"]["Authorization"] == "Bearer abc"


def test_cli_target_url_is_redacted():
    result = audit.redact_cli_args(["crimsonweb", "-u", "https://user:pw@example.test/?key=abc"])
    assert "pw" not in result and "abc" not in result


def test_serialized_headers_hide_cookie_values_but_preserve_findings():
    result = ServiceResult(port=443, headers={"set-cookie-list": ["sid=secret"]},
                           cookie_findings=[{"cookie": "sid", "issue": "Missing Secure"}])
    clean = BlueScanner._serialize_result(result)
    assert "secret" not in json.dumps(clean)
    assert "Missing Secure" in json.dumps(clean)
    assert result.headers["set-cookie-list"] == ["sid=secret"]


def test_jsonl_audit_redacts_structured_secrets(tmp_path):
    try:
        audit.setup_logging(tmp_path)
        audit.audit_event("test", api_key="secret123", url="https://example.test/?token=secret456")
    finally:
        audit.close_audit_log()
    text = (tmp_path / audit.LOG_FILE_JSONL).read_text(encoding="utf-8")
    assert "secret123" not in text and "secret456" not in text
    assert json.loads(text)["event"] == "test"
