import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from crimsonweb.api.models import WAFImport
from crimsonweb.api.waf import parse_logs, retry_after


@pytest.mark.parametrize(
    "value,seconds,valid",
    [
        (None, None, None),
        ("120", 120, True),
        ("Thu, 08 Oct 2026 09:02:00 GMT", 120, True),
        ("Thu, 08 Oct 2026 08:00:00 GMT", 0, True),
        ("-1", None, False),
        ("oops", None, False),
    ],
)
def test_retry_after(value, seconds, valid):
    assert retry_after(value, datetime(2026, 10, 8, 9, tzinfo=UTC)) == (seconds, valid)


def test_modsecurity_rule_timestamp_and_no_sensitive_payload():
    content = (Path(__file__).parent / "fixtures/modsecurity_lab.json").read_text()
    events = parse_logs(
        WAFImport(format="modsecurity_json", content=content, expected_benign=True)
    )
    assert events[0].rule_id == "949110" and events[0].timestamp.hour == 6
    assert (
        events[0].event_type == "rule_match"
    )  # 403 does not prove WAF caused the block.
    assert events[0].assessment == "candidate_false_positive"
    assert (
        "secret" not in events[0].model_dump_json()
        and "private payload" not in events[0].model_dump_json()
    )
    assert (
        parse_logs(WAFImport(format="modsecurity_json", content=content))[0].id
        == events[0].id
    )


def test_modsecurity_naive_time_requires_explicit_offset_and_disruption():
    record = {
        "transaction": {
            "time_stamp": "Thu Oct 08 09:00:00.000000 2026",
            "intervention": {"disruptive": True},
            "response": {"http_code": 403},
            "messages": [{"details": {"ruleId": "949110"}}],
        }
    }
    with pytest.raises(ValueError):
        parse_logs(WAFImport(format="modsecurity_json", content=json.dumps(record)))
    result = parse_logs(
        WAFImport(
            format="modsecurity_json",
            content=json.dumps(record),
            timezone_offset_minutes=180,
        )
    )
    assert result[0].timestamp.hour == 6 and result[0].event_type == "waf_block"


def test_normalized_ndjson_and_no_ground_truth_verdict():
    record = {
        "timestamp": "2026-10-08T09:00:00Z",
        "event_type": "ip_block",
        "rule_id": "lab-rule",
    }
    record2 = {**record, "rule_id": "lab-rule-2"}
    items = parse_logs(
        WAFImport(
            format="normalized_json",
            content=json.dumps(record) + "\n" + json.dumps(record2),
        )
    )
    assert len(items) == 2 and all(e.assessment == "undetermined" for e in items)


@pytest.mark.parametrize(
    "content",
    [
        "not-json",
        "[]",
        "{}",
        "[null]",
        '{"timestamp":"2026-10-08T09:00:00","event_type":"ip_block"}',
        '{"timestamp":"2026-10-08T09:00:00Z","event_type":"unknown"}',
    ],
)
def test_invalid_logs_rejected_atomically(content):
    with pytest.raises(ValueError):
        parse_logs(WAFImport(format="normalized_json", content=content))
