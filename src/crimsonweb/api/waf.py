"""Defense evidence adapters; imported events never schedule or resume network scans."""

import json
from datetime import UTC, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import BaseModel, Field, ValidationError, field_validator

from .models import WAFEvent, WAFImport


def retry_after(value: str | None, now: datetime) -> tuple[int | None, bool | None]:
    if value is None:
        return None, None
    value = value.strip()
    if value.isascii() and value.isdigit() and len(value) <= 10:
        return int(value), True
    try:
        date = parsedate_to_datetime(value)
        if date.tzinfo is None:
            return None, False
        return max(0, int((date - now).total_seconds())), True
    except (ValueError, TypeError, OverflowError):
        return None, False


def http_event(scan_id: str, status: int, value: str | None) -> WAFEvent:
    now = datetime.now(UTC)
    seconds, valid = retry_after(value, now)
    return WAFEvent(
        scan_id=scan_id,
        timestamp=now,
        source="http",
        status_code=status,
        event_type="rate_limited" if status == 429 else "access_denied",
        retry_after_seconds=seconds,
        retry_after_valid=valid,
        evidence=f"HTTP {status}; Retry-After parsed={valid}; delay_seconds={seconds}. "
        "No retry was made. WAF/IP attribution requires defense logs.",
    )


class NormalizedRecord(BaseModel):
    timestamp: datetime
    event_type: Literal[
        "access_denied", "rate_limited", "rule_match", "waf_block", "ip_block"
    ]
    status_code: int | None = Field(default=None, ge=100, le=599)
    rule_id: str | None = Field(
        default=None, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$"
    )
    request_id: str | None = Field(default=None, max_length=128)

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Timestamp must have a timezone")
        return value.astimezone(UTC)


def _modsecurity(record: dict, offset: int | None) -> list[NormalizedRecord]:
    transaction = record["transaction"]
    if not isinstance(transaction, dict):
        raise TypeError("Invalid transaction")
    timestamp = transaction.get("time_stamp") or transaction.get("timestamp")
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp)
        except ValueError:
            for pattern in ("%a %b %d %H:%M:%S.%f %Y", "%a %b %d %H:%M:%S %Y"):
                try:
                    timestamp = datetime.strptime(timestamp, pattern)  # noqa: DTZ007 -- Offset is explicit below; otherwise validation rejects.
                    break
                except ValueError:
                    continue
        if (
            isinstance(timestamp, datetime)
            and timestamp.tzinfo is None
            and offset is not None
        ):
            timestamp = timestamp.replace(tzinfo=timezone(timedelta(minutes=offset)))
    request_id = transaction.get("unique_id")
    status = transaction.get("response", {}).get("http_code")
    messages = transaction.get("messages", record.get("messages", []))
    if not isinstance(messages, list) or not messages:
        raise ValueError("No rule messages found")
    result = []
    for message in messages:
        rule_id = message.get("details", {}).get("ruleId")
        if rule_id is None:
            raise ValueError("Rule id required")
        # 403 alone cannot tell whether a rule was disruptive. Preserve only observed association.
        result.append(
            NormalizedRecord(
                timestamp=timestamp,
                status_code=status,
                request_id=request_id,
                rule_id=str(rule_id),
                event_type="waf_block"
                if transaction.get("intervention", {}).get("disruptive") is True
                else "rule_match",
            )
        )
    return result


def parse_logs(payload: WAFImport) -> list[WAFEvent]:
    try:
        try:
            document = json.loads(payload.content)
            records = document if isinstance(document, list) else [document]
        except json.JSONDecodeError:
            records = [
                json.loads(line)
                for line in payload.content.splitlines()
                if line.strip()
            ]
        if not records or len(records) > 1000:
            raise ValueError("Expected 1 to 1000 records")
        normalized = []
        for record in records:
            if not isinstance(record, dict):
                raise TypeError("Records must be JSON objects")
            normalized.extend(
                _modsecurity(record, payload.timezone_offset_minutes)
                if payload.format == "modsecurity_json"
                else [NormalizedRecord.model_validate(record)]
            )
        if len(normalized) > 1000:
            raise ValueError("Maximum 1000 events per import")
        result = []
        for item in normalized:
            candidate = payload.expected_benign and item.event_type in {
                "access_denied",
                "rate_limited",
                "waf_block",
                "ip_block",
                "rule_match",
            }
            event = WAFEvent(
                scan_id=payload.scan_id,
                source=payload.format,
                **item.model_dump(),
                evidence=f"Imported defense record: type={item.event_type}; "
                f"rule_id={item.rule_id}; HTTP status={item.status_code}.",
                assessment="candidate_false_positive" if candidate else "undetermined",
                assessment_reason=(
                    "Operator labels this test benign; rule context and "
                    "analyst review are required."
                    if candidate
                    else "No ground truth supplied; no false-positive verdict."
                ),
            )
            identity = {
                "source": event.source,
                "scan_id": event.scan_id,
                **item.model_dump(mode="json"),
            }
            event.id = str(uuid5(NAMESPACE_URL, json.dumps(identity, sort_keys=True)))
            result.append(event)
        return result
    except (
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        RecursionError,
        ValidationError,
    ) as exc:
        raise ValueError(
            "Invalid log format, rule id or timezone-aware timestamp"
        ) from exc
