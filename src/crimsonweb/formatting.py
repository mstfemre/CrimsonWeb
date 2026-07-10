"""Shared formatting helpers for scanner evidence."""

from __future__ import annotations

import re


MIN_PRINTABLE_RATIO = 0.7


def format_banner_bytes(data: bytes, max_text: int = 120, max_hex: int = 40) -> str:
    if not data:
        return "open, no banner"
    printable = bytes(b for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = len(printable) / max(len(data), 1)
    if ratio >= MIN_PRINTABLE_RATIO:
        text = data.decode("utf-8", errors="ignore").strip()
        text = re.sub(r"\s+", " ", text)
        if len(text) > max_text:
            text = text[: max_text - 3] + "..."
        return text or "open, no banner"
    hex_repr = data[:max_hex].hex()
    return f"<Binary Data: {hex_repr}>"
