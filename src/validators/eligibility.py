from __future__ import annotations

from datetime import date, datetime
from typing import Any

MIN_WORD_COUNT = 1_000_000
MAX_STALE_DAYS = 14
BLOCKING_FLAGS = {
    "excessive_ads",
    "malicious_redirect",
    "forced_download",
    "content_obscured",
    "high_security_risk",
}


def validate_novel(record: dict[str, Any], today: date | None = None) -> list[str]:
    """Return blocking reasons. An empty list means the record is eligible."""
    today = today or date.today()
    reasons: list[str] = []

    if int(record.get("word_count", 0)) < MIN_WORD_COUNT:
        reasons.append("word_count_below_1m")

    if record.get("status") == "ongoing":
        raw = record.get("last_update")
        if not raw:
            reasons.append("missing_last_update")
        else:
            updated = datetime.fromisoformat(str(raw)).date()
            if (today - updated).days > MAX_STALE_DAYS:
                reasons.append("ongoing_update_older_than_14_days")

    flags = set(record.get("site_flags", []))
    reasons.extend(sorted(flags & BLOCKING_FLAGS))

    if not str(record.get("summary", "")).strip():
        reasons.append("missing_summary")
    if not str(record.get("reading_url", "")).strip():
        reasons.append("missing_reading_url")

    return reasons
