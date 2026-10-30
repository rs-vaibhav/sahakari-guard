"""Time helpers.

India Standard Time has no daylight saving, so a fixed +05:30 offset is used
instead of ``zoneinfo`` (which needs the extra ``tzdata`` package on Windows).
All timestamps inside the engine are timezone-aware.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30), "IST")


def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. Naive timestamps are treated as IST."""
    if value is None:
        raise ValueError("timestamp is missing")
    text = str(value).strip()
    if not text:
        raise ValueError("timestamp is empty")
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid timestamp {value!r}; expected ISO-8601 like 2026-11-01T10:15:00+05:30") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=IST)
    return parsed


def to_ist(dt: datetime) -> datetime:
    return dt.astimezone(IST)


def iso(dt: datetime | None) -> str | None:
    """ISO-8601 string in IST with second precision (None-safe)."""
    if dt is None:
        return None
    return to_ist(dt).isoformat(timespec="seconds")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def fmt_ist(dt: datetime | None) -> str:
    """Human readable IST time, e.g. ``01 Nov 2026, 02:14:05 IST``."""
    if dt is None:
        return "-"
    return to_ist(dt).strftime("%d %b %Y, %H:%M:%S IST")


def fmt_duration(seconds: float | None) -> str:
    """Compact duration such as ``2m 05s`` or ``5h 12m``."""
    if seconds is None:
        return "-"
    seconds = int(round(seconds))
    sign = "-" if seconds < 0 else ""
    seconds = abs(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{sign}{days}d {hours}h"
    if hours:
        return f"{sign}{hours}h {minutes:02d}m"
    if minutes:
        return f"{sign}{minutes}m {secs:02d}s"
    return f"{sign}{secs}s"
