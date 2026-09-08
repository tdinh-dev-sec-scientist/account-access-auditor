"""Date helpers. AWS returns timezone-aware datetimes; normalize defensively."""

from __future__ import annotations

from datetime import UTC, datetime


def _ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def age_in_days(value: datetime | None, now: datetime | None = None) -> int | None:
    """Return the age of a datetime in whole days, or None if unknown."""
    if value is None:
        return None
    now = _ensure_aware(now or datetime.now(UTC))
    return (now - _ensure_aware(value)).days


def isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _ensure_aware(value).isoformat(timespec="seconds")
