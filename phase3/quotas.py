"""Atomic per-browser and global daily invocation limits for Rin."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

SESSION_QUESTION_LIMIT = 10
_SESSION_TOKEN = re.compile(r"^[A-Za-z0-9_-]{22,128}$")


class QuotaError(ValueError):
    """A quota check failed closed."""


def consume_quota(
    table: Any,
    session_token: Any,
    daily_cap: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(session_token, str) or not _SESSION_TOKEN.fullmatch(session_token):
        raise QuotaError("Rin session token is invalid")
    if not isinstance(daily_cap, int) or isinstance(daily_cap, bool) or daily_cap <= 0:
        raise QuotaError("Rin daily cap must be positive")
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise QuotaError("quota clock must include a timezone")
    current = current.astimezone(UTC)
    day = current.date().isoformat()
    expiry = int((datetime.combine(current.date() + timedelta(days=3), datetime.min.time(), UTC)).timestamp())
    session_digest = hashlib.sha256(session_token.encode("ascii")).hexdigest()
    try:
        session_allowed = _increment(
            table,
            partition=f"SESSION#{session_digest}",
            sort_key=f"DAY#{day}",
            limit=SESSION_QUESTION_LIMIT,
            expiry=expiry,
        )
        if not session_allowed:
            return {"allowed": False, "reason": "SESSION_LIMIT"}
        daily_allowed = _increment(
            table,
            partition="GLOBAL",
            sort_key=f"DAY#{day}",
            limit=daily_cap,
            expiry=expiry,
        )
    except QuotaError:
        raise
    except Exception:
        raise QuotaError("Rin quota service is unavailable") from None
    if not daily_allowed:
        return {"allowed": False, "reason": "DAILY_LIMIT"}
    return {"allowed": True, "reason": "OK"}


def _increment(table: Any, *, partition: str, sort_key: str, limit: int, expiry: int) -> bool:
    try:
        table.update_item(
            Key={"pk": partition, "sk": sort_key},
            UpdateExpression="SET #count = if_not_exists(#count, :zero) + :one, expires_at = :expiry",
            ConditionExpression="attribute_not_exists(#count) OR #count < :limit",
            ExpressionAttributeNames={"#count": "count"},
            ExpressionAttributeValues={
                ":zero": 0,
                ":one": 1,
                ":limit": limit,
                ":expiry": expiry,
            },
        )
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise QuotaError("Rin quota service is unavailable") from None
    except (BotoCoreError, KeyError, TypeError, ValueError):
        raise QuotaError("Rin quota service is unavailable") from None


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    """Quota-writer Lambda. It receives no question text and logs no session ID."""
    del context
    if not isinstance(event, dict) or set(event) != {"session_token"}:
        raise QuotaError("Rin quota event is invalid")
    table_name = os.environ.get("PHASE3_RIN_QUOTA_TABLE", "").strip()
    raw_daily_cap = os.environ.get("PHASE3_RIN_DAILY_CAP", "")
    region = os.environ.get("AWS_REGION", "").strip()
    if not table_name or not raw_daily_cap.isascii() or not raw_daily_cap.isdigit() or not region:
        raise QuotaError("Rin quota service is not configured")
    try:
        table = boto3.session.Session(region_name=region).resource("dynamodb").Table(table_name)
        result = consume_quota(table, event["session_token"], int(raw_daily_cap))
        if result.get("reason") == "DAILY_LIMIT":
            _emit_daily_limit_metric()
        return result
    except QuotaError:
        raise
    except Exception:
        raise QuotaError("Rin quota service is unavailable") from None


def _emit_daily_limit_metric() -> None:
    """Emit aggregate-only EMF for a denied provider request; never include the session token."""
    record = {
        "_aws": {
            "Timestamp": int(time.time() * 1000),
            "CloudWatchMetrics": [
                {
                    "Namespace": "Phase3/Rin",
                    "Dimensions": [["Service"]],
                    "Metrics": [{"Name": "DailyLimitReached", "Unit": "Count"}],
                }
            ],
        },
        "Service": "Rin",
        "DailyLimitReached": 1,
    }
    print(json.dumps(record, separators=(",", ":")))
