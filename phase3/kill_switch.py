"""Disable live Phase 3 features after the isolated 100% budget alert."""

from __future__ import annotations

import os
from typing import Any

import boto3


class KillSwitchError(ValueError):
    """A budget event or kill-switch write was invalid or unavailable."""


def disable_live_features(event: Any, *, table: Any, expected_topic_arn: str) -> dict[str, str]:
    """Atomically disable Rin and put the console into static-fixture mode."""
    records = event.get("Records") if isinstance(event, dict) else None
    if (
        not isinstance(records, list)
        or len(records) != 1
        or not isinstance(records[0], dict)
        or records[0].get("EventSource") != "aws:sns"
    ):
        raise KillSwitchError("budget event is invalid")
    sns = records[0].get("Sns")
    if (
        not isinstance(sns, dict)
        or sns.get("Type") != "Notification"
        or sns.get("TopicArn") != expected_topic_arn
        or not isinstance(sns.get("Message"), str)
        or len(sns["Message"]) > 262_144
    ):
        raise KillSwitchError("budget event is invalid")

    try:
        table.update_item(
            Key={"pk": "PLATFORM", "sk": "CONFIG"},
            UpdateExpression="SET rin_enabled = :disabled, static_mode = :enabled",
            ConditionExpression="attribute_exists(pk) AND attribute_exists(sk)",
            ExpressionAttributeValues={":disabled": False, ":enabled": True},
        )
    except Exception:
        raise KillSwitchError("live features could not be disabled") from None
    return {"status": "DISABLED"}


def lambda_handler(event: Any, context: Any) -> dict[str, str]:
    """SNS-triggered budget kill switch; never logs or returns the event body."""
    del context
    topic_arn = os.environ.get("PHASE3_BUDGET_KILL_TOPIC_ARN", "").strip()
    table_name = os.environ.get("PHASE3_FEATURE_TABLE", "").strip()
    region = os.environ.get("AWS_REGION", "").strip()
    if not topic_arn or not table_name or not region:
        raise KillSwitchError("kill switch is not configured")
    try:
        table = boto3.session.Session(region_name=region).resource("dynamodb").Table(table_name)
    except Exception:
        raise KillSwitchError("live features could not be disabled") from None
    return disable_live_features(event, table=table, expected_topic_arn=topic_arn)
