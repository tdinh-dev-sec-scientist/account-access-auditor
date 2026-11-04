from __future__ import annotations

from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from phase3.quotas import QuotaError, consume_quota, lambda_handler


@mock_aws
def test_quota_allows_ten_questions_per_session_and_blocks_the_eleventh():
    table = _table()
    now = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)

    decisions = [
        consume_quota(table, "session-token-with-high-entropy-123456", 100, now=now) for _ in range(11)
    ]

    assert [item["allowed"] for item in decisions] == [True] * 10 + [False]
    assert decisions[-1]["reason"] == "SESSION_LIMIT"
    assert "session-token" not in repr(table.scan().get("Items", []))


@mock_aws
def test_quota_enforces_global_daily_cap_across_sessions_and_utc_day_boundary():
    table = _table()
    now = datetime(2026, 11, 3, 23, 59, tzinfo=UTC)

    assert consume_quota(table, "session-a-high-entropy-1234567890", 2, now=now)["allowed"]
    assert consume_quota(table, "session-b-high-entropy-1234567890", 2, now=now)["allowed"]
    blocked = consume_quota(table, "session-c-high-entropy-1234567890", 2, now=now)
    next_day = consume_quota(
        table,
        "session-c-high-entropy-1234567890",
        2,
        now=datetime(2026, 11, 4, 0, 1, tzinfo=UTC),
    )

    assert blocked == {"allowed": False, "reason": "DAILY_LIMIT"}
    assert next_day["allowed"] is True


@mock_aws
def test_quota_fails_closed_for_invalid_sessions_and_missing_daily_cap():
    table = _table()
    with pytest.raises(QuotaError, match="session token is invalid"):
        consume_quota(table, "short", 10)
    with pytest.raises(QuotaError, match="daily cap must be positive"):
        consume_quota(table, "session-token-with-high-entropy-123456", 0)


@mock_aws
def test_quota_lambda_emits_only_safe_daily_cap_metric_when_provider_is_blocked(monkeypatch, capsys):
    _table()
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PHASE3_RIN_QUOTA_TABLE", "phase3-rin-quotas")
    monkeypatch.setenv("PHASE3_RIN_DAILY_CAP", "1")
    lambda_handler({"session_token": "session-token-with-high-entropy-123456"}, object())
    result = lambda_handler({"session_token": "other-session-with-high-entropy-123456"}, object())
    output = capsys.readouterr().out

    assert result == {"allowed": False, "reason": "DAILY_LIMIT"}
    assert '"DailyLimitReached":1' in output
    assert "other-session-with-high-entropy-123456" not in output
    assert "question" not in output


@mock_aws
def test_quota_lambda_requires_only_session_token_and_configured_table(monkeypatch):
    _table()
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PHASE3_RIN_QUOTA_TABLE", "phase3-rin-quotas")
    monkeypatch.setenv("PHASE3_RIN_DAILY_CAP", "25")
    result = lambda_handler({"session_token": "session-token-with-high-entropy-123456"}, object())

    assert result == {"allowed": True, "reason": "OK"}
    with pytest.raises(QuotaError, match="quota event is invalid"):
        lambda_handler({"session_token": "anything", "question": "should-not-be-sent"}, object())


def _table():
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    return dynamodb.create_table(
        TableName="phase3-rin-quotas",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
