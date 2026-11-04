from __future__ import annotations

from datetime import UTC, datetime

import boto3
import pytest
from botocore.exceptions import ClientError
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


class _FailingTable:
    def __init__(self, error):
        self.error = error

    def update_item(self, **_kwargs):
        raise self.error


SESSION = "session-token-with-high-entropy-123456"


def test_quota_requires_a_timezone_aware_clock():
    with pytest.raises(QuotaError, match="must include a timezone"):
        consume_quota(_FailingTable(RuntimeError()), SESSION, 5, now=datetime(2026, 11, 3, 12, 0))


@pytest.mark.parametrize(
    "error",
    [
        ClientError(
            {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "x"}}, "UpdateItem"
        ),
        ValueError("bad value"),
        RuntimeError("unexpected"),
    ],
)
def test_quota_fails_closed_when_the_counter_table_is_unavailable(error):
    with pytest.raises(QuotaError, match="quota service is unavailable"):
        consume_quota(_FailingTable(error), SESSION, 5, now=datetime(2026, 11, 3, 12, 0, tzinfo=UTC))


def test_quota_lambda_rejects_unexpected_events():
    with pytest.raises(QuotaError, match="event is invalid"):
        lambda_handler({"session_token": SESSION, "question": "leak"}, None)


def test_quota_lambda_hides_session_construction_failures(monkeypatch):
    monkeypatch.setenv("PHASE3_RIN_QUOTA_TABLE", "phase3-rin-quota")
    monkeypatch.setenv("PHASE3_RIN_DAILY_CAP", "5")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    def broken_session(**_kwargs):
        raise RuntimeError("credential detail")

    monkeypatch.setattr("phase3.quotas.boto3.session.Session", broken_session)

    with pytest.raises(QuotaError, match="quota service is unavailable") as raised:
        lambda_handler({"session_token": SESSION}, None)
    assert "credential detail" not in str(raised.value)
