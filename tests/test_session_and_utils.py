"""Session construction, credential errors, date helpers, and logging setup."""

from __future__ import annotations

import datetime as dt
import logging

import boto3
import pytest
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

from auditor.aws_session import SessionError, build_session, describe_caller
from auditor.permissions import ReadOnlyViolation
from auditor.rules import engine
from auditor.utils.dates import age_in_days, isoformat
from auditor.utils.logging import setup_logging

NOW = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


# ------------------------------------------------------------- session ----


def test_sessions_carry_the_read_only_guard_by_default():
    session, guard = build_session(region="us-east-1")
    assert guard is not None and guard.call_count == 0


def test_the_guard_can_be_omitted_for_a_caller_that_does_not_want_counting():
    _, guard = build_session(region="us-east-1", guard=False)
    assert guard is None


def test_every_client_inherits_the_retry_configuration():
    """Throttling retries must not depend on each collector remembering to ask."""
    session, _ = build_session(region="us-east-1")
    client = session.client("iam")
    assert client.meta.config.retries["mode"] == "standard"
    # botocore normalises max_attempts into total_max_attempts (retries + 1).
    assert client.meta.config.retries["total_max_attempts"] == 6
    assert "account-access-auditor" in client.meta.config.user_agent_extra


def test_an_unknown_profile_is_reported_with_where_to_look(monkeypatch):
    def explode(**kwargs):
        raise ProfileNotFound(profile="nope")

    monkeypatch.setattr(boto3.session, "Session", explode)
    with pytest.raises(SessionError, match="~/.aws/config"):
        build_session(profile="nope")


class FakeSTS:
    def __init__(self, error=None, identity=None):
        self._error = error
        self._identity = identity or {}

    def get_caller_identity(self):
        if self._error:
            raise self._error
        return self._identity


class FakeSession:
    def __init__(self, sts):
        self._sts = sts
        self.region_name = "us-east-1"

    def client(self, name, **kwargs):
        return self._sts


def test_describe_caller_returns_the_account_and_arn():
    session = FakeSession(
        FakeSTS(identity={"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/auditor"})
    )
    assert describe_caller(session) == ("123456789012", "arn:aws:iam::123456789012:user/auditor")


@pytest.mark.parametrize(
    "error,expected",
    [
        (NoCredentialsError(), "aws configure"),
        (PartialCredentialsError(provider="env", cred_var="secret"), "Incomplete AWS credentials"),
        (EndpointConnectionError(endpoint_url="https://sts"), "network connectivity"),
    ],
)
def test_credential_problems_produce_an_actionable_message(error, expected):
    with pytest.raises(SessionError, match=expected):
        describe_caller(FakeSession(FakeSTS(error=error)))


@pytest.mark.parametrize(
    "code,hint",
    [
        ("InvalidClientTokenId", "not valid for this partition"),
        ("SignatureDoesNotMatch", "does not match"),
        ("ExpiredToken", "expired"),
        ("AccessDenied", "not allowed to call"),
        ("SomethingElse", "GetCallerIdentity failed"),
    ],
)
def test_sts_client_errors_are_translated_into_a_hint(code, hint):
    error = ClientError({"Error": {"Code": code, "Message": code}}, "GetCallerIdentity")
    with pytest.raises(SessionError, match=hint):
        describe_caller(FakeSession(FakeSTS(error=error)))


@pytest.mark.usefixtures("aws")
def test_a_guarded_session_blocks_a_write_before_it_reaches_aws():
    session, guard = build_session(region="us-east-1")
    iam = session.client("iam")
    iam.list_users()  # allowed
    with pytest.raises(ReadOnlyViolation, match="iam:CreateUser"):
        iam.create_user(UserName="should-never-exist")
    # The blocked call never created anything.
    assert boto3.session.Session(region_name="us-east-1").client("iam").list_users()["Users"] == []


@pytest.mark.usefixtures("aws")
def test_the_guard_counts_the_api_calls_a_scan_makes():
    session, guard = build_session(region="us-east-1")
    session.client("s3").list_buckets()
    session.client("cloudtrail").describe_trails()
    assert guard.counts_by_operation() == {"cloudtrail:DescribeTrails": 1, "s3:ListBuckets": 1}
    assert guard.call_count == 2


@pytest.mark.usefixtures("aws")
def test_uninstalling_the_guard_stops_it_counting():
    from auditor.readonly import uninstall_read_only_guard

    session, guard = build_session(region="us-east-1")
    uninstall_read_only_guard(session)
    session.client("s3").list_buckets()
    assert guard.call_count == 0


# --------------------------------------------------------------- engine ---


def test_evaluate_all_runs_every_service_present():
    from tests.builders import bucket, cloudtrail_state, iam_state, iam_user, s3_state

    findings = engine.evaluate_all(
        {
            "iam": iam_state(users=[iam_user("a", console_access=True, mfa_devices=0)]),
            "s3": s3_state(bucket("b", encryption_configured=False)),
            "cloudtrail": cloudtrail_state(),
        },
        {},
        run_id="all",
    )
    assert {f.rule_id for f in findings} == {"IAM-001", "S3-004", "CT-001"}
    assert all(f.run_id == "all" for f in findings)


def test_evaluate_all_on_nothing_returns_nothing():
    assert engine.evaluate_all({}, {}) == []


# ---------------------------------------------------------------- dates ---


def test_age_in_days_handles_naive_and_aware_datetimes():
    assert age_in_days(dt.datetime(2025, 1, 1, tzinfo=dt.UTC), NOW) == 365
    assert age_in_days(dt.datetime(2025, 1, 1), NOW) == 365  # naive treated as UTC


def test_age_of_an_unknown_date_is_unknown_not_zero():
    assert age_in_days(None, NOW) is None


def test_age_defaults_to_now_when_no_reference_is_given():
    recent = dt.datetime.now(dt.UTC) - dt.timedelta(days=3)
    assert age_in_days(recent) == 3


def test_isoformat_normalises_to_utc_and_second_precision():
    assert isoformat(dt.datetime(2026, 1, 1, 12, 30, 45, 123456)) == "2026-01-01T12:30:45+00:00"
    assert isoformat(None) is None


# -------------------------------------------------------------- logging ---


@pytest.mark.parametrize(
    "verbose,quiet,expected",
    [
        (False, False, logging.INFO),
        (True, False, logging.DEBUG),
        (False, True, logging.ERROR),
    ],
)
def test_log_level_follows_the_verbosity_flags(verbose, quiet, expected):
    """Also pins force=True: pytest configures logging first, so a plain
    basicConfig would silently do nothing here -- and equally inside any host
    application that has already set logging up."""
    original = logging.getLogger().level
    try:
        setup_logging(verbose=verbose, quiet=quiet)
        assert logging.getLogger().level == expected
    finally:
        logging.getLogger().setLevel(original)


def test_botocore_chatter_is_suppressed():
    setup_logging()
    assert logging.getLogger("botocore").level == logging.WARNING
    assert logging.getLogger("boto3").level == logging.WARNING
