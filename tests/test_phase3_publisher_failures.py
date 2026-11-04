"""Failure handling of the Phase 3 publisher: every bad input fails closed."""

from __future__ import annotations

import base64
import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from phase3 import publisher
from phase3.publisher import (
    PublicationError,
    S3DynamoPublicStore,
    lambda_handler,
    publish_private_snapshot,
    publish_snapshot,
)
from phase3.redaction import redact_snapshot
from tests.test_phase3_publisher import KEY, MemoryStore, _report

BUCKET = "phase3-public-results"
ACCOUNT = "123456789012"
SOURCE_KEY = f"snapshots/{ACCOUNT}/2026/11/01/run-1.json"
ENV = {
    "PHASE3_TARGET_ACCOUNT_ID": ACCOUNT,
    "AWS_REGION": "us-east-1",
    "PHASE3_PRIVATE_SNAPSHOT_BUCKET": "private-demo",
    "PHASE3_PSEUDONYM_SECRET_ARN": f"arn:aws:secretsmanager:us-east-1:{ACCOUNT}:secret:p3-hmac",
}
RECEIPT = {
    "run_id": "run-1",
    "status": "PASS",
    "finding_count": 1,
    "snapshot_key": SOURCE_KEY,
    "drift_counts": {},
}


def _public(run_id="run-1", completed_at="2026-11-01T00:00:00+00:00", **kwargs):
    return redact_snapshot(_report(run_id, completed_at, **kwargs), KEY)


def _table():
    return boto3.resource("dynamodb", region_name="us-east-1").create_table(
        TableName="phase3-public-index",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _aws_store():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    table = _table()
    return S3DynamoPublicStore(bucket_name=BUCKET, table=table, s3_client=s3), s3, table


class Body:
    def __init__(self, data: bytes):
        self.data = data

    def read(self, _size):
        return self.data


class S3:
    def __init__(self, body: bytes = b"", error: Exception | None = None):
        self.body = body
        self.error = error

    def get_object(self, **_kwargs):
        if self.error:
            raise self.error
        return {"Body": Body(self.body)}


class Secrets:
    def __init__(self, response):
        self.response = response

    def get_secret_value(self, **_kwargs):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Operation")


def _private(body: bytes, secret=None, **env):
    secret = {"SecretString": base64.b64encode(KEY).decode()} if secret is None else secret
    return publish_private_snapshot(
        RECEIPT,
        {**ENV, **env},
        s3_client=S3(body),
        secrets_client=Secrets(secret),
        public_store=MemoryStore(),
    )


# ------------------------------------------------------------ publish_snapshot --


def test_invalid_public_snapshots_are_rejected_before_any_write():
    store = MemoryStore()

    with pytest.raises(PublicationError):
        publish_snapshot({"not": "a snapshot"}, store)
    assert store.snapshots == [] and store.attempts == []


class BrokenStore(MemoryStore):
    def __init__(self, error: Exception):
        super().__init__()
        self.error = error

    def publish(self, snapshot):
        raise self.error

    def record_attempt(self, *args, **kwargs):
        raise self.error


def test_store_errors_are_wrapped_without_leaking_details():
    with pytest.raises(PublicationError, match="could not be published") as raised:
        publish_snapshot(_public(), BrokenStore(RuntimeError("arn:aws:s3:::private-bucket")))

    assert "private-bucket" not in str(raised.value)


def test_publication_errors_from_the_store_pass_through():
    with pytest.raises(PublicationError, match="already contains different data"):
        publish_snapshot(
            _public(), BrokenStore(PublicationError("public snapshot key already contains different data"))
        )


def test_incomplete_scans_report_attempt_recording_failures():
    with pytest.raises(PublicationError, match="attempt status could not be recorded"):
        publish_snapshot(_public(complete=False), BrokenStore(RuntimeError("down")))


def test_an_older_snapshot_is_reported_as_stale():
    class StaleStore(MemoryStore):
        def publish(self, snapshot):
            return False

    result = publish_snapshot(_public(), StaleStore())

    assert result["status"] == "STALE_IGNORED"


# ------------------------------------------------------- S3DynamoPublicStore --


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"bucket_name": " "}, "bucket is invalid"),
        ({"bucket_name": BUCKET, "partition": ""}, "partition is invalid"),
        ({"bucket_name": BUCKET, "partition": "p" * 33}, "partition is invalid"),
    ],
)
def test_store_rejects_invalid_configuration(kwargs, message):
    with pytest.raises(PublicationError, match=message):
        S3DynamoPublicStore(table=None, s3_client=None, **kwargs)


@pytest.mark.parametrize(
    ("args", "kwargs", "message"),
    [
        (("DONE", "2026-11-01T00:00:00+00:00"), {}, "scan attempt status is invalid"),
        (
            ("PASS", "2026-11-01T00:00:00+00:00"),
            {"publication_status": "LIVE"},
            "publication status is invalid",
        ),
        (("ERROR", "2026-11-01T00:00:00+00:00"), {"affected_services": "s3"}, "affected service status"),
        (
            ("ERROR", "2026-11-01T00:00:00+00:00"),
            {"affected_services": [{"service": "ec2", "status": "ERROR"}]},
            "affected service status",
        ),
        (
            ("PASS", "2026-11-01T00:00:00+00:00"),
            {"affected_services": [{"service": "s3", "status": "ERROR"}]},
            "affected service status",
        ),
    ],
)
def test_record_attempt_rejects_invalid_status_values(args, kwargs, message):
    store = S3DynamoPublicStore(bucket_name=BUCKET, table=None, s3_client=None)

    with pytest.raises(PublicationError, match=message):
        store.record_attempt(*args, **kwargs)


def test_publish_rejects_non_json_and_oversized_snapshots(monkeypatch):
    store = S3DynamoPublicStore(bucket_name=BUCKET, table=None, s3_client=None)
    snapshot = _public()

    with pytest.raises(PublicationError, match="not valid JSON"):
        store.publish({**snapshot, "bad": float("nan")})
    monkeypatch.setattr(publisher, "MAX_PUBLIC_SNAPSHOT_BYTES", 10)
    with pytest.raises(PublicationError, match="exceeds the public size limit"):
        store.publish(snapshot)


@mock_aws
def test_republishing_the_same_snapshot_is_idempotent():
    store, _s3, table = _aws_store()
    snapshot = _public()

    assert store.publish(snapshot) is True
    assert store.publish(snapshot) is True
    assert (
        table.get_item(Key={"pk": "demo", "sk": "LATEST"})["Item"]["snapshot_id"] == snapshot["snapshot_id"]
    )


@mock_aws
def test_an_older_snapshot_never_moves_the_latest_pointer():
    store, _s3, table = _aws_store()
    newer = _public("run-2", "2026-11-02T00:00:00+00:00")
    older = _public("run-1", "2026-11-01T00:00:00+00:00")

    assert store.publish(newer) is True
    assert store.publish(older) is False
    assert table.get_item(Key={"pk": "demo", "sk": "LATEST"})["Item"]["snapshot_id"] == newer["snapshot_id"]


@mock_aws
def test_an_immutable_snapshot_key_cannot_be_overwritten_with_different_data():
    store, s3, _table = _aws_store()
    snapshot = _public()
    s3.put_object(Bucket=BUCKET, Key=f"snapshots/{snapshot['snapshot_id']}.json", Body=b"{}")

    with pytest.raises(PublicationError, match="already contains different data"):
        store.publish(snapshot)


@mock_aws
def test_a_run_index_key_cannot_point_to_a_different_snapshot():
    store, _s3, table = _aws_store()
    snapshot = _public()
    table.put_item(
        Item={
            "pk": "demo",
            "sk": f"RUN#{snapshot['scan']['completed_at']}#{snapshot['snapshot_id']}",
            "snapshot_id": "f" * 24,
        }
    )

    with pytest.raises(PublicationError, match="run index key already contains different data"):
        store.publish(snapshot)


def test_s3_write_failures_fail_closed():
    class FailingS3:
        def put_object(self, **_kwargs):
            raise _client_error("AccessDenied")

    store = S3DynamoPublicStore(bucket_name=BUCKET, table=None, s3_client=FailingS3())

    with pytest.raises(PublicationError, match="could not be written"):
        store.publish(_public())


def test_pointer_and_attempt_write_failures_fail_closed():
    class FailingTable:
        def put_item(self, **_kwargs):
            return {}

        def update_item(self, **_kwargs):
            raise _client_error("ProvisionedThroughputExceededException")

        def get_item(self, **_kwargs):
            raise _client_error("AccessDenied")

    class OkS3:
        def put_object(self, **_kwargs):
            return {}

    store = S3DynamoPublicStore(bucket_name=BUCKET, table=FailingTable(), s3_client=OkS3())

    with pytest.raises(PublicationError, match="latest pointer could not be updated"):
        store.publish(_public())
    with pytest.raises(PublicationError, match="attempt status could not be recorded"):
        store.record_attempt("PASS", "2026-11-01T00:00:00+00:00")


# --------------------------------------------------- publish_private_snapshot --


def test_private_receipts_must_match_the_schema():
    with pytest.raises(PublicationError, match="receipt is invalid"):
        publish_private_snapshot({**RECEIPT, "extra": 1}, ENV, public_store=MemoryStore())


def test_publisher_requires_a_configured_demo_account():
    with pytest.raises(PublicationError, match="demo account is not configured"):
        publish_private_snapshot(RECEIPT, {**ENV, "PHASE3_TARGET_ACCOUNT_ID": ""}, public_store=MemoryStore())


def test_private_keys_cannot_traverse_out_of_the_account_prefix():
    receipt = {**RECEIPT, "snapshot_key": f"snapshots/{ACCOUNT}/../other/run.json"}

    with pytest.raises(PublicationError, match="outside the demo account prefix"):
        publish_private_snapshot(receipt, ENV, public_store=MemoryStore())


def test_publisher_requires_full_configuration_without_an_injected_store():
    with pytest.raises(PublicationError, match="not fully configured"):
        publish_private_snapshot(RECEIPT, {**ENV, "PHASE3_PUBLIC_RESULTS_BUCKET": ""})


def test_publisher_requires_the_private_source_and_service_clients():
    with pytest.raises(PublicationError, match="private source or pseudonym key"):
        publish_private_snapshot(
            RECEIPT, {**ENV, "PHASE3_PRIVATE_SNAPSHOT_BUCKET": ""}, public_store=MemoryStore()
        )
    with pytest.raises(PublicationError, match="service clients are unavailable"):
        publish_private_snapshot(RECEIPT, ENV, public_store=MemoryStore())


def test_private_snapshot_read_failures_fail_closed():
    with pytest.raises(PublicationError, match="could not be read"):
        publish_private_snapshot(
            RECEIPT,
            ENV,
            s3_client=S3(error=_client_error("NoSuchKey")),
            secrets_client=Secrets({}),
            public_store=MemoryStore(),
        )


def test_private_snapshot_size_and_json_are_validated(monkeypatch):
    with pytest.raises(PublicationError, match="invalid JSON"):
        _private(b"{not json")
    with pytest.raises(PublicationError, match="duplicate JSON keys"):
        _private(b'{"metadata": {}, "metadata": {}}')
    with pytest.raises(PublicationError, match="exceeds the size limit"):
        _private(b" " * (10 * 1024 * 1024 + 1))


@pytest.mark.parametrize(
    "secret",
    [
        {"SecretBinary": b"key"},
        {"SecretString": "not base64!"},
        _client_error("AccessDeniedException"),
    ],
)
def test_pseudonym_key_failures_fail_closed(secret):
    body = json.dumps(_report("run-1", "2026-11-01T00:00:00+00:00")).encode()

    with pytest.raises(PublicationError, match="pseudonym key could not be read"):
        _private(body, secret=secret)


def test_reports_that_fail_redaction_are_not_published():
    with pytest.raises(PublicationError):
        _private(json.dumps({"metadata": {}}).encode())


# ------------------------------------------------------------- Lambda handler --


@pytest.mark.parametrize("event", [None, {}, {"receipt": RECEIPT, "extra": True}])
def test_handler_rejects_unexpected_events(event):
    with pytest.raises(PublicationError, match="publisher event is invalid"):
        lambda_handler(event, None, public_store=MemoryStore())


@pytest.mark.parametrize("completed_at", [None, "yesterday", "2026-11-03T12:00:00"])
def test_failure_events_require_an_aware_timestamp(completed_at):
    with pytest.raises(PublicationError):
        lambda_handler(
            {"kind": "scan_failure", "completed_at": completed_at}, None, public_store=MemoryStore()
        )


def test_failure_events_require_configuration_without_an_injected_store(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("PHASE3_PUBLIC_INDEX_TABLE", raising=False)

    with pytest.raises(PublicationError, match="scan status could not be recorded"):
        lambda_handler({"kind": "scan_failure", "completed_at": "2026-11-03T12:00:00Z"}, None)


def test_handler_publishes_a_receipt(monkeypatch):
    seen = {}

    def fake_publish(receipt, *, public_store):
        seen["receipt"] = receipt
        return {"status": "PUBLISHED"}

    monkeypatch.setattr(publisher, "publish_private_snapshot", fake_publish)

    assert lambda_handler({"receipt": RECEIPT}, None) == {"status": "PUBLISHED"}
    assert seen["receipt"] == RECEIPT
