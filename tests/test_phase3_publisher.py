from __future__ import annotations

import base64
import json

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from phase3.publisher import (
    PublicationError,
    S3DynamoPublicStore,
    publish_private_snapshot,
    publish_snapshot,
)
from phase3.publisher import (
    lambda_handler as publisher_handler,
)
from phase3.redaction import redact_snapshot

KEY = b"p3-test-key-material-with-at-least-32-bytes"


def _report(run_id: str, completed_at: str, *, status="PASS", complete=True):
    finding = {
        "fingerprint": "a111111111111111",
        "control_id": "S3-001",
        "severity": "HIGH",
        "title": "Bucket access protection is incomplete",
        "description": "Two bucket-level public access controls are disabled.",
        "evidence": {"raw": "must not reach public store"},
        "remediation": "Enable all four bucket public access block settings.",
        "references": [],
        "lifecycle_state": "open",
        "detected_at": completed_at,
        "resource_reference": "bucket:demo-empty",
        "account_ref": {"provider": "aws", "id": "123456789012"},
        "service": "s3",
        "region": "us-east-1",
    }
    return {
        "metadata": {
            "scan_source": "aws-fleet",
            "scan_coverage": [
                {"account_id": "123456789012", "service": "s3", "region": "us-east-1", "complete": complete}
            ],
        },
        "summary": {"status": status, "gate_status": "NOT_CONFIGURED"},
        "contract": {
            "scan_run": {
                "run_id": run_id,
                "status": status,
                "gate_status": "NOT_CONFIGURED",
                "started_at": completed_at,
                "completed_at": completed_at,
                "regions": ["us-east-1"],
                "scanner_versions": {"account-access-auditor": "1.0.0"},
                "finding_count": 1 if status in {"PASS", "FAIL"} else 0,
            },
            "findings": [finding] if status in {"PASS", "FAIL"} else [],
        },
    }


class MemoryStore:
    def __init__(self):
        self.snapshots = []
        self.attempts = []
        self.publication_statuses = []
        self.affected_services = []

    def publish(self, snapshot):
        self.snapshots.append(snapshot)
        return True

    def record_attempt(self, status, completed_at, *, publication_status="READY", affected_services=()):
        self.attempts.append((status, completed_at))
        self.publication_statuses.append(publication_status)
        self.affected_services.append(list(affected_services))


def test_publisher_publishes_complete_failures_but_retains_last_good_for_partial_or_error():
    store = MemoryStore()
    completed = redact_snapshot(_report("run-1", "2026-11-01T00:00:00+00:00", status="FAIL"), KEY)
    partial = redact_snapshot(
        _report("run-2", "2026-11-02T00:00:00+00:00", status="UNKNOWN", complete=False), KEY
    )

    assert publish_snapshot(completed, store) == {
        "status": "PUBLISHED",
        "snapshot_id": completed["snapshot_id"],
    }
    result = publish_snapshot(partial, store)

    assert result["status"] == "RETAINED_LAST_GOOD"
    assert store.snapshots == [completed]
    assert store.attempts == [
        ("FAIL", "2026-11-01T00:00:00+00:00"),
        ("UNKNOWN", "2026-11-02T00:00:00+00:00"),
    ]
    assert store.affected_services == [[], [{"service": "s3", "status": "UNKNOWN"}]]


@mock_aws
def test_s3_dynamo_publisher_writes_snapshot_before_advancing_pointer():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="phase3-public-results")
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="phase3-public-index",
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
    store = S3DynamoPublicStore(bucket_name="phase3-public-results", table=table, s3_client=s3)
    snapshot = redact_snapshot(_report("run-1", "2026-11-01T00:00:00+00:00", status="FAIL"), KEY)

    result = publish_snapshot(snapshot, store)
    latest = table.get_item(Key={"pk": "demo", "sk": "LATEST"})["Item"]
    stored = s3.get_object(Bucket="phase3-public-results", Key=latest["snapshot_key"])["Body"].read()

    assert result["status"] == "PUBLISHED"
    assert latest["snapshot_id"] == snapshot["snapshot_id"]
    assert b"123456789012" not in stored
    assert b'"evidence_summary":{}' in stored
    assert b'"raw"' not in stored


@mock_aws
def test_failed_public_pointer_update_preserves_previous_good_snapshot():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="phase3-public-results")
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="phase3-public-index",
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
    store = S3DynamoPublicStore(bucket_name="phase3-public-results", table=table, s3_client=s3)
    first = redact_snapshot(_report("run-1", "2026-11-01T00:00:00+00:00", status="PASS"), KEY)
    second = redact_snapshot(_report("run-2", "2026-11-02T00:00:00+00:00", status="FAIL"), KEY)
    publish_snapshot(first, store)

    original_update = table.update_item

    def fail_update(**kwargs):
        raise ClientError({"Error": {"Code": "InternalServerError", "Message": "hidden"}}, "UpdateItem")

    table.update_item = fail_update
    with pytest.raises(PublicationError, match="latest pointer could not be updated"):
        publish_snapshot(second, store)
    table.update_item = original_update

    latest = table.get_item(Key={"pk": "demo", "sk": "LATEST"})["Item"]
    assert latest["snapshot_id"] == first["snapshot_id"]


def test_publisher_rejects_extra_or_malformed_public_data_before_any_store_write():
    store = MemoryStore()
    snapshot = redact_snapshot(_report("run-1", "2026-11-01T00:00:00+00:00"), KEY)
    snapshot["account_id"] = "123456789012"

    with pytest.raises(PublicationError, match="schema"):
        publish_snapshot(snapshot, store)
    assert store.snapshots == []
    assert store.attempts == []


def test_publisher_lambda_reads_only_the_receipted_private_demo_snapshot():
    report = _report("run-1", "2026-11-01T00:00:00+00:00", status="PASS")
    source_key = "snapshots/123456789012/2026/11/01/run-1.json"
    receipt = {
        "run_id": "run-1",
        "status": "PASS",
        "finding_count": 1,
        "snapshot_key": source_key,
        "drift_counts": {"new": 1},
    }
    env = {
        "PHASE3_TARGET_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "us-east-1",
        "PHASE3_PRIVATE_SNAPSHOT_BUCKET": "private-demo",
        "PHASE3_PSEUDONYM_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:p3-hmac",
    }
    seen = {}

    class S3:
        def get_object(self, *, Bucket, Key):
            seen["source"] = (Bucket, Key)
            return {"Body": type("Body", (), {"read": lambda self, _size: json.dumps(report).encode()})()}

    class Secrets:
        def get_secret_value(self, *, SecretId):
            seen["secret_arn"] = SecretId
            return {"SecretString": base64.b64encode(KEY).decode("ascii")}

    store = MemoryStore()
    result = publish_private_snapshot(
        receipt,
        env,
        s3_client=S3(),
        secrets_client=Secrets(),
        public_store=store,
    )

    assert result["status"] == "PUBLISHED"
    assert seen["source"] == ("private-demo", source_key)
    assert seen["secret_arn"] == env["PHASE3_PSEUDONYM_SECRET_ARN"]
    assert "123456789012" not in repr(store.snapshots[0])


def test_publisher_lambda_rejects_private_keys_outside_the_fixed_demo_prefix():
    with pytest.raises(PublicationError, match="outside the demo account prefix"):
        publish_private_snapshot(
            {
                "run_id": "run-1",
                "status": "PASS",
                "finding_count": 0,
                "snapshot_key": "snapshots/210987654321/evil.json",
                "drift_counts": {},
            },
            {"PHASE3_TARGET_ACCOUNT_ID": "123456789012"},
        )


@mock_aws
def test_scan_failure_handler_publishes_only_safe_status_and_never_replaces_latest(monkeypatch):
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="phase3-public-results")
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="phase3-public-index",
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
    previous = redact_snapshot(_report("run-1", "2026-11-01T00:00:00+00:00", status="PASS"), KEY)
    store = S3DynamoPublicStore(bucket_name="phase3-public-results", table=table, s3_client=s3)
    publish_snapshot(previous, store)
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PHASE3_PUBLIC_INDEX_TABLE", "phase3-public-index")
    from phase3.publisher import lambda_handler

    result = lambda_handler(
        {"kind": "scan_failure", "completed_at": "2026-11-02T00:00:00+00:00"},
        object(),
    )

    latest = table.get_item(Key={"pk": "demo", "sk": "LATEST"})["Item"]
    attempt = table.get_item(Key={"pk": "demo", "sk": "LATEST_STATUS"})["Item"]
    assert result == {"status": "SCAN_FAILURE_RECORDED"}
    assert latest["snapshot_id"] == previous["snapshot_id"]
    assert attempt["scan_status"] == "ERROR"
    assert "last complete snapshot" in attempt["message"]


def test_publication_failure_handler_marks_paused_without_receiving_error_details():
    store = MemoryStore()
    result = publisher_handler(
        {"kind": "publication_failure", "completed_at": "2026-11-03T12:00:00+00:00"},
        object(),
        public_store=store,
    )

    assert result == {"status": "PUBLICATION_PAUSED"}
    assert store.attempts == [("ERROR", "2026-11-03T12:00:00+00:00")]
    assert store.publication_statuses == ["PAUSED"]


def test_publisher_rejects_raw_errors_in_failure_events():
    with pytest.raises(PublicationError, match="scan status event is invalid"):
        publisher_handler(
            {
                "kind": "publication_failure",
                "completed_at": "2026-11-03T12:00:00+00:00",
                "error": "untrusted resource data",
            },
            object(),
            public_store=MemoryStore(),
        )
