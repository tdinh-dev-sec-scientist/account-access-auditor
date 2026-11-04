from __future__ import annotations

import json
import time

import boto3
import pytest
from moto import mock_aws

from phase3.private_snapshot_store import PrivateSnapshotError, PrivateSnapshotStore

ACCOUNT_ID = "123456789012"


def _report(run_id: str, completed_at: str, *, findings: list[dict], complete: bool = True):
    status = "PASS" if complete else "UNKNOWN"
    coverage = [
        {
            "account_id": ACCOUNT_ID,
            "service": "s3",
            "region": "aws-global",
            "complete": complete,
        }
    ]
    return {
        "metadata": {
            "scan_source": "aws-fleet",
            "scan_coverage": coverage,
            "accounts": [{"provider": "aws", "id": ACCOUNT_ID}],
        },
        "summary": {"total_findings": len(findings), "status": status},
        "collection_errors": [],
        "contract": {
            "schema_version": "1.0.0",
            "scan_run": {
                "run_id": run_id,
                "status": status,
                "completed_at": completed_at,
            },
            "findings": findings,
        },
    }


def _finding():
    return {
        "fingerprint": "a111111111111111",
        "control_id": "S3-001",
        "severity": "MEDIUM",
        "title": "Public Access Block is incomplete",
        "description": "A bucket has protections disabled.",
        "evidence": {"disabled_settings": ["BlockPublicPolicy"]},
        "remediation": "Enable all Public Access Block settings.",
        "account_ref": {"provider": "aws", "id": ACCOUNT_ID},
        "service": "s3",
        "region": "aws-global",
    }


def _store():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="phase3-private-snapshots")
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="phase3-private-runs",
        KeySchema=[
            {"AttributeName": "account_id", "KeyType": "HASH"},
            {"AttributeName": "sort_key", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "account_id", "AttributeType": "S"},
            {"AttributeName": "sort_key", "AttributeType": "S"},
            {"AttributeName": "status_pk", "AttributeType": "S"},
            {"AttributeName": "status_sk", "AttributeType": "S"},
            {"AttributeName": "scan_run_id", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "status-index",
                "KeySchema": [
                    {"AttributeName": "status_pk", "KeyType": "HASH"},
                    {"AttributeName": "status_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
            {
                "IndexName": "scan-run-index",
                "KeySchema": [{"AttributeName": "scan_run_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return PrivateSnapshotStore(
        bucket_name="phase3-private-snapshots",
        account_id=ACCOUNT_ID,
        s3_client=s3,
        run_index_table=table,
        temporary_directory=None,
    ), s3, table


@mock_aws
def test_private_store_persists_immutable_snapshots_and_replays_drift():
    store, s3, table = _store()
    first = store.persist(
        _report("run-1", "2026-11-01T00:00:00+00:00", findings=[_finding()])
    )
    second = store.persist(
        _report("run-2", "2026-11-02T00:00:00+00:00", findings=[])
    )

    assert first["drift_counts"]["new"] == 1
    assert second["drift_counts"]["resolved"] == 1
    assert first["snapshot_key"] != second["snapshot_key"]
    stored = json.loads(s3.get_object(Bucket=store.bucket_name, Key=second["snapshot_key"])["Body"].read())
    assert stored["drift"][0]["state"] == "resolved"
    assert table.query(KeyConditionExpression=boto3.dynamodb.conditions.Key("account_id").eq(ACCOUNT_ID))[
        "Count"
    ] == 2
    assert store.get_receipt("run-2")["snapshot_key"] == second["snapshot_key"]


@mock_aws
def test_private_store_records_safe_failure_and_returns_receipt_without_writing_snapshot():
    store, s3, table = _store()

    receipt = store.record_failure("run-error", "2026-11-03T12:00:00+00:00")

    assert receipt == {"run_id": "run-error", "status": "ERROR", "completed_at": "2026-11-03T12:00:00+00:00"}
    assert store.get_receipt("run-error") == receipt
    assert s3.list_objects_v2(Bucket=store.bucket_name).get("KeyCount", 0) == 0
    rows = table.query(
        IndexName="scan-run-index",
        KeyConditionExpression=boto3.dynamodb.conditions.Key("scan_run_id").eq("run-error"),
    )["Items"]
    assert rows[0]["status"] == "ERROR"
    assert rows[0]["status_pk"] == f"{ACCOUNT_ID}#incomplete"


@mock_aws
def test_incomplete_scan_keeps_absence_as_unknown_not_resolved():
    store, _s3, _table = _store()
    store.persist(_report("run-1", "2026-11-01T00:00:00+00:00", findings=[_finding()]))

    partial = store.persist(
        _report("run-2", "2026-11-02T00:00:00+00:00", findings=[], complete=False)
    )

    assert partial["drift_counts"]["unknown"] == 1
    assert partial["drift_counts"]["resolved"] == 0


@mock_aws
def test_private_store_rejects_a_report_for_another_account():
    store, _s3, _table = _store()
    report = _report("run-1", "2026-11-01T00:00:00+00:00", findings=[])
    report["metadata"]["scan_coverage"][0]["account_id"] = "210987654321"

    with pytest.raises(PrivateSnapshotError, match="does not match the configured demo account"):
        store.persist(report)


@mock_aws
def test_private_store_refuses_a_concurrent_scan_for_the_same_account():
    store, s3, table = _store()
    table.put_item(
        Item={
            "account_id": ACCOUNT_ID,
            "sort_key": "LOCK#SCAN",
            "lock_owner": "another-run",
            "expires_at": int(time.time()) + 600,
        }
    )

    with pytest.raises(PrivateSnapshotError, match="another scan is already recording this account"):
        store.persist(_report("run-1", "2026-11-01T00:00:00+00:00", findings=[]))

    assert s3.list_objects_v2(Bucket=store.bucket_name).get("KeyCount", 0) == 0


@mock_aws
def test_private_snapshot_key_cannot_be_overwritten_on_a_duplicate_run():
    store, s3, _table = _store()
    report = _report("run-1", "2026-11-01T00:00:00+00:00", findings=[_finding()])
    first = store.persist(report)
    original = s3.get_object(Bucket=store.bucket_name, Key=first["snapshot_key"])["Body"].read()
    changed = _report("run-1", "2026-11-01T00:00:00+00:00", findings=[])

    with pytest.raises(PrivateSnapshotError, match="private snapshot operation failed"):
        store.persist(changed)

    stored = s3.get_object(Bucket=store.bucket_name, Key=first["snapshot_key"])["Body"].read()
    assert stored == original


@mock_aws
def test_private_snapshot_does_not_overwrite_an_orphaned_object_key():
    store, s3, _table = _store()
    key = "snapshots/123456789012/2026/11/01/run-1.json"
    s3.put_object(Bucket=store.bucket_name, Key=key, Body=b"existing immutable object")

    with pytest.raises(PrivateSnapshotError, match="private snapshot operation failed"):
        store.persist(_report("run-1", "2026-11-01T00:00:00+00:00", findings=[]))

    assert s3.get_object(Bucket=store.bucket_name, Key=key)["Body"].read() == b"existing immutable object"
