"""End-to-end check of the live Stage 1 and Stage 2 data path against moto.

Real rules scan an emulated demo account, the private snapshot store persists
two consecutive scans with a bucket drift between them, and the stored
snapshot is redacted for publication. Each step uses the production code, so
contract mismatches between the scanner, history, and publisher fail here.
"""

from __future__ import annotations

import json

import boto3
import pytest
from moto import mock_aws

from auditor import fleet_scan
from auditor.config import defaults
from auditor.fleet import FleetConfig, TargetAccount
from phase3.private_snapshot_store import PrivateSnapshotStore
from phase3.redaction import redact_snapshot, validate_public_snapshot
from scripts.collect_phase3_stage1_evidence import drift_ids

HMAC_KEY = b"live-pipeline-test-key-material-32b!"


def _table(session):
    return session.resource("dynamodb").create_table(
        TableName="vorrin-p3-private-runs",
        BillingMode="PAY_PER_REQUEST",
        KeySchema=[
            {"AttributeName": "account_id", "KeyType": "HASH"},
            {"AttributeName": "sort_key", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": name, "AttributeType": "S"}
            for name in ("account_id", "sort_key", "status_pk", "status_sk", "scan_run_id")
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "status-index",
                "KeySchema": [
                    {"AttributeName": "status_pk", "KeyType": "HASH"},
                    {"AttributeName": "status_sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
            {
                "IndexName": "scan-run-index",
                "KeySchema": [{"AttributeName": "scan_run_id", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
    )


def _block(s3, bucket, *, policy):
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": policy,
            "RestrictPublicBuckets": policy,
        },
    )


@pytest.fixture
def aws(monkeypatch):
    with mock_aws():
        session = boto3.session.Session(region_name="us-east-1")
        monkeypatch.setattr(
            fleet_scan,
            "_assume_role",
            lambda _source, **kw: (boto3.session.Session(region_name=kw["region_name"]), None),
        )
        yield session


def test_two_scheduled_scans_record_bucket_drift_and_publish_safely(aws):
    s3 = aws.client("s3")
    for bucket in ("vorrin-p3-demo-a", "vorrin-p3-demo-b", "vorrin-p3-private"):
        s3.create_bucket(Bucket=bucket)
    _block(s3, "vorrin-p3-demo-a", policy=False)
    _block(s3, "vorrin-p3-demo-b", policy=True)
    account = aws.client("sts").get_caller_identity()["Account"]
    config = FleetConfig(
        accounts=(TargetAccount(account, f"arn:aws:iam::{account}:role/AccountAccessAuditorReadOnly"),),
        regions=("us-east-1",),
        services=("iam", "s3", "cloudtrail"),
    )
    store = PrivateSnapshotStore(
        bucket_name="vorrin-p3-private", account_id=account, s3_client=s3, run_index_table=_table(aws)
    )

    first = fleet_scan.run_fleet_scan(config, defaults(), aws, run_id="run-before")
    assert first["contract"]["scan_run"]["status"] in {"PASS", "FAIL"}
    assert first.get("collection_errors", []) == []
    assert store.persist(first)["finding_count"] > 0

    # The Terraform drift: bucket A fixed, bucket B loosened.
    _block(s3, "vorrin-p3-demo-a", policy=True)
    _block(s3, "vorrin-p3-demo-b", policy=False)
    second = fleet_scan.run_fleet_scan(config, defaults(), aws, run_id="run-after")
    receipt = store.persist(second)
    assert receipt["drift_counts"]["new"] >= 1 and receipt["drift_counts"]["resolved"] >= 1
    assert store.get_receipt("run-after") == receipt

    stored = json.loads(s3.get_object(Bucket="vorrin-p3-private", Key=receipt["snapshot_key"])["Body"].read())
    new, resolved = drift_ids(stored)
    by_fingerprint = {item["fingerprint"]: item["finding"] for item in stored["drift"]}
    assert {by_fingerprint[f]["resource_reference"] for f in new} >= {"vorrin-p3-demo-b"}
    assert {by_fingerprint[f]["resource_reference"] for f in resolved} >= {"vorrin-p3-demo-a"}

    public = redact_snapshot(stored, HMAC_KEY)
    assert validate_public_snapshot(public) is None
    text = json.dumps(public)
    for private in (account, "vorrin-p3-demo-a", "vorrin-p3-demo-b", "arn:aws"):
        assert private not in text
