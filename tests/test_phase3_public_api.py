from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import boto3
import pytest
from moto import mock_aws

from phase3.public_api import (
    AwsPublicReadStore,
    PublicApiError,
    _static_mode,
    public_response,
)
from phase3.publisher import S3DynamoPublicStore
from phase3.redaction import redact_snapshot

KEY = b"p3-test-key-material-with-at-least-32-bytes"


def _snapshot(completed_at="2026-11-03T11:00:00+00:00"):
    finding = {
        "fingerprint": "a111111111111111",
        "control_id": "S3-001",
        "severity": "HIGH",
        "title": "Bucket protection is incomplete",
        "description": "Some bucket controls are disabled.",
        "evidence": {"private": "value"},
        "remediation": "Enable the required controls.",
        "references": [],
        "lifecycle_state": "open",
        "detected_at": completed_at,
        "resource_reference": "bucket:demo-empty",
        "account_ref": {"provider": "aws", "id": "123456789012"},
        "service": "s3",
        "region": "us-east-1",
    }
    report = {
        "metadata": {
            "scan_source": "aws-fleet",
            "scan_coverage": [
                {"account_id": "123456789012", "service": "s3", "region": "us-east-1", "complete": True}
            ],
        },
        "summary": {},
        "contract": {
            "scan_run": {
                "run_id": "run-1",
                "status": "FAIL",
                "gate_status": "NOT_CONFIGURED",
                "started_at": completed_at,
                "completed_at": completed_at,
                "regions": ["us-east-1"],
                "scanner_versions": {"account-access-auditor": "1.0.0"},
            },
            "findings": [finding],
        },
        "drift": [],
    }
    return redact_snapshot(report, KEY)


class Store:
    def __init__(self, snapshot, attempt=None):
        self.snapshot = snapshot
        self.attempt = attempt

    def get_latest(self):
        return self.snapshot, self.attempt

    def list_runs(self, limit):
        return [{"snapshot_id": self.snapshot["snapshot_id"], "status": "FAIL"}][:limit]


def test_latest_endpoint_returns_schema_valid_data_and_freshness():
    snapshot = _snapshot()
    response = public_response(
        {"httpMethod": "GET", "path": "/api/latest"},
        store=Store(snapshot),
        now=datetime(2026, 11, 3, 11, 5, tzinfo=UTC),
    )

    assert response["statusCode"] == 200
    assert response["headers"]["Cache-Control"].startswith("public")
    assert response["headers"]["X-Content-Type-Options"] == "nosniff"
    assert response["body"]
    assert '"age_seconds":300' in response["body"]
    assert "123456789012" not in response["body"]
    assert "private" not in response["body"]


def test_incomplete_latest_attempt_keeps_last_good_snapshot_and_sets_banner():
    snapshot = _snapshot("2026-11-03T10:00:00+00:00")
    attempt = {
        "status": "UNKNOWN",
        "completed_at": "2026-11-03T11:00:00+00:00",
        "affected_services": [{"service": "s3", "status": "UNKNOWN"}],
    }
    response = public_response(
        {"httpMethod": "GET", "path": "/api/latest"},
        store=Store(snapshot, attempt),
        now=datetime(2026, 11, 3, 11, 5, tzinfo=UTC),
    )

    assert response["statusCode"] == 200
    assert '"last_good_preserved":true' in response["body"]
    assert '"latest_attempt_status":"UNKNOWN"' in response["body"]
    assert '"affected_services":[{"service":"s3","status":"UNKNOWN"}]' in response["body"]


@mock_aws
def test_incomplete_service_status_survives_dynamodb_storage_and_public_api_read():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="phase3-status-results")
    dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
    table = dynamodb.create_table(
        TableName="phase3-status-index",
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
    snapshot = _snapshot("2026-11-03T10:00:00+00:00")
    snapshot_key = f"snapshots/{snapshot['snapshot_id']}.json"
    s3.put_object(
        Bucket="phase3-status-results",
        Key=snapshot_key,
        Body=json.dumps(snapshot).encode("utf-8"),
        ContentType="application/json",
    )
    table.put_item(
        Item={
            "pk": "demo",
            "sk": "LATEST",
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_key": snapshot_key,
        }
    )
    publisher_store = S3DynamoPublicStore(bucket_name="phase3-status-results", table=table, s3_client=s3)
    publisher_store.record_attempt(
        "UNKNOWN",
        "2026-11-03T11:00:00+00:00",
        affected_services=[{"service": "s3", "status": "UNKNOWN"}],
    )

    read_store = AwsPublicReadStore(bucket_name="phase3-status-results", table=table, s3_client=s3)
    response = public_response(
        {"httpMethod": "GET", "path": "/api/latest"},
        store=read_store,
        now=datetime(2026, 11, 3, 11, 5, tzinfo=UTC),
    )

    assert response["statusCode"] == 200
    payload = json.loads(response["body"])
    assert payload["data"]["snapshot_id"] == snapshot["snapshot_id"]
    assert payload["freshness"]["latest_attempt_status"] == "UNKNOWN"
    assert payload["freshness"]["affected_services"] == [{"service": "s3", "status": "UNKNOWN"}]


def test_publication_failure_is_distinct_from_failed_scan_and_preserves_last_good():
    snapshot = _snapshot("2026-11-03T10:00:00+00:00")
    attempt = {
        "status": "PASS",
        "completed_at": "2026-11-03T11:00:00+00:00",
        "publication_status": "PAUSED",
    }
    response = public_response(
        {"httpMethod": "GET", "path": "/api/latest"},
        store=Store(snapshot, attempt),
        now=datetime(2026, 11, 3, 11, 5, tzinfo=UTC),
    )

    assert response["statusCode"] == 200
    assert '"publication_paused":true' in response["body"]
    assert '"snapshot_id":"' + snapshot["snapshot_id"] + '"' in response["body"]


def test_api_only_accepts_get_and_head_and_head_has_no_body():
    snapshot = _snapshot()
    post = public_response({"httpMethod": "POST", "path": "/api/latest"}, store=Store(snapshot))
    head = public_response({"httpMethod": "HEAD", "path": "/api/latest"}, store=Store(snapshot))

    assert post["statusCode"] == 405
    assert post["body"] == ""
    assert head["statusCode"] == 200
    assert head["body"] == ""


def test_api_reports_unavailable_data_and_rejects_unknown_routes():
    missing = public_response({"httpMethod": "GET", "path": "/api/latest"}, store=Store(None))
    unknown = public_response({"httpMethod": "GET", "path": "/api/admin"}, store=Store(_snapshot()))

    assert missing["statusCode"] == 503
    assert "NO_SNAPSHOT" in missing["body"]
    assert unknown["statusCode"] == 404


def test_stale_snapshot_is_marked_after_two_scan_intervals():
    snapshot = _snapshot("2026-11-02T20:59:59+00:00")
    response = public_response(
        {"httpMethod": "GET", "path": "/api/latest"},
        store=Store(snapshot),
        now=datetime(2026, 11, 3, 9, 0, tzinfo=UTC),
    )
    assert response["statusCode"] == 200
    assert '"stale":true' in response["body"]


def test_public_store_rejects_a_pointer_to_a_different_snapshot():
    snapshot = _snapshot()

    class Table:
        def get_item(self, *, Key, **_kwargs):
            if Key["sk"] == "LATEST":
                return {
                    "Item": {
                        "snapshot_id": "f" * 24,
                        "snapshot_key": f"snapshots/{snapshot['snapshot_id']}.json",
                    }
                }
            return {}

    class S3:
        def get_object(self, **_kwargs):
            return {"Body": io.BytesIO(json.dumps(snapshot).encode("utf-8"))}

    store = AwsPublicReadStore(bucket_name="public-results", table=Table(), s3_client=S3())
    with pytest.raises(PublicApiError, match="does not match"):
        store.get_latest()


def test_static_mode_flag_fails_closed_when_missing_or_malformed():
    class Table:
        def __init__(self, item):
            self.item = item

        def get_item(self, **_kwargs):
            return {"Item": self.item} if self.item is not None else {}

    assert _static_mode(Table({"static_mode": True})) is True
    assert _static_mode(Table({"static_mode": False})) is False
    with pytest.raises(PublicApiError):
        _static_mode(Table({"static_mode": "false"}))
    with pytest.raises(PublicApiError):
        _static_mode(Table(None))
