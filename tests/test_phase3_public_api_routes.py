"""Query validation, error mapping, and AWS read paths of the public Phase 3 API."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from decimal import Decimal

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from phase3 import public_api
from phase3.public_api import AwsPublicReadStore, PublicApiError, public_response
from phase3.publisher import S3DynamoPublicStore
from tests.test_phase3_public_api import Store, _snapshot

BUCKET = "phase3-public-results"
TABLE = "phase3-public-index"


def _get(path, store, **query):
    event = {"httpMethod": "GET", "path": path}
    if query:
        event["queryStringParameters"] = query
    return public_response(event, store=store, now=datetime(2026, 11, 3, 11, 5, tzinfo=UTC))


def _body(response):
    return json.loads(response["body"])


class FailingStore:
    def get_latest(self):
        raise RuntimeError("backend down")

    def list_runs(self, limit):
        raise RuntimeError("backend down")


# ----------------------------------------------------------------- routing --


@pytest.mark.parametrize("event", [None, [], "GET /api/latest"])
def test_non_object_events_are_rejected(event):
    assert public_response(event, store=Store(_snapshot()))["statusCode"] == 400


def test_a_path_that_is_not_a_string_is_rejected():
    response = public_response({"httpMethod": "GET", "path": 7}, store=Store(_snapshot()))

    assert response["statusCode"] == 400


def test_http_api_raw_path_is_accepted():
    response = public_response({"httpMethod": "GET", "rawPath": "/api/runs"}, store=Store(_snapshot()))

    assert response["statusCode"] == 200


def test_runs_endpoint_returns_the_index_with_default_limit():
    snapshot = _snapshot()
    response = _get("/api/runs", Store(snapshot))

    assert response["statusCode"] == 200
    assert _body(response) == {"runs": [{"snapshot_id": snapshot["snapshot_id"], "status": "FAIL"}]}


@pytest.mark.parametrize(
    "query",
    [
        {"limit": "0"},
        {"limit": "101"},
        {"limit": "ten"},
        {"limit": "５"},
        {"limit": "1" * 33},
        {"unexpected": "1"},
    ],
)
def test_runs_endpoint_rejects_invalid_queries(query):
    response = _get("/api/runs", Store(_snapshot()), **query)

    assert response["statusCode"] == 400
    assert _body(response) == {"error": "INVALID_QUERY"}


def test_query_values_must_be_strings():
    event = {"httpMethod": "GET", "path": "/api/runs", "queryStringParameters": {"limit": 5}}

    assert public_response(event, store=Store(_snapshot()))["statusCode"] == 400


@pytest.mark.parametrize("path", ["/api/runs", "/api/findings", "/api/drift", "/api/latest"])
def test_backend_failures_return_503_without_caching(path):
    response = _get(path, FailingStore())

    assert response["statusCode"] == 503
    assert response["headers"]["Cache-Control"] == "no-store"
    assert _body(response) == {"error": "PUBLIC_DATA_UNAVAILABLE"}


@pytest.mark.parametrize("path", ["/api/findings", "/api/drift"])
def test_collection_endpoints_report_a_missing_snapshot(path):
    response = _get(path, Store(None))

    assert response["statusCode"] == 503
    assert _body(response) == {"error": "NO_SNAPSHOT"}


def test_findings_endpoint_filters_by_severity_and_limit():
    snapshot = _snapshot()

    high = _body(_get("/api/findings", Store(snapshot), severity="HIGH"))
    low = _body(_get("/api/findings", Store(snapshot), severity="LOW"))
    limited = _body(_get("/api/findings", Store(snapshot), limit="1"))

    assert high["snapshot_id"] == snapshot["snapshot_id"]
    assert [item["severity"] for item in high["findings"]] == ["HIGH"]
    assert low["findings"] == []
    assert len(limited["findings"]) == 1


def test_findings_endpoint_rejects_an_unknown_severity():
    assert _get("/api/findings", Store(_snapshot()), severity="SEVERE")["statusCode"] == 400


def test_drift_endpoint_filters_by_state_and_rejects_unknown_states():
    snapshot = _snapshot()
    snapshot["drift"] = [
        {"state": "new", "id": "a"},
        {"state": "resolved", "id": "b"},
    ]

    resolved = _body(_get("/api/drift", Store(snapshot), state="resolved"))
    everything = _body(_get("/api/drift", Store(snapshot)))
    invalid = _get("/api/drift", Store(snapshot), state="deleted")

    assert resolved["drift"] == [{"state": "resolved", "id": "b"}]
    assert len(everything["drift"]) == 2
    assert invalid["statusCode"] == 400


def test_latest_without_a_snapshot_reports_the_latest_attempt_status():
    response = _get("/api/latest", Store(None, {"status": "ERROR"}))

    assert response["statusCode"] == 503
    assert _body(response) == {"error": "NO_SNAPSHOT", "latest_attempt_status": "ERROR"}


def test_latest_accepts_a_naive_now_as_utc():
    snapshot = _snapshot()
    response = public_response(
        {"httpMethod": "GET", "path": "/api/latest"},
        store=Store(snapshot),
        now=datetime(2026, 11, 3, 11, 5),
    )

    assert _body(response)["freshness"]["age_seconds"] == 300


def test_an_older_attempt_does_not_override_the_published_snapshot():
    snapshot = _snapshot("2026-11-03T11:00:00+00:00")
    attempt = {"status": "ERROR", "completed_at": "2026-11-03T10:00:00+00:00", "publication_status": "PAUSED"}

    freshness = _body(_get("/api/latest", Store(snapshot, attempt)))["freshness"]

    assert freshness["latest_attempt_status"] is None
    assert freshness["publication_paused"] is False
    assert freshness["last_good_preserved"] is False


# ------------------------------------------------------------- attempt view --


@pytest.mark.parametrize(
    "attempt",
    [
        None,
        "PASS",
        {"scan_status": "RUNNING", "completed_at": "2026-11-03T11:00:00+00:00"},
        {"scan_status": "PASS", "completed_at": 1},
        {"scan_status": "PASS", "completed_at": "not a time"},
        {"scan_status": "PASS", "completed_at": "2026-11-03T11:00:00"},
    ],
)
def test_untrusted_attempt_records_are_dropped(attempt):
    assert AwsPublicReadStore._safe_attempt(attempt) is None


def test_attempt_record_is_normalized_and_filters_affected_services():
    attempt = AwsPublicReadStore._safe_attempt(
        {
            "scan_status": "UNKNOWN",
            "completed_at": "2026-11-03T12:00:00+01:00",
            "publication_status": "SOMETHING_ELSE",
            "affected_services": [
                {"service": "s3", "status": "UNKNOWN"},
                {"service": "s3", "status": "UNKNOWN"},
                {"service": "ec2", "status": "UNKNOWN"},
            ],
        }
    )

    assert attempt == {
        "status": "UNKNOWN",
        "completed_at": "2026-11-03T11:00:00+00:00",
        "publication_status": "READY",
        "affected_services": [{"service": "s3", "status": "UNKNOWN"}],
    }


def test_attempt_record_drops_an_oversized_affected_services_list():
    services = [{"service": name, "status": "ERROR"} for name in ("iam", "s3", "cloudtrail", "iam")]
    attempt = AwsPublicReadStore._safe_attempt(
        {"scan_status": "ERROR", "completed_at": "2026-11-03T11:00:00+00:00", "affected_services": services}
    )

    assert attempt["affected_services"] == []


# --------------------------------------------------------- AWS read store --


def _aws_store():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=BUCKET)
    table = boto3.resource("dynamodb", region_name="us-east-1").create_table(
        TableName=TABLE,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return AwsPublicReadStore(bucket_name=BUCKET, table=table, s3_client=s3), s3, table


@mock_aws
def test_list_runs_returns_only_well_formed_index_rows():
    store, _s3, table = _aws_store()
    good = {"snapshot_id": "a" * 24, "completed_at": "2026-11-03T11:00:00+00:00", "scan_status": "PASS"}
    table.put_item(Item={"pk": "demo", "sk": "RUN#2", **good, "finding_count": 3})
    table.put_item(Item={"pk": "demo", "sk": "RUN#3", **good, "snapshot_id": "not-hex", "finding_count": 1})
    table.put_item(Item={"pk": "demo", "sk": "RUN#4", **good, "scan_status": "ERROR", "finding_count": 1})
    table.put_item(Item={"pk": "demo", "sk": "RUN#5", **good, "finding_count": "3"})

    runs = store.list_runs(10)

    assert runs == [
        {
            "snapshot_id": "a" * 24,
            "completed_at": "2026-11-03T11:00:00+00:00",
            "status": "PASS",
            "finding_count": 3,
        }
    ]


@mock_aws
def test_runs_written_by_the_publisher_are_listed_by_the_public_api():
    """Regression: DynamoDB returns numbers as Decimal, which list_runs used to drop."""
    store, s3, table = _aws_store()
    snapshot = _snapshot()
    publisher = S3DynamoPublicStore(bucket_name=BUCKET, table=table, s3_client=s3)

    assert publisher.publish(snapshot) is True
    runs = store.list_runs(10)

    assert runs == [
        {
            "snapshot_id": snapshot["snapshot_id"],
            "completed_at": snapshot["scan"]["completed_at"],
            "status": snapshot["scan"]["status"],
            "finding_count": snapshot["summary"]["total_findings"],
        }
    ]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (3, 3),
        (Decimal("3"), 3),
        (0, 0),
        (True, None),
        (Decimal("2.5"), None),
        (Decimal("NaN"), None),
        (-1, None),
        ("3", None),
    ],
)
def test_index_count_accepts_only_non_negative_integers(value, expected):
    assert public_api._index_count(value) == expected


@mock_aws
def test_get_latest_without_a_pointer_returns_no_snapshot():
    store, _s3, _table = _aws_store()

    assert store.get_latest() == (None, None)


@mock_aws
@pytest.mark.parametrize(
    ("pointer", "body", "message"),
    [
        ({"snapshot_key": "../private/raw.json"}, None, "pointer is invalid"),
        ({"snapshot_key": f"snapshots/{'b' * 24}.json"}, None, "snapshot is unavailable"),
        ({"snapshot_key": f"snapshots/{'c' * 24}.json"}, b"{not json", "failed schema validation"),
        ({"snapshot_key": f"snapshots/{'d' * 24}.json"}, b'{"snapshot_id": "x"}', "failed schema validation"),
    ],
)
def test_get_latest_rejects_unsafe_pointers_and_invalid_objects(pointer, body, message):
    store, s3, table = _aws_store()
    table.put_item(Item={"pk": "demo", "sk": "LATEST", "snapshot_id": "e" * 24, **pointer})
    if body is not None:
        s3.put_object(Bucket=BUCKET, Key=pointer["snapshot_key"], Body=body)

    with pytest.raises(PublicApiError, match=message):
        store.get_latest()


def test_get_latest_rejects_oversized_snapshots(monkeypatch):
    monkeypatch.setattr(public_api, "MAX_PUBLIC_SNAPSHOT_BYTES", 8)

    class Table:
        def get_item(self, *, Key, **_kwargs):
            if Key["sk"] == "LATEST":
                return {"Item": {"snapshot_id": "a" * 24, "snapshot_key": f"snapshots/{'a' * 24}.json"}}
            return {}

    class S3:
        def get_object(self, **_kwargs):
            return {"Body": io.BytesIO(b"x" * 64)}

    store = AwsPublicReadStore(bucket_name=BUCKET, table=Table(), s3_client=S3())
    with pytest.raises(PublicApiError, match="exceeds the size limit"):
        store.get_latest()


def test_index_failures_are_reported_as_unavailable():
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetItem")

    class Table:
        def get_item(self, **_kwargs):
            raise error

        def query(self, **_kwargs):
            raise error

    store = AwsPublicReadStore(bucket_name=BUCKET, table=Table(), s3_client=None)
    with pytest.raises(PublicApiError, match="result index is unavailable"):
        store.get_latest()
    with pytest.raises(PublicApiError, match="run index is unavailable"):
        store.list_runs(5)


# ----------------------------------------------------------- Lambda handler --


def test_handler_fails_closed_without_configuration(monkeypatch):
    monkeypatch.setenv("PHASE3_ACCESS_MODE", "public")
    for name in ("PHASE3_PUBLIC_RESULTS_BUCKET", "PHASE3_PUBLIC_INDEX_TABLE", "AWS_REGION"):
        monkeypatch.delenv(name, raising=False)

    response = public_api.lambda_handler({"httpMethod": "GET", "path": "/api/latest"}, None)

    assert response["statusCode"] == 503
    assert response["headers"]["Cache-Control"] == "no-store"


@mock_aws
def test_handler_serves_reads_and_reports_static_mode(monkeypatch):
    _store, _s3, _table = _aws_store()
    features = boto3.resource("dynamodb", region_name="us-east-1").create_table(
        TableName="phase3-features",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    features.put_item(Item={"pk": "PLATFORM", "sk": "CONFIG", "static_mode": True})
    monkeypatch.setenv("PHASE3_PUBLIC_RESULTS_BUCKET", BUCKET)
    monkeypatch.setenv("PHASE3_PUBLIC_INDEX_TABLE", TABLE)
    monkeypatch.setenv("PHASE3_FEATURE_TABLE", "phase3-features")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PHASE3_ACCESS_MODE", "public")

    response = public_api.lambda_handler({"httpMethod": "GET", "path": "/api/runs"}, None)

    assert response["statusCode"] == 200
    assert _body(response) == {"runs": []}
    assert response["headers"]["X-Phase3-Static-Mode"] == "true"


@mock_aws
def test_handler_fails_closed_when_static_mode_is_unreadable(monkeypatch):
    _aws_store()
    monkeypatch.setenv("PHASE3_PUBLIC_RESULTS_BUCKET", BUCKET)
    monkeypatch.setenv("PHASE3_PUBLIC_INDEX_TABLE", TABLE)
    monkeypatch.setenv("PHASE3_FEATURE_TABLE", "missing-feature-table")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("PHASE3_ACCESS_MODE", "public")

    response = public_api.lambda_handler({"httpMethod": "GET", "path": "/api/runs"}, None)

    assert response["statusCode"] == 503
