"""Input validation and fail-closed behavior of the private Phase 3 snapshot store."""

from __future__ import annotations

import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from phase3.private_snapshot_store import PrivateSnapshotError, PrivateSnapshotStore, _dynamodb_count
from tests.test_phase3_private_snapshot_store import ACCOUNT_ID, _finding, _report, _store


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Operation")


class FailingTable:
    def __init__(self, code: str = "InternalServerError"):
        self.code = code

    def query(self, **_kwargs):
        raise _client_error(self.code)

    def put_item(self, **_kwargs):
        raise _client_error(self.code)

    def update_item(self, **_kwargs):
        raise _client_error(self.code)


def _offline_store(table) -> PrivateSnapshotStore:
    return PrivateSnapshotStore(
        bucket_name="private", account_id=ACCOUNT_ID, s3_client=None, run_index_table=table
    )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"bucket_name": "", "account_id": ACCOUNT_ID}, "bucket is invalid"),
        ({"bucket_name": "private", "account_id": "12345"}, "account ID is invalid"),
    ],
)
def test_store_rejects_invalid_configuration(kwargs, message):
    with pytest.raises(PrivateSnapshotError, match=message):
        PrivateSnapshotStore(s3_client=None, run_index_table=None, **kwargs)


@pytest.mark.parametrize("run_id", [None, "", "../escape", "x" * 65])
def test_receipt_and_failure_lookups_reject_invalid_run_ids(run_id):
    store = _offline_store(FailingTable())

    with pytest.raises(PrivateSnapshotError, match="run ID is invalid"):
        store.get_receipt(run_id)
    with pytest.raises(PrivateSnapshotError, match="run ID is invalid"):
        store.record_failure(run_id, "2026-11-03T12:00:00+00:00")


def test_index_failures_fail_closed():
    store = _offline_store(FailingTable())

    with pytest.raises(PrivateSnapshotError, match="receipt is unavailable"):
        store.get_receipt("run-1")
    with pytest.raises(PrivateSnapshotError, match="failure could not be recorded"):
        store.record_failure("run-1", "2026-11-03T12:00:00+00:00")
    with pytest.raises(PrivateSnapshotError, match="lock could not be acquired"):
        store.persist(_report("run-1", "2026-11-01T00:00:00+00:00", findings=[_finding()]))


@mock_aws
def test_recording_the_same_failure_twice_is_idempotent():
    store, _s3, _table = _store()

    first = store.record_failure("run-error", "2026-11-03T12:00:00Z")
    second = store.record_failure("run-error", "2026-11-03T12:00:00Z")

    assert (
        first
        == second
        == {"run_id": "run-error", "status": "ERROR", "completed_at": "2026-11-03T12:00:00+00:00"}
    )


@mock_aws
def test_a_missing_receipt_is_reported_as_unavailable(monkeypatch):
    store, _s3, _table = _store()
    monkeypatch.setattr("phase3.private_snapshot_store.time.sleep", lambda _seconds: None)

    with pytest.raises(PrivateSnapshotError, match="receipt is unavailable"):
        store.get_receipt("never-ran")


@mock_aws
def test_a_tampered_index_row_is_not_returned_as_a_receipt():
    store, _s3, table = _store()
    receipt = store.persist(_report("run-1", "2026-11-01T00:00:00+00:00", findings=[_finding()]))
    row = table.scan()["Items"]
    run_row = next(item for item in row if item.get("scan_run_id") == "run-1")
    table.update_item(
        Key={"account_id": run_row["account_id"], "sort_key": run_row["sort_key"]},
        UpdateExpression="SET snapshot_key = :key",
        ExpressionAttributeValues={":key": "snapshots/210987654321/other.json"},
    )

    assert receipt["run_id"] == "run-1"
    with pytest.raises(PrivateSnapshotError, match="receipt is invalid"):
        store.get_receipt("run-1")


@mock_aws
@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda report: report["contract"].pop("scan_run"), "does not match the fleet contract"),
        (
            lambda report: report["contract"]["scan_run"].update(run_id="bad run id!"),
            "run ID is invalid",
        ),
    ],
)
def test_persist_rejects_reports_outside_the_contract(change, message):
    store, _s3, _table = _store()
    report = _report("run-1", "2026-11-01T00:00:00+00:00", findings=[_finding()])
    change(report)

    with pytest.raises(PrivateSnapshotError, match=message):
        store.persist(report)


@pytest.mark.parametrize(
    ("value", "expected"),
    [(3, 3), (True, None), (-1, None), ("3", None)],
)
def test_dynamodb_counts_accept_only_non_negative_integers(value, expected):
    from decimal import Decimal

    assert _dynamodb_count(value) == expected
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        assert _dynamodb_count(Decimal(value)) == expected
    assert _dynamodb_count(Decimal("1.5")) is None
