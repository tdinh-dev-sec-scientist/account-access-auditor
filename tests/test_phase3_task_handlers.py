"""Failure paths of the Phase 3 scan task, snapshot writer, and kill switch."""

from __future__ import annotations

import json
from io import BytesIO

import boto3
import pytest
from moto import mock_aws

from phase3 import kill_switch, scan_task, snapshot_writer
from phase3.kill_switch import KillSwitchError
from phase3.private_snapshot_store import PrivateSnapshotError
from phase3.scan_task import ScanTaskError, configured_fleet, run_scan_task
from phase3.snapshot_writer import SnapshotWriterError
from tests.test_phase3_kill_switch import TOPIC, _event

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/AccountAccessAuditorReadOnly"
RUN_ID = "12345678-1234-1234-1234-123456789abc"
ENV = {
    "PHASE3_TARGET_ACCOUNT_ID": ACCOUNT,
    "PHASE3_TARGET_ROLE_ARN": ROLE,
    "PHASE3_SCAN_RUN_ID": RUN_ID,
    "PHASE3_SNAPSHOT_WRITER_FUNCTION": "phase3-snapshot-writer",
    "AWS_REGION": "us-east-1",
}
DRIFT = {"new": 0, "persistent": 0, "changed": 0, "resolved": 0, "unknown": 0}
RECEIPT = {
    "run_id": RUN_ID,
    "status": "PASS",
    "finding_count": 0,
    "snapshot_key": f"snapshots/{ACCOUNT}/2026/11/03/{RUN_ID}.json",
    "drift_counts": DRIFT,
}


def _session(**_kwargs):
    return object(), object()


def _scanner(*_args, **_kwargs):
    return {"contract": {"scan_run": {"run_id": RUN_ID}}}


class Writer:
    def __init__(self, response):
        self.response = response

    def invoke(self, **_kwargs):
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _ok(receipt) -> dict:
    return {"StatusCode": 200, "Payload": BytesIO(json.dumps(receipt).encode())}


def _run(env=None, *, scanner=_scanner, session=_session, writer=None):
    return run_scan_task(
        {**ENV, **(env or {})},
        session_factory=session,
        scanner=scanner,
        snapshot_writer=writer or Writer(_ok(RECEIPT)),
    )


# ----------------------------------------------------------------- scan task --


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"PHASE3_TARGET_ACCOUNT_ID": "12345"}, "account ID is invalid"),
        ({"AWS_REGION": "Mars"}, "AWS region is invalid"),
        ({"PHASE3_SCAN_REGIONS": "us-east-1,not a region"}, "demo target is invalid"),
    ],
)
def test_configured_fleet_rejects_invalid_targets(env, message):
    with pytest.raises(ScanTaskError, match=message):
        configured_fleet({**ENV, **env})


def test_scan_task_returns_the_writer_receipt():
    assert _run() == RECEIPT


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"PHASE3_SCAN_RUN_ID": "../escape"}, "run ID is invalid"),
        ({"PHASE3_FAIL_ON": "urgent"}, "finding threshold is invalid"),
        ({"PHASE3_SNAPSHOT_WRITER_FUNCTION": ""}, "writer is not configured"),
    ],
)
def test_scan_task_rejects_invalid_configuration(env, message):
    with pytest.raises(ScanTaskError, match=message):
        _run(env)


def test_scan_task_hides_session_and_scanner_failures():
    def broken_session(**_kwargs):
        raise RuntimeError("arn:aws:iam::123456789012:role/secret")

    def broken_scanner(*_args, **_kwargs):
        raise RuntimeError("raw scanner detail")

    with pytest.raises(ScanTaskError, match="session is unavailable") as session_error:
        _run(session=broken_session)
    with pytest.raises(ScanTaskError, match="fleet scan failed") as scanner_error:
        _run(scanner=broken_scanner)

    assert "secret" not in str(session_error.value)
    assert "raw scanner detail" not in str(scanner_error.value)


def test_scan_task_rejects_non_json_and_oversized_reports(monkeypatch):
    with pytest.raises(ScanTaskError, match="invalid report data"):
        _run(scanner=lambda *_a, **_k: {"value": float("nan")})
    monkeypatch.setattr(scan_task, "MAX_SNAPSHOT_WRITER_PAYLOAD_BYTES", 10)
    with pytest.raises(ScanTaskError, match="exceeds the private writer handoff limit"):
        _run()


@pytest.mark.parametrize(
    "response",
    [
        RuntimeError("throttled"),
        {"StatusCode": 500, "Payload": BytesIO(b"{}")},
        {"StatusCode": 200, "FunctionError": "Unhandled", "Payload": BytesIO(b"{}")},
        {"StatusCode": 200},
        {"StatusCode": 200, "Payload": BytesIO(b" " * (64 * 1024 + 1))},
        {"StatusCode": 200, "Payload": BytesIO(b"not json")},
    ],
)
def test_scan_task_rejects_failed_writer_invocations(response):
    with pytest.raises(ScanTaskError, match="could not be persisted"):
        _run(writer=Writer(response))


@pytest.mark.parametrize(
    "receipt",
    [
        [],
        {**RECEIPT, "extra": True},
        {**RECEIPT, "run_id": "other-run"},
        {**RECEIPT, "status": "RUNNING"},
        {**RECEIPT, "finding_count": True},
        {**RECEIPT, "finding_count": -1},
        {**RECEIPT, "snapshot_key": "snapshots/210987654321/run.json"},
        {**RECEIPT, "snapshot_key": f"snapshots/{ACCOUNT}/../other.json"},
        {**RECEIPT, "drift_counts": {"new": 0}},
        {**RECEIPT, "drift_counts": {**DRIFT, "new": -1}},
    ],
)
def test_scan_task_rejects_untrusted_writer_receipts(receipt):
    with pytest.raises(ScanTaskError, match="invalid receipt"):
        _run(writer=Writer(_ok(receipt)))


def test_scan_task_main_reports_errors_without_a_traceback(monkeypatch, capsys):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)

    assert scan_task.main() == 2
    output = json.loads(capsys.readouterr().out)
    assert output["status"] == "ERROR"
    assert output["code"] == "Phase3ScanTaskError"


def test_scan_task_main_prints_the_receipt(monkeypatch, capsys):
    monkeypatch.setattr(scan_task, "run_scan_task", lambda: RECEIPT)

    assert scan_task.main() == 0
    assert json.loads(capsys.readouterr().out) == RECEIPT


# ----------------------------------------------------------- snapshot writer --


class Store:
    def __init__(self, error: Exception | None = None, receipt=RECEIPT):
        self.error = error
        self.receipt = receipt

    def _result(self):
        if self.error:
            raise self.error
        return self.receipt

    def persist(self, _report):
        return self._result()

    def get_receipt(self, _run_id):
        return self._result()

    def record_failure(self, _run_id, _completed_at):
        return self._result()


@pytest.mark.parametrize(
    ("event", "message"),
    [
        ("report", "scan workflow event is invalid"),
        ({"kind": "scan_failure", "run_id": RUN_ID}, "scan failure event is invalid"),
        ({"kind": "get_receipt", "run_id": RUN_ID, "extra": 1}, "scan receipt event is invalid"),
    ],
)
def test_snapshot_writer_rejects_malformed_events(event, message):
    with pytest.raises(SnapshotWriterError, match=message):
        snapshot_writer.lambda_handler(event, None, store=Store())


def test_snapshot_writer_hides_store_failures():
    error = PrivateSnapshotError("bucket arn:aws:s3:::private")

    with pytest.raises(SnapshotWriterError, match="could not be persisted"):
        snapshot_writer.persist_report({}, store=Store(error))
    with pytest.raises(SnapshotWriterError, match="receipt is unavailable"):
        snapshot_writer.get_scan_receipt(RUN_ID, store=Store(error))
    with pytest.raises(SnapshotWriterError, match="failure could not be recorded"):
        snapshot_writer.record_scan_failure(RUN_ID, "2026-11-03T00:00:00+00:00", store=Store(error))


def test_snapshot_writer_rejects_a_non_object_receipt():
    with pytest.raises(SnapshotWriterError, match="receipt is invalid"):
        snapshot_writer.get_scan_receipt(RUN_ID, store=Store(receipt=["not", "a", "receipt"]))


def test_snapshot_writer_requires_configuration_without_an_injected_store():
    with pytest.raises(SnapshotWriterError, match="not configured"):
        snapshot_writer.persist_report({}, {})


def test_snapshot_writer_hides_session_failures():
    def broken_session(**_kwargs):
        raise RuntimeError("credential detail")

    env = {
        "PHASE3_TARGET_ACCOUNT_ID": ACCOUNT,
        "AWS_REGION": "us-east-1",
        "PHASE3_PRIVATE_SNAPSHOT_BUCKET": "private",
        "PHASE3_PRIVATE_RUN_INDEX_TABLE": "runs",
    }

    with pytest.raises(SnapshotWriterError, match="store is unavailable"):
        snapshot_writer.get_scan_receipt(RUN_ID, env, session_factory=broken_session)


# --------------------------------------------------------------- kill switch --


def test_kill_switch_handler_requires_configuration(monkeypatch):
    for name in ("PHASE3_BUDGET_KILL_TOPIC_ARN", "PHASE3_FEATURE_TABLE", "AWS_REGION"):
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(KillSwitchError, match="not configured"):
        kill_switch.lambda_handler(_event(), None)


def test_kill_switch_fails_closed_when_the_table_write_fails():
    class FailingTable:
        def update_item(self, **_kwargs):
            raise RuntimeError("ConditionalCheckFailed")

    with pytest.raises(KillSwitchError, match="could not be disabled"):
        kill_switch.disable_live_features(_event(), table=FailingTable(), expected_topic_arn=TOPIC)


@mock_aws
def test_kill_switch_handler_disables_live_features(monkeypatch):
    table = boto3.resource("dynamodb", region_name="us-east-1").create_table(
        TableName="phase3-features",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    table.put_item(Item={"pk": "PLATFORM", "sk": "CONFIG", "rin_enabled": True, "static_mode": False})
    monkeypatch.setenv("PHASE3_BUDGET_KILL_TOPIC_ARN", TOPIC)
    monkeypatch.setenv("PHASE3_FEATURE_TABLE", "phase3-features")
    monkeypatch.setenv("AWS_REGION", "us-east-1")

    assert kill_switch.lambda_handler(_event(), None) == {"status": "DISABLED"}
    item = table.get_item(Key={"pk": "PLATFORM", "sk": "CONFIG"})["Item"]
    assert item["rin_enabled"] is False
    assert item["static_mode"] is True
