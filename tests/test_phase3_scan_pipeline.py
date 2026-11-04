from __future__ import annotations

import pytest

from phase3.snapshot_writer import SnapshotWriterError, persist_report
from phase3.snapshot_writer import lambda_handler as snapshot_writer_handler

ENV = {
    "PHASE3_TARGET_ACCOUNT_ID": "123456789012",
    "AWS_REGION": "us-east-1",
}


def test_snapshot_writer_returns_only_store_receipt_and_rejects_non_object_reports():
    receipt = {"run_id": "r1", "status": "FAIL", "finding_count": 1}
    seen = []

    class Store:
        def persist(self, report):
            seen.append(report)
            return receipt

    report = {"private_evidence": {"email": "private@example.invalid"}}
    assert persist_report(report, ENV, store=Store()) is receipt
    assert seen == [report]

    with pytest.raises(SnapshotWriterError, match="must be an object"):
        persist_report([], ENV, store=Store())


def test_snapshot_writer_lambda_requires_internal_report_envelope():
    class Store:
        def persist(self, report):
            return {"run_id": report["run_id"], "status": "PASS"}

    with pytest.raises(SnapshotWriterError, match="workflow event is invalid"):
        snapshot_writer_handler({"untrusted": "event"}, object())


def test_snapshot_writer_can_record_failure_without_persisting_untrusted_error_text():
    calls = []

    class Store:
        def record_failure(self, run_id, completed_at):
            calls.append((run_id, completed_at))
            return {"run_id": run_id, "status": "ERROR", "completed_at": completed_at}

    result = snapshot_writer_handler(
        {
            "kind": "scan_failure",
            "run_id": "run-2",
            "completed_at": "2026-11-03T12:00:00+00:00",
        },
        object(),
        store=Store(),
    )

    assert result == {"run_id": "run-2", "status": "ERROR", "completed_at": "2026-11-03T12:00:00+00:00"}
    assert calls == [("run-2", "2026-11-03T12:00:00+00:00")]


def test_snapshot_writer_rejects_raw_failure_details():
    with pytest.raises(SnapshotWriterError, match="failure event is invalid"):
        snapshot_writer_handler(
            {"kind": "scan_failure", "run_id": "run-2", "completed_at": "2026-11-03T12:00:00+00:00", "error": "raw"},
            object(),
        )


def test_snapshot_writer_reads_one_completed_receipt_by_run_id():
    expected = {"run_id": "run-2", "status": "PASS", "finding_count": 0}

    class Store:
        def get_receipt(self, run_id):
            assert run_id == "run-2"
            return expected

    assert snapshot_writer_handler({"kind": "get_receipt", "run_id": "run-2"}, object(), store=Store()) == expected
