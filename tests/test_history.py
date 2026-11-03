from __future__ import annotations

import stat
import sqlite3

import pytest

from auditor.history import HistoryError, HistoryStore


def test_history_records_new_persistent_changed_and_resolved_findings(tmp_path):
    store = HistoryStore(tmp_path / "history")

    first = store.record_scan(_report("run-1", [_finding("a111111111111111", "HIGH", {"version": 1})]))
    second = store.record_scan(_report("run-2", [_finding("a111111111111111", "HIGH", {"version": 1})]))
    third = store.record_scan(_report("run-3", [_finding("a111111111111111", "CRITICAL", {"version": 2})]))
    fourth = store.record_scan(_report("run-4", []))

    assert [row["state"] for row in first["drift"]] == ["new"]
    assert [row["state"] for row in second["drift"]] == ["persistent"]
    assert [row["state"] for row in third["drift"]] == ["changed"]
    assert [row["state"] for row in fourth["drift"]] == ["resolved"]


def test_incomplete_snapshot_marks_absence_unknown_and_does_not_erase_baseline(tmp_path):
    store = HistoryStore(tmp_path / "history")
    finding = _finding("a111111111111111", "HIGH", {"version": 1})
    store.record_scan(_report("run-1", [finding]))

    partial = store.record_scan(_report("run-2", [], complete=False, status="UNKNOWN"))
    after_recovery = store.record_scan(_report("run-3", [finding]))
    resolved = store.record_scan(_report("run-4", []))

    assert [row["state"] for row in partial["drift"]] == ["unknown"]
    assert [row["state"] for row in after_recovery["drift"]] == ["persistent"]
    assert [row["state"] for row in resolved["drift"]] == ["resolved"]


def test_history_does_not_resolve_findings_in_regions_not_scanned(tmp_path):
    store = HistoryStore(tmp_path / "history")
    finding = _finding("a222222222222222", "MEDIUM", {"region": "us-west-2"}, region="us-west-2")
    store.record_scan(_report("run-1", [finding], regions=("us-east-1", "us-west-2")))

    partial_scope = store.record_scan(
        _report("run-2", [], regions=("us-east-1",), coverage_regions=("us-east-1",))
    )

    assert partial_scope["drift"] == []


def test_history_rejects_reusing_a_run_id_for_different_snapshot_data(tmp_path):
    store = HistoryStore(tmp_path / "history")
    store.record_scan(_report("run-1", []))

    with pytest.raises(HistoryError, match="already exists with different contents"):
        store.record_scan(_report("run-1", [_finding("a333333333333333", "LOW", {})]))


def test_history_files_are_private_and_dashboard_escapes_untrusted_finding_text(tmp_path):
    store = HistoryStore(tmp_path / "history")
    report = _report("run-1", [_finding("a444444444444444", "HIGH", {"title": "<script>alert(1)</script>"})])
    report["contract"]["findings"][0]["title"] = "<script>alert(1)</script>"
    enriched = store.record_scan(report)

    assert stat.S_IMODE(store.database_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in store.dashboard_html()
    assert "<script>alert(1)</script>" not in store.dashboard_html()
    assert enriched["summary"]["drift"]["new"] == 1


def test_history_is_idempotent_for_the_same_immutable_snapshot(tmp_path):
    store = HistoryStore(tmp_path / "history")
    report = _report("run-1", [_finding("a555555555555555", "HIGH", {})])

    first = store.record_scan(report)
    second = store.record_scan(report)

    assert first["drift"] == second["drift"]
    assert len(store.list_runs()) == 1


def test_history_orders_drift_by_scan_time_not_run_id(tmp_path):
    store = HistoryStore(tmp_path / "history")
    older = _report("run-zz", [_finding("a666666666666666", "HIGH", {})])
    newer = _report("run-aa", [_finding("a777777777777777", "LOW", {})])
    older["contract"]["scan_run"]["completed_at"] = "2026-11-01T00:00:00+00:00"
    newer["contract"]["scan_run"]["completed_at"] = "2026-11-02T00:00:00+00:00"
    store.record_scan(older)
    store.record_scan(newer)

    assert [row["run_id"] for row in store.list_drift()] == ["run-aa", "run-aa", "run-zz"]


def test_history_closes_database_connections(monkeypatch, tmp_path):
    from auditor import history

    opened = []
    connect = sqlite3.connect

    class TrackedConnection(sqlite3.Connection):
        was_closed = False

        def close(self):
            self.was_closed = True
            super().close()

    def tracked_connect(database, **kwargs):
        connection = connect(database, factory=TrackedConnection, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(history.sqlite3, "connect", tracked_connect)
    HistoryStore(tmp_path / "history")

    assert opened
    assert all(connection.was_closed for connection in opened)


def _finding(fingerprint: str, severity: str, evidence: dict, *, region="aws-global"):
    return {
        "fingerprint": fingerprint,
        "control_id": "IAM-004" if region == "aws-global" else "CT-001",
        "severity": severity,
        "title": evidence.get("title", "A finding"),
        "description": "Observed issue",
        "evidence": evidence,
        "remediation": "Correct the configuration",
        "account_ref": {"provider": "aws", "id": "123456789012"},
        "service": "iam" if region == "aws-global" else "cloudtrail",
        "region": region,
    }


def _report(
    run_id: str,
    findings: list[dict],
    *,
    complete=True,
    status="PASS",
    regions=("us-east-1",),
    coverage_regions=None,
):
    covered_regions = tuple(coverage_regions or regions)
    coverage = [
        {
            "account_id": "123456789012",
            "service": "iam",
            "region": "aws-global",
            "complete": complete,
        },
        *[
            {
                "account_id": "123456789012",
                "service": "cloudtrail",
                "region": region,
                "complete": complete,
            }
            for region in covered_regions
        ],
    ]
    return {
        "metadata": {
            "scan_source": "aws-fleet",
            "scan_coverage": coverage,
        },
        "summary": {},
        "collection_errors": [] if complete else [{"service": "CloudTrail", "operation": "list", "code": "AccessDenied"}],
        "findings": findings,
        "contract": {
            "scan_run": {
                "run_id": run_id,
                "status": status,
                "started_at": "2026-11-02T00:00:00+00:00",
                "completed_at": "2026-11-02T00:01:00+00:00",
                "account_refs": [{"provider": "aws", "id": "123456789012"}],
                "regions": list(regions),
            },
            "findings": findings,
        },
    }
