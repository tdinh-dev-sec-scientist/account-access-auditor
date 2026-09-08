"""Reporters: schema, flattening, determinism, and the ticket format."""

from __future__ import annotations

import csv
import json

import pytest

from auditor.models.finding import Finding
from auditor.models.report import build_report, exceeds, severity_counts
from auditor.redaction import mask_access_keys, redact_report
from auditor.reporters import EXTENSIONS, WRITERS, csv_reporter, json_reporter, terminal, ticket


@pytest.fixture
def report():
    findings = [
        Finding.build(
            "IAM-004",
            "user:admin/full",
            "wildcard policy",
            {"policy_name": "full", "username": "admin"},
            detected_at="2026-01-01T00:00:00+00:00",
        ),
        Finding.build(
            "S3-001",
            "public-bucket",
            "pab off",
            {"bucket": "public-bucket"},
            detected_at="2026-01-01T00:00:00+00:00",
        ),
        Finding.build(
            "IAM-006",
            "user:svc",
            "programmatic",
            {"username": "svc"},
            detected_at="2026-01-01T00:00:00+00:00",
        ),
    ]
    return build_report(
        account_id="123456789012",
        region="us-east-1",
        findings=findings,
        collection_errors=[
            {
                "service": "S3",
                "operation": "s3:GetBucketAcl",
                "resource": "denied-bucket",
                "code": "AccessDenied",
                "category": "access_denied",
                "message": "denied",
            }
        ],
        services_scanned=["IAM", "S3"],
        tool_version="1.0.0",
        run_id="run-1",
        resource_counts={"iam_users": 2, "s3_buckets": 3},
        duration_seconds=1.23456,
        api_call_count=42,
    )


# ------------------------------------------------------------- report ------


def test_report_metadata_records_the_provenance_of_the_scan(report):
    metadata = report["metadata"]
    assert metadata["account_id"] == "123456789012"
    assert metadata["services_scanned"] == ["IAM", "S3"]
    assert metadata["run_id"] == "run-1"
    assert metadata["read_only"] is True
    assert metadata["severity_model"] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert "v3.0.0" in metadata["compliance_framework"]
    assert metadata["cis_mapped_rule_count"] == 11


def test_summary_tallies_every_axis_a_reader_needs(report):
    summary = report["summary"]
    assert summary["total_findings"] == 3
    assert summary["by_severity"] == {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "INFO": 1}
    assert summary["by_service"] == {"IAM": 2, "S3": 1}
    assert summary["by_rule"] == {"IAM-004": 1, "IAM-006": 1, "S3-001": 1}
    assert summary["affected_resource_count"] == 3
    assert summary["resources_scanned"] == {"iam_users": 2, "s3_buckets": 3}
    assert summary["api_call_count"] == 42 and summary["duration_seconds"] == 1.235


def test_collection_errors_are_reported_separately_from_findings(report):
    """A resource that could not be read is a coverage gap, not a clean result."""
    assert report["summary"]["collection_errors"] == 1
    assert report["collection_errors"][0]["code"] == "AccessDenied"
    assert all(f["rule_id"] != "AccessDenied" for f in report["findings"])


def test_findings_are_sorted_most_urgent_first(report):
    assert [f["severity"] for f in report["findings"]] == ["CRITICAL", "MEDIUM", "INFO"]


def test_severity_counts_are_zero_filled():
    assert severity_counts([]) == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}


def test_exceeds_drives_the_fail_on_threshold():
    findings = [Finding.build("S3-001", "b", "d")]  # MEDIUM
    assert exceeds(findings, "medium") and exceeds(findings, "low")
    assert not exceeds(findings, "high")
    assert not exceeds([], "info")


# --------------------------------------------------------------- JSON ------


def test_json_output_round_trips(report, tmp_path):
    path = json_reporter.write(report, str(tmp_path / "out" / "r.json"))
    with open(path, encoding="utf-8") as handle:
        assert json.load(handle) == report


def test_json_rendering_is_deterministic(report):
    assert json_reporter.render(report) == json_reporter.render(report)


def test_json_survives_non_serialisable_evidence(tmp_path):
    import datetime as dt

    finding = Finding.build("S3-001", "b", "d", {"when": dt.datetime(2026, 1, 1)})
    payload = json_reporter.render(build_report(None, None, [finding]))
    assert "2026-01-01" in payload


# ---------------------------------------------------------------- CSV ------


def test_csv_has_a_stable_column_set_and_one_row_per_finding(report, tmp_path):
    path = csv_reporter.write(report, str(tmp_path / "r.csv"))
    with open(path, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert list(rows[0]) == csv_reporter.COLUMNS
    assert len(rows) == 3


def test_csv_flattens_compliance_into_filterable_columns(report):
    rows = csv_reporter.rows(report)
    critical = next(r for r in rows if r["rule_id"] == "IAM-004")
    assert critical["compliance_control"] == "1.16"
    assert critical["compliance_status"] == "mapped"
    unmapped = next(r for r in rows if r["rule_id"] == "IAM-006")
    assert unmapped["compliance_control"] == ""


def test_csv_keeps_evidence_as_sorted_json_rather_than_dropping_it(report):
    row = csv_reporter.rows(report)[0]
    assert json.loads(row["evidence"])["policy_name"] == "full"
    assert row["evidence"] == json.dumps(json.loads(row["evidence"]), sort_keys=True)


def test_csv_handles_a_report_with_no_findings(tmp_path):
    path = csv_reporter.write(build_report(None, None, []), str(tmp_path / "empty.csv"))
    with open(path, encoding="utf-8") as handle:
        assert handle.read().strip() == ",".join(csv_reporter.COLUMNS)


# ------------------------------------------------------------- tickets -----


def test_ticket_contains_every_field_a_triager_needs(report):
    text = ticket.render(report)
    for heading in [
        "Ticket ID:",
        "Category:",
        "Priority:",
        "AWS Account:",
        "Affected Resource:",
        "Issue:",
        "Detail:",
        "Why It Matters:",
        "Evidence:",
        "Recommended Action:",
        "Compliance Reference:",
        "Detection Rule:",
        "Status:",
    ]:
        assert heading in text, heading


def test_ticket_priority_uses_the_human_severity_label(report):
    text = ticket.render(report)
    assert "Informational" in text  # the INFO finding
    assert "Critical" in text


def test_ticket_ids_are_unique_and_carry_the_rule_id(report):
    text = ticket.render(report)
    ids = [line.split("Ticket ID: ")[1] for line in text.splitlines() if line.startswith("Ticket ID:")]
    assert len(set(ids)) == 3
    assert ids[0].startswith("AUTO-IAM-004-20260101-")


def test_unmapped_rules_say_so_rather_than_showing_a_blank_control(report):
    text = ticket.render(report)
    assert "No mapped control in the referenced benchmark version." in text


def test_ticket_output_for_a_clean_account_says_so(tmp_path):
    path = ticket.write(build_report(None, None, []), str(tmp_path / "t.txt"))
    with open(path, encoding="utf-8") as handle:
        assert "No findings" in handle.read()


def test_ticket_with_no_evidence_does_not_render_an_empty_block():
    finding = Finding.build("CT-001", "aws-account", "no trail").to_dict()
    finding["evidence"] = {}
    assert "(none recorded)" in ticket.format_ticket(finding, 1)


# ------------------------------------------------------------ terminal -----


def test_terminal_summary_lists_every_tier_even_at_zero(report, capsys):
    terminal.print_summary(report, ["reports/a.json"])
    out = capsys.readouterr().out
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL"]:
        assert tier in out
    assert "reports/a.json" in out
    assert "coverage gap" in out  # the collection-error caveat


def test_terminal_truncates_long_resource_names(report, capsys):
    long_name = "x" * 80
    report["findings"][0]["resource"] = long_name
    terminal.print_summary(report)
    assert long_name not in capsys.readouterr().out


def test_terminal_rule_listing_shows_the_cis_control(capsys):
    from auditor.rules import all_rules

    terminal.print_rules([r.to_dict() for r in all_rules()])
    out = capsys.readouterr().out
    assert "14 rules." in out and "1.16" in out


def test_terminal_header_reports_unknown_account_rather_than_blank(capsys):
    terminal.print_header(None, None)
    out = capsys.readouterr().out
    assert "unknown" in out and "default" in out


# ------------------------------------------------------------ redaction ----

# Assembled from parts so the repository's own credential scanner
# (test_security_properties.py) stays strict about literal key IDs in source.
EXAMPLE_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"


def test_access_key_ids_are_masked_keeping_the_last_four():
    assert mask_access_keys(f"key {EXAMPLE_KEY_ID} here") == "key AKIA…MPLE here"


def test_redaction_reaches_nested_evidence_and_never_mutates_the_original(report):
    report["findings"][0]["evidence"]["access_key_id"] = EXAMPLE_KEY_ID
    redacted = redact_report(report)
    assert redacted["findings"][0]["evidence"]["access_key_id"] == "AKIA…MPLE"
    assert report["findings"][0]["evidence"]["access_key_id"] == EXAMPLE_KEY_ID
    assert redacted["metadata"]["redacted"]["access_key_ids"] is True


def test_account_id_redaction_is_opt_in(report):
    assert redact_report(report)["metadata"]["account_id"] == "123456789012"
    assert redact_report(report, account_ids=True)["metadata"]["account_id"] == "1234…12"


def test_redaction_changes_no_finding_counts(report):
    redacted = redact_report(report, access_keys=True, account_ids=True)
    assert redacted["summary"] == report["summary"]


# --------------------------------------------------------------- wiring ----


def test_every_output_format_has_a_writer_and_an_extension():
    assert set(WRITERS) == set(EXTENSIONS) == {"json", "csv", "tickets"}
