"""Reporters: schema, flattening, determinism, and the ticket format."""

from __future__ import annotations

import csv
import json
import pathlib
import re
from html.parser import HTMLParser

import pytest

from auditor.models.finding import Finding
from auditor.models.report import build_report, exceeds, severity_counts
from auditor.redaction import mask_access_keys, redact_report
from auditor.reporters import (
    EXTENSIONS,
    WRITERS,
    csv_reporter,
    html_reporter,
    json_reporter,
    terminal,
    ticket,
)
from auditor.severity import Severity, ordered_names


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
    assert set(WRITERS) == set(EXTENSIONS) == {"json", "csv", "tickets", "html"}


# ----------------------------------------------------------------- HTML ----

# A bucket name, IAM user name, or policy Sid is chosen by whoever controls the
# audited account, and every one of these is a legal AWS name. They are the
# reason the HTML reporter escapes without exception: a findings report is read
# in a browser, so unescaped account data would make the report the payload.
# Markup payloads: these must never survive into the document unescaped.
HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "'><svg onload=alert(1)>",
]

# A URL payload is a different problem: escaping does not change it, because
# there is nothing to escape. It is inert as long as it never lands in an
# attribute that dereferences a URL -- which is what
# ``test_no_account_data_can_become_a_url`` pins.
HOSTILE_URL = "javascript:alert(1)"


@pytest.fixture
def hostile_report():
    """A report whose every free-text field carries markup."""
    findings = [
        Finding.build(
            "S3-002",
            HOSTILE[0],
            f"bucket {HOSTILE[1]} is public",
            {
                "bucket": HOSTILE[1],
                "grants": [{"uri": HOSTILE_URL}],
                "note": HOSTILE[2],
            },
            detected_at="2026-01-01T00:00:00+00:00",
        )
    ]
    return build_report(
        account_id=HOSTILE[0],
        region=HOSTILE[1],
        findings=findings,
        collection_errors=[
            {
                "service": "S3",
                "operation": HOSTILE[0],
                "resource": HOSTILE[1],
                "code": "AccessDenied",
                "category": "access_denied",
                "message": HOSTILE_URL,
            }
        ],
        services_scanned=["S3"],
        tool_version="1.0.0",
        environment_label=HOSTILE[2],
    )


class _Tags(HTMLParser):
    """Collects the document's real elements and attributes.

    Escaped account data such as ``&lt;img src=x&gt;`` is character data, not a
    tag, so a structural check sees through payloads that a regex would match.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attrs: list[tuple[str, str, str | None]] = []
        self.data: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.extend((tag, name, value) for name, value in attrs)

    def handle_data(self, data):
        self.data.append(data)


def _parse(document: str) -> _Tags:
    parser = _Tags()
    parser.feed(document)
    parser.close()
    return parser


def test_html_renders_every_finding_as_its_own_article(report):
    document = html_reporter.render(report)
    assert document.count('class="finding"') == len(report["findings"])
    for finding in report["findings"]:
        assert finding["rule_id"] in document
        assert finding["title"] in document


@pytest.mark.parametrize("fixture", ["report", "hostile_report"])
def test_html_contains_no_script_of_any_kind(fixture, request):
    """Filtering is CSS. A report handed to an auditor is not a program."""
    parsed = _parse(html_reporter.render(request.getfixturevalue(fixture)))
    assert "script" not in parsed.tags
    handlers = [a for _, name, _ in parsed.attrs if (a := name).startswith("on")]
    assert not handlers, f"inline event handler in the report: {handlers}"


def test_html_declares_a_policy_that_forbids_scripts(report):
    assert "default-src 'none'" in html_reporter.render(report)


def test_html_loads_nothing_from_the_network(report):
    """Self-contained: it must render identically offline and air-gapped."""
    document = html_reporter.render(report)
    assert "http://" not in document
    assert "https://" not in document
    assert "@import" not in document
    assert "url(" not in document


def test_hostile_account_data_is_escaped_rather_than_rendered(hostile_report):
    """The property that matters most: account-controlled strings cannot execute."""
    document = html_reporter.render(hostile_report)
    for payload in HOSTILE:
        assert payload not in document, f"unescaped payload in the report: {payload}"
    # Escaped, not dropped -- the reviewer still has to be able to read the name.
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in document
    assert "&lt;img src=x onerror=alert(1)&gt;" in document


def test_no_account_data_can_become_a_url(hostile_report):
    """The report dereferences no URL anywhere, so a `javascript:` name stays text.

    The auditor cannot sanitise a URL it does not emit, so the property is
    structural: the document has no href, no src, and no CSS url(), which is
    also what makes it render identically with no network.
    """
    document = html_reporter.render(hostile_report)
    assert HOSTILE_URL in "".join(_parse(document).data), "the name stays readable, just inert"
    dereferencing = [
        (tag, name)
        for tag, name, _ in _parse(document).attrs
        if name in {"href", "src", "action", "formaction", "srcset", "data"}
    ]
    assert not dereferencing, f"the report dereferences a URL: {dereferencing}"
    assert "url(" not in document


def test_hostile_data_does_not_break_out_of_an_attribute(hostile_report):
    """`data-severity` and `title` carry account data; a bare quote would escape them."""
    document = html_reporter.render(hostile_report)
    assert '"><img' not in document
    assert "&quot;&gt;&lt;img" in document


def test_html_lists_every_severity_tier_even_at_zero(report):
    """The ramp is multi-hue, so its scale legend is not optional."""
    document = html_reporter.render(report)
    for tier in ordered_names():
        assert Severity(tier).label in document
    assert document.count('class="swatch"') == len(ordered_names())


def test_html_severity_table_carries_every_number_the_bar_encodes(report):
    """The relief for the two tiers that sit under the contrast floor."""
    document = html_reporter.render(report)
    table = document.split("By severity")[1].split("</table>")[0]
    for tier, count in report["summary"]["by_severity"].items():
        assert Severity(tier).label in table
        assert f">{count}</td>" in table


def _bar(document: str) -> str:
    return document.split('<div class="bar"', 1)[1].split("</div>", 1)[0]


def test_distribution_bar_segments_are_proportional_to_the_counts(report):
    widths = [float(w) for w in re.findall(r"width: ([\d.]+)%", _bar(html_reporter.render(report)))]
    assert widths, "no bar segments rendered"
    assert sum(widths) == pytest.approx(100.0, abs=0.01)


def test_a_tier_with_no_findings_gets_no_bar_segment(report):
    """A zero-width segment would still show as a 2px gap and read as a tier."""
    bar = _bar(html_reporter.render(report))
    present = {t for t, c in report["summary"]["by_severity"].items() if c}
    assert len(re.findall(r"width: [\d.]+%", bar)) == len(present)


def test_a_report_with_no_findings_renders_an_empty_track_not_a_broken_bar():
    clean = build_report("123456789012", "us-east-1", [], services_scanned=["IAM"])
    assert "bar-empty" in _bar(html_reporter.render(clean))


def test_html_reports_collection_errors_above_the_findings(report):
    """Unknown is not clean, so the coverage gap is read before the findings."""
    document = html_reporter.render(report)
    assert document.index("Collection errors") < document.index('class="finding"')
    assert "denied-bucket" in document
    assert "AccessDenied" in document


def test_a_scan_with_no_collection_errors_says_so_explicitly(tmp_path):
    clean = build_report("123456789012", "us-east-1", [], services_scanned=["IAM"])
    document = html_reporter.render(clean)
    assert "Every declared read succeeded" in document


def test_html_for_a_clean_account_does_not_claim_the_account_is_clean():
    clean = build_report("123456789012", "us-east-1", [], services_scanned=["IAM"])
    document = html_reporter.render(clean)
    assert "No findings" in document
    assert "before reading this as a clean" in document
    assert 'class="finding"' not in document
    assert 'class="filters"' not in document  # nothing to filter


def test_html_rendering_is_deterministic(report):
    assert html_reporter.render(report) == html_reporter.render(report)


def test_html_survives_evidence_that_is_not_a_flat_string(report):
    report["findings"][0]["evidence"] = {
        "statements": [{"actions": ["*"], "sid": "FullAdmin"}],
        "nested": {"a": {"b": 1}},
        "long": "x" * 400,
    }
    document = html_reporter.render(report)
    assert "FullAdmin" in document
    assert "<pre>" in document


def test_html_writes_a_file_that_a_browser_would_accept(report, tmp_path):
    path = html_reporter.write(report, str(tmp_path / "nested" / "audit.html"))
    document = pathlib.Path(path).read_text(encoding="utf-8")
    assert document.startswith("<!DOCTYPE html>")
    assert document.rstrip().endswith("</html>")


def test_filter_controls_exist_for_every_tier_that_fired(report):
    document = html_reporter.render(report)
    for tier, count in report["summary"]["by_severity"].items():
        expected = f'id="f-sev-{tier.lower()}"'
        assert (expected in document) is bool(count)


def test_html_renders_a_finding_that_is_missing_its_optional_fields():
    """Reports are read back from JSON, including files written by older versions.

    A finding with no evidence, no rationale, no remediation, and a compliance
    block that names a control but no framework must still render -- the
    reporter's job is to show what it was given, not to require a full record.
    """
    sparse = build_report("123456789012", "us-east-1", [], services_scanned=["S3"])
    sparse["findings"] = [
        {
            "rule_id": "S3-001",
            "severity": "MEDIUM",
            "service": "S3",
            "resource": "some-bucket",
            "title": "Public Access Block is not fully enabled",
            "description": "Two of the four settings are off.",
            "evidence": {},
            "compliance": {"control_id": "2.1.4"},
            "fingerprint": "abc123",
            "detected_at": "2026-01-01T00:00:00+00:00",
        }
    ]
    sparse["summary"]["total_findings"] = 1
    sparse["summary"]["by_severity"]["MEDIUM"] = 1

    document = html_reporter.render(sparse)
    assert "some-bucket" in document
    assert "control 2.1.4" in document  # no framework name to shorten
    assert 'class="evidence"' not in document
    assert "Why it matters" not in document
    assert "Remediation" not in document
