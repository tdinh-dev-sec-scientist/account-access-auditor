"""End-to-end: provision the deliberately misconfigured lab, then audit it.

This is the test behind the "findings across a deliberately misconfigured test
account" claim. It runs the full pipeline -- provisioning, real boto3 clients,
collectors, normalization, rules, reporting -- and scores the result against the
expectations declared in ``lab/resources.py``.

The lab account is emulated in-process, not a live AWS account. What is real is
everything on the auditor's side of the endpoint.
"""

from __future__ import annotations

import pytest

from auditor.config import defaults
from lab.resources import PROFILES, expectations_for, negative_controls
from lab.run_benchmark import run_profile, score


@pytest.fixture(scope="module")
def benchmark():
    return {profile: run_profile(profile, "moto", "us-east-1", defaults()) for profile in PROFILES}


def test_primary_profile_detects_every_planted_misconfiguration(benchmark):
    report, scoring = benchmark["misconfigured"]
    assert scoring["false_negatives"] == 0, scoring["false_negative_detail"]
    assert scoring["true_positives"] == scoring["expected_count"]
    assert scoring["detection_rate"] == 1.0


def test_primary_profile_produces_no_unexpected_findings(benchmark):
    """Negative controls exist so a false positive fails the build."""
    _, scoring = benchmark["misconfigured"]
    assert scoring["false_positives"] == 0, scoring["unexpected_finding_detail"]


def test_no_trail_profile_detects_the_absent_trail(benchmark):
    report, scoring = benchmark["no-trail"]
    assert scoring["detection_rate"] == 1.0
    assert [f["rule_id"] for f in report["findings"]] == ["CT-001"]


def test_all_fourteen_rules_fire_somewhere_across_the_two_profiles(benchmark):
    """CT-001 cannot coexist with CT-002/003/004, hence the second profile."""
    from auditor.rules import registry

    fired = {rule for _, scoring in benchmark.values() for rule in scoring["rules_fired"]}
    assert fired == set(registry.rule_ids())


def test_negative_controls_appear_in_no_finding(benchmark):
    report, _ = benchmark["misconfigured"]
    clean_names = {control.name for control in negative_controls("misconfigured")}
    flagged = {
        f["resource"]
        for f in report["findings"]
        if any(f["resource"].endswith(name) or name in f["resource"] for name in clean_names)
    }
    assert not flagged, f"clean resources were reported: {flagged}"


def test_the_scan_completes_with_no_collection_errors(benchmark):
    report, _ = benchmark["misconfigured"]
    assert report["summary"]["collection_errors"] == 0, report["collection_errors"]


def test_every_severity_tier_is_exercised_by_the_lab(benchmark):
    report, _ = benchmark["misconfigured"]
    assert all(count > 0 for count in report["summary"]["by_severity"].values())


def test_the_audit_made_only_declared_read_only_api_calls(benchmark):
    from auditor.permissions import ALLOWED_OPERATIONS

    report, _ = benchmark["misconfigured"]
    observed = set(report["lab"]["api_calls_by_operation"])
    assert observed <= ALLOWED_OPERATIONS
    assert report["summary"]["api_call_count"] == sum(report["lab"]["api_calls_by_operation"].values())


def test_the_lab_environment_is_labelled_as_emulated(benchmark):
    """The report must not imply these findings came from a live AWS account."""
    report, _ = benchmark["misconfigured"]
    assert "not a live AWS account" in report["metadata"]["environment"]


def test_scoring_reports_a_severity_mismatch_as_a_distinct_failure():
    """The scorer must not accept a right-rule/wrong-tier match as a hit."""
    from auditor.models.finding import Finding
    from auditor.severity import Severity

    expected = expectations_for("no-trail")
    wrong_tier = [Finding.build("CT-001", "aws-account", "d")]
    wrong_tier[0].severity = Severity.LOW  # force an off-model tier for the test
    result = score(expected, wrong_tier)
    assert result["false_negatives"] == 1
    assert "detected but at severity LOW" in result["false_negative_detail"][0]["reason"]


def test_scoring_counts_an_extra_finding_as_a_false_positive():
    from auditor.models.finding import Finding

    result = score([], [Finding.build("S3-001", "surprise", "d")])
    assert result["false_positives"] == 1
    assert result["true_positives"] == 0
    assert result["detection_rate"] is None
