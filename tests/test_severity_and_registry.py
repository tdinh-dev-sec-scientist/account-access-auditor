"""The severity model and the rule registry: the two things every rule depends on."""

from __future__ import annotations

import pytest

from auditor import severity
from auditor.models.finding import Finding
from auditor.rules import registry
from auditor.severity import Severity

# ------------------------------------------------------------- severity ----


def test_five_tiers_in_urgency_order():
    assert severity.ordered_names() == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert len(list(Severity)) == 5


def test_ranks_are_strictly_decreasing_in_urgency():
    ranks = [s.rank for s in severity.ordered()]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == 5


@pytest.mark.parametrize(
    "text,expected",
    [
        ("high", Severity.HIGH),
        ("HIGH", Severity.HIGH),
        ("  Critical ", Severity.CRITICAL),
        ("info", Severity.INFO),
        ("Low", Severity.LOW),
        ("medium", Severity.MEDIUM),
    ],
)
def test_parsing_is_case_and_whitespace_insensitive(text, expected):
    assert Severity.from_string(text) is expected


@pytest.mark.parametrize("bad", ["urgent", "", "sev1", "none"])
def test_unknown_severity_names_are_rejected_with_the_valid_options(bad):
    with pytest.raises(ValueError, match="CRITICAL"):
        Severity.from_string(bad)


def test_non_string_severity_is_rejected():
    with pytest.raises(ValueError, match="must be a string"):
        Severity.from_string(3)


def test_at_least_compares_by_urgency_not_alphabetically():
    assert Severity.CRITICAL.at_least(Severity.LOW)
    assert Severity.HIGH.at_least(Severity.HIGH)
    assert not Severity.LOW.at_least(Severity.HIGH)


def test_counts_are_zero_filled_so_every_tier_appears():
    assert severity.counts([Severity.HIGH, Severity.HIGH]) == {
        "CRITICAL": 0,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }


def test_most_severe_picks_the_most_urgent():
    assert severity.most_severe([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL
    assert severity.most_severe([]) is None


def test_labels_are_human_facing():
    assert Severity.INFO.label == "Informational"
    assert Severity.CRITICAL.label == "Critical"


# ------------------------------------------------------------- registry ----


def test_registry_contains_exactly_fourteen_rules():
    assert len(registry.REGISTRY) == registry.EXPECTED_RULE_COUNT == 14


def test_rule_ids_are_unique_and_prefixed_by_service():
    prefixes = {"IAM": "IAM-", "S3": "S3-", "CloudTrail": "CT-"}
    for spec in registry.all_rules():
        assert spec.rule_id.startswith(prefixes[spec.service]), spec.rule_id
    assert len(set(registry.rule_ids())) == 14


def test_every_rule_declares_complete_metadata():
    for spec in registry.all_rules():
        assert spec.title and spec.summary
        assert len(spec.rationale) > 60, f"{spec.rule_id} rationale is too thin to be useful"
        assert len(spec.remediation) > 30, f"{spec.rule_id} remediation is not actionable"
        assert spec.severities, spec.rule_id
        assert spec.default_severity in spec.severities
        assert spec.required_permissions, f"{spec.rule_id} declares no permissions"


def test_declared_severities_are_ordered_most_urgent_first():
    for spec in registry.all_rules():
        ranks = [s.rank for s in spec.severities]
        assert ranks == sorted(ranks), spec.rule_id


def test_rules_span_all_three_services():
    assert len(registry.by_service("iam")) == 6
    assert len(registry.by_service("s3")) == 4
    assert len(registry.by_service("cloudtrail")) == 4
    assert registry.by_service("ec2") == []


def test_all_five_tiers_are_reachable_by_some_rule():
    """A five-tier model with an unreachable tier is really a four-tier model."""
    declared = {s for spec in registry.all_rules() for s in spec.severities}
    assert declared == set(Severity)


def test_registry_permissions_are_a_subset_of_the_granted_policy():
    from auditor.permissions import ALLOWED_IAM_ACTIONS

    missing = sorted(set(registry.required_permissions()) - set(ALLOWED_IAM_ACTIONS))
    assert not missing, f"rules need permissions the policy does not grant: {missing}"


def test_unknown_rule_id_raises_with_the_known_ids():
    with pytest.raises(KeyError, match="IAM-001"):
        registry.get("IAM-999")


def test_registry_entry_rejects_a_default_outside_its_declared_tiers():
    with pytest.raises(ValueError, match="not in declared severities"):
        registry.RuleSpec(
            rule_id="X-1",
            title="t",
            service="IAM",
            resource_type="x",
            summary="s",
            rationale="r",
            remediation="m",
            default_severity=Severity.LOW,
            severities=(Severity.HIGH,),
        )


# ------------------------------------------------- severity determinism ----


def test_a_rule_cannot_emit_a_tier_it_did_not_declare():
    """The core determinism guarantee of the five-tier model."""
    with pytest.raises(ValueError, match="may only emit"):
        Finding.build("IAM-001", "user:x", "d", severity=Severity.INFO)


def test_findings_default_to_the_registry_severity():
    assert Finding.build("IAM-004", "user:x/p", "d").severity is Severity.CRITICAL
    assert Finding.build("S3-001", "b", "d").severity is Severity.MEDIUM


def test_finding_inherits_static_metadata_from_the_registry():
    spec = registry.get("S3-003")
    finding = Finding.build("S3-003", "bucket", "described")
    assert finding.title == spec.title
    assert finding.remediation == spec.remediation
    assert finding.rationale == spec.rationale
    assert finding.service == spec.service
    assert finding.resource_type == spec.resource_type


def test_title_and_remediation_can_be_overridden_per_finding():
    finding = Finding.build("S3-002", "b", "d", title="custom", remediation="do this")
    assert finding.title == "custom" and finding.remediation == "do this"


def test_fingerprint_is_stable_across_runs_and_ignores_timestamp():
    a = Finding.build("IAM-001", "user:x", "one", detected_at="2026-01-01T00:00:00+00:00")
    b = Finding.build("IAM-001", "user:x", "two", detected_at="2026-06-01T00:00:00+00:00")
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != Finding.build("IAM-001", "user:y", "one").fingerprint


def test_findings_sort_by_severity_then_service_then_rule_then_resource():
    findings = [
        Finding.build("S3-001", "b2", "d"),
        Finding.build("IAM-004", "user:a/p", "d"),
        Finding.build("S3-001", "b1", "d"),
    ]
    ordered = sorted(findings, key=lambda f: f.sort_key)
    assert [f.rule_id for f in ordered] == ["IAM-004", "S3-001", "S3-001"]
    assert [f.resource for f in ordered][1:] == ["b1", "b2"]


def test_finding_serialises_severity_as_a_plain_string():
    data = Finding.build("IAM-001", "user:x", "d").to_dict()
    assert data["severity"] == "HIGH" and isinstance(data["severity"], str)
    assert set(data) >= {
        "rule_id",
        "severity",
        "service",
        "resource",
        "resource_type",
        "title",
        "description",
        "rationale",
        "remediation",
        "evidence",
        "compliance",
        "detected_at",
        "run_id",
        "status",
        "fingerprint",
    }
