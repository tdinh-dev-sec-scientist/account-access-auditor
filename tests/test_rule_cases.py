"""The offline fixture suite: every case in tests/cases, run through the engine.

Each case asserts the *complete* set of findings, not merely that the expected
one appeared. That is what catches a rule firing twice, firing on the wrong
resource, or firing at the wrong tier -- the failure modes that make a scanner's
output untrustworthy but that a "at least one finding" assertion never sees.

No test in this file touches AWS.
"""

from __future__ import annotations

import pytest

from auditor.config import defaults
from auditor.rules import engine, registry
from tests.cases import CASES, cases_by_rule, covered_rule_ids


def _actual(case):
    findings = engine.evaluate_service(case.service, case.data, defaults(), run_id="test")
    return sorted((f.rule_id, f.resource, f.severity.value) for f in findings)


@pytest.mark.parametrize("case", CASES, ids=[case.case_id for case in CASES])
def test_case_produces_exactly_the_expected_findings(case):
    assert _actual(case) == case.expected_tuples, f"{case.case_id}: {case.description}"


@pytest.mark.parametrize("case", CASES, ids=[case.case_id for case in CASES])
def test_case_findings_are_well_formed(case):
    """Every finding a case produces carries the full schema, not a partial one."""
    findings = engine.evaluate_service(case.service, case.data, defaults(), run_id="test")
    for finding in findings:
        spec = registry.get(finding.rule_id)
        assert finding.severity in spec.severities
        assert finding.service == spec.service
        assert finding.resource_type == spec.resource_type
        assert finding.title and finding.description and finding.remediation
        assert finding.rationale, f"{finding.rule_id} lost its rationale"
        assert finding.run_id == "test"
        assert isinstance(finding.evidence, dict)
        assert "framework" in finding.compliance
        assert finding.fingerprint


def test_every_rule_has_at_least_one_vulnerable_and_one_clean_case():
    """A rule with no negative case is a rule nobody has proved can stay quiet."""
    by_rule = cases_by_rule()
    positive = {case.case_id for case in CASES if case.expected}
    negative = {case.case_id for case in CASES if not case.expected}

    missing_positive = [r for r, ids in by_rule.items() if not set(ids) & positive]
    missing_negative = [r for r, ids in by_rule.items() if not set(ids) & negative]

    assert not missing_positive, f"rules with no case that fires them: {missing_positive}"
    assert not missing_negative, f"rules with no case that must stay silent: {missing_negative}"


def test_fixture_suite_covers_every_registered_rule():
    assert set(covered_rule_ids()) == set(registry.rule_ids())


def test_case_ids_and_descriptions_are_unique():
    """Guards the fixture count against padding with near-duplicates."""
    assert len({case.case_id for case in CASES}) == len(CASES)
    assert len({case.description for case in CASES}) == len(CASES)


def test_evaluation_is_deterministic():
    """The same input twice produces byte-identical findings apart from timestamps."""
    for case in CASES:
        assert _actual(case) == _actual(case)


def test_unknown_service_is_rejected():
    with pytest.raises(KeyError, match="No rule set for service"):
        engine.evaluate_service("ec2", {}, defaults())
