"""The offline fixture-case registry.

A *case* is one scenario: a piece of normalized AWS state plus the exact set of
findings the rule engine must produce from it -- rule ID, resource, and severity
for each, and nothing else. Asserting the complete output rather than "at least
one finding fired" is what makes these cases able to catch a rule that fires
twice, fires on the wrong resource, or fires at the wrong tier.

Cases are data, so the suite can be counted, grouped, and exported:
``results/fixture_manifest.json`` is generated from this registry, which is
where the fixture-count metric comes from. Nothing here contacts AWS.

Case categories
    clean         a correct configuration that must produce nothing
    vulnerable    the misconfiguration the rule exists to find
    severity      the same issue at a different tier, to pin the ladder
    edge          boundary values, unknown state, optional fields absent
    malformed     responses that are wrong, not just bad
    multi         several resources at once, to pin per-resource attribution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

CATEGORIES = ("clean", "vulnerable", "severity", "edge", "malformed", "multi")


@dataclass(frozen=True)
class Expected:
    """One finding a case must produce."""

    rule_id: str
    resource: str
    severity: str

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.rule_id, self.resource, self.severity)


@dataclass(frozen=True)
class Case:
    """One offline fixture scenario."""

    case_id: str
    service: str  # iam | s3 | cloudtrail
    category: str
    covers: tuple[str, ...]  # rule IDs this case is about
    description: str
    data: dict[str, Any]  # normalized state, as a collector would emit it
    expected: tuple[Expected, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            raise ValueError(f"{self.case_id}: unknown category '{self.category}'")
        if not self.covers:
            raise ValueError(f"{self.case_id}: a case must name the rule(s) it covers")

    @property
    def expected_tuples(self) -> list[tuple[str, str, str]]:
        return sorted(item.as_tuple() for item in self.expected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "service": self.service,
            "category": self.category,
            "covers": list(self.covers),
            "description": self.description,
            "expected_finding_count": len(self.expected),
            "expected": [item.as_tuple() for item in self.expected],
        }


def build_registry() -> list[Case]:
    from . import cloudtrail_cases, iam_cases, s3_cases

    cases = iam_cases.CASES + s3_cases.CASES + cloudtrail_cases.CASES

    seen_ids = set()
    seen_descriptions = set()
    for case in cases:
        if case.case_id in seen_ids:
            raise ValueError(f"Duplicate case_id: {case.case_id}")
        if case.description in seen_descriptions:
            raise ValueError(
                f"Duplicate case description for {case.case_id}: two cases testing the "
                "same thing inflate the fixture count without adding coverage"
            )
        seen_ids.add(case.case_id)
        seen_descriptions.add(case.description)
    return list(cases)


CASES: list[Case] = build_registry()


def covered_rule_ids() -> list[str]:
    return sorted({rule for case in CASES for rule in case.covers})


def cases_by_rule() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for case in CASES:
        for rule in case.covers:
            result.setdefault(rule, []).append(case.case_id)
    return {rule: sorted(ids) for rule, ids in sorted(result.items())}


def cases_by_category() -> dict[str, int]:
    result = dict.fromkeys(CATEGORIES, 0)
    for case in CASES:
        result[case.category] += 1
    return result


def manifest() -> dict[str, Any]:
    """The machine-readable fixture manifest, written to results/."""
    return {
        "generated_by": "pytest tests/test_fixture_manifest.py",
        "total_cases": len(CASES),
        "total_expected_findings": sum(len(case.expected) for case in CASES),
        "by_category": cases_by_category(),
        "by_service": {
            service: sum(1 for case in CASES if case.service == service)
            for service in ("iam", "s3", "cloudtrail")
        },
        "cases_per_rule": {rule: len(ids) for rule, ids in cases_by_rule().items()},
        "rules_covered": covered_rule_ids(),
        "cases": [case.to_dict() for case in CASES],
    }
