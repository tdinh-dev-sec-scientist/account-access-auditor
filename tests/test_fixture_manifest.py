"""Generate and check the fixture manifest.

The fixture-count metric comes from ``results/fixture_manifest.json``, and that
file is written here rather than maintained by hand, so the number in the README
is whatever the suite actually contains at the moment it last ran.
"""

from __future__ import annotations

import json
import os

from auditor.rules import registry
from tests.cases import CASES, manifest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(REPO_ROOT, "results", "fixture_manifest.json")


def test_manifest_is_written_for_the_metric_evidence():
    document = manifest()
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")

    assert document["total_cases"] == len(CASES)
    assert document["total_cases"] > 0


def test_manifest_counts_add_up():
    document = manifest()
    assert sum(document["by_category"].values()) == document["total_cases"]
    assert sum(document["by_service"].values()) == document["total_cases"]
    assert document["total_expected_findings"] == sum(len(c.expected) for c in CASES)


def test_every_rule_has_several_cases_not_a_token_one():
    """One case per rule would be a checkbox, not a test suite."""
    per_rule = manifest()["cases_per_rule"]
    assert set(per_rule) == set(registry.rule_ids())
    thin = {rule: count for rule, count in per_rule.items() if count < 3}
    assert not thin, f"rules with fewer than three fixture cases: {thin}"


def test_all_six_case_categories_are_represented():
    by_category = manifest()["by_category"]
    empty = [name for name, count in by_category.items() if count == 0]
    assert not empty, f"unused fixture categories: {empty}"


def test_each_service_is_meaningfully_covered():
    by_service = manifest()["by_service"]
    assert all(count >= 10 for count in by_service.values()), by_service
