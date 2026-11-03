from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("collect_metrics", ROOT / "scripts/collect_metrics.py")
assert SPEC and SPEC.loader
collect_metrics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collect_metrics)


def test_readme_metrics_replacement_preserves_surrounding_text():
    original = "before\n<!-- BEGIN GENERATED METRICS -->\nold values\n<!-- END GENERATED METRICS -->\nafter\n"

    updated = collect_metrics.replace_readme_metrics(original, "| Metric | Value |")

    assert updated == (
        "before\n"
        "<!-- BEGIN GENERATED METRICS -->\n\n| Metric | Value |\n\n<!-- END GENERATED METRICS -->\n"
        "after\n"
    )


def test_collect_preserves_test_process_exit_code_for_release_gate(monkeypatch):
    fixtures = {"total_cases": 0, "by_category": {}, "by_service": {}, "rules_covered": []}
    audit = {
        "metadata": {"environment": "test"},
        "summary": {
            "total_findings": 0,
            "by_severity": {},
            "by_service": {},
            "by_rule": {},
            "affected_resource_count": 0,
            "resources_scanned": 0,
            "api_call_count": 0,
            "duration_seconds": 0,
        },
    }
    scoring = {
        "profiles": [
            {
                "profile": "misconfigured",
                "detection_rate": 1,
                "true_positives": 0,
                "false_negatives": 0,
                "false_positives": 0,
            }
        ]
    }
    metric_sources = {
        "schema_version": "1.0.0",
        "tool_version": "0.1.0",
        "metrics": {
            "security_rules": {
                "value": 999,
                "source_file": "auditor/rules/registry.py",
                "source_command": "python -m auditor.cli list-rules",
            },
            "tests": {
                "total": 5,
                "passed": 5,
                "failed": 0,
                "skipped": 0,
                "exit_code": 0,
                "source_command": "pytest",
            },
            "cis_mapped_rules": {
                "value": 3,
                "of": 4,
                "benchmark_version": "3.0.0",
                "status_counts": {"mapped": 3, "partial": 1, "unmapped": 0},
                "source_file": "compliance/cis_mapping.json",
                "source_command": "python -m auditor.cli list-rules",
            },
            "self_audit": {
                "value": "PASS",
                "wildcard_findings": 0,
                "declared_operations_all_read_only": True,
                "source_file": "policies/auditor-readonly-policy.json",
                "source_command": "python -m auditor.cli validate-policy",
            },
        },
    }
    monkeypatch.setattr(
        collect_metrics,
        "coverage_metrics",
        lambda _: {
            "detection_percent": 0,
            "detection_statements": 0,
            "detection_branches": 0,
            "detection_modules": [],
            "overall_percent": 0,
            "overall_branch_inclusive_percent": 85.9,
            "overall_statements": 0,
        },
    )
    monkeypatch.setattr(
        collect_metrics,
        "_load",
        lambda name: {
            "fixture_manifest.json": fixtures,
            "aws_audit_results.json": audit,
            "expected_vs_actual.json": scoring,
            "metrics_sources.json": metric_sources,
        }.get(name, {}),
    )
    monkeypatch.setattr(
        collect_metrics,
        "test_counts",
        lambda: {"total": 5, "passed": 5, "failed": 0, "skipped": 0, "exit_code": 0},
    )
    monkeypatch.setattr(
        collect_metrics,
        "self_audit",
        lambda: {"passed": True, "wildcard_findings": [], "declared_operations_all_read_only": True},
    )

    document = collect_metrics.collect()

    assert document["metrics"]["tests"]["exit_code"] == 0
    assert document["metrics"]["security_rules"]["value"] == 999
    assert document["metrics"]["security_rules"]["evidence"] == "results/metrics_sources.json"
    assert document["metrics"]["cis_mapped_rules"]["evidence"] == "results/metrics_sources.json"
    assert document["metrics"]["self_audit"]["evidence"] == "results/metrics_sources.json"
    table = collect_metrics.render_table(document)
    assert "PASS (exact count in results/metrics.json)" in table
    assert "Exact percentage in results/metrics.json" in table
    assert "FAIL (86% CI floor)" in table
    assert all("`results/" in row for row in table.splitlines()[2:])


def test_source_metrics_records_test_and_policy_inputs_as_result_artifact(monkeypatch):
    monkeypatch.setattr(
        collect_metrics,
        "test_counts",
        lambda: {"total": 8, "passed": 7, "failed": 1, "skipped": 2, "exit_code": 1},
    )
    monkeypatch.setattr(
        collect_metrics,
        "self_audit",
        lambda: {
            "passed": False,
            "wildcard_findings": [{"rule_id": "IAM-004"}],
            "declared_operations_all_read_only": True,
        },
    )

    artifact = collect_metrics.source_metrics()

    assert artifact["schema_version"] == "1.0.0"
    assert artifact["metrics"]["tests"]["exit_code"] == 1
    assert artifact["metrics"]["tests"]["skipped"] == 2
    assert artifact["metrics"]["self_audit"]["value"] == "FAIL"
    assert artifact["metrics"]["self_audit"]["wildcard_findings"] == 1


@pytest.mark.parametrize(
    "readme",
    [
        "No generated block",
        "<!-- BEGIN GENERATED METRICS -->\nmissing end",
        "<!-- END GENERATED METRICS -->\n<!-- BEGIN GENERATED METRICS -->",
        "<!-- BEGIN GENERATED METRICS --><!-- BEGIN GENERATED METRICS --><!-- END GENERATED METRICS -->",
    ],
)
def test_readme_metrics_replacement_rejects_missing_duplicate_or_reversed_markers(readme):
    with pytest.raises(ValueError):
        collect_metrics.replace_readme_metrics(readme, "| Metric | Value |")
