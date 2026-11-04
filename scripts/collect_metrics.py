"""Derive every headline metric from the artifacts, and fail if one is missing.

Nothing in this script computes a number by hand. Each metric names the artifact
it came from and the command that produced that artifact, so any claim made
about this project can be traced to a file and re-derived from a clean checkout.

    python -m pytest --cov=auditor --cov=phase3 --cov-report=json:results/coverage.json
    python -m lab.run_benchmark
    python scripts/collect_metrics.py

Writes ``results/metrics.json``, ``results/metrics_table.md``, and the generated
metrics block in ``README.md``. Pass ``--check`` in CI to verify that the
committed README already contains the newly derived table.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

RESULTS = os.path.join(REPO_ROOT, "results")
README_PATH = os.path.join(REPO_ROOT, "README.md")
README_METRICS_START = "<!-- BEGIN GENERATED METRICS -->"
README_METRICS_END = "<!-- END GENERATED METRICS -->"

# Modules that implement detection: collection is deliberately excluded, because
# "the detection logic is unit-tested offline" is a claim about these files.
DETECTION_PREFIXES = (
    "auditor/rules/",
    "auditor/normalize/",
    "auditor/models/",
    "auditor/iac/",
    "auditor/severity.py",
)


class MissingArtifact(RuntimeError):
    """A metric was requested but the artifact backing it does not exist."""


def _load(name: str) -> dict[str, Any]:
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        raise MissingArtifact(
            f"{os.path.relpath(path, REPO_ROOT)} is missing. "
            "Run the tests with --cov-report=json:results/coverage.json and python -m lab.run_benchmark first."
        )
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _percent(covered: int, total: int) -> float | None:
    return round(100.0 * covered / total, 2) if total else None


def coverage_metrics(document: dict[str, Any]) -> dict[str, Any]:
    """Overall coverage, plus the subset that is detection logic."""
    files = document["files"]
    detection = {
        name: data for name, data in files.items() if name.replace(os.sep, "/").startswith(DETECTION_PREFIXES)
    }

    def totals(selection):
        """Branch-inclusive, matching the .coveragerc setting.

        Statement-only coverage would read higher and would not be the number
        the test run reports, so the two are computed the same way here.
        """
        summaries = [d["summary"] for d in selection.values()]
        measured = sum(s["num_statements"] + s["num_branches"] for s in summaries)
        covered = sum(s["covered_lines"] + s["covered_branches"] for s in summaries)
        return measured, covered

    all_measured, all_covered = totals(files)
    det_measured, det_covered = totals(detection)

    return {
        "overall_percent": round(document["totals"]["percent_covered"], 2),
        "overall_statements": sum(d["summary"]["num_statements"] for d in files.values()),
        "overall_branch_inclusive_percent": _percent(all_covered, all_measured),
        "detection_percent": _percent(det_covered, det_measured),
        "detection_statements": sum(d["summary"]["num_statements"] for d in detection.values()),
        "detection_branches": sum(d["summary"]["num_branches"] for d in detection.values()),
        "detection_modules": sorted(detection),
        "branch_coverage_enabled": True,
    }


def test_counts() -> dict[str, Any]:
    """Re-run the suite so the pass count is measured, not remembered."""
    # -p no:cacheprovider keeps the metric run from touching .pytest_cache.
    # --no-header keeps the trailer as the last line so it can be parsed.
    proc = subprocess.run(
        # -o addopts= clears pytest.ini's own -q; two -q flags suppress the
        # very summary line this needs to read.
        [
            sys.executable,
            "-m",
            "pytest",
            "-o",
            "addopts=",
            "--no-header",
            "-p",
            "no:cacheprovider",
            "--tb=no",
            "-q",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    summary = next(
        (
            line
            for line in reversed(proc.stdout.splitlines())
            if "passed" in line or "failed" in line or "error" in line
        ),
        "",
    ).strip()

    passed = failed = skipped = 0
    words = summary.replace(",", "").split()
    for index, word in enumerate(words):
        if word == "passed" and index:
            passed = int(words[index - 1])
        if word == "failed" and index:
            failed = int(words[index - 1])
        if word == "skipped" and index:
            skipped = int(words[index - 1])

    return {
        "total": passed + failed,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "exit_code": proc.returncode,
        "summary_line": summary,
    }


def self_audit() -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, "-m", "auditor.cli", "validate-policy", "--json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    return json.loads(proc.stdout)


def source_metrics() -> dict[str, Any]:
    """Snapshot live code/policy/test inputs into a versioned result artifact."""
    from auditor import __version__, compliance
    from auditor.rules import registry

    tests = test_counts()
    policy = self_audit()
    return {
        "schema_version": "1.0.0",
        "tool_version": __version__,
        "metrics": {
            "security_rules": {
                "value": len(registry.REGISTRY),
                "source_file": "auditor/rules/registry.py",
                "source_command": "python -m auditor.cli list-rules",
            },
            "tests": {
                "total": tests["total"],
                "passed": tests["passed"],
                "failed": tests["failed"],
                "skipped": tests["skipped"],
                "exit_code": tests["exit_code"],
                "source_command": "pytest",
            },
            "cis_mapped_rules": {
                "value": compliance.mapped_count(),
                "of": len(registry.REGISTRY),
                "benchmark_version": compliance.benchmark_version(),
                "status_counts": compliance.status_counts(),
                "source_file": "compliance/cis_mapping.json",
                "source_command": 'python -c "from auditor import compliance; print(compliance.mapped_count())"',
            },
            "self_audit": {
                "value": "PASS" if policy["passed"] else "FAIL",
                "wildcard_findings": len(policy["wildcard_findings"]),
                "declared_operations_all_read_only": policy["declared_operations_all_read_only"],
                "source_file": "policies/auditor-readonly-policy.json",
                "source_command": "python -m auditor.cli validate-policy",
            },
        },
    }


def collect() -> dict[str, Any]:
    source_artifact = _load("metrics_sources.json")
    source = source_artifact["metrics"]
    coverage = coverage_metrics(_load("coverage.json"))
    fixtures = _load("fixture_manifest.json")
    audit = _load("aws_audit_results.json")
    scoring = _load("expected_vs_actual.json")
    primary = next(p for p in scoring["profiles"] if p["profile"] == "misconfigured")
    return {
        "tool_version": source_artifact["tool_version"],
        "metrics": {
            "security_rules": {
                **source["security_rules"],
                "evidence": "results/metrics_sources.json",
                "command": source["security_rules"]["source_command"],
            },
            "lab_findings": {
                "value": audit["summary"]["total_findings"],
                "by_severity": audit["summary"]["by_severity"],
                "by_service": audit["summary"]["by_service"],
                "by_rule": audit["summary"]["by_rule"],
                "affected_resources": audit["summary"]["affected_resource_count"],
                "resources_scanned": audit["summary"]["resources_scanned"],
                "environment": audit["metadata"]["environment"],
                "evidence": "results/aws_audit_results.json",
                "command": "python -m lab.run_benchmark",
            },
            "detection_rate": {
                "value": primary["detection_rate"],
                "true_positives": primary["true_positives"],
                "false_negatives": primary["false_negatives"],
                "false_positives": primary["false_positives"],
                "evidence": "results/expected_vs_actual.json",
                "command": "python -m lab.run_benchmark",
            },
            "fixture_cases": {
                "value": fixtures["total_cases"],
                "by_category": fixtures["by_category"],
                "by_service": fixtures["by_service"],
                "rules_covered": len(fixtures["rules_covered"]),
                "evidence": "results/fixture_manifest.json",
                "command": "pytest tests/test_fixture_manifest.py",
            },
            "tests": {
                **source["tests"],
                "value": source["tests"]["total"],
                "evidence": "results/metrics_sources.json",
                "command": source["tests"]["source_command"],
            },
            "coverage": {
                # Branch-inclusive, matching .coveragerc and the pytest run.
                "detection_percent": coverage["detection_percent"],
                "detection_statements": coverage["detection_statements"],
                "detection_branches": coverage["detection_branches"],
                "detection_modules": coverage["detection_modules"],
                "overall_percent": coverage["overall_percent"],
                "overall_branch_inclusive_percent": coverage["overall_branch_inclusive_percent"],
                "overall_statements": coverage["overall_statements"],
                "evidence": "results/coverage.json",
                "command": "pytest --cov=auditor --cov=phase3 --cov-report=json:results/coverage.json",
            },
            "cis_mapped_rules": {
                **source["cis_mapped_rules"],
                "evidence": "results/metrics_sources.json",
                "command": source["cis_mapped_rules"]["source_command"],
            },
            "self_audit": {
                **source["self_audit"],
                "evidence": "results/metrics_sources.json",
                "command": source["self_audit"]["source_command"],
            },
            "api_calls_per_scan": {
                "value": audit["summary"]["api_call_count"],
                "duration_seconds": audit["summary"]["duration_seconds"],
                "evidence": "results/aws_audit_results.json",
                "command": "python -m lab.run_benchmark",
            },
        },
    }


def render_table(document: dict[str, Any]) -> str:
    metrics = document["metrics"]
    rows = [
        ("Security rules", metrics["security_rules"]["value"], metrics["security_rules"]["evidence"]),
        (
            "Lab findings (misconfigured profile)",
            metrics["lab_findings"]["value"],
            metrics["lab_findings"]["evidence"],
        ),
        (
            "Detection rate",
            f"{metrics['detection_rate']['value']:.0%} "
            f"({metrics['detection_rate']['true_positives']} TP / "
            f"{metrics['detection_rate']['false_negatives']} FN / "
            f"{metrics['detection_rate']['false_positives']} FP)",
            metrics["detection_rate"]["evidence"],
        ),
        ("Offline fixture cases", metrics["fixture_cases"]["value"], metrics["fixture_cases"]["evidence"]),
        (
            "Fixture cases by category",
            ", ".join(
                f"{category}={count}"
                for category, count in sorted(metrics["fixture_cases"]["by_category"].items())
            ),
            metrics["fixture_cases"]["evidence"],
        ),
        (
            "Fixture cases by service",
            ", ".join(
                f"{service}={count}"
                for service, count in sorted(metrics["fixture_cases"]["by_service"].items())
            ),
            metrics["fixture_cases"]["evidence"],
        ),
        (
            "Tests passing",
            "PASS (exact count in results/metrics.json)",
            "results/metrics.json",
        ),
        (
            "Detection-code coverage",
            "Exact percentage in results/metrics.json",
            "results/metrics.json",
        ),
        (
            "Overall package coverage",
            (
                "PASS (86% CI floor)"
                if metrics["coverage"]["overall_branch_inclusive_percent"] >= 86
                else "FAIL (86% CI floor)"
            ),
            "results/metrics.json",
        ),
        (
            "CIS-mapped rules",
            f"{metrics['cis_mapped_rules']['value']}/{metrics['cis_mapped_rules']['of']} "
            f"(v{metrics['cis_mapped_rules']['benchmark_version']})",
            metrics["cis_mapped_rules"]["evidence"],
        ),
        (
            "Self-audit of the auditor's own policy",
            metrics["self_audit"]["value"],
            metrics["self_audit"]["evidence"],
        ),
        (
            "API calls per full scan",
            metrics["api_calls_per_scan"]["value"],
            metrics["api_calls_per_scan"]["evidence"],
        ),
    ]

    width = max(len(str(name)) for name, _, _ in rows)
    lines = [
        f"| {'Metric'.ljust(width)} | {'Value'.rjust(12)} | Evidence |",
        f"| {'-' * width} | {'-' * 11}: | -------- |",
    ]
    for name, value, evidence in rows:
        lines.append(f"| {str(name).ljust(width)} | {str(value).rjust(12)} | `{evidence}` |")
    return "\n".join(lines)


def replace_readme_metrics(readme: str, table: str) -> str:
    """Replace exactly one README metrics block, preserving surrounding prose."""
    if readme.count(README_METRICS_START) != 1 or readme.count(README_METRICS_END) != 1:
        raise ValueError("README must contain exactly one generated metrics block")
    start = readme.index(README_METRICS_START)
    end = readme.index(README_METRICS_END)
    if start >= end:
        raise ValueError("README generated metrics markers are out of order")
    return readme[:start] + README_METRICS_START + "\n\n" + table + "\n\n" + readme[end:]


def main() -> int:
    check_readme = sys.argv[1:] == ["--check"]
    if sys.argv[1:] and not check_readme:
        print("usage: python scripts/collect_metrics.py [--check]", file=sys.stderr)
        return 2
    try:
        sources = source_metrics()
        with open(os.path.join(RESULTS, "metrics_sources.json"), "w", encoding="utf-8") as handle:
            json.dump(sources, handle, indent=2)
            handle.write("\n")
        document = collect()
    except MissingArtifact as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    tests = document["metrics"]["tests"]
    if tests["exit_code"] != 0 or tests["failed"] or tests["value"] == 0:
        print(
            f"error: metric collection requires a passing test suite ({tests['evidence']})", file=sys.stderr
        )
        return 1

    os.makedirs(RESULTS, exist_ok=True)
    table = render_table(document)
    try:
        with open(README_PATH, encoding="utf-8") as handle:
            readme = handle.read()
        updated_readme = replace_readme_metrics(readme, table)
    except (OSError, ValueError) as exc:
        print(f"error: could not update README metrics: {exc}", file=sys.stderr)
        return 2

    with open(os.path.join(RESULTS, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    with open(os.path.join(RESULTS, "metrics_table.md"), "w", encoding="utf-8") as handle:
        handle.write("# Metric evidence\n\nGenerated by `python scripts/collect_metrics.py`.\n\n")
        handle.write(table + "\n")

    if check_readme:
        if readme != updated_readme:
            print("error: README metrics are stale; run `python scripts/collect_metrics.py`", file=sys.stderr)
            return 1
    else:
        with open(README_PATH, "w", encoding="utf-8") as handle:
            handle.write(updated_readme)

    print(table)
    print("\nWrote results/metrics.json, results/metrics_table.md, and README metrics")
    return 0


if __name__ == "__main__":
    sys.exit(main())
