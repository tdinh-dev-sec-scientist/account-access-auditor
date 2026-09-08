"""Derive every headline metric from the artifacts, and fail if one is missing.

Nothing in this script computes a number by hand. Each metric names the artifact
it came from and the command that produced that artifact, so any claim made
about this project can be traced to a file and re-derived from a clean checkout.

    python -m pytest --cov=auditor --cov-report=json:results/coverage.json
    python -m lab.run_benchmark
    python scripts/collect_metrics.py

Writes ``results/metrics.json`` and prints the evidence table.
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

# Modules that implement detection: collection is deliberately excluded, because
# "the detection logic is unit-tested offline" is a claim about these files.
DETECTION_PREFIXES = ("auditor/rules/", "auditor/normalize/", "auditor/models/", "auditor/severity.py")


class MissingArtifact(RuntimeError):
    """A metric was requested but the artifact backing it does not exist."""


def _load(name: str) -> dict[str, Any]:
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        raise MissingArtifact(
            f"{os.path.relpath(path, REPO_ROOT)} is missing. "
            "Run the full workflow in README 'Reproducing the numbers' first."
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

    passed = failed = 0
    words = summary.replace(",", "").split()
    for index, word in enumerate(words):
        if word == "passed" and index:
            passed = int(words[index - 1])
        if word == "failed" and index:
            failed = int(words[index - 1])

    return {
        "total": passed + failed,
        "passed": passed,
        "failed": failed,
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


def collect() -> dict[str, Any]:
    from auditor import __version__, compliance
    from auditor.rules import registry

    coverage = coverage_metrics(_load("coverage.json"))
    fixtures = _load("fixture_manifest.json")
    audit = _load("aws_audit_results.json")
    scoring = _load("expected_vs_actual.json")
    primary = next(p for p in scoring["profiles"] if p["profile"] == "misconfigured")
    tests = test_counts()
    policy = self_audit()

    return {
        "tool_version": __version__,
        "metrics": {
            "security_rules": {
                "value": len(registry.REGISTRY),
                "evidence": "auditor/rules/registry.py",
                "command": "python -m auditor.cli list-rules",
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
                "value": tests["total"],
                "passed": tests["passed"],
                "failed": tests["failed"],
                "evidence": tests["summary_line"],
                "command": "pytest",
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
                "command": "pytest --cov=auditor --cov-report=json:results/coverage.json",
            },
            "cis_mapped_rules": {
                "value": compliance.mapped_count(),
                "of": len(registry.REGISTRY),
                "benchmark_version": compliance.benchmark_version(),
                "status_counts": compliance.status_counts(),
                "evidence": "compliance/cis_mapping.json",
                "command": 'python -c "from auditor import compliance; print(compliance.mapped_count())"',
            },
            "self_audit": {
                "value": "PASS" if policy["passed"] else "FAIL",
                "wildcard_findings": len(policy["wildcard_findings"]),
                "declared_operations_all_read_only": policy["declared_operations_all_read_only"],
                "evidence": "policies/auditor-readonly-policy.json",
                "command": "python -m auditor.cli validate-policy",
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
            "Tests passing",
            f"{metrics['tests']['passed']}/{metrics['tests']['value']}",
            metrics["tests"]["evidence"],
        ),
        (
            "Detection-code coverage",
            f"{metrics['coverage']['detection_percent']}%",
            metrics["coverage"]["evidence"],
        ),
        (
            "Overall package coverage",
            f"{metrics['coverage']['overall_branch_inclusive_percent']}%",
            metrics["coverage"]["evidence"],
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


def main() -> int:
    try:
        document = collect()
    except MissingArtifact as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "metrics.json"), "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")

    table = render_table(document)
    with open(os.path.join(RESULTS, "metrics_table.md"), "w", encoding="utf-8") as handle:
        handle.write("# Metric evidence\n\nGenerated by `python scripts/collect_metrics.py`.\n\n")
        handle.write(table + "\n")

    print(table)
    print("\nWrote results/metrics.json and results/metrics_table.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
