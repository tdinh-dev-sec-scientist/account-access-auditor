"""Provision the lab, audit it, and score the results against expectations.

The whole point of this script is that the numbers in the README and the resume
come out of it rather than out of anyone's head. It writes:

  results/aws_audit_results.json          full audit report, primary profile
  results/aws_audit_results_no-trail.json full audit report, no-trail profile
  results/expected_vs_actual.json         TP / FP / FN scoring per profile
  results/benchmark_report.md             the human-readable version

A missed expectation is a real failure and is reported as one. The correct
response is to fix the rule and re-run, never to delete the expectation.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)

from auditor import __version__  # noqa: E402
from auditor.aws_session import build_session, describe_caller  # noqa: E402
from auditor.cli import run_scan  # noqa: E402
from auditor.config import load_config  # noqa: E402
from auditor.models.report import build_report  # noqa: E402
from auditor.redaction import redact_report  # noqa: E402
from auditor.reporters import csv_reporter, json_reporter, ticket  # noqa: E402
from auditor.rules import registry  # noqa: E402
from lab.provision import build_lab_session, provision  # noqa: E402
from lab.resources import PROFILES, expectations_for, negative_controls  # noqa: E402

log = logging.getLogger("lab.benchmark")

RESULTS_DIR = os.path.join(REPO_ROOT, "results")
SERVICES = ["iam", "s3", "cloudtrail"]

# Expectation resources contain "<key>" where an access key ID is generated at
# provisioning time and cannot be written down in advance.
KEY_PLACEHOLDER = "<key>"


def _resource_matches(expected: str, actual: str) -> bool:
    if KEY_PLACEHOLDER not in expected:
        return expected == actual
    prefix = expected.split(KEY_PLACEHOLDER)[0]
    return actual.startswith(prefix)


def score(expected, actual_findings) -> dict[str, Any]:
    """Match expectations to findings, once each, and report what is left over."""
    remaining = list(actual_findings)
    true_positives: list[dict[str, Any]] = []
    false_negatives: list[dict[str, Any]] = []

    for item in expected:
        match = next(
            (
                f
                for f in remaining
                if f.rule_id == item.rule_id
                and f.severity.value == item.severity
                and _resource_matches(item.resource, f.resource)
            ),
            None,
        )
        if match is None:
            # Same rule and resource but the wrong tier is a distinct failure
            # from "not detected at all", so record which one it was.
            near = next(
                (
                    f
                    for f in remaining
                    if f.rule_id == item.rule_id and _resource_matches(item.resource, f.resource)
                ),
                None,
            )
            false_negatives.append(
                {
                    "rule_id": item.rule_id,
                    "resource": item.resource,
                    "expected_severity": item.severity,
                    "why_expected": item.why,
                    "reason": (f"detected but at severity {near.severity.value}" if near else "not detected"),
                }
            )
            if near is not None:
                remaining.remove(near)
            continue
        remaining.remove(match)
        true_positives.append(
            {
                "rule_id": item.rule_id,
                "resource": match.resource,
                "severity": match.severity.value,
                "why_expected": item.why,
            }
        )

    false_positives = [
        {"rule_id": f.rule_id, "resource": f.resource, "severity": f.severity.value, "title": f.title}
        for f in remaining
    ]

    total_expected = len(expected)
    return {
        "expected_count": total_expected,
        "actual_count": len(actual_findings),
        "true_positives": len(true_positives),
        "false_negatives": len(false_negatives),
        "false_positives": len(false_positives),
        "detection_rate": round(len(true_positives) / total_expected, 4) if total_expected else None,
        "true_positive_detail": true_positives,
        "false_negative_detail": false_negatives,
        "unexpected_finding_detail": false_positives,
    }


def run_profile(profile: str, backend: str, region: str, config) -> tuple[dict[str, Any], dict[str, Any]]:
    """Provision one profile, audit it, and return (report, scoring)."""
    from moto import mock_aws

    if backend != "moto":  # pragma: no cover - operator path
        raise SystemExit("run_benchmark currently drives the moto backend only.")

    with mock_aws():
        lab_session = build_lab_session(backend, region)
        account_id = lab_session.client("sts").get_caller_identity()["Account"]
        created = provision(lab_session, profile, account_id, suffix="", backend=backend)

        # The auditor gets its own session, with the read-only guard installed.
        # The provisioning session above is a separate, unguarded one, so the
        # guard's operation count reflects only the audit.
        audit_session, guard = build_session(region=region)
        scanned_account, caller_arn = describe_caller(audit_session)

        started = time.perf_counter()
        findings, errors, resource_counts = run_scan(audit_session, SERVICES, config, run_id=profile)
        duration = time.perf_counter() - started

    report = build_report(
        account_id=scanned_account,
        region=region,
        findings=findings,
        collection_errors=errors,
        services_scanned=["IAM", "S3", "CloudTrail"],
        tool_version=__version__,
        run_id=f"lab-{profile}",
        rules_evaluated=registry.rule_ids(),
        resource_counts=resource_counts,
        duration_seconds=duration,
        api_call_count=guard.call_count if guard else None,
        environment_label=f"lab/{profile} ({backend} emulated account, not a live AWS account)",
    )
    report["lab"] = {
        "profile": profile,
        "backend": backend,
        "provisioned": created,
        "caller_arn": caller_arn,
        "api_calls_by_operation": guard.counts_by_operation() if guard else {},
        "negative_controls": [
            {"name": r.name, "kind": r.kind, "intent": r.intent} for r in negative_controls(profile)
        ],
    }

    scoring = score(expectations_for(profile), findings)
    scoring["profile"] = profile
    scoring["rules_fired"] = sorted({f.rule_id for f in findings})
    return report, scoring


def write_markdown(path: str, results: list[tuple[dict[str, Any], dict[str, Any]]]) -> None:
    lines = [
        "# Lab benchmark",
        "",
        "Generated by `python -m lab.run_benchmark`. Every number below comes from that run.",
        "",
        "> The lab account is emulated in-process by moto, not a live AWS account. The "
        "auditor reaches it through real boto3 clients and the real botocore request "
        "path, so collectors, pagination, error handling, and response parsing are all "
        "exercised against genuine AWS API shapes.",
        "",
    ]
    for report, scoring in results:
        summary = report["summary"]
        lines += [
            f"## Profile: {scoring['profile']}",
            "",
            f"- Findings: **{summary['total_findings']}**",
            f"- Resources scanned: {', '.join(f'{k}={v}' for k, v in sorted(summary['resources_scanned'].items()))}",
            f"- Affected resources: {summary['affected_resource_count']}",
            f"- API calls: {summary['api_call_count']}   Duration: {summary['duration_seconds']}s",
            f"- Collection errors: {summary['collection_errors']}",
            "",
            "### By severity",
            "",
            "| Severity | Count |",
            "| -------- | ----: |",
        ]
        for severity, count in summary["by_severity"].items():
            lines.append(f"| {severity} | {count} |")
        lines += ["", "### By rule", "", "| Rule | Count |", "| ---- | ----: |"]
        for rule, count in summary["by_rule"].items():
            lines.append(f"| {rule} | {count} |")
        lines += [
            "",
            "### Expected vs actual",
            "",
            f"- Expected findings: {scoring['expected_count']}",
            f"- True positives: {scoring['true_positives']}",
            f"- False negatives: {scoring['false_negatives']}",
            f"- Unexpected findings: {scoring['false_positives']}",
            f"- Detection rate: {scoring['detection_rate']}",
            "",
        ]
        if scoring["false_negative_detail"]:
            lines += ["#### Missed expectations", ""]
            for item in scoring["false_negative_detail"]:
                lines.append(f"- `{item['rule_id']}` on `{item['resource']}` ({item['reason']})")
            lines.append("")
        if scoring["unexpected_finding_detail"]:
            lines += ["#### Unexpected findings", ""]
            for item in scoring["unexpected_finding_detail"]:
                lines.append(
                    f"- `{item['rule_id']}` {item['severity']} on `{item['resource']}`: {item['title']}"
                )
            lines.append("")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lab.run_benchmark")
    parser.add_argument("--backend", choices=["moto"], default="moto")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--results-dir", default=RESULTS_DIR)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.ERROR if args.quiet else logging.WARNING,
        format="%(levelname)-7s %(message)s",
    )
    os.makedirs(args.results_dir, exist_ok=True)
    config = load_config(None)

    results: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for profile in PROFILES:
        report, scoring = run_profile(profile, args.backend, args.region, config)
        results.append((report, scoring))

        # These artifacts are committed to the repository, so access key IDs are
        # masked. Redaction runs after detection and changes nothing that was found.
        publishable = redact_report(report, access_keys=True)
        stem = "aws_audit_results" if profile == "misconfigured" else f"aws_audit_results_{profile}"
        json_reporter.write(publishable, os.path.join(args.results_dir, f"{stem}.json"))
        if profile == "misconfigured":
            csv_reporter.write(publishable, os.path.join(args.results_dir, "aws_audit_results.csv"))
            ticket.write(publishable, os.path.join(args.results_dir, "aws_audit_tickets.txt"))

    with open(os.path.join(args.results_dir, "expected_vs_actual.json"), "w", encoding="utf-8") as handle:
        json.dump(
            redact_report(
                {
                    "generated_by": "python -m lab.run_benchmark",
                    "tool_version": __version__,
                    "profiles": [scoring for _, scoring in results],
                    "totals": {
                        "expected": sum(s["expected_count"] for _, s in results),
                        "actual": sum(s["actual_count"] for _, s in results),
                        "true_positives": sum(s["true_positives"] for _, s in results),
                        "false_negatives": sum(s["false_negatives"] for _, s in results),
                        "false_positives": sum(s["false_positives"] for _, s in results),
                        "rules_fired": sorted({r for _, s in results for r in s["rules_fired"]}),
                    },
                }
            ),
            handle,
            indent=2,
        )
        handle.write("\n")

    write_markdown(os.path.join(args.results_dir, "benchmark_report.md"), results)

    print("Lab benchmark complete")
    for report, scoring in results:
        print(
            f"  {scoring['profile']:<16} findings={report['summary']['total_findings']:<4}"
            f" expected={scoring['expected_count']:<4} TP={scoring['true_positives']:<4}"
            f" FN={scoring['false_negatives']:<4} FP={scoring['false_positives']:<4}"
            f" detection_rate={scoring['detection_rate']}"
        )
    print(f"  artifacts in {args.results_dir}/")

    # A missed expectation is a failure of the scanner, so the exit code says so.
    failed = any(s["false_negatives"] for _, s in results)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
