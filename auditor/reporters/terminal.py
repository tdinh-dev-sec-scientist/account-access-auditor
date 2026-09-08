"""Terminal reporter: the human-facing summary on stdout.

Everything here goes to stdout; logs go to stderr. That split is what lets
`auditor audit --output json > report.json` work while progress is still visible.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from typing import Any

from ..severity import ordered_names

BANNER = "AWS Account & Access Configuration Auditor"


def _out(text: str = "") -> None:
    print(text, file=sys.stdout)


def _truncate(value: str, width: int) -> str:
    return value if len(value) <= width else value[: width - 1] + "…"


def print_header(
    account_id: str | None,
    region: str | None,
    caller_arn: str | None = None,
    environment: str | None = None,
) -> None:
    _out(BANNER)
    _out("=" * len(BANNER))
    _out()
    _out(f"Account: {account_id or 'unknown'}")
    _out(f"Region:  {region or 'default'}")
    if caller_arn:
        _out(f"Caller:  {caller_arn}")
    if environment:
        _out(f"Env:     {environment}")
    _out()


def print_scan_line(service: str, status: str = "DONE") -> None:
    _out(f"{f'Scanning {service}':.<30}{status}")


def print_summary(report: dict[str, Any], output_paths: Iterable[str] = ()) -> None:
    summary = report.get("summary", {})
    counts = summary.get("by_severity", {})

    _out()
    _out("Findings")
    _out("--------")
    for severity in ordered_names():
        _out(f"{severity:<10} {counts.get(severity, 0)}")
    _out(f"{'TOTAL':<10} {summary.get('total_findings', 0)}")
    _out()

    findings: list[dict[str, Any]] = report.get("findings", [])
    if findings:
        _out(f"{'SEVERITY':<10} {'RULE':<9} {'CIS':<7} {'RESOURCE':<34} TITLE")
        for finding in findings:
            control = (finding.get("compliance") or {}).get("control_id") or "-"
            _out(
                f"{finding['severity']:<10} {finding['rule_id']:<9} {control:<7} "
                f"{_truncate(finding['resource'], 33):<34} {finding['title']}"
            )
        _out()

    scanned = summary.get("resources_scanned") or {}
    if scanned:
        _out("Resources scanned: " + ", ".join(f"{k}={v}" for k, v in sorted(scanned.items())))
    if summary.get("api_call_count") is not None:
        _out(
            f"API calls: {summary['api_call_count']}"
            + (
                f"   Duration: {summary['duration_seconds']}s"
                if summary.get("duration_seconds") is not None
                else ""
            )
        )
    if scanned or summary.get("api_call_count") is not None:
        _out()

    errors = report.get("collection_errors", [])
    if errors:
        _out(f"Collection errors: {len(errors)} (these resources could not be fully read)")
        for error in errors[:10]:
            _out(f"  {error['operation']} on {error.get('resource') or '-'}: {error['code']}")
        if len(errors) > 10:
            _out(f"  ... and {len(errors) - 10} more")
        _out("  An unreadable resource is a coverage gap, not a clean result.")
        _out()

    paths = list(output_paths)
    if paths:
        _out("Reports:")
        for path in paths:
            _out(f"  {path}")
        _out()

    _out(report.get("metadata", {}).get("severity_disclaimer", ""))


def print_rules(rules: list[dict[str, Any]]) -> None:
    """The `list-rules` table."""
    _out(f"{'RULE':<9} {'SERVICE':<11} {'SEVERITIES':<22} {'CIS':<7} TITLE")
    for rule in rules:
        control = (rule.get("compliance") or {}).get("control_id") or "-"
        severities = ",".join(rule["severities"])
        _out(
            f"{rule['rule_id']:<9} {rule['service']:<11} {_truncate(severities, 21):<22} "
            f"{control:<7} {rule['title']}"
        )
    _out()
    _out(f"{len(rules)} rules.")
