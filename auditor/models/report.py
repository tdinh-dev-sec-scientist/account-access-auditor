"""Report assembly: findings plus the metadata needed to interpret them.

A findings list without its provenance is not evidence. The report records the
account, the region, which services were scanned, which rules were evaluated,
what could not be read, and the run identifier -- so a reader can tell the
difference between "no findings" and "nothing was scanned".
"""

from __future__ import annotations

import platform
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from ..compliance import benchmark_version, mapped_count
from ..severity import Severity, counts, ordered_names
from .finding import Finding

SEVERITY_DISCLAIMER = (
    "Severity is this project's internal prioritisation model. It is not a CVSS "
    "score, an AWS risk rating, or a formal industry classification."
)


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    return counts([f.severity for f in findings])


def _tally(findings: Iterable[Finding], key) -> dict[str, int]:
    result: dict[str, int] = {}
    for finding in findings:
        result[key(finding)] = result.get(key(finding), 0) + 1
    return dict(sorted(result.items()))


def build_report(
    account_id: str | None,
    region: str | None,
    findings: list[Finding],
    collection_errors: list[dict[str, Any]] | None = None,
    services_scanned: list[str] | None = None,
    tool_version: str = "0.0.0",
    run_id: str | None = None,
    rules_evaluated: list[str] | None = None,
    resource_counts: dict[str, int] | None = None,
    duration_seconds: float | None = None,
    api_call_count: int | None = None,
    environment_label: str | None = None,
) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda f: f.sort_key)
    errors = collection_errors or []
    affected = sorted({f.resource for f in ordered})

    return {
        "metadata": {
            "tool": "account-access-auditor",
            "tool_version": tool_version,
            "run_id": run_id,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "account_id": account_id,
            "region": region,
            "environment": environment_label,
            "services_scanned": services_scanned or [],
            "rules_evaluated": rules_evaluated or [],
            "compliance_framework": f"CIS AWS Foundations Benchmark v{benchmark_version()}",
            "cis_mapped_rule_count": mapped_count(),
            "severity_model": ordered_names(),
            "severity_disclaimer": SEVERITY_DISCLAIMER,
            "read_only": True,
            "python_version": platform.python_version(),
            "platform": sys.platform,
        },
        "summary": {
            "total_findings": len(ordered),
            "by_severity": severity_counts(ordered),
            "by_service": _tally(ordered, lambda f: f.service),
            "by_rule": _tally(ordered, lambda f: f.rule_id),
            "by_resource_type": _tally(ordered, lambda f: f.resource_type),
            "affected_resource_count": len(affected),
            "resources_scanned": resource_counts or {},
            "collection_errors": len(errors),
            "api_call_count": api_call_count,
            "duration_seconds": round(duration_seconds, 3) if duration_seconds is not None else None,
        },
        "collection_errors": errors,
        "findings": [f.to_dict() for f in ordered],
    }


def exceeds(findings: Iterable[Finding], threshold: str) -> bool:
    """True if any finding is at or above ``threshold``. Drives --fail-on."""
    limit = Severity.from_string(threshold)
    return any(f.severity.at_least(limit) for f in findings)
