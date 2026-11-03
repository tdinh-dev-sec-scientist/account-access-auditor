"""Report assembly: findings plus the metadata needed to interpret them.

A findings list without its provenance is not evidence. The report records the
account, the region, which services were scanned, which rules were evaluated,
what could not be read, and the run identifier -- so a reader can tell the
difference between "no findings" and "nothing was scanned".
"""

from __future__ import annotations

import platform
import sys
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from ..compliance import benchmark_version, mapped_count
from ..severity import Severity, counts, ordered_names
from .contracts import CONTRACT_VERSION, GateStatus, ScanRun, classify_scan, finding_record
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
    scan_source: str = "aws-account-audit",
    scan_started_at: str | None = None,
    commit_ref: str | None = None,
    workflow_ref: str | None = None,
    scanner_versions: dict[str, str] | None = None,
    policy_pack_version: str | None = None,
    gate_status: GateStatus | str | None = None,
) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda f: f.sort_key)
    errors = collection_errors or []
    affected = sorted({f.resource for f in ordered})
    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    completed_at = generated_at
    started_at = scan_started_at
    if started_at is None and duration_seconds is not None:
        started_at = (
            datetime.fromisoformat(completed_at) - timedelta(seconds=max(duration_seconds, 0))
        ).isoformat(timespec="seconds")
    if started_at is None:
        started_at = completed_at

    outcome = classify_scan(errors, gate_status)
    contract_run_id = run_id or uuid.uuid4().hex
    scan_run = ScanRun(
        schema_version=CONTRACT_VERSION,
        run_id=contract_run_id,
        scan_source=scan_source,
        commit_ref=commit_ref,
        workflow_ref=workflow_ref,
        account_refs=([{"provider": "aws", "id": account_id}] if account_id else []),
        regions=([region] if region else []),
        scanner_versions=scanner_versions or {"account-access-auditor": tool_version},
        policy_pack_version=policy_pack_version,
        started_at=started_at,
        completed_at=completed_at,
        status=outcome.status,
        gate_status=outcome.gate_status,
        exit_code=outcome.exit_code,
        finding_count=len(ordered),
        collection_error_count=len(errors),
    ).to_dict()
    contract_findings = [finding_record(finding, run_id=contract_run_id) for finding in ordered]

    return {
        "metadata": {
            "tool": "account-access-auditor",
            "tool_version": tool_version,
            "run_id": run_id,
            "generated_at": generated_at,
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
        "contract": {
            "schema_version": CONTRACT_VERSION,
            "scan_run": scan_run,
            "findings": contract_findings,
        },
    }


def exceeds(findings: Iterable[Finding], threshold: str) -> bool:
    """True if any finding is at or above ``threshold``. Drives --fail-on."""
    limit = Severity.from_string(threshold)
    return any(f.severity.at_least(limit) for f in findings)
