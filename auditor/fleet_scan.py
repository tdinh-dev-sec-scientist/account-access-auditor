"""Read-only, configured multi-account and multi-region AWS scan orchestration."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .aws_session import ReadOnlyGuard, build_assumed_role_session, describe_caller
from .fleet import FleetConfig, FleetConfigError, TargetAccount, resolve_external_id
from .models.contracts import (
    CONTRACT_VERSION,
    GateStatus,
    ScanRun,
    classify_scan,
    finding_record,
)
from .models.finding import Finding
from .severity import Severity, counts

_SERVICE_LABELS = {"iam": "IAM", "s3": "S3", "cloudtrail": "CloudTrail"}
_GLOBAL_SERVICES = {"iam", "s3"}


def _run_scan(session, services, audit_config, run_id):
    from .cli import run_scan

    return run_scan(session, services, audit_config, run_id)


def _assume_role(
    source_session,
    *,
    role_arn,
    role_session_name,
    external_id,
    region_name,
):
    return build_assumed_role_session(
        source_session,
        role_arn=role_arn,
        role_session_name=role_session_name,
        external_id=external_id,
        region_name=region_name,
    )


_describe_caller = describe_caller


def run_fleet_scan(
    fleet_config: FleetConfig,
    audit_config: dict[str, Any],
    source_session,
    *,
    source_guard: ReadOnlyGuard | None = None,
    run_id: str | None = None,
    fail_on: str | None = None,
    assume_role: Callable[..., tuple[Any, ReadOnlyGuard | None]] | None = None,
    scan: Callable[..., tuple[list[Finding], list[dict[str, Any]], dict[str, int]]] | None = None,
    caller: Callable[..., tuple[str | None, str | None]] | None = None,
) -> dict[str, Any]:
    """Scan IAM/S3 once per account and CloudTrail in every configured region.

    Target roles are assumed independently in each required region. A failed
    account or region degrades only its coverage; other configured targets are
    still scanned and the result can never be reported as a clean pass.
    """
    actual_run_id = run_id or uuid.uuid4().hex[:12]
    threshold = Severity.from_string(fail_on).value if fail_on else None
    assume = assume_role or _assume_role
    scan_target = scan or _run_scan
    read_identity = caller or _describe_caller
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    started_clock = time.perf_counter()
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    resource_counts: dict[str, int] = {}
    target_guards: list[ReadOnlyGuard] = []
    expected_global = [service for service in fleet_config.services if service in _GLOBAL_SERVICES]
    regions = list(fleet_config.regions)

    for account in fleet_config.accounts:
        try:
            external_id = resolve_external_id(account)
        except FleetConfigError as exc:
            errors.append(_account_error(account, None, "external-id", "ConfigurationError", str(exc)))
            _record_incomplete_coverage(coverage, account, fleet_config)
            continue

        account_findings: list[dict[str, Any]] = []
        account_errors: list[dict[str, Any]] = []
        account_coverage: list[dict[str, Any]] = []
        first_region = regions[0]
        first_session, first_guard = _target_session(
            assume,
            read_identity,
            source_session,
            account,
            external_id,
            first_region,
            actual_run_id,
            account_errors,
        )
        if first_guard is not None:
            target_guards.append(first_guard)
        global_scanned = not expected_global
        if expected_global and first_session is not None:
            _collect_scope(
                first_session,
                account,
                "aws-global",
                expected_global,
                audit_config,
                actual_run_id,
                scan_target,
                account_findings,
                account_errors,
                resource_counts,
                account_coverage,
            )
            global_scanned = True
        elif expected_global and "cloudtrail" not in fleet_config.services:
            for region in regions[1:]:
                session, guard = _target_session(
                    assume,
                    read_identity,
                    source_session,
                    account,
                    external_id,
                    region,
                    actual_run_id,
                    account_errors,
                )
                if guard is not None:
                    target_guards.append(guard)
                if session is None:
                    continue
                _collect_scope(
                    session,
                    account,
                    "aws-global",
                    expected_global,
                    audit_config,
                    actual_run_id,
                    scan_target,
                    account_findings,
                    account_errors,
                    resource_counts,
                    account_coverage,
                )
                global_scanned = True
                break

        if "cloudtrail" in fleet_config.services:
            for region_index, region in enumerate(regions):
                if region_index == 0:
                    session = first_session
                else:
                    session, guard = _target_session(
                        assume,
                        read_identity,
                        source_session,
                        account,
                        external_id,
                        region,
                        actual_run_id,
                        account_errors,
                    )
                    if guard is not None:
                        target_guards.append(guard)
                if session is None:
                    account_coverage.append(
                        {
                            "account_id": account.account_id,
                            "service": "cloudtrail",
                            "region": region,
                            "complete": False,
                        }
                    )
                    continue
                if expected_global and not global_scanned:
                    _collect_scope(
                        session,
                        account,
                        "aws-global",
                        expected_global,
                        audit_config,
                        actual_run_id,
                        scan_target,
                        account_findings,
                        account_errors,
                        resource_counts,
                        account_coverage,
                    )
                    global_scanned = True
                _collect_scope(
                    session,
                    account,
                    region,
                    ["cloudtrail"],
                    audit_config,
                    actual_run_id,
                    scan_target,
                    account_findings,
                    account_errors,
                    resource_counts,
                    account_coverage,
                )

        if not global_scanned:
            for service in expected_global:
                account_coverage.append(
                    {
                        "account_id": account.account_id,
                        "service": service,
                        "region": "aws-global",
                        "complete": False,
                    }
                )

        findings.extend(account_findings)
        errors.extend(account_errors)
        coverage.extend(account_coverage)

    _deduplicate_contract_findings(findings)
    gate_status = GateStatus.NOT_CONFIGURED
    if threshold is not None:
        has_violation = any(
            Severity.from_string(item["severity"]).at_least(Severity.from_string(threshold))
            for item in findings
        )
        gate_status = GateStatus.FAIL if has_violation else GateStatus.PASS
    outcome = classify_scan(errors, gate_status)
    completed_at = datetime.now(UTC).isoformat(timespec="seconds")
    elapsed = round(time.perf_counter() - started_clock, 3)
    account_refs = [{"provider": "aws", "id": account.account_id} for account in fleet_config.accounts]
    run = ScanRun(
        schema_version=CONTRACT_VERSION,
        run_id=actual_run_id,
        scan_source="aws-fleet",
        commit_ref=None,
        workflow_ref=None,
        account_refs=account_refs,
        regions=regions,
        scanner_versions={"account-access-auditor": __version__},
        policy_pack_version=None,
        started_at=started_at,
        completed_at=completed_at,
        status=outcome.status,
        gate_status=outcome.gate_status,
        exit_code=outcome.exit_code,
        finding_count=len(findings),
        collection_error_count=len(errors),
        gate_threshold=threshold,
    ).to_dict()
    severity_counts = counts([item["severity"] for item in findings])
    services_scanned = list(fleet_config.services)
    return {
        "metadata": {
            "tool": "account-access-auditor",
            "tool_version": __version__,
            "run_id": actual_run_id,
            "scan_source": "aws-fleet",
            "read_only": True,
            "aws_accessed": True,
            "accounts": account_refs,
            "regions": regions,
            "services_scanned": services_scanned,
            "scan_coverage": coverage,
            "generated_at": completed_at,
            "duration_seconds": elapsed,
            "api_call_count": (source_guard.call_count if source_guard else 0)
            + sum(guard.call_count for guard in target_guards),
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "collection_errors": len(errors),
            "gate_threshold": threshold,
            "gate_status": outcome.gate_status.value,
            "status": outcome.status.value,
            "complete_scopes": sum(entry["complete"] for entry in coverage),
            "incomplete_scopes": sum(not entry["complete"] for entry in coverage),
        },
        "collection_errors": errors,
        "findings": findings,
        "contract": {
            "schema_version": CONTRACT_VERSION,
            "scan_run": run,
            "findings": findings,
        },
    }


def _target_session(assume, read_identity, source_session, account, external_id, region, run_id, errors):
    session_name = f"auditor-{run_id[:12]}-{region.replace('-', '')[:8]}"
    try:
        session, guard = assume(
            source_session,
            role_arn=account.role_arn,
            role_session_name=session_name,
            external_id=external_id,
            region_name=region,
        )
        actual_account_id, _caller_arn = read_identity(session)
    except Exception as exc:
        errors.append(
            _account_error(account, region, "assume-role", exc.__class__.__name__, _safe_error(exc))
        )
        return None, None
    if actual_account_id != account.account_id:
        errors.append(
            _account_error(
                account,
                region,
                "verify-target",
                "TargetAccountMismatch",
                "assumed role returned an identity for a different account",
            )
        )
        return None, guard
    return session, guard


def _collect_scope(
    session,
    account,
    region,
    services,
    audit_config,
    run_id,
    scan,
    findings,
    errors,
    resource_counts,
    coverage,
):
    try:
        raw_findings, scan_errors, counts_by_resource = scan(session, services, audit_config, run_id)
    except Exception as exc:
        scan_errors = [
            {
                "service": "AWS",
                "operation": "scan",
                "resource": None,
                "code": exc.__class__.__name__,
                "category": "error",
                "message": _safe_error(exc),
            }
        ]
        raw_findings, counts_by_resource = [], {}
    label_to_service = {label: service for service, label in _SERVICE_LABELS.items()}
    for error in scan_errors:
        enriched = {**error, "account_id": account.account_id, "region": region}
        errors.append(enriched)
    for name, count in counts_by_resource.items():
        resource_counts[name] = resource_counts.get(name, 0) + count
    for finding in raw_findings:
        service = label_to_service.get(finding.service, "unknown")
        finding_region = "aws-global" if service in _GLOBAL_SERVICES else region
        account_ref = {"provider": "aws", "id": account.account_id}
        findings.append(
            finding_record(
                finding,
                run_id=run_id,
                account_ref=account_ref,
                region=finding_region,
                service=finding.service,
            )
        )
    for service in services:
        # Only failures for this service make its coverage incomplete.
        relevant = [
            error
            for error in scan_errors
            if error.get("service") in {service, _SERVICE_LABELS[service]} or error.get("operation") == "scan"
        ]
        coverage.append(
            {
                "account_id": account.account_id,
                "service": service,
                "region": "aws-global" if service in _GLOBAL_SERVICES else region,
                "complete": not relevant,
            }
        )


def _record_incomplete_coverage(coverage, account, fleet_config):
    for service in fleet_config.services:
        service_regions = ["aws-global"] if service in _GLOBAL_SERVICES else list(fleet_config.regions)
        for region in service_regions:
            coverage.append(
                {"account_id": account.account_id, "service": service, "region": region, "complete": False}
            )


def _account_error(account: TargetAccount, region: str | None, operation: str, code: str, message: str):
    return {
        "service": "AWS Account",
        "operation": operation,
        "resource": account.account_id,
        "account_id": account.account_id,
        "region": region,
        "code": code,
        "category": "error",
        "message": message[:500],
    }


def _safe_error(exc: Exception) -> str:
    text = str(exc)
    return text[:500] if len(text) <= 500 else text[:497] + "..."


def _deduplicate_contract_findings(findings: list[dict[str, Any]]) -> None:
    unique = {item["fingerprint"]: item for item in findings}
    findings[:] = sorted(
        unique.values(), key=lambda item: (item["severity"], item["control_id"], item["fingerprint"])
    )
