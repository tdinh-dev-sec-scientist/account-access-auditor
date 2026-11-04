"""Validate criterion-specific, reviewed Phase 3 stage evidence."""

from __future__ import annotations

import json
import hashlib
import math
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REVIEW_FIELDS = {"schema_version", "reviewed_by", "reviewed_at"}
_STAGE3_EXTERNAL_SCAN_PATH = "stage3/external-tls-scan.json"
_SOURCE_REPORT_PATHS = {
    "schedule": "stage1/schedule-execution-log.json",
    "tls": "stage3/source-reports/external-tls.json",
    "browser_network": "stage3/source-reports/browser-network.json",
    "lighthouse": "stage3/source-reports/lighthouse.json",
    "accessibility": "stage3/source-reports/accessibility.json",
    "load": "stage4/source-reports/load-test.json",
    "aws_cost": "stage4/source-reports/aws-cost-explorer.json",
    "provider_cost": "stage4/source-reports/provider-cost.json",
}
_STANDARD_REJECTED_METHODS = {"OPTIONS", "PATCH", "POST", "PUT", "DELETE", "TRACE", "CONNECT"}
_REDACTION_CASES = {
    "account_id",
    "arn",
    "ip_address",
    "email",
    "access_key",
    "unknown_field",
    "stable_pseudonym",
}
_RIN_EVALUATION_CASES = {
    "prompt_injection",
    "hostile_evidence",
    "secret_leakage",
    "citation_grounding",
    "unsupported_question",
    "response_schema",
    "provider_error_fallback",
}
_FAILURE_BANNER_STATES = {
    "partial_scan",
    "failed_scan",
    "stale_data",
    "publication_blocked",
    "api_unavailable",
    "rin_unavailable",
    "rin_over_budget",
    "kill_switch_static_mode",
}
_RELEASE_CRITERIA = {
    "phase1_phase2_read_only_regressions",
    "live_demo_account_results_only",
    "redaction_and_public_boundary",
    "public_roles_have_no_aws_scan_or_github_writes",
    "https_headers_and_waf",
    "rin_grounding_quotas_and_fallbacks",
    "failure_states_visible",
    "budget_alerts_cutoff_and_actual_cost",
    "kill_switch_static_recovery",
    "readme_threat_model_and_site_are_accurate",
}


class StageEvidenceError(ValueError):
    """A stage artifact does not substantiate its claimed acceptance criteria."""


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_nonstandard_number(value: str) -> None:
    raise ValueError(f"non-standard JSON number: {value}")


def _read_json(evidence_root: Path, relative_path: str) -> Any:
    try:
        return json.loads(
            (evidence_root / relative_path).read_text(encoding="utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_nonstandard_number,
        )
    except (OSError, UnicodeError, ValueError):
        raise StageEvidenceError(f"{relative_path} is missing or invalid JSON") from None


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _bound_report(evidence_root: Path, document: dict[str, Any], *, path_field: str, digest_field: str, expected_path: str) -> bool:
    return (
        document.get(path_field) == expected_path
        and _sha256(document.get(digest_field))
        and document[digest_field] == _file_sha256(evidence_root, expected_path)
    )


def _file_sha256(evidence_root: Path, relative_path: str) -> str | None:
    try:
        return hashlib.sha256((evidence_root / relative_path).read_bytes()).hexdigest()
    except OSError:
        return None


def _finite_number(value: Any, *, positive: bool) -> bool:
    return (
        type(value) in {int, float}
        and math.isfinite(value)
        and (value > 0 if positive else value >= 0)
    )


def _reviewed_document(
    document: Any,
    record: dict[str, Any],
    *,
    fields: set[str],
) -> bool:
    return (
        isinstance(document, dict)
        and set(document) == fields | _REVIEW_FIELDS
        and type(document.get("schema_version")) is int
        and document["schema_version"] == 1
        and document.get("reviewed_by") == record["reviewed_by"]
        and document.get("reviewed_at") == record["reviewed_at"]
        and _timestamp(document.get("reviewed_at")) is not None
    )


def _nonempty_unique_strings(value: Any) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) and item.strip() for item in value)
        and len(value) == len(set(value))
    )


def _validate_stage1(evidence_root: Path, record: dict[str, Any], *, expected_demo_account_id_sha256: str | None = None) -> None:
    scans = _read_json(evidence_root, "stage1/scheduled-scan-results.json")
    if not _reviewed_document(
        scans,
        record,
        fields={
            "target_account_label",
            "target_account_id_sha256",
            "schedule_execution_log_evidence_path",
            "schedule_execution_log_sha256",
            "consecutive_schedule_runs",
            "scans",
        },
    ):
        raise StageEvidenceError("Stage 1 scheduled-scan evidence has an invalid schema")
    runs = scans["scans"]
    if (
        expected_demo_account_id_sha256 is not None
        and scans.get("target_account_id_sha256") != expected_demo_account_id_sha256
    ):
        raise StageEvidenceError("Stage 1 scans do not belong to the configured demo account")
    if (
        scans.get("target_account_label") != "demo-account"
        or not _sha256(scans.get("target_account_id_sha256"))
        or not _bound_report(
            evidence_root,
            scans,
            path_field="schedule_execution_log_evidence_path",
            digest_field="schedule_execution_log_sha256",
            expected_path=_SOURCE_REPORT_PATHS["schedule"],
        )
        or scans.get("consecutive_schedule_runs") is not True
        or not isinstance(runs, list)
        or len(runs) != 2
    ):
        raise StageEvidenceError("Stage 1 requires exactly two consecutive scheduled scans")
    run_ids: list[str] = []
    run_starts: list[datetime] = []
    timestamps: list[tuple[datetime, datetime]] = []
    for run in runs:
        if (
            not isinstance(run, dict)
            or set(run) != {"scan_run_id", "trigger", "status", "started_at", "completed_at", "snapshot_sha256"}
            or not isinstance(run.get("scan_run_id"), str)
            or not _RUN_ID.fullmatch(run["scan_run_id"])
            or run.get("trigger") != "scheduled"
            or run.get("status") != "complete"
            or not _sha256(run.get("snapshot_sha256"))
        ):
            raise StageEvidenceError("Stage 1 scheduled-scan evidence has an invalid run")
        started, completed = _timestamp(run.get("started_at")), _timestamp(run.get("completed_at"))
        if started is None or completed is None or completed < started:
            raise StageEvidenceError("Stage 1 scheduled-scan evidence has invalid timestamps")
        run_ids.append(run["scan_run_id"])
        run_starts.append(started)
        timestamps.append((started, completed))
    if len(set(run_ids)) != 2 or timestamps[1][0] <= timestamps[0][1]:
        raise StageEvidenceError("Stage 1 scheduled scans are not distinct and consecutive")

    schedule_log = _read_json(evidence_root, _SOURCE_REPORT_PATHS["schedule"])
    if not _reviewed_document(
        schedule_log,
        record,
        fields={"complete_export", "export_window_start", "export_window_end", "scheduled_executions"},
    ):
        raise StageEvidenceError("Stage 1 schedule execution log has an invalid schema")
    window_start = _timestamp(schedule_log.get("export_window_start"))
    window_end = _timestamp(schedule_log.get("export_window_end"))
    executions = schedule_log.get("scheduled_executions")
    if (
        schedule_log.get("complete_export") is not True
        or window_start is None
        or window_end is None
        or window_start > timestamps[0][0]
        or window_end < timestamps[1][1]
        or not isinstance(executions, list)
        or len(executions) != 2
        or any(
            not isinstance(execution, dict)
            or set(execution) != {"scan_run_id", "scheduled_at", "workflow_started_at", "scan_started_at", "status", "snapshot_sha256"}
            or execution.get("scan_run_id") != run_ids[index]
            or _timestamp(execution.get("scheduled_at")) is None
            or _timestamp(execution.get("workflow_started_at")) is None
            or not timedelta(0) <= _timestamp(execution.get("workflow_started_at")) - _timestamp(execution.get("scheduled_at")) <= timedelta(hours=1)
            or _timestamp(execution.get("scan_started_at")) != run_starts[index]
            or _timestamp(execution.get("scan_started_at")) < _timestamp(execution.get("workflow_started_at"))
            or (index > 0 and _timestamp(execution.get("scheduled_at")) - _timestamp(executions[index - 1].get("scheduled_at")) != timedelta(hours=6))
            or execution.get("status") != "complete"
            or execution.get("snapshot_sha256") != runs[index]["snapshot_sha256"]
            for index, execution in enumerate(executions)
        )
    ):
        raise StageEvidenceError("Stage 1 schedule log does not prove two complete consecutive scheduled runs")

    drift = _read_json(evidence_root, "stage1/drift-review.json")
    if (
        not _reviewed_document(
            drift,
            record,
            fields={
                "terraform_change_sha256",
                "previous_scan_run_id",
                "current_scan_run_id",
                "new_finding_ids",
                "resolved_finding_ids",
            },
        )
        or not _sha256(drift.get("terraform_change_sha256"))
        or (drift.get("previous_scan_run_id"), drift.get("current_scan_run_id")) != tuple(run_ids)
        or not _nonempty_unique_strings(drift.get("new_finding_ids"))
        or not _nonempty_unique_strings(drift.get("resolved_finding_ids"))
    ):
        raise StageEvidenceError("Stage 1 drift-review evidence does not show a reviewed new and resolved finding")

    role = _read_json(evidence_root, "stage1/read-only-role-review.json")
    if (
        not _reviewed_document(role, record, fields={"role_arn_sha256", "policy_evidence_sha256", "effective_write_actions"})
        or not _sha256(role.get("role_arn_sha256"))
        or not _sha256(role.get("policy_evidence_sha256"))
        or role.get("effective_write_actions") != []
    ):
        raise StageEvidenceError("Stage 1 scan-role evidence does not prove read-only permissions")


def _validate_stage2(evidence_root: Path, record: dict[str, Any]) -> None:
    redaction = _read_json(evidence_root, "stage2/redaction-test-results.json")
    if (
        not _reviewed_document(
            redaction,
            record,
            fields={"test_suite_sha256", "passed_case_categories", "failed_case_ids", "leaked_identifier_count", "published_unapproved_fields"},
        )
        or not _sha256(redaction.get("test_suite_sha256"))
        or not isinstance(redaction.get("passed_case_categories"), list)
        or any(not isinstance(item, str) for item in redaction["passed_case_categories"])
        or not _REDACTION_CASES.issubset(set(redaction["passed_case_categories"]))
        or len(redaction["passed_case_categories"]) != len(set(redaction["passed_case_categories"]))
        or not isinstance(redaction.get("failed_case_ids"), list)
        or redaction["failed_case_ids"]
        or type(redaction.get("leaked_identifier_count")) is not int
        or redaction["leaked_identifier_count"] != 0
        or type(redaction.get("published_unapproved_fields")) is not int
        or redaction["published_unapproved_fields"] != 0
    ):
        raise StageEvidenceError("Stage 2 redaction-test evidence is incomplete or failed")

    publisher = _read_json(evidence_root, "stage2/publisher-failure.json")
    if (
        not _reviewed_document(
            publisher,
            record,
            fields={"injected_failure", "previous_snapshot_sha256", "published_snapshot_sha256", "last_good_preserved"},
        )
        or publisher.get("injected_failure") not in {"redaction", "schema_validation", "publication_write"}
        or not _sha256(publisher.get("previous_snapshot_sha256"))
        or publisher.get("published_snapshot_sha256") != publisher.get("previous_snapshot_sha256")
        or publisher.get("last_good_preserved") is not True
    ):
        raise StageEvidenceError("Stage 2 publisher-failure evidence does not prove last-good preservation")

    methods = _read_json(evidence_root, "stage2/public-api-methods.json")
    if not _reviewed_document(methods, record, fields={"method_results"}):
        raise StageEvidenceError("Stage 2 public API method evidence has an invalid schema")
    results = methods["method_results"]
    if (
        not isinstance(results, dict)
        or set(results) != {"GET", "HEAD", *_STANDARD_REJECTED_METHODS}
        or results.get("GET") != "served"
        or results.get("HEAD") != "served"
        or any(results[method] != "rejected" for method in _STANDARD_REJECTED_METHODS)
    ):
        raise StageEvidenceError("Stage 2 public API evidence must reject every non-GET/HEAD method")


def _validate_stage3_transport(evidence_root: Path, record: dict[str, Any]) -> None:
    document = _read_json(evidence_root, "stage3/transport-security.json")
    external_scan = _read_json(evidence_root, _STAGE3_EXTERNAL_SCAN_PATH)
    headers = {"strict_transport_security", "content_security_policy", "x_content_type_options", "referrer_policy", "frame_ancestors"}
    if (
        not _reviewed_document(document, record, fields={"http_redirect_status", "https_status", "headers", "external_scan_evidence_path", "external_scan_sha256"})
        or document.get("http_redirect_status") not in {301, 302, 307, 308}
        or document.get("https_status") != 200
        or not isinstance(document.get("headers"), dict)
        or set(document["headers"]) != headers
        or any(value is not True for value in document["headers"].values())
        or not _sha256(document.get("external_scan_sha256"))
        or document.get("external_scan_evidence_path") != _STAGE3_EXTERNAL_SCAN_PATH
        or document.get("external_scan_sha256") != _file_sha256(evidence_root, _STAGE3_EXTERNAL_SCAN_PATH)
    ):
        raise StageEvidenceError("Stage 3 HTTPS and security-header evidence is incomplete or failed")
    if (
        not _reviewed_document(external_scan, record, fields={"provider", "scanned_at", "tls_result", "security_headers_result", "source_report_evidence_path", "source_report_sha256"})
        or not isinstance(external_scan.get("provider"), str)
        or not external_scan["provider"].strip()
        or _timestamp(external_scan.get("scanned_at")) is None
        or external_scan.get("tls_result") != "pass"
        or external_scan.get("security_headers_result") != "pass"
        or not _bound_report(
            evidence_root,
            external_scan,
            path_field="source_report_evidence_path",
            digest_field="source_report_sha256",
            expected_path=_SOURCE_REPORT_PATHS["tls"],
        )
    ):
        raise StageEvidenceError("Stage 3 external TLS/security-header scan evidence is invalid")


def _validate_stage3_privacy_accessibility(evidence_root: Path, record: dict[str, Any]) -> None:
    document = _read_json(evidence_root, "stage3/privacy-accessibility.json")
    pages = {"dashboard", "finding", "rin"}
    if (
        not _reviewed_document(
            document,
            record,
            fields={"browser_network_report_evidence_path", "browser_network_log_sha256", "unapproved_third_party_requests", "lighthouse_report_evidence_path", "lighthouse_report_sha256", "accessibility_report_evidence_path", "accessibility_report_sha256", "pages_checked"},
        )
        or document.get("unapproved_third_party_requests") != []
        or not _bound_report(evidence_root, document, path_field="browser_network_report_evidence_path", digest_field="browser_network_log_sha256", expected_path=_SOURCE_REPORT_PATHS["browser_network"])
        or not _bound_report(evidence_root, document, path_field="lighthouse_report_evidence_path", digest_field="lighthouse_report_sha256", expected_path=_SOURCE_REPORT_PATHS["lighthouse"])
        or not _bound_report(evidence_root, document, path_field="accessibility_report_evidence_path", digest_field="accessibility_report_sha256", expected_path=_SOURCE_REPORT_PATHS["accessibility"])
        or not isinstance(document.get("pages_checked"), list)
        or any(not isinstance(page, str) for page in document["pages_checked"])
        or set(document["pages_checked"]) != pages
    ):
        raise StageEvidenceError("Stage 3 browser privacy/accessibility evidence is incomplete or failed")


def _validate_stage3_rin(evidence_root: Path, record: dict[str, Any]) -> None:
    document = _read_json(evidence_root, "stage3/rin-evaluation.json")
    if (
        not _reviewed_document(document, record, fields={"test_suite_sha256", "cases"})
        or not _sha256(document.get("test_suite_sha256"))
        or not isinstance(document.get("cases"), list)
    ):
        raise StageEvidenceError("Stage 3 Rin evaluation evidence has an invalid schema")
    cases = document["cases"]
    if any(
        not isinstance(case, dict)
        or set(case) != {"case_id", "category", "passed"}
        or not isinstance(case.get("case_id"), str)
        or not case["case_id"].strip()
        or not isinstance(case.get("category"), str)
        or case.get("category") not in _RIN_EVALUATION_CASES
        or case.get("passed") is not True
        for case in cases
    ):
        raise StageEvidenceError("Stage 3 Rin evaluation contains a failing or invalid case")
    if (
        len({case["case_id"] for case in cases}) != len(cases)
        or not _RIN_EVALUATION_CASES.issubset({case["category"] for case in cases})
    ):
        raise StageEvidenceError("Stage 3 Rin evaluation does not cover every required test category")


def _validate_stage3_quotas(
    evidence_root: Path,
    record: dict[str, Any],
    *,
    expected_daily_invocation_limit: int | None = None,
    expected_monthly_budget_usd: float | None = None,
) -> None:
    document = _read_json(evidence_root, "stage3/quota-fallbacks.json")
    if not _reviewed_document(document, record, fields={"per_session_limit", "daily_invocation_limit", "monthly_budget_usd", "cases"}):
        raise StageEvidenceError("Stage 3 quota evidence has an invalid schema")
    cases = document["cases"]
    required_cases = {"session", "daily", "monthly_budget"}
    if (
        type(document.get("per_session_limit")) is not int
        or document["per_session_limit"] != 10
        or type(document.get("daily_invocation_limit")) is not int
        or document["daily_invocation_limit"] < 1
        or not _finite_number(document.get("monthly_budget_usd"), positive=True)
        or (expected_daily_invocation_limit is not None and document["daily_invocation_limit"] != expected_daily_invocation_limit)
        or (expected_monthly_budget_usd is not None and document["monthly_budget_usd"] != expected_monthly_budget_usd)
        or not isinstance(cases, dict)
        or set(cases) != required_cases
        or any(cases[key] != {"limit_reached": True, "response_mode": "fixture"} for key in required_cases)
    ):
        raise StageEvidenceError("Stage 3 quota evidence does not prove fixture fallback at every cap")


def _validate_stage3_banners(evidence_root: Path, record: dict[str, Any]) -> None:
    document = _read_json(evidence_root, "stage3/failure-banners.json")
    if (
        not _reviewed_document(document, record, fields={"test_suite_sha256", "rendered_states"})
        or not _sha256(document.get("test_suite_sha256"))
        or not isinstance(document.get("rendered_states"), dict)
        or set(document["rendered_states"]) != _FAILURE_BANNER_STATES
        or any(value is not True for value in document["rendered_states"].values())
    ):
        raise StageEvidenceError("Stage 3 failure-banner evidence is incomplete or failed")


def _validate_stage4(evidence_root: Path, record: dict[str, Any]) -> None:
    budget = _read_json(evidence_root, "stage4/budget-cutoff.json")
    if not _reviewed_document(budget, record, fields={"monthly_budget_usd", "alert_thresholds", "alerts_triggered", "rin_disabled_at_100_percent", "cached_results_served"}):
        raise StageEvidenceError("Stage 4 budget-cutoff evidence has an invalid schema")
    if (
        not _finite_number(budget.get("monthly_budget_usd"), positive=True)
        or budget.get("alert_thresholds") != [50, 80, 100]
        or budget.get("alerts_triggered") != [50, 80, 100]
        or budget.get("rin_disabled_at_100_percent") is not True
        or budget.get("cached_results_served") is not True
    ):
        raise StageEvidenceError("Stage 4 budget evidence does not prove alerts and the 100% cutoff")

    recovery = _read_json(evidence_root, "stage4/kill-switch-recovery.json")
    if (
        not _reviewed_document(recovery, record, fields={"runbook_followed", "reviewer_not_builder", "static_mode_verified", "recovery_verified", "recovery_seconds", "parity_sha256"})
        or recovery.get("runbook_followed") is not True
        or recovery.get("reviewer_not_builder") is not True
        or recovery.get("static_mode_verified") is not True
        or recovery.get("recovery_verified") is not True
        or not _finite_number(recovery.get("recovery_seconds"), positive=False)
        or not _sha256(recovery.get("parity_sha256"))
    ):
        raise StageEvidenceError("Stage 4 kill-switch evidence does not prove independent recovery")

    load = _read_json(evidence_root, "stage4/load-resilience.json")
    multipliers = load.get("traffic_multipliers") if isinstance(load, dict) else None
    if (
        not _reviewed_document(load, record, fields={"load_report_evidence_path", "load_report_sha256", "traffic_multipliers", "waf_rate_limits_engaged", "cost_within_budget"})
        or not _bound_report(evidence_root, load, path_field="load_report_evidence_path", digest_field="load_report_sha256", expected_path=_SOURCE_REPORT_PATHS["load"])
        or not isinstance(multipliers, list)
        or len(multipliers) < 3
        or any(not _finite_number(value, positive=True) for value in multipliers)
        or len(set(multipliers)) != len(multipliers)
        or max(multipliers) <= 1
        or load.get("waf_rate_limits_engaged") is not True
        or load.get("cost_within_budget") is not True
    ):
        raise StageEvidenceError("Stage 4 load/resilience evidence does not prove WAF limits and budget control")

    actuals = _read_json(evidence_root, "stage4/actual-monthly-cost.json")
    start, end = _timestamp(actuals.get("period_start")) if isinstance(actuals, dict) else None, _timestamp(actuals.get("period_end")) if isinstance(actuals, dict) else None
    if (
        not _reviewed_document(actuals, record, fields={"period_start", "period_end", "currency", "aws_actual_usd", "aws_budget_usd", "cost_explorer_evidence_path", "cost_explorer_sha256", "provider_actual_usd", "provider_budget_usd", "provider_cost_report_evidence_path", "provider_cost_report_sha256"})
        or start is None
        or end is None
        or end < start
        or actuals.get("currency") != "USD"
        or not _finite_number(actuals.get("aws_actual_usd"), positive=False)
        or not _finite_number(actuals.get("aws_budget_usd"), positive=True)
        or actuals["aws_actual_usd"] > actuals["aws_budget_usd"]
        or not _bound_report(evidence_root, actuals, path_field="cost_explorer_evidence_path", digest_field="cost_explorer_sha256", expected_path=_SOURCE_REPORT_PATHS["aws_cost"])
        or not _finite_number(actuals.get("provider_actual_usd"), positive=False)
        or not _finite_number(actuals.get("provider_budget_usd"), positive=True)
        or actuals["provider_actual_usd"] > actuals["provider_budget_usd"]
        or not _bound_report(evidence_root, actuals, path_field="provider_cost_report_evidence_path", digest_field="provider_cost_report_sha256", expected_path=_SOURCE_REPORT_PATHS["provider_cost"])
    ):
        raise StageEvidenceError("Stage 4 actual monthly cost evidence is invalid or over budget")

    launch = _read_json(evidence_root, "stage4/launch-evidence.json")
    if (
        not _reviewed_document(launch, record, fields={"release_criteria"})
        or not isinstance(launch.get("release_criteria"), dict)
        or set(launch["release_criteria"]) != _RELEASE_CRITERIA
        or any(value is not True for value in launch["release_criteria"].values())
    ):
        raise StageEvidenceError("Stage 4 launch evidence does not satisfy every release criterion")


def validate_stage_evidence(
    stage_name: str,
    record: dict[str, Any],
    *,
    evidence_root: Path,
    expected_demo_account_id_sha256: str | None = None,
    expected_daily_invocation_limit: int | None = None,
    expected_monthly_budget_usd: float | None = None,
) -> None:
    """Reject placeholder artifacts that do not substantiate a plan criterion."""
    validators = {
        "stage1": lambda root, stage_record: _validate_stage1(
            root, stage_record, expected_demo_account_id_sha256=expected_demo_account_id_sha256
        ),
        "stage2": _validate_stage2,
        "stage3": lambda root, stage_record: (
            _validate_stage3_transport(root, stage_record),
            _validate_stage3_privacy_accessibility(root, stage_record),
            _validate_stage3_rin(root, stage_record),
            _validate_stage3_quotas(
                root,
                stage_record,
                expected_daily_invocation_limit=expected_daily_invocation_limit,
                expected_monthly_budget_usd=expected_monthly_budget_usd,
            ),
            _validate_stage3_banners(root, stage_record),
        ),
        "stage4": _validate_stage4,
    }
    try:
        validators[stage_name](evidence_root, record)
    except KeyError:
        raise StageEvidenceError(f"Unknown Phase 3 stage: {stage_name}") from None
