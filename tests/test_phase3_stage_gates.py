from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from phase3.stage_gates import STAGE_CRITERIA as IMPLEMENTED_STAGE_CRITERIA
from phase3.stage_gates import StageGateError, validate_stage_gates

STAGE_CRITERIA = {
    "stage1": [
        "two_consecutive_scheduled_scans",
        "reviewed_new_and_resolved_drift",
        "read_only_target_role_evidence",
    ],
    "stage2": ["redaction_and_secret_tests", "publisher_failure_atomicity", "public_api_method_tests"],
    "stage3": [
        "https_and_security_headers",
        "rin_evaluation",
        "quota_fallbacks",
        "failure_banners",
        "published_guardrail_policy_review",
        "bedrock_invocation_logging_review",
    ],
    "stage4": ["budget_cutoff", "kill_switch_recovery", "actual_monthly_cost", "launch_evidence"],
}
STAGE_EVIDENCE = {
    "stage1": [
        "stage1/scheduled-scan-results.json",
        "stage1/schedule-execution-log.json",
        "stage1/drift-review.json",
        "stage1/read-only-role-review.json",
    ],
    "stage2": [
        "stage2/redaction-test-results.json",
        "stage2/publisher-failure.json",
        "stage2/public-api-methods.json",
    ],
    "stage3": [
        "stage3/transport-security.json",
        "stage3/external-tls-scan.json",
        "stage3/source-reports/external-tls.json",
        "stage3/privacy-accessibility.json",
        "stage3/source-reports/browser-network.json",
        "stage3/source-reports/lighthouse.json",
        "stage3/source-reports/accessibility.json",
        "stage3/rin-evaluation.json",
        "stage3/quota-fallbacks.json",
        "stage3/failure-banners.json",
        "stage3/guardrail-policy-review.json",
        "stage3/bedrock-logging-review.json",
        "stage3/guardrail-configuration.json",
        "stage3/guardrail-evaluation.json",
        "stage3/bedrock-logging-settings.json",
        "stage3/external-provider-logging-settings.json",
    ],
    "stage4": [
        "stage4/budget-cutoff.json",
        "stage4/kill-switch-recovery.json",
        "stage4/load-resilience.json",
        "stage4/source-reports/load-test.json",
        "stage4/actual-monthly-cost.json",
        "stage4/source-reports/aws-cost-explorer.json",
        "stage4/source-reports/provider-cost.json",
        "stage4/launch-evidence.json",
    ],
}

SOURCE_REPORTS = {
    "stage1/schedule-execution-log.json": {
        "schema_version": 1,
        "reviewed_by": "security-reviewer",
        "reviewed_at": "2026-11-03T00:00:00+00:00",
        "complete_export": True,
        "export_window_start": "2026-11-02T00:00:00+00:00",
        "export_window_end": "2026-11-02T06:21:00+00:00",
        "scheduled_executions": [
            {
                "scan_run_id": "scan-1",
                "scheduled_at": "2026-11-02T00:00:00+00:00",
                "workflow_started_at": "2026-11-02T00:01:00+00:00",
                "scan_started_at": "2026-11-02T00:05:00+00:00",
                "status": "complete",
                "snapshot_sha256": "a" * 64,
            },
            {
                "scan_run_id": "scan-2",
                "scheduled_at": "2026-11-02T06:00:00+00:00",
                "workflow_started_at": "2026-11-02T06:02:00+00:00",
                "scan_started_at": "2026-11-02T06:06:00+00:00",
                "status": "complete",
                "snapshot_sha256": "b" * 64,
            },
        ],
    },
    "stage3/source-reports/external-tls.json": {"scanner": "test-scanner", "tls": "pass", "headers": "pass"},
    "stage3/source-reports/browser-network.json": {"requests": [], "unapproved_third_party_requests": 0},
    "stage3/source-reports/lighthouse.json": {
        "pages": ["dashboard", "finding", "rin"],
        "minimum_performance": 90,
    },
    "stage3/source-reports/accessibility.json": {
        "pages": ["dashboard", "finding", "rin"],
        "critical_violations": 0,
    },
    "stage4/source-reports/load-test.json": {"traffic_multipliers": [1, 2, 4], "waf_limits_engaged": True},
    "stage4/source-reports/aws-cost-explorer.json": {"currency": "USD", "actual_usd": 8.5},
    "stage4/source-reports/provider-cost.json": {"currency": "USD", "actual_usd": 3.0},
}


def _source_report_bytes(relative: str) -> bytes:
    return (json.dumps(SOURCE_REPORTS[relative], sort_keys=True) + "\n").encode()


def _stage_artifact(relative: str, reviewer: str, reviewed_at: str) -> dict:
    common = {"schema_version": 1, "reviewed_by": reviewer, "reviewed_at": reviewed_at}
    if relative == "stage1/scheduled-scan-results.json":
        schedule_log = "stage1/schedule-execution-log.json"
        return {
            **common,
            "scans": [
                {
                    "scan_run_id": "scan-1",
                    "trigger": "scheduled",
                    "status": "complete",
                    "started_at": "2026-11-02T00:05:00+00:00",
                    "completed_at": "2026-11-02T00:20:00+00:00",
                    "snapshot_sha256": "a" * 64,
                },
                {
                    "scan_run_id": "scan-2",
                    "trigger": "scheduled",
                    "status": "complete",
                    "started_at": "2026-11-02T06:06:00+00:00",
                    "completed_at": "2026-11-02T06:21:00+00:00",
                    "snapshot_sha256": "b" * 64,
                },
            ],
            "target_account_label": "demo-account",
            "target_account_id_sha256": "7" * 64,
            "schedule_execution_log_evidence_path": schedule_log,
            "schedule_execution_log_sha256": hashlib.sha256(_source_report_bytes(schedule_log)).hexdigest(),
            "consecutive_schedule_runs": True,
        }
    if relative == "stage1/drift-review.json":
        return {
            **common,
            "terraform_change_sha256": "c" * 64,
            "previous_scan_run_id": "scan-1",
            "current_scan_run_id": "scan-2",
            "new_finding_ids": ["finding-new"],
            "resolved_finding_ids": ["finding-resolved"],
        }
    if relative == "stage1/read-only-role-review.json":
        return {
            **common,
            "role_arn_sha256": "d" * 64,
            "policy_evidence_sha256": "e" * 64,
            "effective_write_actions": [],
        }
    if relative == "stage2/redaction-test-results.json":
        return {
            **common,
            "test_suite_sha256": "f" * 64,
            "passed_case_categories": [
                "account_id",
                "arn",
                "ip_address",
                "email",
                "access_key",
                "unknown_field",
                "stable_pseudonym",
            ],
            "failed_case_ids": [],
            "leaked_identifier_count": 0,
            "published_unapproved_fields": 0,
        }
    if relative == "stage2/publisher-failure.json":
        return {
            **common,
            "injected_failure": "schema_validation",
            "previous_snapshot_sha256": "1" * 64,
            "published_snapshot_sha256": "1" * 64,
            "last_good_preserved": True,
        }
    if relative == "stage2/public-api-methods.json":
        return {
            **common,
            "method_results": {
                "GET": "served",
                "HEAD": "served",
                **dict.fromkeys(
                    ("OPTIONS", "PATCH", "POST", "PUT", "DELETE", "TRACE", "CONNECT"), "rejected"
                ),
            },
        }
    if relative == "stage3/transport-security.json":
        external = _stage_artifact("stage3/external-tls-scan.json", reviewer, reviewed_at)
        digest = hashlib.sha256((json.dumps(external, sort_keys=True) + "\n").encode()).hexdigest()
        return {
            **common,
            "http_redirect_status": 301,
            "https_status": 200,
            "headers": {
                "strict_transport_security": True,
                "content_security_policy": True,
                "x_content_type_options": True,
                "referrer_policy": True,
                "frame_ancestors": True,
            },
            "external_scan_evidence_path": "stage3/external-tls-scan.json",
            "external_scan_sha256": digest,
        }
    if relative == "stage3/external-tls-scan.json":
        report = "stage3/source-reports/external-tls.json"
        return {
            **common,
            "provider": "external-scanner",
            "scanned_at": "2026-11-03T00:00:00+00:00",
            "tls_result": "pass",
            "security_headers_result": "pass",
            "source_report_evidence_path": report,
            "source_report_sha256": hashlib.sha256(_source_report_bytes(report)).hexdigest(),
        }
    if relative == "stage3/privacy-accessibility.json":
        browser, lighthouse, accessibility = (
            "stage3/source-reports/browser-network.json",
            "stage3/source-reports/lighthouse.json",
            "stage3/source-reports/accessibility.json",
        )
        return {
            **common,
            "browser_network_report_evidence_path": browser,
            "browser_network_log_sha256": hashlib.sha256(_source_report_bytes(browser)).hexdigest(),
            "unapproved_third_party_requests": [],
            "lighthouse_report_evidence_path": lighthouse,
            "lighthouse_report_sha256": hashlib.sha256(_source_report_bytes(lighthouse)).hexdigest(),
            "accessibility_report_evidence_path": accessibility,
            "accessibility_report_sha256": hashlib.sha256(_source_report_bytes(accessibility)).hexdigest(),
            "pages_checked": ["dashboard", "finding", "rin"],
        }
    if relative == "stage3/rin-evaluation.json":
        categories = (
            "prompt_injection",
            "hostile_evidence",
            "secret_leakage",
            "citation_grounding",
            "unsupported_question",
            "response_schema",
            "provider_error_fallback",
        )
        return {
            **common,
            "test_suite_sha256": "3" * 64,
            "cases": [{"case_id": category, "category": category, "passed": True} for category in categories],
        }
    if relative == "stage3/quota-fallbacks.json":
        return {
            **common,
            "per_session_limit": 10,
            "daily_invocation_limit": 100,
            "monthly_budget_usd": 25.0,
            "cases": {
                name: {"limit_reached": True, "response_mode": "fixture"}
                for name in ("session", "daily", "monthly_budget")
            },
        }
    if relative == "stage3/failure-banners.json":
        states = (
            "partial_scan",
            "failed_scan",
            "stale_data",
            "publication_blocked",
            "api_unavailable",
            "rin_unavailable",
            "rin_over_budget",
            "kill_switch_static_mode",
        )
        return {**common, "test_suite_sha256": "4" * 64, "rendered_states": dict.fromkeys(states, True)}
    if relative == "stage4/budget-cutoff.json":
        return {
            **common,
            "monthly_budget_usd": 25.0,
            "alert_thresholds": [50, 80, 100],
            "alerts_triggered": [50, 80, 100],
            "rin_disabled_at_100_percent": True,
            "cached_results_served": True,
        }
    if relative == "stage4/kill-switch-recovery.json":
        return {
            **common,
            "runbook_followed": True,
            "reviewer_not_builder": True,
            "static_mode_verified": True,
            "recovery_verified": True,
            "recovery_seconds": 45,
            "parity_sha256": "5" * 64,
        }
    if relative == "stage4/load-resilience.json":
        report = "stage4/source-reports/load-test.json"
        return {
            **common,
            "load_report_evidence_path": report,
            "load_report_sha256": hashlib.sha256(_source_report_bytes(report)).hexdigest(),
            "traffic_multipliers": [1, 2, 4],
            "waf_rate_limits_engaged": True,
            "cost_within_budget": True,
        }
    if relative == "stage4/actual-monthly-cost.json":
        aws_report, provider_report = (
            "stage4/source-reports/aws-cost-explorer.json",
            "stage4/source-reports/provider-cost.json",
        )
        return {
            **common,
            "period_start": "2026-10-01T00:00:00+00:00",
            "period_end": "2026-10-31T23:59:59+00:00",
            "currency": "USD",
            "aws_actual_usd": 8.5,
            "aws_budget_usd": 25.0,
            "cost_explorer_evidence_path": aws_report,
            "cost_explorer_sha256": hashlib.sha256(_source_report_bytes(aws_report)).hexdigest(),
            "provider_actual_usd": 3.0,
            "provider_budget_usd": 10.0,
            "provider_cost_report_evidence_path": provider_report,
            "provider_cost_report_sha256": hashlib.sha256(_source_report_bytes(provider_report)).hexdigest(),
        }
    if relative == "stage4/launch-evidence.json":
        criteria = (
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
        )
        return {**common, "release_criteria": dict.fromkeys(criteria, True)}
    return {"checked": True}


def _write_manifest(root: Path, *, accepted: set[str] = frozenset(), missing_evidence: bool = False) -> Path:
    evidence_root = root / "docs/evidence"
    evidence_root.mkdir(parents=True)
    stages = {}
    for name, criteria in STAGE_CRITERIA.items():
        is_accepted = name in accepted
        evidence = []
        if is_accepted:
            evidence = STAGE_EVIDENCE[name]
            for relative in evidence:
                if missing_evidence:
                    continue
                evidence_path = evidence_root / relative
                evidence_path.parent.mkdir(parents=True, exist_ok=True)
                if relative in SOURCE_REPORTS:
                    evidence_path.write_bytes(_source_report_bytes(relative))
                    continue
                artifact = _stage_artifact(
                    relative, "security-reviewer", datetime(2026, 11, 3, tzinfo=UTC).isoformat()
                )
                evidence_path.write_text(json.dumps(artifact, sort_keys=True) + "\n", encoding="utf-8")
        evidence_hashes = {}
        if is_accepted:
            for relative in evidence:
                evidence_path = evidence_root / relative
                evidence_hashes[relative] = (
                    hashlib.sha256(evidence_path.read_bytes()).hexdigest()
                    if evidence_path.exists()
                    else "0" * 64
                )
        stages[name] = {
            "status": "passed" if is_accepted else "pending",
            "reviewed_by": "security-reviewer" if is_accepted else None,
            "reviewed_at": datetime(2026, 11, 3, tzinfo=UTC).isoformat() if is_accepted else None,
            "criteria": dict.fromkeys(criteria, is_accepted),
            "evidence": evidence,
            "evidence_sha256": evidence_hashes if is_accepted else {},
        }
    path = evidence_root / "phase3-stage-acceptance.json"
    path.write_text(json.dumps({"schema_version": 3, "stages": stages}), encoding="utf-8")
    return path


def _add_guardrail_review_artifacts(manifest: Path) -> None:
    value = json.loads(manifest.read_text(encoding="utf-8"))
    record = value["stages"]["stage3"]
    reviewed_by = record["reviewed_by"]
    reviewed_at = record["reviewed_at"]
    guardrail_arn = "arn:aws:bedrock:us-east-1:123456789012:guardrail/guardrail123"
    input_controls = {
        "prompt_attack_filter": True,
        "off_scope_topics": ["credential disclosure"],
        "sensitive_data_filter": True,
    }
    output_controls = {
        "prompt_attack_filter": True,
        "off_scope_topics": ["credential disclosure"],
        "sensitive_data_filter": True,
    }
    source_artifacts = {
        "stage3/guardrail-configuration.json": {
            "schema_version": 1,
            "guardrail_arn": guardrail_arn,
            "published_version": "1",
            "input_controls": input_controls,
            "output_controls": output_controls,
        },
        "stage3/guardrail-evaluation.json": {
            "schema_version": 1,
            "guardrail_arn": guardrail_arn,
            "published_version": "1",
            "passed": True,
            "case_count": 7,
            "cases": [
                {
                    "case_id": category,
                    "category": category,
                    "expected_action": "BLOCK",
                    "observed_action": "BLOCK",
                    "passed": True,
                }
                for category in (
                    "input_prompt_attack",
                    "input_sensitive_data",
                    "input_off_scope",
                    "output_prompt_attack",
                    "output_sensitive_data",
                    "output_off_scope",
                )
            ]
            + [
                {
                    "case_id": "safe_in_scope",
                    "category": "safe_in_scope",
                    "expected_action": "ALLOW",
                    "observed_action": "ALLOW",
                    "passed": True,
                }
            ],
        },
        "stage3/bedrock-logging-settings.json": {
            "schema_version": 1,
            "enabled": False,
            "includes_prompt_content": False,
            "retention_days": None,
        },
        "stage3/external-provider-logging-settings.json": {
            "schema_version": 1,
            "provider": "approved-external-model",
            "enabled": False,
            "includes_prompt_content": False,
            "retention_days": None,
        },
    }
    source_hashes = {}
    for relative_path, artifact in source_artifacts.items():
        artifact_bytes = (json.dumps(artifact, sort_keys=True) + "\n").encode()
        (manifest.parent / relative_path).write_bytes(artifact_bytes)
        source_hashes[relative_path] = hashlib.sha256(artifact_bytes).hexdigest()

    policy = {
        "schema_version": 1,
        "guardrail_arn": guardrail_arn,
        "published_version": "1",
        "configuration_evidence_path": "stage3/guardrail-configuration.json",
        "configuration_sha256": source_hashes["stage3/guardrail-configuration.json"],
        "input_controls": input_controls,
        "output_controls": output_controls,
        "evaluation": {
            "evidence_path": "stage3/guardrail-evaluation.json",
            "sha256": source_hashes["stage3/guardrail-evaluation.json"],
            "passed": True,
            "case_count": 7,
        },
        "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at,
    }
    logging = {
        "schema_version": 1,
        "guardrail_arn": guardrail_arn,
        "published_version": "1",
        "bedrock_model_invocation_logging": {
            "enabled": False,
            "includes_prompt_content": False,
            "retention_days": None,
            "evidence_path": "stage3/bedrock-logging-settings.json",
            "settings_sha256": source_hashes["stage3/bedrock-logging-settings.json"],
        },
        "external_provider_logging": {
            "provider": "approved-external-model",
            "enabled": False,
            "includes_prompt_content": False,
            "retention_days": None,
            "evidence_path": "stage3/external-provider-logging-settings.json",
            "settings_sha256": source_hashes["stage3/external-provider-logging-settings.json"],
        },
        "maximum_prompt_retention_days": 30,
        "reviewed_by": reviewed_by,
        "reviewed_at": reviewed_at,
    }
    for path, artifact in (
        ("stage3/guardrail-policy-review.json", policy),
        ("stage3/bedrock-logging-review.json", logging),
    ):
        (manifest.parent / path).write_text(json.dumps(artifact, sort_keys=True) + "\n", encoding="utf-8")
        if path not in record["evidence"]:
            record["evidence"].append(path)
    for path in source_artifacts:
        if path not in record["evidence"]:
            record["evidence"].append(path)
    record["evidence_sha256"] = {
        path: hashlib.sha256((manifest.parent / path).read_bytes()).hexdigest() for path in record["evidence"]
    }
    manifest.write_text(json.dumps(value), encoding="utf-8")


def _refresh_stage_evidence_hashes(manifest: Path, stage_name: str) -> None:
    value = json.loads(manifest.read_text(encoding="utf-8"))
    record = value["stages"][stage_name]
    record["evidence_sha256"] = {
        relative: hashlib.sha256((manifest.parent / relative).read_bytes()).hexdigest()
        for relative in record["evidence"]
    }
    manifest.write_text(json.dumps(value), encoding="utf-8")


def test_stage_two_is_blocked_until_stage_one_has_reviewed_evidence(tmp_path):
    manifest = _write_manifest(tmp_path)

    with pytest.raises(StageGateError, match="Stage 1 acceptance"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_one_cannot_pass_with_a_generic_placeholder_file(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})
    value = json.loads(manifest.read_text(encoding="utf-8"))
    record = value["stages"]["stage1"]
    placeholder = manifest.parent / "stage1/acceptance.json"
    placeholder.write_text('{"checked":true}\n', encoding="utf-8")
    record["evidence"] = ["stage1/acceptance.json"]
    record["evidence_sha256"] = {
        "stage1/acceptance.json": hashlib.sha256(placeholder.read_bytes()).hexdigest()
    }
    manifest.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(StageGateError, match="requires evidence for every plan criterion"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_one_rejects_placeholder_content_under_a_required_evidence_path(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})
    evidence = manifest.parent / "stage1/scheduled-scan-results.json"
    evidence.write_text('{"checked":true}\n', encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage1")

    with pytest.raises(StageGateError, match="scheduled-scan evidence has an invalid schema"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_two_rejects_placeholder_content_under_a_required_evidence_path(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2"})
    evidence = manifest.parent / "stage2/redaction-test-results.json"
    evidence.write_text('{"checked":true}\n', encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage2")

    with pytest.raises(StageGateError, match="redaction-test evidence is incomplete or failed"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_one_evidence_tampering_after_review_blocks_the_next_stage(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})
    evidence = manifest.parent / "stage1/scheduled-scan-results.json"
    evidence.write_text('{"review_status":"changed"}\n', encoding="utf-8")

    with pytest.raises(StageGateError, match="evidence digest does not match the reviewed file"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_three_requires_both_stage_one_and_stage_two_acceptance(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})

    with pytest.raises(StageGateError, match="Stage 2 acceptance"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_three_acceptance_explicitly_requires_guardrail_policy_and_logging_review():
    assert {
        "published_guardrail_policy_review",
        "bedrock_invocation_logging_review",
    }.issubset(IMPLEMENTED_STAGE_CRITERIA["stage3"])


def test_stage_three_cannot_pass_without_guardrail_policy_and_logging_artifacts(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})

    with pytest.raises(StageGateError, match="Guardrail policy review evidence is invalid"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_three_passes_with_guardrail_policy_and_logging_artifacts(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)

    validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_three_rin_evaluation_requires_every_plan_test_category(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)
    evaluation_path = manifest.parent / "stage3/rin-evaluation.json"
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    evaluation["cases"] = evaluation["cases"][:1]
    evaluation_path.write_text(json.dumps(evaluation), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage3")

    with pytest.raises(StageGateError, match="Rin evaluation does not cover every required test category"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_three_rejects_placeholder_guardrail_review_documents(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    value = json.loads(manifest.read_text(encoding="utf-8"))
    evidence = value["stages"]["stage3"]["evidence"]
    for path in ("stage3/guardrail-policy-review.json", "stage3/bedrock-logging-review.json"):
        artifact = manifest.parent / path
        artifact.write_text('{"reviewed":true}\n', encoding="utf-8")
        if path not in evidence:
            evidence.append(path)
    for path in (
        "stage3/guardrail-configuration.json",
        "stage3/guardrail-evaluation.json",
        "stage3/bedrock-logging-settings.json",
        "stage3/external-provider-logging-settings.json",
    ):
        (manifest.parent / path).write_text("{}\n", encoding="utf-8")
        if path not in evidence:
            evidence.append(path)
    value["stages"]["stage3"]["evidence_sha256"] = {
        path: hashlib.sha256((manifest.parent / path).read_bytes()).hexdigest() for path in evidence
    }
    manifest.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(StageGateError, match="Guardrail policy review evidence is invalid"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_three_rejects_prompt_logging_beyond_the_approved_retention(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)
    logging_path = manifest.parent / "stage3/bedrock-logging-review.json"
    logging = json.loads(logging_path.read_text(encoding="utf-8"))
    logging["external_provider_logging"]["includes_prompt_content"] = True
    logging["external_provider_logging"]["enabled"] = True
    logging["external_provider_logging"]["retention_days"] = 90
    logging_path.write_text(json.dumps(logging), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage3")

    with pytest.raises(StageGateError, match="logging review evidence is invalid"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


@pytest.mark.parametrize(
    "evidence_path",
    [
        "stage3/guardrail-configuration.json",
        "stage3/guardrail-evaluation.json",
        "stage3/bedrock-logging-settings.json",
        "stage3/external-provider-logging-settings.json",
    ],
)
def test_stage_three_binds_review_digests_to_captured_evidence_files(tmp_path, evidence_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)
    (manifest.parent / evidence_path).write_text('{"tampered":true}\n', encoding="utf-8")

    with pytest.raises(StageGateError, match="stage3 evidence digest does not match the reviewed file"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


@pytest.mark.parametrize(
    ("source_path", "review_path", "source_section", "field", "value", "review_section"),
    [
        (
            "stage3/guardrail-configuration.json",
            "stage3/guardrail-policy-review.json",
            "input_controls",
            "prompt_attack_filter",
            False,
            "input_controls",
        ),
        (
            "stage3/guardrail-evaluation.json",
            "stage3/guardrail-policy-review.json",
            None,
            "passed",
            False,
            "evaluation",
        ),
        (
            "stage3/bedrock-logging-settings.json",
            "stage3/bedrock-logging-review.json",
            None,
            "includes_prompt_content",
            True,
            "bedrock_model_invocation_logging",
        ),
        (
            "stage3/external-provider-logging-settings.json",
            "stage3/bedrock-logging-review.json",
            None,
            "includes_prompt_content",
            True,
            "external_provider_logging",
        ),
    ],
)
def test_stage_three_rejects_hash_correct_captures_that_contradict_the_review(
    tmp_path, source_path, review_path, source_section, field, value, review_section
):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)
    source_file = manifest.parent / source_path
    source = json.loads(source_file.read_text(encoding="utf-8"))
    target = source[source_section] if source_section else source
    target[field] = value
    source_bytes = (json.dumps(source, sort_keys=True) + "\n").encode()
    source_file.write_bytes(source_bytes)

    review_file = manifest.parent / review_path
    review = json.loads(review_file.read_text(encoding="utf-8"))
    if review_path.endswith("guardrail-policy-review.json"):
        if review_section == "evaluation":
            review[review_section][field] = not value
        else:
            review[review_section][field] = not value
    else:
        review[review_section][field] = not value
    digest = hashlib.sha256(source_bytes).hexdigest()
    if source_path.endswith("guardrail-configuration.json"):
        review["configuration_sha256"] = digest
    elif source_path.endswith("guardrail-evaluation.json"):
        review["evaluation"]["sha256"] = digest
    else:
        review[review_section]["settings_sha256"] = digest
    review_file.write_text(json.dumps(review), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage3")

    with pytest.raises(StageGateError, match="review evidence is invalid"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_three_rejects_a_passing_evaluation_with_a_wrong_observed_action(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)
    evidence_root = manifest.parent
    evaluation_path = evidence_root / "stage3/guardrail-evaluation.json"
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    evaluation["cases"][0]["observed_action"] = "ALLOW"
    evaluation_bytes = (json.dumps(evaluation, sort_keys=True) + "\n").encode()
    evaluation_path.write_bytes(evaluation_bytes)

    review_path = evidence_root / "stage3/guardrail-policy-review.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["evaluation"]["sha256"] = hashlib.sha256(evaluation_bytes).hexdigest()
    review_path.write_text(json.dumps(review), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage3")

    with pytest.raises(StageGateError, match="Guardrail policy review evidence is invalid"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_three_rejects_prompt_retention_over_thirty_days(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)
    logging_path = manifest.parent / "stage3/bedrock-logging-review.json"
    logging = json.loads(logging_path.read_text(encoding="utf-8"))
    logging["maximum_prompt_retention_days"] = 90
    logging_path.write_text(json.dumps(logging), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage3")

    with pytest.raises(StageGateError, match="logging review evidence is invalid"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_gate_rejects_a_passed_stage_with_missing_evidence_artifact(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"}, missing_evidence=True)

    with pytest.raises(StageGateError, match="missing or empty evidence"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_gate_rejects_evidence_paths_that_escape_docs_evidence(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})
    value = json.loads(manifest.read_text(encoding="utf-8"))
    value["stages"]["stage1"]["evidence"] = ["../../README.md"]
    manifest.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(StageGateError, match="invalid evidence path"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_gate_rejects_duplicate_json_keys_in_the_acceptance_manifest(tmp_path):
    manifest = _write_manifest(tmp_path)
    manifest_text = manifest.read_text(encoding="utf-8").replace(
        '"schema_version": 3,',
        '"schema_version": 3, "schema_version": 3,',
        1,
    )
    manifest.write_text(manifest_text, encoding="utf-8")

    with pytest.raises(StageGateError, match="manifest is missing or invalid"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages=set())


def test_stage_gate_rejects_duplicate_json_keys_in_reviewed_stage_three_evidence(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)
    review_path = manifest.parent / "stage3/guardrail-policy-review.json"
    review_text = review_path.read_text(encoding="utf-8")
    review_text = review_text.replace(
        '"reviewed_by": "security-reviewer"',
        '"reviewed_by": "security-reviewer", "reviewed_by": "security-reviewer"',
        1,
    )
    review_path.write_text(review_text, encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage3")

    with pytest.raises(StageGateError, match="Guardrail policy review evidence is invalid"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3})


def test_stage_gate_rejects_a_symlinked_evidence_directory(tmp_path):
    root = tmp_path / "repo"
    manifest = _write_manifest(root, accepted={"stage1"})
    evidence_directory = root / "docs/evidence"
    external_directory = tmp_path / "external-evidence"
    evidence_directory.rename(external_directory)
    evidence_directory.symlink_to(external_directory, target_is_directory=True)

    with pytest.raises(StageGateError, match="evidence directory"):
        validate_stage_gates(manifest, root=root, enabled_stages={2})


def test_stage_four_requires_all_preceding_stage_acceptance(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2"})

    with pytest.raises(StageGateError, match="Stage 3 acceptance"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3, 4})


def test_stage_four_rejects_actual_cost_above_the_recorded_budget(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3", "stage4"})
    _add_guardrail_review_artifacts(manifest)
    actuals_path = manifest.parent / "stage4/actual-monthly-cost.json"
    actuals = json.loads(actuals_path.read_text(encoding="utf-8"))
    actuals["aws_actual_usd"] = 30.0
    actuals_path.write_text(json.dumps(actuals), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage4")

    with pytest.raises(StageGateError, match="actual monthly cost evidence is invalid or over budget"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3, 4})


def test_stage_one_binds_scan_evidence_to_the_configured_demo_account(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})

    with pytest.raises(StageGateError, match="configured demo account"):
        validate_stage_gates(
            manifest,
            root=tmp_path,
            enabled_stages={2},
            expected_demo_account_id_sha256=hashlib.sha256(b"999999999999").hexdigest(),
        )


def test_stage_one_schedule_export_binds_scan_ids_times_and_snapshot_digests(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})
    schedule_path = manifest.parent / "stage1/schedule-execution-log.json"
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    schedule["scheduled_executions"][0]["snapshot_sha256"] = "f" * 64
    schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
    scans_path = manifest.parent / "stage1/scheduled-scan-results.json"
    scans = json.loads(scans_path.read_text(encoding="utf-8"))
    scans["schedule_execution_log_sha256"] = hashlib.sha256(schedule_path.read_bytes()).hexdigest()
    scans_path.write_text(json.dumps(scans), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage1")

    with pytest.raises(StageGateError, match="schedule log does not prove"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


@pytest.mark.parametrize(
    "scheduled_at",
    ["2026-11-01T22:00:00+00:00", "2026-11-02T06:01:00+00:00"],
)
def test_stage_one_schedule_export_enforces_six_hour_cadence_and_retry_window(tmp_path, scheduled_at):
    manifest = _write_manifest(tmp_path, accepted={"stage1"})
    schedule_path = manifest.parent / "stage1/schedule-execution-log.json"
    schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
    if scheduled_at.startswith("2026-11-01"):
        schedule["export_window_start"] = scheduled_at
        schedule["scheduled_executions"][0]["scheduled_at"] = scheduled_at
    else:
        schedule["scheduled_executions"][1]["scheduled_at"] = scheduled_at
    schedule_path.write_text(json.dumps(schedule), encoding="utf-8")
    scans_path = manifest.parent / "stage1/scheduled-scan-results.json"
    scans = json.loads(scans_path.read_text(encoding="utf-8"))
    scans["schedule_execution_log_sha256"] = hashlib.sha256(schedule_path.read_bytes()).hexdigest()
    scans_path.write_text(json.dumps(scans), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage1")

    with pytest.raises(StageGateError, match="schedule log does not prove"):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2})


def test_stage_three_binds_quota_evidence_to_runtime_caps(tmp_path):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)

    with pytest.raises(StageGateError, match="quota evidence"):
        validate_stage_gates(
            manifest,
            root=tmp_path,
            enabled_stages={2, 3},
            expected_daily_invocation_limit=99,
            expected_monthly_budget_usd=25.0,
        )


def test_precredential_cli_binds_account_and_rin_runtime_settings(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts/validate_phase3_stage_gates.py"
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3"})
    _add_guardrail_review_artifacts(manifest)
    scans_path = manifest.parent / "stage1/scheduled-scan-results.json"
    scans = json.loads(scans_path.read_text(encoding="utf-8"))
    scans["target_account_id_sha256"] = hashlib.sha256(b"123456789012").hexdigest()
    scans_path.write_text(json.dumps(scans), encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage1")
    _refresh_stage_evidence_hashes(manifest, "stage3")
    environment = {
        **os.environ,
        "PHASE3_ENABLE_STAGE2": "true",
        "PHASE3_ENABLE_STAGE3": "true",
        "PHASE3_ENABLE_STAGE4": "false",
        "TF_VAR_demo_account_id": "123456789012",
        "TF_VAR_provider_monthly_budget_usd": "25",
        "TF_VAR_rin_input_cost_per_million_tokens_usd": "6.66",
        "TF_VAR_rin_output_cost_per_million_tokens_usd": "0",
        "TF_VAR_rin_max_input_tokens": "1000",
        "TF_VAR_rin_max_output_tokens": "500",
    }

    passed = subprocess.run(
        [sys.executable, str(script), "--root", str(tmp_path)],
        cwd=script.parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    mismatched = subprocess.run(
        [sys.executable, str(script), "--root", str(tmp_path)],
        cwd=script.parents[1],
        env={**environment, "TF_VAR_demo_account_id": "999999999999"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert passed.returncode == 0, passed.stderr
    assert mismatched.returncode == 1
    assert "configured demo account" in mismatched.stderr


@pytest.mark.parametrize(
    ("report_path", "message"),
    [
        ("stage3/source-reports/external-tls.json", "external TLS"),
        ("stage3/source-reports/browser-network.json", "privacy/accessibility"),
        ("stage3/source-reports/lighthouse.json", "privacy/accessibility"),
        ("stage3/source-reports/accessibility.json", "privacy/accessibility"),
        ("stage4/source-reports/load-test.json", "load/resilience"),
        ("stage4/source-reports/aws-cost-explorer.json", "actual monthly cost"),
        ("stage4/source-reports/provider-cost.json", "actual monthly cost"),
    ],
)
def test_stage_reports_must_match_their_bound_source_files(tmp_path, report_path, message):
    manifest = _write_manifest(tmp_path, accepted={"stage1", "stage2", "stage3", "stage4"})
    _add_guardrail_review_artifacts(manifest)
    source_report = manifest.parent / report_path
    source_report.write_text('{"tampered":true}\n', encoding="utf-8")
    _refresh_stage_evidence_hashes(manifest, "stage3" if report_path.startswith("stage3/") else "stage4")

    with pytest.raises(StageGateError, match=message):
        validate_stage_gates(manifest, root=tmp_path, enabled_stages={2, 3, 4})


def test_workflow_gate_cli_allows_disabled_stages_but_blocks_stage_two(tmp_path):
    script = Path(__file__).resolve().parents[1] / "scripts/validate_phase3_stage_gates.py"
    # Run against all-pending stage records so the result does not depend on the
    # repository's real, checked-in acceptance evidence.
    manifest = json.loads((script.parents[1] / "docs/evidence/phase3-stage-acceptance.json").read_text())
    for name, stage in manifest["stages"].items():
        manifest["stages"][name] = {
            "status": "pending",
            "reviewed_by": None,
            "reviewed_at": None,
            "criteria": dict.fromkeys(stage["criteria"], False),
            "evidence": [],
            "evidence_sha256": {},
        }
    (tmp_path / "docs/evidence").mkdir(parents=True)
    (tmp_path / "docs/evidence/phase3-stage-acceptance.json").write_text(json.dumps(manifest))
    environment = {
        **os.environ,
        "PHASE3_ENABLE_STAGE2": "false",
        "PHASE3_ENABLE_STAGE3": "false",
        "PHASE3_ENABLE_STAGE4": "false",
    }
    disabled = subprocess.run(
        [sys.executable, str(script), "--root", str(tmp_path)],
        cwd=script.parents[1],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    enabled = subprocess.run(
        [sys.executable, str(script), "--root", str(tmp_path)],
        cwd=script.parents[1],
        env={**environment, "PHASE3_ENABLE_STAGE2": "true"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert disabled.returncode == 0, disabled.stderr
    assert enabled.returncode == 1
    assert "Stage 2 requires reviewed Stage 1 acceptance evidence" in enabled.stderr
