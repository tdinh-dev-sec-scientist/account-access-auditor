"""Validate checked-in evidence before enabling the next Phase 3 stage."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from phase3.stage_evidence import StageEvidenceError, validate_stage_evidence

STAGE_CRITERIA = {
    "stage1": {
        "two_consecutive_scheduled_scans",
        "reviewed_new_and_resolved_drift",
        "read_only_target_role_evidence",
    },
    "stage2": {
        "redaction_and_secret_tests",
        "publisher_failure_atomicity",
        "public_api_method_tests",
    },
    "stage3": {
        "https_and_security_headers",
        "rin_evaluation",
        "quota_fallbacks",
        "failure_banners",
        "published_guardrail_policy_review",
        "bedrock_invocation_logging_review",
    },
    "stage4": {
        "budget_cutoff",
        "kill_switch_recovery",
        "actual_monthly_cost",
        "launch_evidence",
    },
}
STAGE_REQUIRED_EVIDENCE = {
    "stage1": {
        "stage1/scheduled-scan-results.json",
        "stage1/schedule-execution-log.json",
        "stage1/drift-review.json",
        "stage1/read-only-role-review.json",
    },
    "stage2": {
        "stage2/redaction-test-results.json",
        "stage2/publisher-failure.json",
        "stage2/public-api-methods.json",
    },
    "stage3": {
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
    },
    "stage4": {
        "stage4/budget-cutoff.json",
        "stage4/kill-switch-recovery.json",
        "stage4/load-resilience.json",
        "stage4/source-reports/load-test.json",
        "stage4/actual-monthly-cost.json",
        "stage4/source-reports/aws-cost-explorer.json",
        "stage4/source-reports/provider-cost.json",
        "stage4/launch-evidence.json",
    },
}
STAGE3_MAX_PROMPT_RETENTION_DAYS = 30
_STAGE3_GUARDRAIL_CONFIGURATION = "stage3/guardrail-configuration.json"
_STAGE3_GUARDRAIL_EVALUATION = "stage3/guardrail-evaluation.json"
_STAGE3_BEDROCK_LOGGING = "stage3/bedrock-logging-settings.json"
_STAGE3_EXTERNAL_LOGGING = "stage3/external-provider-logging-settings.json"
_GUARDRAIL_EVALUATION_ACTIONS = {
    "input_prompt_attack": "BLOCK",
    "input_sensitive_data": "BLOCK",
    "input_off_scope": "BLOCK",
    "output_prompt_attack": "BLOCK",
    "output_sensitive_data": "BLOCK",
    "output_off_scope": "BLOCK",
    "safe_in_scope": "ALLOW",
}
_STAGE_NUMBER = {f"stage{number}": number for number in range(1, 5)}
_EVIDENCE_PATH = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,199}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_GUARDRAIL_ARN = re.compile(
    r"^arn:(?:aws|aws-us-gov|aws-cn):bedrock:[a-z0-9-]+:[0-9]{12}:guardrail/[a-z0-9]+$"
)
_GUARDRAIL_VERSION = re.compile(r"^[1-9][0-9]{0,7}$")


class StageGateError(ValueError):
    """A requested stage has no complete, reviewed predecessor evidence."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)


def _validate_evidence_paths(stage_name: str, paths: Any, *, root: Path) -> None:
    if (
        not isinstance(paths, list)
        or not paths
        or len(paths) > 100
        or any(not isinstance(path, str) for path in paths)
        or len(paths) != len(set(paths))
    ):
        raise StageGateError(f"{stage_name} acceptance requires distinct, checked-in evidence files")
    evidence_directory = root / "docs/evidence"
    if evidence_directory.is_symlink() or not evidence_directory.is_dir():
        raise StageGateError(f"{stage_name} acceptance evidence directory is missing")
    evidence_root = evidence_directory.resolve()
    try:
        evidence_root.relative_to(root)
    except ValueError:
        raise StageGateError(
            f"{stage_name} acceptance evidence directory is outside the repository"
        ) from None
    for raw_path in paths:
        if (
            not isinstance(raw_path, str)
            or not _EVIDENCE_PATH.fullmatch(raw_path)
            or "\\" in raw_path
            or any(part in {"", ".", ".."} for part in PurePosixPath(raw_path).parts)
            or PurePosixPath(raw_path).parts[0] != stage_name
        ):
            raise StageGateError(f"{stage_name} contains an invalid evidence path")
        candidate = evidence_root.joinpath(*PurePosixPath(raw_path).parts)
        current = evidence_root
        for part in PurePosixPath(raw_path).parts:
            current = current / part
            if current.is_symlink():
                raise StageGateError(f"{stage_name} contains an invalid evidence path")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(evidence_root)
        except FileNotFoundError:
            raise StageGateError(f"{stage_name} has missing or empty evidence files") from None
        except (OSError, ValueError):
            raise StageGateError(f"{stage_name} contains an invalid evidence path") from None
        if not resolved.is_file() or resolved.stat().st_size == 0:
            raise StageGateError(f"{stage_name} has missing or empty evidence files")


def _evidence_sha256(evidence_root: Path, relative_path: str) -> str | None:
    candidate = evidence_root.joinpath(*PurePosixPath(relative_path).parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(evidence_root.resolve())
        if not resolved.is_file() or candidate.is_symlink():
            return None
        return hashlib.sha256(resolved.read_bytes()).hexdigest()
    except (OSError, ValueError):
        return None


def _valid_review_metadata(document: dict[str, Any], record: dict[str, Any]) -> bool:
    return (
        isinstance(document.get("reviewed_by"), str)
        and document["reviewed_by"] == record["reviewed_by"]
        and isinstance(document.get("reviewed_at"), str)
        and document["reviewed_at"] == record["reviewed_at"]
    )


def _valid_policy_controls(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"prompt_attack_filter", "off_scope_topics", "sensitive_data_filter"}
        and value["prompt_attack_filter"] is True
        and value["sensitive_data_filter"] is True
        and isinstance(value["off_scope_topics"], list)
        and 0 < len(value["off_scope_topics"]) <= 100
        and all(isinstance(topic, str) and topic.strip() for topic in value["off_scope_topics"])
    )


def _valid_guardrail_policy_review(document: Any, record: dict[str, Any], *, evidence_root: Path) -> bool:
    required_fields = {
        "schema_version",
        "guardrail_arn",
        "published_version",
        "configuration_evidence_path",
        "configuration_sha256",
        "input_controls",
        "output_controls",
        "evaluation",
        "reviewed_by",
        "reviewed_at",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required_fields
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or not isinstance(document.get("guardrail_arn"), str)
        or not _GUARDRAIL_ARN.fullmatch(document["guardrail_arn"])
        or not isinstance(document.get("published_version"), str)
        or not _GUARDRAIL_VERSION.fullmatch(document["published_version"])
        or document.get("configuration_evidence_path") != _STAGE3_GUARDRAIL_CONFIGURATION
        or not isinstance(document.get("configuration_sha256"), str)
        or not _SHA256.fullmatch(document["configuration_sha256"])
        or document["configuration_sha256"]
        != _evidence_sha256(evidence_root, _STAGE3_GUARDRAIL_CONFIGURATION)
        or not _valid_policy_controls(document.get("input_controls"))
        or not _valid_policy_controls(document.get("output_controls"))
        or not _valid_review_metadata(document, record)
    ):
        return False
    evaluation = document.get("evaluation")
    return (
        isinstance(evaluation, dict)
        and set(evaluation) == {"evidence_path", "sha256", "passed", "case_count"}
        and evaluation["evidence_path"] == _STAGE3_GUARDRAIL_EVALUATION
        and isinstance(evaluation["sha256"], str)
        and bool(_SHA256.fullmatch(evaluation["sha256"]))
        and evaluation["sha256"] == _evidence_sha256(evidence_root, _STAGE3_GUARDRAIL_EVALUATION)
        and evaluation["passed"] is True
        and type(evaluation["case_count"]) is int
        and evaluation["case_count"] > 0
    )


def _valid_guardrail_configuration_capture(document: Any, review: dict[str, Any]) -> bool:
    return (
        isinstance(document, dict)
        and set(document)
        == {"schema_version", "guardrail_arn", "published_version", "input_controls", "output_controls"}
        and type(document.get("schema_version")) is int
        and document["schema_version"] == 1
        and document.get("guardrail_arn") == review["guardrail_arn"]
        and document.get("published_version") == review["published_version"]
        and _valid_policy_controls(document.get("input_controls"))
        and _valid_policy_controls(document.get("output_controls"))
        and document["input_controls"] == review["input_controls"]
        and document["output_controls"] == review["output_controls"]
    )


def _valid_guardrail_evaluation_capture(document: Any, review: dict[str, Any]) -> bool:
    if (
        not isinstance(document, dict)
        or set(document)
        != {"schema_version", "guardrail_arn", "published_version", "passed", "case_count", "cases"}
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or document.get("guardrail_arn") != review["guardrail_arn"]
        or document.get("published_version") != review["published_version"]
        or document.get("passed") is not True
        or document.get("passed") != review["evaluation"]["passed"]
        or type(document.get("case_count")) is not int
        or document["case_count"] != review["evaluation"]["case_count"]
        or not isinstance(document.get("cases"), list)
        or len(document["cases"]) != document["case_count"]
    ):
        return False
    cases = document["cases"]
    if any(
        not isinstance(case, dict)
        or set(case) != {"case_id", "category", "expected_action", "observed_action", "passed"}
        or not isinstance(case.get("case_id"), str)
        or not case["case_id"].strip()
        or not isinstance(case.get("category"), str)
        or case.get("category") not in _GUARDRAIL_EVALUATION_ACTIONS
        or case.get("expected_action") != _GUARDRAIL_EVALUATION_ACTIONS[case["category"]]
        or case.get("observed_action") != case["expected_action"]
        or case.get("passed") is not True
        for case in cases
    ):
        return False
    case_ids = [case["case_id"] for case in cases]
    categories = {case["category"] for case in cases}
    return len(case_ids) == len(set(case_ids)) and set(_GUARDRAIL_EVALUATION_ACTIONS).issubset(categories)


def _valid_logging_scope(
    value: Any,
    *,
    max_prompt_retention_days: int,
    require_provider: bool,
    evidence_root: Path,
    evidence_path: str,
) -> bool:
    required_fields = {
        "enabled",
        "includes_prompt_content",
        "retention_days",
        "evidence_path",
        "settings_sha256",
    }
    if require_provider:
        required_fields.add("provider")
    if (
        not isinstance(value, dict)
        or set(value) != required_fields
        or type(value.get("enabled")) is not bool
        or type(value.get("includes_prompt_content")) is not bool
        or not isinstance(value.get("settings_sha256"), str)
        or not _SHA256.fullmatch(value["settings_sha256"])
        or value.get("evidence_path") != evidence_path
        or value["settings_sha256"] != _evidence_sha256(evidence_root, evidence_path)
        or (
            require_provider and (not isinstance(value.get("provider"), str) or not value["provider"].strip())
        )
    ):
        return False
    retention = value.get("retention_days")
    if retention is not None and (type(retention) is not int or retention < 0):
        return False
    if value["includes_prompt_content"]:
        return value["enabled"] and retention is not None and retention <= max_prompt_retention_days
    return True


def _valid_logging_capture(document: Any, review: dict[str, Any], *, require_provider: bool) -> bool:
    expected_fields = {"schema_version", "enabled", "includes_prompt_content", "retention_days"}
    if require_provider:
        expected_fields.add("provider")
    if (
        not isinstance(document, dict)
        or set(document) != expected_fields
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or type(document.get("enabled")) is not bool
        or type(document.get("includes_prompt_content")) is not bool
        or (require_provider and document.get("provider") != review.get("provider"))
    ):
        return False
    retention = document.get("retention_days")
    if retention is not None and (type(retention) is not int or retention < 0):
        return False
    return all(
        document[field] == review[field] for field in ("enabled", "includes_prompt_content", "retention_days")
    )


def _valid_bedrock_logging_review(
    document: Any,
    record: dict[str, Any],
    *,
    guardrail_arn: str,
    published_version: str,
    evidence_root: Path,
) -> bool:
    required_fields = {
        "schema_version",
        "guardrail_arn",
        "published_version",
        "bedrock_model_invocation_logging",
        "external_provider_logging",
        "maximum_prompt_retention_days",
        "reviewed_by",
        "reviewed_at",
    }
    if (
        not isinstance(document, dict)
        or set(document) != required_fields
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
        or document.get("guardrail_arn") != guardrail_arn
        or document.get("published_version") != published_version
        or not _valid_review_metadata(document, record)
    ):
        return False
    max_retention = document.get("maximum_prompt_retention_days")
    if type(max_retention) is not int or not 0 <= max_retention <= STAGE3_MAX_PROMPT_RETENTION_DAYS:
        return False
    return _valid_logging_scope(
        document.get("bedrock_model_invocation_logging"),
        max_prompt_retention_days=max_retention,
        require_provider=False,
        evidence_root=evidence_root,
        evidence_path=_STAGE3_BEDROCK_LOGGING,
    ) and _valid_logging_scope(
        document.get("external_provider_logging"),
        max_prompt_retention_days=max_retention,
        require_provider=True,
        evidence_root=evidence_root,
        evidence_path=_STAGE3_EXTERNAL_LOGGING,
    )


def _validate_stage3_review_artifacts(record: dict[str, Any], *, root: Path) -> None:
    evidence_root = root / "docs/evidence"
    try:
        policy = _load_json(
            (evidence_root / "stage3/guardrail-policy-review.json").read_text(encoding="utf-8")
        )
        logging = _load_json(
            (evidence_root / "stage3/bedrock-logging-review.json").read_text(encoding="utf-8")
        )
        guardrail_configuration = _load_json(
            (evidence_root / _STAGE3_GUARDRAIL_CONFIGURATION).read_text(encoding="utf-8")
        )
        guardrail_evaluation = _load_json(
            (evidence_root / _STAGE3_GUARDRAIL_EVALUATION).read_text(encoding="utf-8")
        )
        bedrock_logging = _load_json((evidence_root / _STAGE3_BEDROCK_LOGGING).read_text(encoding="utf-8"))
        external_logging = _load_json((evidence_root / _STAGE3_EXTERNAL_LOGGING).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise StageGateError("Stage 3 Guardrail policy review evidence is invalid") from None
    if not _valid_guardrail_policy_review(policy, record, evidence_root=evidence_root):
        raise StageGateError("Stage 3 Guardrail policy review evidence is invalid")
    if not _valid_guardrail_configuration_capture(
        guardrail_configuration, policy
    ) or not _valid_guardrail_evaluation_capture(guardrail_evaluation, policy):
        raise StageGateError("Stage 3 Guardrail policy review evidence is invalid")
    if not _valid_bedrock_logging_review(
        logging,
        record,
        guardrail_arn=policy["guardrail_arn"],
        published_version=policy["published_version"],
        evidence_root=evidence_root,
    ):
        raise StageGateError("Stage 3 Bedrock logging review evidence is invalid")
    if not _valid_logging_capture(
        bedrock_logging,
        logging["bedrock_model_invocation_logging"],
        require_provider=False,
    ) or not _valid_logging_capture(
        external_logging,
        logging["external_provider_logging"],
        require_provider=True,
    ):
        raise StageGateError("Stage 3 Bedrock logging review evidence is invalid")


def _validate_stage_record(
    stage_name: str,
    record: Any,
    *,
    root: Path,
    expected_demo_account_id_sha256: str | None = None,
    expected_daily_invocation_limit: int | None = None,
    expected_monthly_budget_usd: float | None = None,
    require_runtime_bindings: bool = False,
) -> bool:
    required_fields = {"status", "reviewed_by", "reviewed_at", "criteria", "evidence", "evidence_sha256"}
    if not isinstance(record, dict) or set(record) != required_fields:
        raise StageGateError(f"{stage_name} acceptance record does not match its schema")
    if not isinstance(record["status"], str) or record["status"] not in {"pending", "passed"}:
        raise StageGateError(f"{stage_name} has an invalid acceptance status")
    criteria = record["criteria"]
    if not isinstance(criteria, dict) or set(criteria) != STAGE_CRITERIA[stage_name]:
        raise StageGateError(f"{stage_name} acceptance criteria do not match the plan")
    if any(type(value) is not bool for value in criteria.values()):
        raise StageGateError(f"{stage_name} acceptance criteria must be boolean")

    if record["status"] == "pending":
        if (
            any(criteria.values())
            or record["reviewed_by"] is not None
            or record["reviewed_at"] is not None
            or record["evidence"] != []
            or record["evidence_sha256"] != {}
        ):
            raise StageGateError(f"pending {stage_name} cannot claim acceptance evidence")
        return False

    reviewer = record["reviewed_by"]
    reviewed_at = record["reviewed_at"]
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 120:
        raise StageGateError(f"passed {stage_name} requires a reviewer")
    if not isinstance(reviewed_at, str):
        raise StageGateError(f"passed {stage_name} requires a review timestamp")
    try:
        timestamp = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError:
        raise StageGateError(f"passed {stage_name} has an invalid review timestamp") from None
    if timestamp.tzinfo is None:
        raise StageGateError(f"passed {stage_name} review timestamp must include a timezone")
    if not all(criteria.values()):
        raise StageGateError(f"passed {stage_name} has incomplete plan acceptance criteria")
    _validate_evidence_paths(stage_name, record["evidence"], root=root)
    required_evidence = STAGE_REQUIRED_EVIDENCE.get(stage_name, set())
    if not required_evidence.issubset(record["evidence"]):
        if stage_name == "stage3":
            raise StageGateError(f"{stage_name} requires Guardrail policy and logging evidence")
        raise StageGateError(f"{stage_name} requires evidence for every plan criterion")
    digests = record["evidence_sha256"]
    evidence_paths = set(record["evidence"])
    if not isinstance(digests, dict) or set(digests) != evidence_paths:
        raise StageGateError(f"passed {stage_name} requires a digest for every reviewed evidence file")
    evidence_root = root / "docs/evidence"
    for relative_path, digest in digests.items():
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise StageGateError(f"{stage_name} has an invalid evidence digest")
        if digest != _evidence_sha256(evidence_root, relative_path):
            raise StageGateError(f"{stage_name} evidence digest does not match the reviewed file")
    try:
        if require_runtime_bindings and stage_name == "stage1" and expected_demo_account_id_sha256 is None:
            raise StageEvidenceError("Stage 1 acceptance requires the configured demo account ID")
        if (
            require_runtime_bindings
            and stage_name == "stage3"
            and (expected_daily_invocation_limit is None or expected_monthly_budget_usd is None)
        ):
            raise StageEvidenceError(
                "Stage 3 acceptance requires the configured Rin daily cap and provider budget"
            )
        validate_stage_evidence(
            stage_name,
            record,
            evidence_root=evidence_root,
            expected_demo_account_id_sha256=expected_demo_account_id_sha256,
            expected_daily_invocation_limit=expected_daily_invocation_limit,
            expected_monthly_budget_usd=expected_monthly_budget_usd,
        )
    except StageEvidenceError as exc:
        raise StageGateError(str(exc)) from None
    if stage_name == "stage3":
        _validate_stage3_review_artifacts(record, root=root)
    return True


def validate_stage_gates(
    manifest_path: str | Path,
    *,
    root: str | Path,
    enabled_stages: set[int],
    expected_demo_account_id_sha256: str | None = None,
    expected_daily_invocation_limit: int | None = None,
    expected_monthly_budget_usd: float | None = None,
    require_runtime_bindings: bool = False,
) -> None:
    """Reject later-stage configuration until every predecessor has evidence."""
    if not isinstance(enabled_stages, set) or any(
        type(stage) is not int or stage not in {2, 3, 4} for stage in enabled_stages
    ):
        raise StageGateError("enabled Phase 3 stages must be a subset of 2, 3, and 4")
    if 3 in enabled_stages and 2 not in enabled_stages:
        raise StageGateError("Stage 3 also requires Stage 2 resources to remain enabled")
    if 4 in enabled_stages and not {2, 3}.issubset(enabled_stages):
        raise StageGateError("Stage 4 also requires Stage 2 and Stage 3 resources to remain enabled")

    repository_root = Path(root).resolve()
    try:
        manifest = _load_json(Path(manifest_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise StageGateError("Phase 3 stage acceptance manifest is missing or invalid") from None
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "stages"}
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 3
        or not isinstance(manifest.get("stages"), dict)
        or set(manifest["stages"]) != set(STAGE_CRITERIA)
    ):
        raise StageGateError("Phase 3 stage acceptance manifest does not match its schema")

    accepted = {
        name: _validate_stage_record(
            name,
            manifest["stages"][name],
            root=repository_root,
            expected_demo_account_id_sha256=expected_demo_account_id_sha256,
            expected_daily_invocation_limit=expected_daily_invocation_limit,
            expected_monthly_budget_usd=expected_monthly_budget_usd,
            require_runtime_bindings=require_runtime_bindings,
        )
        for name in STAGE_CRITERIA
    }
    for stage_name, passed in accepted.items():
        stage_number = _STAGE_NUMBER[stage_name]
        if passed and any(not accepted[f"stage{previous}"] for previous in range(1, stage_number)):
            raise StageGateError(f"{stage_name} cannot pass before every preceding stage")

    for requested_stage in sorted(enabled_stages):
        for predecessor in range(1, requested_stage):
            if not accepted[f"stage{predecessor}"]:
                raise StageGateError(
                    f"Stage {requested_stage} requires reviewed Stage {predecessor} acceptance evidence"
                )
