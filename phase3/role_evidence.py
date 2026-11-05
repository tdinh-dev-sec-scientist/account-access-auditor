"""Validate checked-in review evidence before using owner-provisioned OIDC roles."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

_PHASES = {"plan", "apply"}
_ROLE_EVIDENCE_NAMES = {
    "trust-policy.json",
    "attached-policies.json",
    "inline-policies.json",
    "permissions-boundary.json",
}
ROLE_EVIDENCE_FILES = {
    stack: {
        phase: {f"terraform-roles/{stack}/{phase}/{name}" for name in _ROLE_EVIDENCE_NAMES}
        for phase in _PHASES
    }
    for stack in ("org", "control-plane")
}
ROLE_SOURCE_FILES = {
    stack: {
        phase: {
            f".private-role-captures/{stack}/{phase}/{name}"
            for name in {*_ROLE_EVIDENCE_NAMES, "capture-metadata.json"}
        }
        for phase in _PHASES
    }
    for stack in ("org", "control-plane")
}
_ALL_STACKS = {"org", "demo-bootstrap", "demo-account", "control-plane"}
_ROLE_ARN = re.compile(r"^arn:[a-z0-9-]+:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
_ACCOUNT_ID_VALUE = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
_POLICY_ARN = re.compile(
    r"^arn:[a-z0-9-]+:iam::(?:[0-9]{12}|aws|<TARGET_ACCOUNT>|<ACCOUNT_[1-9][0-9]*>):policy/.+$"
)
_POLICY_VERSION = re.compile(r"^v[0-9]+$")
_GITHUB_OIDC = "token.actions.githubusercontent.com"
_GITHUB_REPOSITORY = "tdinh-dev-sec-scientist/Vorrin"
# GitHub issues this repository's OIDC subject in the immutable-ID format
# (owner@owner_id/repo@repo_id), verified with a live probe on 2026-11-05. A
# trust policy written for "repo:owner/repo:..." never matches its tokens.
GITHUB_SUBJECT_REPOSITORY = "tdinh-dev-sec-scientist@172205018/Vorrin@1360779179"


def github_environment_subject(environment: str) -> str:
    """The exact OIDC sub claim GitHub sends for a job in a protected environment."""
    return f"repo:{GITHUB_SUBJECT_REPOSITORY}:environment:{environment}"


class RoleEvidenceError(ValueError):
    """The selected privileged role has not been independently reviewed."""


def _read_manifest(path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RoleEvidenceError("Phase 3 Terraform role-scope evidence is missing or invalid") from None
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "roles"}
        or type(manifest.get("schema_version")) is not int
        or manifest.get("schema_version") != 3
        or not isinstance(manifest.get("roles"), dict)
        or set(manifest["roles"]) != set(ROLE_EVIDENCE_FILES)
        or any(
            not isinstance(stack_roles, dict) or set(stack_roles) != _PHASES
            for stack_roles in manifest["roles"].values()
        )
    ):
        raise RoleEvidenceError("Phase 3 Terraform role-scope evidence does not match its schema")
    return manifest


def _string_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def _validate_policy_document(document: Any, *, context: str, require_resource: bool) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or document.get("Version") not in {"2012-10-17", "2008-10-17"}:
        raise RoleEvidenceError(f"{context} is not a valid IAM policy document")
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise RoleEvidenceError(f"{context} is not a valid IAM policy document")
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            raise RoleEvidenceError(f"{context} is not a valid IAM policy document")
        if ("Action" in statement) == ("NotAction" in statement):
            raise RoleEvidenceError(f"{context} is not a valid IAM policy document")
        if not _string_values(statement.get("Action", statement.get("NotAction"))):
            raise RoleEvidenceError(f"{context} is not a valid IAM policy document")
        if require_resource and (("Resource" in statement) == ("NotResource" in statement)):
            raise RoleEvidenceError(f"{context} is not a valid IAM policy document")
        if require_resource and not _string_values(statement.get("Resource", statement.get("NotResource"))):
            raise RoleEvidenceError(f"{context} is not a valid IAM policy document")
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            raise RoleEvidenceError(f"{context} is not a valid IAM policy document")
    return statements


def _validate_redacted_values(value: Any, *, context: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and _ACCOUNT_ID_VALUE.search(key):
                raise RoleEvidenceError(f"{context} contains a tracked account ID")
            if isinstance(key, str) and any(
                token in key.lower() for token in ("externalid", "external_id", "external-id")
            ):
                values = child if isinstance(child, list) else [child]
                if any(item != "<EXTERNAL_ID>" for item in values):
                    raise RoleEvidenceError(f"{context} contains an unredacted external ID")
            _validate_redacted_values(child, context=context)
    elif isinstance(value, list):
        for child in value:
            _validate_redacted_values(child, context=context)
    elif isinstance(value, str) and _ACCOUNT_ID_VALUE.search(value):
        raise RoleEvidenceError(f"{context} contains a tracked account ID")


def _validate_trust_policy(stack: str, phase: str, document: Any, *, role_arn: str) -> None:
    statements = _validate_policy_document(
        document, context=f"{stack} trust-policy evidence", require_resource=False
    )
    expected_subjects = {github_environment_subject(f"phase3-{stack}-{phase}")}
    partition = role_arn.split(":")[1]
    expected_provider = f"arn:{partition}:iam::<TARGET_ACCOUNT>:oidc-provider/{_GITHUB_OIDC}"
    allowed_subjects: set[str] = set()

    for statement in statements:
        if statement["Effect"] != "Allow":
            continue
        actions = _string_values(statement.get("Action"))
        principal = statement.get("Principal")
        if (
            "sts:AssumeRoleWithWebIdentity" not in actions
            or not isinstance(principal, dict)
            or set(principal) != {"Federated"}
            or _string_values(principal.get("Federated")) != {expected_provider}
        ):
            raise RoleEvidenceError(f"{stack} trust-policy evidence allows an unreviewed principal")
        condition = statement.get("Condition")
        if not isinstance(condition, dict):
            raise RoleEvidenceError(f"{stack} trust-policy evidence lacks GitHub OIDC conditions")
        claims: dict[str, tuple[str, set[str]]] = {}
        for operator, values in condition.items():
            if operator not in {"StringEquals", "StringLike"} or not isinstance(values, dict):
                raise RoleEvidenceError(f"{stack} trust-policy evidence has invalid conditions")
            for key, value in values.items():
                if isinstance(key, str) and key.startswith(f"{_GITHUB_OIDC}:"):
                    if key in claims:
                        raise RoleEvidenceError(
                            f"{stack} trust-policy evidence repeats a GitHub OIDC condition"
                        )
                    claims[key] = (operator, _string_values(value))
        aud_operator, audiences = claims.get(f"{_GITHUB_OIDC}:aud", ("", set()))
        workflow_operator, workflows = claims.get(f"{_GITHUB_OIDC}:workflow", ("", set()))
        ref_operator, refs = claims.get(f"{_GITHUB_OIDC}:ref", ("", set()))
        sub_operator, subjects = claims.get(f"{_GITHUB_OIDC}:sub", ("", set()))
        if (
            (aud_operator, audiences) != ("StringEquals", {"sts.amazonaws.com"})
            or (workflow_operator, workflows) != ("StringEquals", {"Phase 3 Terraform"})
            or (ref_operator, refs) != ("StringEquals", {"refs/heads/main"})
            or sub_operator not in {"StringEquals", "StringLike"}
            or not subjects
            or any("*" in subject or "?" in subject for subject in subjects)
            or not subjects.issubset(expected_subjects)
        ):
            raise RoleEvidenceError(
                f"{stack} trust-policy evidence is not restricted to the protected workflow"
            )
        allowed_subjects.update(subjects)

    if allowed_subjects != expected_subjects:
        raise RoleEvidenceError(
            f"{stack} {phase} trust-policy evidence must cover only its protected environment"
        )


def _validate_managed_policies(stack: str, value: Any) -> None:
    if not isinstance(value, list):
        raise RoleEvidenceError(f"{stack} attached policy evidence has an invalid shape")
    seen_arns: set[str] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"PolicyArn", "DefaultVersionId", "PolicyDocument"}
            or not isinstance(item["PolicyArn"], str)
            or not _POLICY_ARN.fullmatch(item["PolicyArn"])
            or item["PolicyArn"] in seen_arns
            or not isinstance(item["DefaultVersionId"], str)
            or not _POLICY_VERSION.fullmatch(item["DefaultVersionId"])
        ):
            raise RoleEvidenceError(f"{stack} attached policy evidence has an invalid shape")
        seen_arns.add(item["PolicyArn"])
        _validate_policy_document(
            item["PolicyDocument"], context=f"{stack} attached policy document", require_resource=True
        )


def _validate_inline_policies(stack: str, value: Any) -> None:
    if not isinstance(value, list):
        raise RoleEvidenceError(f"{stack} inline policy evidence has an invalid shape")
    seen_names: set[str] = set()
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"PolicyName", "PolicyDocument"}
            or not isinstance(item["PolicyName"], str)
            or not item["PolicyName"].strip()
            or item["PolicyName"] in seen_names
        ):
            raise RoleEvidenceError(f"{stack} inline policy evidence has an invalid shape")
        seen_names.add(item["PolicyName"])
        _validate_policy_document(
            item["PolicyDocument"], context=f"{stack} inline policy document", require_resource=True
        )


def _validate_boundary(stack: str, value: Any) -> None:
    if value is None:
        return
    if (
        not isinstance(value, dict)
        or set(value) != {"PolicyArn", "DefaultVersionId", "PolicyDocument"}
        or not isinstance(value["PolicyArn"], str)
        or not _POLICY_ARN.fullmatch(value["PolicyArn"])
        or not isinstance(value["DefaultVersionId"], str)
        or not _POLICY_VERSION.fullmatch(value["DefaultVersionId"])
    ):
        raise RoleEvidenceError(f"{stack} permissions-boundary evidence has an invalid shape")
    _validate_policy_document(
        value["PolicyDocument"], context=f"{stack} permissions-boundary document", require_resource=True
    )


def _validate_evidence_files(
    stack: str,
    phase: str,
    files: Any,
    digests: Any,
    *,
    root: Path,
    role_arn: str,
) -> None:
    expected_files = ROLE_EVIDENCE_FILES[stack][phase]
    if (
        not isinstance(files, list)
        or len(files) != len(expected_files)
        or any(not isinstance(path, str) for path in files)
        or set(files) != expected_files
    ):
        raise RoleEvidenceError(f"{stack} role evidence files are missing or incomplete")
    if not isinstance(digests, dict) or set(digests) != expected_files:
        raise RoleEvidenceError(f"{stack} role evidence digests are missing or incomplete")

    evidence_dir = root / "docs/evidence"
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise RoleEvidenceError("Phase 3 role evidence directory is missing or unsafe")
    evidence_root = evidence_dir.resolve()
    try:
        evidence_root.relative_to(root)
    except ValueError:
        raise RoleEvidenceError("Phase 3 role evidence directory is outside the repository") from None

    artifacts = {}
    for relative in expected_files:
        candidate = evidence_root / relative
        current = evidence_root
        for part in Path(relative).parts:
            current = current / part
            if current.is_symlink():
                raise RoleEvidenceError(f"{stack} role evidence files must not use symlinks")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(evidence_root)
        except (OSError, ValueError):
            raise RoleEvidenceError(f"{stack} role evidence files are missing or unsafe") from None
        if not resolved.is_file() or resolved.stat().st_size == 0:
            raise RoleEvidenceError(f"{stack} role evidence files are missing or empty")
        try:
            content = resolved.read_bytes()
            artifact = json.loads(content)
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise RoleEvidenceError(f"{stack} role evidence files must contain valid JSON") from None
        digest = digests[relative]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise RoleEvidenceError(f"{stack} role evidence digest is invalid")
        if not hmac.compare_digest(digest, hashlib.sha256(content).hexdigest()):
            raise RoleEvidenceError(f"{stack} role evidence digest does not match the reviewed file")
        _validate_redacted_values(artifact, context=f"{stack} role evidence")
        artifacts[Path(relative).name] = artifact

    _validate_trust_policy(stack, phase, artifacts["trust-policy.json"], role_arn=role_arn)
    _validate_managed_policies(stack, artifacts["attached-policies.json"])
    _validate_inline_policies(stack, artifacts["inline-policies.json"])
    _validate_boundary(stack, artifacts["permissions-boundary.json"])


def validate_role_scope_evidence(
    *,
    root: str | Path,
    stack: str,
    phase: str,
    role_arn: str,
) -> None:
    """Require a reviewed, exact-role evidence record before role assumption."""
    if stack not in _ALL_STACKS:
        raise RoleEvidenceError("Unknown Phase 3 Terraform stack")
    if phase not in _PHASES:
        raise RoleEvidenceError("Unknown Phase 3 Terraform role phase")
    if stack not in ROLE_EVIDENCE_FILES:
        return
    if not isinstance(role_arn, str) or not _ROLE_ARN.fullmatch(role_arn):
        raise RoleEvidenceError("Phase 3 Terraform role ARN is missing or invalid")

    repository_root = Path(root).resolve()
    manifest = _read_manifest(repository_root / "docs/evidence/phase3-role-scope.json")
    roles = manifest["roles"]
    required_record_fields = {
        "status",
        "role_arn_sha256",
        "reviewed_by",
        "reviewed_at",
        "evidence",
        "evidence_sha256",
    }
    required_record_fields.add("source_evidence_sha256")
    record = roles[stack][phase]
    if not isinstance(record, dict) or set(record) != required_record_fields:
        raise RoleEvidenceError(f"{stack} {phase} role-scope record does not match its schema")
    if record["status"] == "pending":
        if (
            any(record[field] is not None for field in ("role_arn_sha256", "reviewed_by", "reviewed_at"))
            or record["evidence"] != []
            or record["evidence_sha256"] != {}
            or record["source_evidence_sha256"] != {}
        ):
            raise RoleEvidenceError(f"pending {stack} {phase} role scope cannot claim review evidence")
        raise RoleEvidenceError(
            f"{stack} {phase} stack requires reviewed role-scope evidence before AWS credentials"
        )
    if record["status"] != "reviewed":
        raise RoleEvidenceError(f"{stack} {phase} role-scope status is invalid")

    recorded_fingerprint = record["role_arn_sha256"]
    if not isinstance(recorded_fingerprint, str) or not _SHA256.fullmatch(recorded_fingerprint):
        raise RoleEvidenceError(f"{stack} {phase} reviewed role fingerprint is invalid")
    current_fingerprint = hashlib.sha256(role_arn.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(recorded_fingerprint, current_fingerprint):
        raise RoleEvidenceError(f"{stack} {phase} configured role does not match the reviewed role")

    reviewer = record["reviewed_by"]
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 120:
        raise RoleEvidenceError(f"{stack} {phase} role-scope review requires a reviewer")
    reviewed_at = record["reviewed_at"]
    if not isinstance(reviewed_at, str):
        raise RoleEvidenceError(f"{stack} {phase} role-scope review requires a timestamp")
    try:
        timestamp = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError:
        raise RoleEvidenceError(f"{stack} {phase} role-scope review timestamp is invalid") from None
    if timestamp.tzinfo is None:
        raise RoleEvidenceError(f"{stack} {phase} role-scope review timestamp must include a timezone")

    _validate_evidence_files(
        stack,
        phase,
        record["evidence"],
        record["evidence_sha256"],
        root=repository_root,
        role_arn=role_arn,
    )
    if (
        not isinstance(record["source_evidence_sha256"], dict)
        or set(record["source_evidence_sha256"]) != ROLE_SOURCE_FILES[stack][phase]
        or any(
            not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            for digest in record["source_evidence_sha256"].values()
        )
    ):
        raise RoleEvidenceError(f"{stack} {phase} raw-source digests are missing or invalid")
