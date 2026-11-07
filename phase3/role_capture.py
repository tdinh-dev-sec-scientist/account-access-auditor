"""Capture exact IAM role policy documents using read-only IAM APIs."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from phase3.role_evidence import ROLE_EVIDENCE_FILES, ROLE_SOURCE_FILES, github_environment_subject

_ROLE_ARN = re.compile(r"^arn:[a-z0-9-]+:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$")
_ACCOUNT_ID = re.compile(r"(?<![0-9])([0-9]{12})(?![0-9])")
_CREDENTIAL_PATTERN = re.compile(
    r"(?:\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b)"
)
_POLICY_VERSION = re.compile(r"^v[1-9][0-9]*$")
_GITHUB_CLAIM_VALUES = {
    "token.actions.githubusercontent.com:aud",
    "token.actions.githubusercontent.com:sub",
    "token.actions.githubusercontent.com:workflow",
    "token.actions.githubusercontent.com:ref",
}
_SAFE_CONDITION_KEYS = {
    "aws:CurrentTime",
    "aws:EpochTime",
    "aws:MultiFactorAuthPresent",
    "aws:MultiFactorAuthAge",
    "aws:PrincipalArn",
    "aws:PrincipalAccount",
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    "aws:PrincipalType",
    "aws:RequestedRegion",
    "aws:ResourceAccount",
    "aws:ResourceOrgID",
    "aws:SecureTransport",
    "aws:SourceAccount",
    "aws:SourceArn",
    "aws:SourceIp",
    "aws:VpcSourceIp",
    "aws:ViaAWSService",
    "aws:CalledVia",
    "aws:CalledViaFirst",
    "aws:CalledViaLast",
    "sts:ExternalId",
}
_SAFE_TAG_CONDITION_PREFIXES = {
    "aws:PrincipalTag",
    "aws:RequestTag",
    "aws:ResourceTag",
    "iam:PrincipalTag",
    "iam:ResourceTag",
    "s3:ExistingObjectTag",
    "s3:RequestObjectTag",
}
_CONDITION_OPERATOR = re.compile(
    r"^(?:(?:ForAnyValue|ForAllValues):)?(?:Null|(?:String|Numeric|Date|Bool|Binary|Arn|IpAddress|NotIpAddress)"
    r"(?:Equals|Like|LessThan|LessThanEquals|GreaterThan|GreaterThanEquals|NotEquals|NotLike|"
    r"EqualsIfExists|LikeIfExists|NotEqualsIfExists|NotLikeIfExists|IfExists|EqualsIgnoreCase|NotEqualsIgnoreCase)?)$"
)


class RoleCaptureError(ValueError):
    """The requested IAM role cannot be captured safely."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RoleCaptureError("IAM policy JSON contains a duplicate object key")
        result[key] = value
    return result


def _policy_document(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(unquote(value), object_pairs_hook=_unique_object)
        except json.JSONDecodeError:
            raise RoleCaptureError("AWS returned an invalid IAM policy document") from None
    if not isinstance(value, dict):
        raise RoleCaptureError("AWS returned an invalid IAM policy document")
    return value


def _default_policy(iam_client: Any, policy_arn: str) -> dict[str, Any]:
    response = iam_client.get_policy(PolicyArn=policy_arn)
    policy = response.get("Policy") if isinstance(response, dict) else None
    if not isinstance(policy, dict) or policy.get("Arn") != policy_arn:
        raise RoleCaptureError("AWS returned a managed policy that does not match the requested ARN")
    default_version = policy.get("DefaultVersionId")
    if not isinstance(default_version, str) or not _POLICY_VERSION.fullmatch(default_version):
        raise RoleCaptureError("AWS returned a managed policy without a default version")
    version_response = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version)
    version = version_response.get("PolicyVersion") if isinstance(version_response, dict) else None
    if (
        not isinstance(version, dict)
        or version.get("VersionId") != default_version
        or version.get("IsDefaultVersion") is not True
    ):
        raise RoleCaptureError("AWS returned a managed policy version that does not match the default")
    return {
        "PolicyArn": policy_arn,
        "DefaultVersionId": default_version,
        "PolicyDocument": _policy_document(version.get("Document")),
    }


def _role_name(role_arn: str) -> str:
    if not isinstance(role_arn, str) or not _ROLE_ARN.fullmatch(role_arn):
        raise RoleCaptureError("The requested IAM role ARN is invalid")
    name = role_arn.rsplit("/", 1)[-1]
    if not name:
        raise RoleCaptureError("The requested IAM role ARN is invalid")
    return name


def collect_role_evidence(*, iam_client: Any, role_arn: str) -> dict[str, Any]:
    """Fetch a role trust policy, attached/inline policies, and its boundary."""
    role_name = _role_name(role_arn)
    response = iam_client.get_role(RoleName=role_name)
    role = response.get("Role") if isinstance(response, dict) else None
    if not isinstance(role, dict) or role.get("RoleName") != role_name or role.get("Arn") != role_arn:
        raise RoleCaptureError("AWS returned a role that does not match the requested role")

    trust_policy = _policy_document(role.get("AssumeRolePolicyDocument"))
    attached_policies = []
    attached_arns: set[str] = set()
    for page in iam_client.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
        attached_items = page.get("AttachedPolicies") if isinstance(page, dict) else None
        if not isinstance(attached_items, list):
            raise RoleCaptureError("AWS returned invalid attached policy results")
        for attached in attached_items:
            if not isinstance(attached, dict):
                raise RoleCaptureError("AWS returned an invalid attached policy record")
            policy_arn = attached.get("PolicyArn")
            if not isinstance(policy_arn, str) or not policy_arn or policy_arn in attached_arns:
                raise RoleCaptureError("AWS returned an attached policy with a missing or duplicate ARN")
            attached_arns.add(policy_arn)
            attached_policies.append(_default_policy(iam_client, policy_arn))

    inline_policies = []
    inline_names: set[str] = set()
    for page in iam_client.get_paginator("list_role_policies").paginate(RoleName=role_name):
        policy_names = page.get("PolicyNames") if isinstance(page, dict) else None
        if not isinstance(policy_names, list):
            raise RoleCaptureError("AWS returned invalid inline policy results")
        for policy_name in policy_names:
            if not isinstance(policy_name, str) or not policy_name or policy_name in inline_names:
                raise RoleCaptureError("AWS returned an inline policy with a missing or duplicate name")
            inline_names.add(policy_name)
            response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            if (
                not isinstance(response, dict)
                or response.get("RoleName") != role_name
                or response.get("PolicyName") != policy_name
            ):
                raise RoleCaptureError(
                    "AWS returned an inline policy that does not match the requested role policy"
                )
            inline_policies.append(
                {
                    "PolicyName": policy_name,
                    "PolicyDocument": _policy_document(response.get("PolicyDocument")),
                }
            )

    permissions_boundary = role.get("PermissionsBoundary")
    if permissions_boundary is None:
        boundary = None
    else:
        if not isinstance(permissions_boundary, dict):
            raise RoleCaptureError("AWS returned an invalid permissions boundary")
        boundary_arn = permissions_boundary.get("PermissionsBoundaryArn")
        if not isinstance(boundary_arn, str) or not boundary_arn:
            raise RoleCaptureError("AWS returned a permissions boundary without a policy ARN")
        boundary = _default_policy(iam_client, boundary_arn)

    return {
        "trust-policy.json": trust_policy,
        "attached-policies.json": attached_policies,
        "inline-policies.json": inline_policies,
        "permissions-boundary.json": boundary,
    }


def _ensure_safe_directory(path: Path, *, root: Path) -> None:
    if path.is_symlink():
        raise RoleCaptureError("Role evidence path must not contain symlinks")
    if path.exists():
        if not path.is_dir():
            raise RoleCaptureError("Role evidence path is not a directory")
        try:
            path.resolve().relative_to(root.resolve())
        except ValueError:
            raise RoleCaptureError("Role evidence path is outside docs/evidence") from None


def _collect_account_ids(value: Any, found: set[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str):
                found.update(_ACCOUNT_ID.findall(key))
            _collect_account_ids(child, found)
    elif isinstance(value, list):
        for child in value:
            _collect_account_ids(child, found)
    elif isinstance(value, str):
        found.update(_ACCOUNT_ID.findall(value))


def _redact_account_ids(value: Any, replacements: dict[str, str]) -> Any:
    if isinstance(value, dict):
        output = {}
        for key, child in value.items():
            if isinstance(key, str) and any(
                token in key.lower() for token in ("externalid", "external_id", "external-id")
            ):
                if isinstance(child, str):
                    redacted_external_id: Any = "<EXTERNAL_ID>"
                elif isinstance(child, list) and all(isinstance(item, str) for item in child):
                    redacted_external_id = ["<EXTERNAL_ID>" for _ in child]
                else:
                    raise RoleCaptureError("AWS returned an unsupported external ID condition shape")
                output[_ACCOUNT_ID.sub(lambda match: replacements[match.group(1)], key)] = (
                    redacted_external_id
                )
                continue
            safe_key = (
                _ACCOUNT_ID.sub(lambda match: replacements[match.group(1)], key)
                if isinstance(key, str)
                else key
            )
            if safe_key in output:
                raise RoleCaptureError("Account redaction produced a duplicate policy key")
            output[safe_key] = _redact_account_ids(child, replacements)
        return output
    if isinstance(value, list):
        return [_redact_account_ids(child, replacements) for child in value]
    if isinstance(value, str):
        return _ACCOUNT_ID.sub(lambda match: replacements[match.group(1)], value)
    return value


def _redact_resource(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact_resource(item) for item in value]
    if not isinstance(value, str):
        raise RoleCaptureError("AWS returned an unsupported IAM resource shape")
    if value == "*":
        return value
    wildcard = "*" in value or "?" in value
    placeholder = "<RESOURCE_PATTERN>" if wildcard else "<RESOURCE>"
    if not value.startswith("arn:"):
        return placeholder
    parts = value.split(":", 5)
    if len(parts) != 6:
        return placeholder
    service, resource = parts[2], parts[5]
    if service == "s3":
        parts[5] = placeholder
        return ":".join(parts)
    delimiter = "/" if "/" in resource else (":" if ":" in resource else "")
    if delimiter:
        resource_type = resource.split(delimiter, 1)[0]
        parts[5] = f"{resource_type}{delimiter}{placeholder}"
    else:
        parts[5] = placeholder
    return ":".join(parts)


def _redact_condition_value(value: Any) -> Any:
    if isinstance(value, list):
        if any(not isinstance(item, str) for item in value):
            raise RoleCaptureError("AWS returned a non-string IAM condition value")
        return [_redact_condition_value(item) for item in value]
    if (
        isinstance(value, str)
        and value not in {"*", "<TARGET_ACCOUNT>", "<EXTERNAL_ID>"}
        and not re.fullmatch(r"<ACCOUNT_[1-9][0-9]*>", value)
    ):
        return "<CONDITION_VALUE>"
    if isinstance(value, str):
        return value
    raise RoleCaptureError("AWS returned an unsupported IAM condition value shape")


def _expected_github_claim_value(key: str, *, stack: str, phase: str) -> str:
    expected = {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": github_environment_subject(f"phase3-{stack}-{phase}"),
        "token.actions.githubusercontent.com:workflow": "Phase 3 Terraform",
        "token.actions.githubusercontent.com:ref": "refs/heads/main",
    }
    return expected[key]


def _redacted_condition_key(key: Any, *, index: int, stack: str, phase: str, value: Any) -> str:
    if not isinstance(key, str):
        raise RoleCaptureError("AWS returned a non-string IAM condition key")
    if key in _GITHUB_CLAIM_VALUES:
        expected = _expected_github_claim_value(key, stack=stack, phase=phase)
        actual = value if isinstance(value, list) else [value]
        if actual != [expected]:
            raise RoleCaptureError("AWS returned a GitHub OIDC claim value outside the protected workflow")
        return key
    if key in _SAFE_CONDITION_KEYS:
        return key
    for prefix in _SAFE_TAG_CONDITION_PREFIXES:
        if key.startswith(prefix + "/"):
            return f"{prefix}/<CONDITION_KEY_{index}>"
    return f"<CONDITION_KEY_{index}>"


def _redact_principal(value: Any) -> Any:
    if isinstance(value, list):
        return [_redact_principal(item) for item in value]
    if isinstance(value, dict):
        redacted = {}
        for key, child in value.items():
            principal_values = child if isinstance(child, list) else [child]
            if key == "Service":
                raise RoleCaptureError(
                    "AWS returned an unexpected service principal for a GitHub Terraform role"
                )
            elif key == "Federated":
                expected_provider = re.compile(
                    r"arn:[a-z0-9-]+:iam::<TARGET_ACCOUNT>:oidc-provider/token\.actions\.githubusercontent\.com"
                )
                redacted[key] = (
                    [
                        item
                        if isinstance(item, str) and expected_provider.fullmatch(item)
                        else _redact_resource(item)
                        for item in principal_values
                    ]
                    if isinstance(child, list)
                    else (
                        child
                        if isinstance(child, str) and expected_provider.fullmatch(child)
                        else _redact_resource(child)
                    )
                )
            else:
                redacted[key] = _redact_resource(child)
        return redacted
    if isinstance(value, str) and value.endswith(".amazonaws.com"):
        raise RoleCaptureError("AWS returned an unexpected service principal for a GitHub Terraform role")
    if isinstance(value, str) and value != "*":
        return _redact_resource(value)
    return value


def _redact_policy_identifiers(value: Any, *, key: str | None = None, stack: str, phase: str) -> Any:
    if isinstance(value, dict):
        output = {}
        for child_key, child in value.items():
            if child_key in {"Resource", "NotResource"}:
                output[child_key] = _redact_resource(child)
            elif child_key in {"Principal", "NotPrincipal"}:
                output[child_key] = _redact_principal(child)
            elif child_key == "Condition":
                if not isinstance(child, dict):
                    raise RoleCaptureError("AWS returned an unsupported IAM condition shape")
                conditions_by_operator = {}
                for operator, conditions in sorted(child.items()):
                    if (
                        not isinstance(operator, str)
                        or not _CONDITION_OPERATOR.fullmatch(operator)
                        or not isinstance(conditions, dict)
                    ):
                        raise RoleCaptureError("AWS returned an unsupported IAM condition shape")
                    redacted_conditions = {}
                    for index, (condition_key, condition_value) in enumerate(
                        sorted(conditions.items()), start=1
                    ):
                        safe_key = _redacted_condition_key(
                            condition_key,
                            index=index,
                            stack=stack,
                            phase=phase,
                            value=condition_value,
                        )
                        if safe_key in redacted_conditions:
                            raise RoleCaptureError(
                                "Condition-key redaction produced a duplicate IAM condition"
                            )
                        redacted_conditions[safe_key] = (
                            condition_value
                            if condition_key in _GITHUB_CLAIM_VALUES
                            else _redact_condition_value(condition_value)
                        )
                    conditions_by_operator[operator] = redacted_conditions
                output[child_key] = conditions_by_operator
            elif child_key in {"PolicyArn", "PermissionsBoundaryArn"}:
                output[child_key] = _redact_resource(child)
            elif child_key == "PolicyName":
                output[child_key] = "<POLICY_NAME>"
            elif child_key in {"Sid", "Id"}:
                output[child_key] = "<STATEMENT_ID>"
            else:
                output[child_key] = _redact_policy_identifiers(child, key=child_key, stack=stack, phase=phase)
        return output
    if isinstance(value, list):
        return [_redact_policy_identifiers(child, key=key, stack=stack, phase=phase) for child in value]
    if isinstance(value, str):
        if key in {"Version", "DefaultVersionId", "Effect", "Action", "NotAction"}:
            return value
        if key == "Federated" and value.endswith("token.actions.githubusercontent.com"):
            return value
        if key == "Service":
            raise RoleCaptureError("AWS returned an unexpected service principal for a GitHub Terraform role")
        if key in {"Resource", "NotResource", "PolicyArn", "PermissionsBoundaryArn"}:
            return _redact_resource(value)
        if key in {"PolicyName"}:
            return "<POLICY_NAME>"
        if key in {"Sid", "Id"}:
            return "<STATEMENT_ID>"
        if key in {"Principal", "NotPrincipal"}:
            return _redact_principal(value)
        if value == "*" or value.startswith("<ACCOUNT_") or value in {"<TARGET_ACCOUNT>", "<EXTERNAL_ID>"}:
            return value
        if value.startswith("arn:"):
            return _redact_resource(value)
        if key in {"Version", "DefaultVersionId", "Effect", "Action", "NotAction"}:
            return value
        return "<IDENTIFIER>"
    return value


def redact_role_artifacts(
    artifacts: dict[str, Any], *, role_arn: str, stack: str, phase: str
) -> dict[str, Any]:
    """Return a review projection without account, resource, or condition identifiers."""
    _role_name(role_arn)
    if stack not in ROLE_EVIDENCE_FILES or phase not in ROLE_EVIDENCE_FILES[stack]:
        raise RoleCaptureError("Only the org/control-plane plan and apply roles can be redacted")
    account_ids: set[str] = set()
    _collect_account_ids(artifacts, account_ids)
    target_account = role_arn.split(":")[4]
    account_ids.add(target_account)
    replacements = {target_account: "<TARGET_ACCOUNT>"}
    replacements.update(
        (account_id, f"<ACCOUNT_{index}>")
        for index, account_id in enumerate(sorted(account_ids - {target_account}), start=1)
    )
    redacted = _redact_policy_identifiers(
        _redact_account_ids(artifacts, replacements),
        stack=stack,
        phase=phase,
    )
    remaining_account_ids: set[str] = set()
    _collect_account_ids(redacted, remaining_account_ids)
    if remaining_account_ids:
        raise RoleCaptureError("Account redaction did not remove every account ID")
    return redacted


def _reject_credential_patterns(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and _CREDENTIAL_PATTERN.search(key):
                raise RoleCaptureError("An IAM policy contains a credential-like value; capture was stopped")
            _reject_credential_patterns(child)
    elif isinstance(value, list):
        for child in value:
            _reject_credential_patterns(child)
    elif isinstance(value, str) and _CREDENTIAL_PATTERN.search(value):
        raise RoleCaptureError("An IAM policy contains a credential-like value; capture was stopped")


def _write_artifacts(
    directory: Path,
    artifacts: dict[str, Any],
    *,
    stack: str,
    private: bool,
) -> dict[str, str]:
    written: list[tuple[Path, int, int]] = []
    digests: dict[str, str] = {}
    created = False
    try:
        directory.mkdir(mode=0o700 if private else 0o755, exist_ok=False)
        created = True
        if private:
            directory.chmod(0o700)
        for filename, artifact in artifacts.items():
            content = (json.dumps(artifact, sort_keys=True, indent=2) + "\n").encode("utf-8")
            output = directory / filename
            if private:
                descriptor = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                try:
                    metadata = os.fstat(descriptor)
                    written.append((output, metadata.st_dev, metadata.st_ino))
                    handle = os.fdopen(descriptor, "wb")
                except BaseException:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)
                    raise
                with handle:
                    handle.write(content)
            else:
                with output.open("xb") as handle:
                    metadata = os.fstat(handle.fileno())
                    written.append((output, metadata.st_dev, metadata.st_ino))
                    handle.write(content)
            prefix = ".private-role-captures" if private else "terraform-roles"
            relative = f"{prefix}/{stack}/{directory.name}/{filename}"
            digests[relative] = hashlib.sha256(content).hexdigest()
    except (OSError, TypeError, ValueError):
        for output, device, inode in written:
            try:
                metadata = output.lstat()
                if stat.S_ISREG(metadata.st_mode) and metadata.st_dev == device and metadata.st_ino == inode:
                    output.unlink()
            except OSError:
                pass
        if created:
            with contextlib.suppress(OSError):
                directory.rmdir()
        raise RoleCaptureError("Could not write the captured role evidence files") from None
    return digests


def _rollback_artifacts(directory: Path, digests: dict[str, str]) -> None:
    """Remove only a complete set of unchanged files written by this capture."""
    if not digests or directory.is_symlink() or not directory.is_dir():
        return
    expected_names = {Path(relative).name for relative in digests}
    try:
        if {path.name for path in directory.iterdir()} != expected_names:
            return
        for relative, expected_digest in digests.items():
            output = directory / Path(relative).name
            if output.is_symlink() or not output.is_file():
                return
            if hashlib.sha256(output.read_bytes()).hexdigest() != expected_digest:
                return
        for relative in digests:
            (directory / Path(relative).name).unlink()
        directory.rmdir()
    except OSError:
        # Preserve anything that cannot be proven to be this capture's output.
        return


def _read_capture_json(path: Path) -> tuple[Any, bytes]:
    try:
        content = path.read_bytes()
        value = json.loads(content, object_pairs_hook=_unique_object)
    except RoleCaptureError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RoleCaptureError("Captured IAM evidence is missing or invalid JSON") from None
    return value, content


def _require_capture_directory(path: Path, *, root: Path, private: bool) -> None:
    if path.is_symlink() or not path.is_dir():
        raise RoleCaptureError("Captured IAM evidence directory is missing or unsafe")
    _ensure_safe_directory(path, root=root)
    if private and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise RoleCaptureError("Private role capture directory must not be accessible to other users")


def verify_role_capture(
    *,
    root: str | Path,
    stack: str,
    phase: str,
    role_arn: str,
    allow_superseded_review: bool = False,
) -> dict[str, dict[str, str]]:
    """Verify that private source captures produce the checked-in projection.

    This read-only local verification never changes the role-scope manifest or
    review status. A human reviewer must still evaluate the policy semantics.
    ``allow_superseded_review`` skips only the comparison with an earlier
    review's digests, for a re-review after the role changed and was captured
    again; the capture itself is still verified in full.
    """
    if stack not in ROLE_EVIDENCE_FILES or phase not in ROLE_EVIDENCE_FILES[stack]:
        raise RoleCaptureError("Only the org/control-plane plan and apply roles can be verified")
    _role_name(role_arn)
    repository_root = Path(root).resolve()
    evidence_root = repository_root / "docs/evidence"
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise RoleCaptureError("The docs/evidence directory is missing or unsafe")
    try:
        evidence_root.resolve().relative_to(repository_root)
    except ValueError:
        raise RoleCaptureError("The docs/evidence directory is outside the repository") from None

    source_relative_paths = ROLE_SOURCE_FILES[stack][phase]
    projection_relative_paths = ROLE_EVIDENCE_FILES[stack][phase]
    private_root = evidence_root / ".private-role-captures"
    private_stack_directory = private_root / stack
    source_directory = evidence_root / ".private-role-captures" / stack / phase
    projection_directory = evidence_root / "terraform-roles" / stack / phase
    _require_capture_directory(private_root, root=evidence_root, private=True)
    _require_capture_directory(private_stack_directory, root=evidence_root, private=True)
    _require_capture_directory(source_directory, root=evidence_root, private=True)
    _require_capture_directory(projection_directory, root=evidence_root, private=False)

    expected_source_names = {Path(path).name for path in source_relative_paths}
    expected_projection_names = {Path(path).name for path in projection_relative_paths}
    if {path.name for path in source_directory.iterdir()} != expected_source_names:
        raise RoleCaptureError("Private role captures are incomplete or contain unexpected files")
    if {path.name for path in projection_directory.iterdir()} != expected_projection_names:
        raise RoleCaptureError("Redacted role projections are incomplete or contain unexpected files")

    artifacts: dict[str, Any] = {}
    capture_metadata: Any = None
    source_digests: dict[str, str] = {}
    for relative in source_relative_paths:
        source_path = evidence_root / relative
        if (
            source_path.is_symlink()
            or not source_path.is_file()
            or stat.S_IMODE(source_path.stat().st_mode) & 0o077
        ):
            raise RoleCaptureError("Private role capture files must be regular owner-only files")
        artifact, content = _read_capture_json(source_path)
        if Path(relative).name == "capture-metadata.json":
            capture_metadata = artifact
        else:
            artifacts[Path(relative).name] = artifact
        source_digests[relative] = hashlib.sha256(content).hexdigest()

    expected_role_fingerprint = hashlib.sha256(role_arn.encode("utf-8")).hexdigest()
    if (
        not isinstance(capture_metadata, dict)
        or set(capture_metadata) != {"schema_version", "role_arn_sha256"}
        or type(capture_metadata.get("schema_version")) is not int
        or capture_metadata.get("schema_version") != 1
        or capture_metadata.get("role_arn_sha256") != expected_role_fingerprint
    ):
        raise RoleCaptureError("Private capture metadata does not match the requested role")
    _reject_credential_patterns(artifacts)
    if set(artifacts) != {Path(path).name for path in projection_relative_paths}:
        raise RoleCaptureError("Private role captures do not match the evidence schema")
    redacted_artifacts = redact_role_artifacts(
        artifacts,
        role_arn=role_arn,
        stack=stack,
        phase=phase,
    )
    projection_digests: dict[str, str] = {}
    for relative in projection_relative_paths:
        path = evidence_root / relative
        if path.is_symlink() or not path.is_file():
            raise RoleCaptureError("Redacted role projections are missing or unsafe")
        content = path.read_bytes()
        expected = (
            json.dumps(redacted_artifacts[Path(relative).name], sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        if content != expected:
            raise RoleCaptureError("Redacted role projection does not match its private source capture")
        projection_digests[relative] = hashlib.sha256(content).hexdigest()

    manifest_path = evidence_root / "phase3-role-scope.json"
    try:
        manifest = json.loads(manifest_path.read_bytes(), object_pairs_hook=_unique_object)
    except RoleCaptureError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise RoleCaptureError("Phase 3 role-scope manifest is missing or invalid") from None
    record = manifest.get("roles", {}).get(stack, {}).get(phase) if isinstance(manifest, dict) else None
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 3 or not isinstance(record, dict):
        raise RoleCaptureError("Phase 3 role-scope manifest does not match its schema")
    if record.get("status") == "reviewed" and not allow_superseded_review:
        fingerprint = hashlib.sha256(role_arn.encode("utf-8")).hexdigest()
        if (
            record.get("role_arn_sha256") != fingerprint
            or record.get("evidence_sha256") != projection_digests
            or record.get("source_evidence_sha256") != source_digests
        ):
            raise RoleCaptureError("Reviewed manifest digests do not match the verified capture")
    elif record.get("status") not in {"pending", "reviewed"}:
        raise RoleCaptureError("Phase 3 role-scope status is invalid")
    return {"evidence_sha256": projection_digests, "source_evidence_sha256": source_digests}


def capture_role_evidence(
    *,
    root: str | Path,
    stack: str,
    phase: str,
    role_arn: str,
    iam_client: Any,
) -> dict[str, dict[str, str]]:
    """Write fresh captures and return their SHA-256 digests.

    This function never changes the role-scope manifest or marks evidence
    reviewed. Existing capture directories are left untouched and rejected.
    """
    if stack not in ROLE_EVIDENCE_FILES or phase not in ROLE_EVIDENCE_FILES[stack]:
        raise RoleCaptureError("Only the org/control-plane plan and apply roles can be captured")
    _role_name(role_arn)

    repository_root = Path(root).resolve()
    evidence_root = repository_root / "docs/evidence"
    if evidence_root.is_symlink() or not evidence_root.is_dir():
        raise RoleCaptureError("The docs/evidence directory is missing or unsafe")
    try:
        evidence_root.resolve().relative_to(repository_root)
    except ValueError:
        raise RoleCaptureError("The docs/evidence directory is outside the repository") from None

    tracked_root = evidence_root / "terraform-roles"
    private_root = evidence_root / ".private-role-captures"
    _ensure_safe_directory(tracked_root, root=evidence_root)
    _ensure_safe_directory(private_root, root=evidence_root)
    tracked_stack_root = tracked_root / stack
    private_stack_root = private_root / stack
    _ensure_safe_directory(tracked_stack_root, root=evidence_root)
    _ensure_safe_directory(private_stack_root, root=evidence_root)
    tracked_destination = tracked_stack_root / phase
    private_destination = private_stack_root / phase
    if any(path.exists() or path.is_symlink() for path in (tracked_destination, private_destination)):
        raise RoleCaptureError(
            "Role evidence capture directory already exists; existing evidence was not overwritten"
        )

    artifacts = collect_role_evidence(iam_client=iam_client, role_arn=role_arn)
    _reject_credential_patterns(artifacts)
    if set(artifacts) != {Path(path).name for path in ROLE_EVIDENCE_FILES[stack][phase]}:
        raise RoleCaptureError("Captured IAM artifacts do not match the evidence schema")

    redacted_artifacts = redact_role_artifacts(
        artifacts,
        role_arn=role_arn,
        stack=stack,
        phase=phase,
    )

    tracked_stack_root.mkdir(parents=True, exist_ok=True)
    _ensure_safe_directory(tracked_root, root=evidence_root)
    _ensure_safe_directory(tracked_stack_root, root=evidence_root)
    private_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if stat.S_IMODE(private_root.stat().st_mode) & 0o077:
        raise RoleCaptureError("Private role capture directory must not be accessible to other users")
    private_stack_root.mkdir(mode=0o700, exist_ok=True)
    if stat.S_IMODE(private_stack_root.stat().st_mode) & 0o077:
        raise RoleCaptureError("Private role capture directory must not be accessible to other users")
    _ensure_safe_directory(private_root, root=evidence_root)
    _ensure_safe_directory(private_stack_root, root=evidence_root)
    tracked_digests: dict[str, str] = {}
    role_fingerprint = hashlib.sha256(role_arn.encode("utf-8")).hexdigest()
    private_artifacts = {
        **artifacts,
        "capture-metadata.json": {"schema_version": 1, "role_arn_sha256": role_fingerprint},
    }
    try:
        tracked_digests = _write_artifacts(
            tracked_destination, redacted_artifacts, stack=stack, private=False
        )
        source_digests = _write_artifacts(private_destination, private_artifacts, stack=stack, private=True)
    except FileExistsError:
        _rollback_artifacts(tracked_destination, tracked_digests)
        raise RoleCaptureError(
            "Role evidence capture directory already exists; existing evidence was not overwritten"
        ) from None
    except RoleCaptureError:
        _rollback_artifacts(tracked_destination, tracked_digests)
        raise
    return {"evidence_sha256": tracked_digests, "source_evidence_sha256": source_digests}
