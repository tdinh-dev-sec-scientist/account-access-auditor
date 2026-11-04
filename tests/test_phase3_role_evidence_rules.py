"""Rejection rules of the Phase 3 role-scope evidence gate, one rule per case.

Each case starts from a valid reviewed manifest, changes one artifact or one
record field, re-hashes any changed artifact so the digest check passes, and
asserts the specific reason the gate refuses the role.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from phase3.role_evidence import RoleEvidenceError, validate_role_scope_evidence
from tests.test_phase3_role_evidence import ROLE_ARN, _write_manifest

OIDC = "token.actions.githubusercontent.com"
EVIDENCE_DIR = "docs/evidence"
MANIFEST = f"{EVIDENCE_DIR}/phase3-role-scope.json"
PLAN_DIR = "terraform-roles/org/plan"
VALID_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "arn:aws:s3:::state"}],
}


def _validate(root: Path, *, stack: str = "org", phase: str = "plan", role_arn: str = ROLE_ARN) -> None:
    validate_role_scope_evidence(root=root, stack=stack, phase=phase, role_arn=role_arn)


def _load(root: Path, relative: str) -> Any:
    return json.loads((root / relative).read_text(encoding="utf-8"))


def _rewrite_artifact(root: Path, name: str, change: Callable[[Any], Any]) -> None:
    relative = f"{PLAN_DIR}/{name}"
    path = root / EVIDENCE_DIR / relative
    current = json.loads(path.read_text(encoding="utf-8"))
    updated = change(copy.deepcopy(current))
    path.write_text(json.dumps(updated, sort_keys=True) + "\n", encoding="utf-8")
    manifest = _load(root, MANIFEST)
    manifest["roles"]["org"]["plan"]["evidence_sha256"][relative] = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()
    (root / MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")


def _edit_record(root: Path, change: Callable[[dict[str, Any]], None]) -> None:
    manifest = _load(root, MANIFEST)
    change(manifest["roles"]["org"]["plan"])
    (root / MANIFEST).write_text(json.dumps(manifest), encoding="utf-8")


@pytest.fixture
def reviewed(tmp_path: Path) -> Path:
    _write_manifest(tmp_path, status="reviewed")
    _validate(tmp_path)  # the baseline must pass, or every case below proves nothing
    return tmp_path


# --------------------------------------------------------------- arguments --


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"stack": "unknown"}, "Unknown Phase 3 Terraform stack"),
        ({"phase": "destroy"}, "Unknown Phase 3 Terraform role phase"),
        ({"role_arn": "not-an-arn"}, "role ARN is missing or invalid"),
        ({"role_arn": ""}, "role ARN is missing or invalid"),
    ],
)
def test_gate_rejects_invalid_arguments(reviewed: Path, kwargs: dict[str, str], message: str) -> None:
    with pytest.raises(RoleEvidenceError, match=message):
        _validate(reviewed, **kwargs)


# ---------------------------------------------------------------- manifest --


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("not json", "missing or invalid"),
        ("[]", "does not match its schema"),
        (json.dumps({"schema_version": 2, "roles": {}}), "does not match its schema"),
        (json.dumps({"schema_version": True, "roles": {}}), "does not match its schema"),
        (
            json.dumps({"schema_version": 3, "roles": {"org": {}, "control-plane": {}}}),
            "does not match its schema",
        ),
    ],
)
def test_gate_rejects_malformed_manifests(reviewed: Path, content: str, message: str) -> None:
    (reviewed / MANIFEST).write_text(content, encoding="utf-8")

    with pytest.raises(RoleEvidenceError, match=message):
        _validate(reviewed)


def test_gate_rejects_a_missing_manifest(tmp_path: Path) -> None:
    with pytest.raises(RoleEvidenceError, match="missing or invalid"):
        _validate(tmp_path)


def _set(field: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def change(record: dict[str, Any]) -> None:
        record[field] = value

    return change


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda record: record.pop("reviewed_by"), "does not match its schema"),
        (_set("status", "approved"), "role-scope status is invalid"),
        (_set("role_arn_sha256", "ABC"), "reviewed role fingerprint is invalid"),
        (_set("reviewed_by", "   "), "review requires a reviewer"),
        (_set("reviewed_by", "x" * 121), "review requires a reviewer"),
        (_set("reviewed_at", None), "review requires a timestamp"),
        (_set("reviewed_at", "yesterday"), "review timestamp is invalid"),
        (_set("reviewed_at", "2026-11-03T00:00:00"), "must include a timezone"),
        (_set("evidence", ["terraform-roles/org/plan/trust-policy.json"]), "files are missing or incomplete"),
        (_set("evidence_sha256", {}), "digests are missing or incomplete"),
        (_set("source_evidence_sha256", {}), "raw-source digests are missing or invalid"),
    ],
)
def test_gate_rejects_invalid_review_records(
    reviewed: Path, change: Callable[[dict[str, Any]], None], message: str
) -> None:
    _edit_record(reviewed, change)

    with pytest.raises(RoleEvidenceError, match=message):
        _validate(reviewed)


def test_pending_record_cannot_claim_review_evidence(reviewed: Path) -> None:
    _edit_record(reviewed, _set("status", "pending"))

    with pytest.raises(RoleEvidenceError, match="cannot claim review evidence"):
        _validate(reviewed)


def test_gate_rejects_a_malformed_evidence_digest(reviewed: Path) -> None:
    def change(record: dict[str, Any]) -> None:
        record["evidence_sha256"][f"{PLAN_DIR}/trust-policy.json"] = "not-a-digest"

    _edit_record(reviewed, change)

    with pytest.raises(RoleEvidenceError, match="evidence digest is invalid"):
        _validate(reviewed)


# ------------------------------------------------------------ evidence files --


def test_gate_rejects_invalid_json_evidence(reviewed: Path) -> None:
    (reviewed / EVIDENCE_DIR / PLAN_DIR / "inline-policies.json").write_text("{", encoding="utf-8")

    with pytest.raises(RoleEvidenceError, match="must contain valid JSON"):
        _validate(reviewed)


def test_gate_rejects_empty_evidence_files(reviewed: Path) -> None:
    (reviewed / EVIDENCE_DIR / PLAN_DIR / "inline-policies.json").write_bytes(b"")

    with pytest.raises(RoleEvidenceError, match="missing or empty"):
        _validate(reviewed)


def test_gate_rejects_symlinked_evidence_files(
    reviewed: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    target = reviewed / EVIDENCE_DIR / PLAN_DIR / "inline-policies.json"
    outside = tmp_path_factory.mktemp("outside") / "inline-policies.json"
    outside.write_bytes(target.read_bytes())
    target.unlink()
    target.symlink_to(outside)

    with pytest.raises(RoleEvidenceError, match="must not use symlinks"):
        _validate(reviewed)


def test_gate_rejects_a_symlinked_evidence_directory(
    reviewed: Path, tmp_path_factory: pytest.TempPathFactory
) -> None:
    evidence = reviewed / EVIDENCE_DIR
    moved = tmp_path_factory.mktemp("elsewhere") / "evidence"
    evidence.rename(moved)
    evidence.symlink_to(moved, target_is_directory=True)

    with pytest.raises(RoleEvidenceError, match="directory is missing or unsafe"):
        _validate(reviewed)


# ------------------------------------------------------------- trust policy --


def _statement(trust: dict[str, Any]) -> dict[str, Any]:
    return trust["Statement"][0]


def _claims(trust: dict[str, Any]) -> dict[str, Any]:
    return _statement(trust)["Condition"]["StringEquals"]


def _trust(change: Callable[[dict[str, Any]], None]) -> Callable[[Any], Any]:
    def apply(trust: Any) -> Any:
        change(trust)
        return trust

    return apply


def _deny_only(trust: dict[str, Any]) -> None:
    _statement(trust)["Effect"] = "Deny"


def _second_principal(trust: dict[str, Any]) -> None:
    _statement(trust)["Principal"]["AWS"] = "*"


def _wrong_provider(trust: dict[str, Any]) -> None:
    _statement(trust)["Principal"]["Federated"] = "arn:aws:iam::<TARGET_ACCOUNT>:oidc-provider/example.com"


def _assume_role_action(trust: dict[str, Any]) -> None:
    _statement(trust)["Action"] = "sts:AssumeRole"


def _no_condition(trust: dict[str, Any]) -> None:
    del _statement(trust)["Condition"]


def _unsupported_operator(trust: dict[str, Any]) -> None:
    _statement(trust)["Condition"] = {"ForAnyValue:StringLike": _claims(trust)}


def _repeated_claim(trust: dict[str, Any]) -> None:
    _statement(trust)["Condition"]["StringLike"] = {f"{OIDC}:sub": _claims(trust)[f"{OIDC}:sub"]}


def _feature_branch(trust: dict[str, Any]) -> None:
    _claims(trust)[f"{OIDC}:ref"] = "refs/heads/feature"


def _other_audience(trust: dict[str, Any]) -> None:
    _claims(trust)[f"{OIDC}:aud"] = "example.com"


def _account_id_in_trust(trust: dict[str, Any]) -> None:
    _statement(trust)["Principal"]["Federated"] = f"arn:aws:iam::123456789012:oidc-provider/{OIDC}"


def _unredacted_external_id(trust: dict[str, Any]) -> None:
    _statement(trust)["Condition"]["StringEquals"]["sts:ExternalId"] = "secret-value"


def _account_id_key(trust: dict[str, Any]) -> None:
    _statement(trust)["Condition"]["StringEquals"]["aws:PrincipalAccount/123456789012"] = "x"


def _not_a_policy(trust: dict[str, Any]) -> None:
    trust["Version"] = "2020-01-01"


def _action_and_not_action(trust: dict[str, Any]) -> None:
    _statement(trust)["NotAction"] = "iam:*"


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (_deny_only, "must cover only its protected environment"),
        (_second_principal, "allows an unreviewed principal"),
        (_wrong_provider, "allows an unreviewed principal"),
        (_assume_role_action, "allows an unreviewed principal"),
        (_no_condition, "lacks GitHub OIDC conditions"),
        (_unsupported_operator, "has invalid conditions"),
        (_repeated_claim, "repeats a GitHub OIDC condition"),
        (_feature_branch, "not restricted to the protected workflow"),
        (_other_audience, "not restricted to the protected workflow"),
        (_account_id_in_trust, "contains a tracked account ID"),
        (_unredacted_external_id, "contains an unredacted external ID"),
        (_account_id_key, "contains a tracked account ID"),
        (_not_a_policy, "is not a valid IAM policy document"),
        (_action_and_not_action, "is not a valid IAM policy document"),
    ],
)
def test_gate_rejects_unsafe_trust_policies(
    reviewed: Path, change: Callable[[dict[str, Any]], None], message: str
) -> None:
    _rewrite_artifact(reviewed, "trust-policy.json", _trust(change))

    with pytest.raises(RoleEvidenceError, match=message):
        _validate(reviewed)


def test_redacted_external_id_placeholder_is_accepted(reviewed: Path) -> None:
    def redacted(trust: dict[str, Any]) -> None:
        _statement(trust)["Condition"]["StringEquals"]["sts:ExternalId"] = "<EXTERNAL_ID>"

    _rewrite_artifact(reviewed, "trust-policy.json", _trust(redacted))

    _validate(reviewed)


def test_single_statement_object_is_accepted(reviewed: Path) -> None:
    def as_object(trust: dict[str, Any]) -> None:
        trust["Statement"] = trust["Statement"][0]

    _rewrite_artifact(reviewed, "trust-policy.json", _trust(as_object))

    _validate(reviewed)


# ----------------------------------------------------- identity policy shapes --


def _managed(**overrides: Any) -> list[dict[str, Any]]:
    item = {
        "PolicyArn": "arn:aws:iam::<TARGET_ACCOUNT>:policy/Phase3Terraform",
        "DefaultVersionId": "v1",
        "PolicyDocument": VALID_POLICY,
    }
    item.update(overrides)
    return [item]


def _inline(name: str = "state-access", document: Any = None) -> list[dict[str, Any]]:
    return [{"PolicyName": name, "PolicyDocument": VALID_POLICY if document is None else document}]


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        ("attached-policies.json", {}, "attached policy evidence has an invalid shape"),
        (
            "attached-policies.json",
            _managed(PolicyArn="arn:aws:iam::123:policy/x"),
            "attached policy evidence has an invalid shape",
        ),
        (
            "attached-policies.json",
            _managed(DefaultVersionId="1"),
            "attached policy evidence has an invalid shape",
        ),
        ("attached-policies.json", _managed() + _managed(), "attached policy evidence has an invalid shape"),
        (
            "attached-policies.json",
            _managed(
                PolicyDocument={"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*"}]}
            ),
            "attached policy document is not a valid IAM policy document",
        ),
        ("inline-policies.json", {}, "inline policy evidence has an invalid shape"),
        ("inline-policies.json", _inline(name=" "), "inline policy evidence has an invalid shape"),
        ("inline-policies.json", _inline() + _inline(), "inline policy evidence has an invalid shape"),
        (
            "inline-policies.json",
            _inline(document={"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": []}]}),
            "inline policy document is not a valid IAM policy document",
        ),
        (
            "inline-policies.json",
            _inline(
                document={
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*", "Condition": []}],
                }
            ),
            "inline policy document is not a valid IAM policy document",
        ),
        ("permissions-boundary.json", [], "permissions-boundary evidence has an invalid shape"),
        (
            "permissions-boundary.json",
            _managed(PolicyDocument={"Version": "2012-10-17", "Statement": []})[0],
            "permissions-boundary document is not a valid IAM policy document",
        ),
    ],
)
def test_gate_rejects_invalid_identity_policy_evidence(
    reviewed: Path, name: str, value: Any, message: str
) -> None:
    _rewrite_artifact(reviewed, name, lambda _current: value)

    with pytest.raises(RoleEvidenceError, match=message):
        _validate(reviewed)


def test_inline_policies_and_a_missing_boundary_are_accepted(reviewed: Path) -> None:
    _rewrite_artifact(reviewed, "inline-policies.json", lambda _current: _inline())
    _rewrite_artifact(reviewed, "permissions-boundary.json", lambda _current: None)

    _validate(reviewed)
