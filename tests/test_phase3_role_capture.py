from __future__ import annotations

import hashlib
import json
import sys

import pytest

from phase3 import role_capture
from phase3.role_capture import RoleCaptureError, capture_role_evidence, verify_role_capture
from scripts import capture_phase3_role_evidence as capture_cli

ROLE_ARN = "arn:aws:iam::123456789012:role/phase3/OrgTerraformPlan"
BOUNDARY_ARN = "arn:aws:iam::123456789012:policy/Phase3TerraformBoundary"
ATTACHED_ARN = "arn:aws:iam::123456789012:policy/Phase3TerraformRead"


class _Paginator:
    def __init__(self, response_key, items, calls):
        self.response_key = response_key
        self.items = items
        self.calls = calls

    def paginate(self, **kwargs):
        self.calls.append(("paginate", self.response_key, kwargs))
        yield {self.response_key: self.items}


class _FakeIam:
    def __init__(self, role_arn=ROLE_ARN, *, boundary=True):
        self.role_arn = role_arn
        self.boundary = boundary
        self.calls = []
        self.trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {
                "sts:ExternalId": "fixture-external-id-value",
                "aws:PrincipalTag/private-tenant-key": "private-tenant-condition-value",
            }},
            }],
        }
        self.policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::private-state-bucket/*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/private-workspace-key": "private-tenant-label"}},
            }],
        }

    def get_role(self, *, RoleName):
        self.calls.append(("get_role", RoleName))
        permissions_boundary = {"PermissionsBoundaryArn": BOUNDARY_ARN} if self.boundary else None
        return {
            "Role": {
                "Arn": self.role_arn,
                "RoleName": RoleName,
                "AssumeRolePolicyDocument": self.trust,
                "PermissionsBoundary": permissions_boundary,
            }
        }

    def get_paginator(self, operation_name):
        self.calls.append(("get_paginator", operation_name))
        if operation_name == "list_attached_role_policies":
            return _Paginator(
                "AttachedPolicies",
                [{"PolicyArn": ATTACHED_ARN}],
                self.calls,
            )
        if operation_name == "list_role_policies":
            return _Paginator("PolicyNames", ["InlineStatePolicy"], self.calls)
        raise AssertionError(f"unexpected AWS API operation: {operation_name}")

    def get_policy(self, *, PolicyArn):
        self.calls.append(("get_policy", PolicyArn))
        return {"Policy": {"Arn": PolicyArn, "DefaultVersionId": "v3"}}

    def get_policy_version(self, *, PolicyArn, VersionId):
        self.calls.append(("get_policy_version", PolicyArn, VersionId))
        return {"PolicyVersion": {"VersionId": VersionId, "IsDefaultVersion": True, "Document": self.policy}}

    def get_role_policy(self, *, RoleName, PolicyName):
        self.calls.append(("get_role_policy", RoleName, PolicyName))
        return {"RoleName": RoleName, "PolicyName": PolicyName, "PolicyDocument": self.policy}


def test_role_capture_writes_actual_policy_artifacts_and_hash_receipt(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    iam = _FakeIam()

    digests = capture_role_evidence(
        root=tmp_path,
        stack="org",
        phase="plan",
        role_arn=ROLE_ARN,
        iam_client=iam,
    )

    evidence_dir = tmp_path / "docs/evidence/terraform-roles/org/plan"
    assert {path.name for path in evidence_dir.iterdir()} == {
        "trust-policy.json",
        "attached-policies.json",
        "inline-policies.json",
        "permissions-boundary.json",
    }
    sanitized_trust = json.loads((evidence_dir / "trust-policy.json").read_text())
    assert sanitized_trust["Statement"][0]["Principal"]["Federated"] == (
        "arn:aws:iam::<TARGET_ACCOUNT>:oidc-provider/token.actions.githubusercontent.com"
    )
    assert sanitized_trust["Statement"][0]["Condition"]["StringEquals"]["sts:ExternalId"] == "<EXTERNAL_ID>"
    assert sanitized_trust["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalTag/<CONDITION_KEY_1>"] == "<CONDITION_VALUE>"
    projected_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::<RESOURCE_PATTERN>",
            "Condition": {"StringEquals": {"aws:PrincipalTag/<CONDITION_KEY_1>": "<CONDITION_VALUE>"}},
        }],
    }
    assert json.loads((evidence_dir / "attached-policies.json").read_text()) == [
        {
            "PolicyArn": "arn:aws:iam::<TARGET_ACCOUNT>:policy/<RESOURCE>",
            "DefaultVersionId": "v3",
            "PolicyDocument": projected_policy,
        }
    ]
    assert json.loads((evidence_dir / "inline-policies.json").read_text()) == [
        {"PolicyName": "<POLICY_NAME>", "PolicyDocument": projected_policy}
    ]
    assert json.loads((evidence_dir / "permissions-boundary.json").read_text()) == {
        "PolicyArn": "arn:aws:iam::<TARGET_ACCOUNT>:policy/<RESOURCE>",
        "DefaultVersionId": "v3",
        "PolicyDocument": projected_policy,
    }
    assert all(
        digests["evidence_sha256"][path]
        == hashlib.sha256((tmp_path / "docs/evidence" / path).read_bytes()).hexdigest()
        for path in digests["evidence_sha256"]
    )
    assert all(
        digests["source_evidence_sha256"][path]
        == hashlib.sha256(
            (tmp_path / "docs/evidence" / path).read_bytes()
        ).hexdigest()
        for path in digests["source_evidence_sha256"]
    )
    assert set(digests["source_evidence_sha256"]) == {
        f".private-role-captures/org/plan/{name}"
        for name in (
            "capture-metadata.json",
            "trust-policy.json",
            "attached-policies.json",
            "inline-policies.json",
            "permissions-boundary.json",
        )
    }
    private_dir = tmp_path / "docs/evidence/.private-role-captures/org/plan"
    assert (private_dir / "trust-policy.json").read_text(encoding="utf-8") == (
        json.dumps(iam.trust, sort_keys=True, indent=2) + "\n"
    )
    assert (private_dir.stat().st_mode & 0o777) == 0o700
    assert (private_dir / "trust-policy.json").stat().st_mode & 0o077 == 0
    assert json.loads((private_dir / "capture-metadata.json").read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "role_arn_sha256": hashlib.sha256(ROLE_ARN.encode("utf-8")).hexdigest(),
    }
    assert "123456789012" not in (evidence_dir / "trust-policy.json").read_text(encoding="utf-8")
    assert "fixture-external-id-value" not in (evidence_dir / "trust-policy.json").read_text(encoding="utf-8")
    projections = " ".join(path.read_text(encoding="utf-8") for path in evidence_dir.iterdir())
    assert "private-state-bucket" not in projections
    assert "private-tenant-label" not in projections
    assert "private-tenant-key" not in projections
    assert "private-tenant-condition-value" not in projections
    assert "private-workspace-key" not in projections
    assert "Workspace" not in projections
    assert "Phase3TerraformRead" not in projections
    assert "InlineStatePolicy" not in projections
    assert {call[0] for call in iam.calls} <= {
        "get_role",
        "get_paginator",
        "paginate",
        "get_policy",
        "get_policy_version",
        "get_role_policy",
    }


def test_role_capture_verifier_matches_private_source_to_projection_without_approving_manifest(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    digests = capture_role_evidence(
        root=tmp_path,
        stack="org",
        phase="plan",
        role_arn=ROLE_ARN,
        iam_client=_FakeIam(),
    )
    manifest = tmp_path / "docs/evidence/phase3-role-scope.json"
    manifest.write_text(json.dumps({"schema_version": 3, "roles": {"org": {"plan": {"status": "pending"}}}}))
    before = manifest.read_bytes()

    verified = verify_role_capture(root=tmp_path, stack="org", phase="plan", role_arn=ROLE_ARN)

    assert verified == digests
    assert manifest.read_bytes() == before


def test_role_capture_verifier_rejects_projection_that_differs_from_private_source(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    capture_role_evidence(
        root=tmp_path,
        stack="org",
        phase="plan",
        role_arn=ROLE_ARN,
        iam_client=_FakeIam(),
    )
    (tmp_path / "docs/evidence/phase3-role-scope.json").write_text(
        json.dumps({"schema_version": 3, "roles": {"org": {"plan": {"status": "pending"}}}})
    )
    projection = tmp_path / "docs/evidence/terraform-roles/org/plan/attached-policies.json"
    changed = json.loads(projection.read_text(encoding="utf-8"))
    changed[0]["PolicyDocument"]["Statement"][0]["Resource"] = "arn:aws:s3:::<RESOURCE>"
    projection.write_text(json.dumps(changed, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(RoleCaptureError, match="does not match its private source capture"):
        verify_role_capture(root=tmp_path, stack="org", phase="plan", role_arn=ROLE_ARN)


def test_role_capture_verifier_checks_reviewed_raw_source_digest(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    digests = capture_role_evidence(
        root=tmp_path,
        stack="org",
        phase="plan",
        role_arn=ROLE_ARN,
        iam_client=_FakeIam(),
    )
    record = {
        "status": "reviewed",
        "role_arn_sha256": hashlib.sha256(ROLE_ARN.encode("utf-8")).hexdigest(),
        "evidence_sha256": digests["evidence_sha256"],
        "source_evidence_sha256": digests["source_evidence_sha256"],
    }
    (tmp_path / "docs/evidence/phase3-role-scope.json").write_text(
        json.dumps({"schema_version": 3, "roles": {"org": {"plan": record}}})
    )
    raw_trust = tmp_path / "docs/evidence/.private-role-captures/org/plan/trust-policy.json"
    changed = json.loads(raw_trust.read_text(encoding="utf-8"))
    changed["Statement"][0]["Condition"]["StringEquals"]["sts:ExternalId"] = "changed-but-redacted"
    raw_trust.write_text(json.dumps(changed, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(RoleCaptureError, match="Reviewed manifest digests do not match"):
        verify_role_capture(root=tmp_path, stack="org", phase="plan", role_arn=ROLE_ARN)


def test_role_capture_verifier_rejects_same_account_role_substitution(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    capture_role_evidence(
        root=tmp_path,
        stack="org",
        phase="plan",
        role_arn=ROLE_ARN,
        iam_client=_FakeIam(),
    )
    (tmp_path / "docs/evidence/phase3-role-scope.json").write_text(
        json.dumps({"schema_version": 3, "roles": {"org": {"plan": {"status": "pending"}}}})
    )

    with pytest.raises(RoleCaptureError, match="capture metadata does not match the requested role"):
        verify_role_capture(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn="arn:aws:iam::123456789012:role/phase3/OrgTerraformApply",
        )


def test_role_capture_rejects_unexpected_github_claim_values_before_writing(tmp_path):
    evidence = tmp_path / "docs/evidence"
    evidence.mkdir(parents=True)
    iam = _FakeIam()
    iam.trust["Statement"][0]["Condition"] = {
        "StringEquals": {
            "token.actions.githubusercontent.com:sub": "repo:another-owner/private-project:environment:admin"
        }
    }

    with pytest.raises(RoleCaptureError, match="claim value outside the protected workflow"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )

    assert not (evidence / "terraform-roles").exists()
    assert not (evidence / ".private-role-captures").exists()


def test_role_capture_rejects_unexpected_service_principals_before_writing(tmp_path):
    evidence = tmp_path / "docs/evidence"
    evidence.mkdir(parents=True)
    iam = _FakeIam()
    iam.trust["Statement"][0]["Principal"] = {"Service": "lambda.amazonaws.com"}

    with pytest.raises(RoleCaptureError, match="unexpected service principal"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )

    assert not (evidence / "terraform-roles").exists()
    assert not (evidence / ".private-role-captures").exists()


def test_role_capture_rejects_nonstring_condition_scalars_before_writing(tmp_path):
    evidence = tmp_path / "docs/evidence"
    evidence.mkdir(parents=True)
    iam = _FakeIam()
    iam.trust["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalTag/private-tenant-key"] = 7

    with pytest.raises(RoleCaptureError, match="unsupported IAM condition value shape"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )

    assert not (evidence / "terraform-roles").exists()
    assert not (evidence / ".private-role-captures").exists()


def test_role_capture_preserves_absent_permissions_boundary_as_null(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    iam = _FakeIam(boundary=False)

    capture_role_evidence(
        root=tmp_path,
        stack="control-plane",
        phase="apply",
        role_arn=ROLE_ARN,
        iam_client=iam,
    )

    boundary = tmp_path / "docs/evidence/terraform-roles/control-plane/apply/permissions-boundary.json"
    assert boundary.read_text(encoding="utf-8") == "null\n"


def test_role_capture_rolls_back_redacted_files_when_private_write_fails(tmp_path, monkeypatch):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    original_write = role_capture._write_artifacts

    def fail_private_write(directory, artifacts, *, stack, private):
        if private:
            raise RoleCaptureError("simulated private capture failure")
        return original_write(directory, artifacts, stack=stack, private=private)

    monkeypatch.setattr(role_capture, "_write_artifacts", fail_private_write)

    with pytest.raises(RoleCaptureError, match="simulated private capture failure"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=_FakeIam(),
        )

    assert not (tmp_path / "docs/evidence/terraform-roles/org/plan").exists()


def test_role_capture_rejects_role_arn_mismatch(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    iam = _FakeIam(role_arn="arn:aws:iam::123456789012:role/UnexpectedRole")

    with pytest.raises(RoleCaptureError, match="does not match the requested role"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )


def test_role_capture_rejects_role_name_mismatch(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    iam = _FakeIam()
    iam.get_role = lambda *, RoleName: {
        "Role": {
            "Arn": ROLE_ARN,
            "RoleName": "DifferentRole",
            "AssumeRolePolicyDocument": iam.trust,
            "PermissionsBoundary": None,
        }
    }

    with pytest.raises(RoleCaptureError, match="does not match the requested role"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )


def test_role_capture_rejects_managed_policy_arn_mismatch(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    iam = _FakeIam()
    original_get_policy = iam.get_policy
    iam.get_policy = lambda *, PolicyArn: original_get_policy(PolicyArn="arn:aws:iam::123456789012:policy/Other")

    with pytest.raises(RoleCaptureError, match="does not match the requested ARN"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )


def test_role_capture_rejects_non_default_policy_version_response(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    iam = _FakeIam()
    iam.get_policy_version = lambda *, PolicyArn, VersionId: {
        "PolicyVersion": {"VersionId": "v2", "IsDefaultVersion": False, "Document": iam.policy}
    }

    with pytest.raises(RoleCaptureError, match="does not match the default"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )


def test_role_capture_rejects_mismatched_inline_policy_response(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    iam = _FakeIam()
    iam.get_role_policy = lambda *, RoleName, PolicyName: {
        "RoleName": RoleName,
        "PolicyName": "DifferentPolicy",
        "PolicyDocument": iam.policy,
    }

    with pytest.raises(RoleCaptureError, match="does not match the requested role policy"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )


def test_role_capture_rejects_malformed_external_id_without_writing_projection(tmp_path):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    iam = _FakeIam()
    iam.trust["Statement"][0]["Condition"]["StringEquals"]["sts:ExternalId"] = {
        "123456789012": "unexpected-object-shape"
    }

    with pytest.raises(RoleCaptureError, match="unsupported external ID condition shape"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )

    assert not (tmp_path / "docs/evidence/terraform-roles/org/plan").exists()


def test_role_capture_removes_partial_raw_file_and_projection_on_write_failure(tmp_path, monkeypatch):
    (tmp_path / "docs/evidence").mkdir(parents=True)
    original_fdopen = role_capture.os.fdopen

    class _FailAfterPartialWrite:
        def __init__(self, handle):
            self.handle = handle

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.handle.close()

        def write(self, content):
            self.handle.write(content[:8])
            self.handle.flush()
            raise OSError("simulated disk failure")

    monkeypatch.setattr(
        role_capture.os,
        "fdopen",
        lambda descriptor, mode: _FailAfterPartialWrite(original_fdopen(descriptor, mode)),
    )

    with pytest.raises(RoleCaptureError, match="Could not write the captured role evidence files"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=_FakeIam(),
        )

    assert not (tmp_path / "docs/evidence/terraform-roles/org/plan").exists()
    assert not (tmp_path / "docs/evidence/.private-role-captures/org/plan").exists()


def test_role_capture_refuses_to_overwrite_existing_evidence_before_aws_calls(tmp_path):
    evidence_dir = tmp_path / "docs/evidence/terraform-roles/org/plan"
    evidence_dir.mkdir(parents=True)
    (evidence_dir / "keep.json").write_text("user data", encoding="utf-8")
    iam = _FakeIam()

    with pytest.raises(RoleCaptureError, match="already exists"):
        capture_role_evidence(
            root=tmp_path,
            stack="org",
            phase="plan",
            role_arn=ROLE_ARN,
            iam_client=iam,
        )

    assert iam.calls == []
    assert (evidence_dir / "keep.json").read_text(encoding="utf-8") == "user data"


@pytest.mark.parametrize(
    ("stack", "phase"),
    [("demo-account", "plan"), ("org", "admin"), ("org/../control-plane", "apply")],
)
def test_role_capture_rejects_invalid_scope_before_aws_calls(tmp_path, stack, phase):
    iam = _FakeIam()

    with pytest.raises(RoleCaptureError):
        capture_role_evidence(
            root=tmp_path,
            stack=stack,
            phase=phase,
            role_arn=ROLE_ARN,
            iam_client=iam,
        )

    assert iam.calls == []


class _FakeSession:
    def __init__(self, *, arn, account, iam):
        self.arn = arn
        self.account = account
        self.iam = iam
        self.clients = []

    def client(self, service):
        self.clients.append(service)
        if service == "sts":
            return self
        if service == "iam":
            return self.iam
        raise AssertionError(f"unexpected AWS client: {service}")

    def get_caller_identity(self):
        return {"Arn": self.arn, "Account": self.account}


def test_capture_cli_rejects_root_identity_before_iam_calls(tmp_path, monkeypatch, capsys):
    iam = _FakeIam()
    session = _FakeSession(arn="arn:aws:iam::123456789012:root", account="123456789012", iam=iam)
    monkeypatch.setattr(capture_cli.boto3, "Session", lambda profile_name: session)
    monkeypatch.setattr(sys, "argv", [
        "capture_phase3_role_evidence.py",
        "--root", str(tmp_path),
        "--profile", "default",
        "--stack", "org",
        "--phase", "plan",
        "--role-arn", ROLE_ARN,
    ])

    assert capture_cli.main() == 1
    assert "Root credentials are not accepted" in capsys.readouterr().err
    assert session.clients == ["sts"]
    assert iam.calls == []


def test_capture_cli_does_not_change_manifest_review_state(tmp_path, monkeypatch, capsys):
    iam = _FakeIam()
    session = _FakeSession(
        arn="arn:aws:iam::123456789012:user/account-auditor",
        account="123456789012",
        iam=iam,
    )
    monkeypatch.setattr(capture_cli.boto3, "Session", lambda profile_name: session)
    monkeypatch.setattr(sys, "argv", [
        "capture_phase3_role_evidence.py",
        "--root", str(tmp_path),
        "--profile", "audit-readonly",
        "--stack", "org",
        "--phase", "plan",
        "--role-arn", ROLE_ARN,
    ])
    evidence = tmp_path / "docs/evidence"
    evidence.mkdir(parents=True)
    manifest = evidence / "phase3-role-scope.json"
    pending = json.dumps({"schema_version": 3, "roles": {"org": {"plan": {"status": "pending"}}}})
    manifest.write_text(pending, encoding="utf-8")

    assert capture_cli.main() == 0
    assert manifest.read_text(encoding="utf-8") == pending
    assert "was not changed or approved" in capsys.readouterr().out
    assert session.clients == ["sts", "iam"]


def test_capture_cli_rejects_cross_account_profile_before_iam_calls(tmp_path, monkeypatch, capsys):
    iam = _FakeIam()
    session = _FakeSession(
        arn="arn:aws:iam::999999999999:user/account-auditor",
        account="999999999999",
        iam=iam,
    )
    monkeypatch.setattr(capture_cli.boto3, "Session", lambda profile_name: session)
    monkeypatch.setattr(sys, "argv", [
        "capture_phase3_role_evidence.py",
        "--root", str(tmp_path),
        "--profile", "audit-readonly",
        "--stack", "org",
        "--phase", "plan",
        "--role-arn", ROLE_ARN,
    ])

    assert capture_cli.main() == 1
    assert "must belong to the same AWS account" in capsys.readouterr().err
    assert session.clients == ["sts"]
    assert iam.calls == []
