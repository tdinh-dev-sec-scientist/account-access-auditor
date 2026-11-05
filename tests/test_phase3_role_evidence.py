from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from phase3.role_evidence import ROLE_SOURCE_FILES, github_environment_subject
from scripts import validate_phase3_role_evidence as validate_cli

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate_phase3_role_evidence.py"
ROLE_ARN = "arn:aws:iam::123456789012:role/Phase3Terraform"
STACKS = ("org", "control-plane")


def _evidence_files(stack: str, phase: str = "plan"):
    return tuple(
        f"terraform-roles/{stack}/{phase}/{name}.json"
        for name in ("trust-policy", "attached-policies", "inline-policies", "permissions-boundary")
    )


def _write_manifest(
    root: Path,
    *,
    status: str,
    stack: str = "org",
    phase: str = "plan",
    role_arn: str = ROLE_ARN,
    include_evidence: bool = True,
):
    evidence_root = root / "docs/evidence"
    roles = {}
    for role_stack in STACKS:
        roles[role_stack] = {}
        for role_phase in ("plan", "apply"):
            accepted = role_stack == stack and role_phase == phase and status == "reviewed"
            evidence = []
            evidence_hashes = {}
            if accepted and include_evidence:
                evidence = list(_evidence_files(role_stack, role_phase))
                provider_arn = (
                    "arn:aws:iam::<TARGET_ACCOUNT>:oidc-provider/token.actions.githubusercontent.com"
                )
                trust_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Federated": provider_arn},
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                                    "token.actions.githubusercontent.com:workflow": "Phase 3 Terraform",
                                    "token.actions.githubusercontent.com:ref": "refs/heads/main",
                                    "token.actions.githubusercontent.com:sub": github_environment_subject(
                                        f"phase3-{role_stack}-{role_phase}"
                                    ),
                                }
                            },
                        },
                    ],
                }
                identity_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:ListBucket"],
                            "Resource": "arn:aws:s3:::phase3-terraform-state",
                        }
                    ],
                }
                artifacts = {
                    evidence[0]: trust_policy,
                    evidence[1]: [
                        {
                            "PolicyArn": "arn:aws:iam::<TARGET_ACCOUNT>:policy/Phase3Terraform",
                            "DefaultVersionId": "v1",
                            "PolicyDocument": identity_policy,
                        }
                    ],
                    evidence[2]: [],
                    evidence[3]: {
                        "PolicyArn": "arn:aws:iam::<TARGET_ACCOUNT>:policy/Phase3TerraformBoundary",
                        "DefaultVersionId": "v1",
                        "PolicyDocument": identity_policy,
                    },
                }
                for relative in evidence:
                    path = evidence_root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(artifacts[relative], sort_keys=True) + "\n", encoding="utf-8")
                    evidence_hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
            roles[role_stack][role_phase] = {
                "status": "reviewed" if accepted else "pending",
                "role_arn_sha256": hashlib.sha256(role_arn.encode("utf-8")).hexdigest() if accepted else None,
                "reviewed_by": "independent-security-reviewer" if accepted else None,
                "reviewed_at": datetime(2026, 11, 3, tzinfo=UTC).isoformat() if accepted else None,
                "evidence": evidence,
                "evidence_sha256": evidence_hashes if accepted else {},
                "source_evidence_sha256": {
                    path: hashlib.sha256(f"private-source:{path}".encode()).hexdigest()
                    for path in ROLE_SOURCE_FILES[role_stack][role_phase]
                }
                if accepted
                else {},
            }
    manifest = {"schema_version": 3, "roles": roles}
    path = evidence_root / "phase3-role-scope.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _argv(root: Path, stack: str, phase: str) -> list[str]:
    return [str(SCRIPT), "--root", str(root), "--stack", stack, "--phase", phase]


def _run(root: Path, *, stack: str, phase: str = "plan", role_arn: str = ROLE_ARN):
    """Run the gate CLI in-process so coverage sees phase3.role_evidence."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with (
        mock.patch.object(sys, "argv", _argv(root, stack, phase)),
        mock.patch.dict(os.environ, {"PHASE3_TERRAFORM_ROLE_ARN": role_arn}),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        returncode = validate_cli.main()
    return SimpleNamespace(returncode=returncode, stdout=stdout.getvalue(), stderr=stderr.getvalue())


def test_role_evidence_gate_script_runs_as_a_standalone_process(tmp_path):
    _write_manifest(tmp_path, status="reviewed")

    result = subprocess.run(
        [sys.executable, *_argv(tmp_path, "org", "plan")],
        cwd=ROOT,
        env={**os.environ, "PHASE3_TERRAFORM_ROLE_ARN": ROLE_ARN},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "org plan Terraform role-scope evidence matches" in result.stdout


def test_role_evidence_gate_blocks_org_stack_until_policy_review_is_recorded(tmp_path):
    _write_manifest(tmp_path, status="pending")

    result = _run(tmp_path, stack="org")

    assert result.returncode == 1
    assert "requires reviewed role-scope evidence" in result.stderr


def test_role_evidence_gate_requires_exact_role_fingerprint_and_all_policy_artifacts(tmp_path):
    _write_manifest(tmp_path, status="reviewed")

    result = _run(tmp_path, stack="org")

    assert result.returncode == 0, result.stderr


def test_reviewing_plan_role_does_not_authorize_the_separate_apply_role(tmp_path):
    _write_manifest(tmp_path, status="reviewed", phase="plan")

    plan_result = _run(tmp_path, stack="org", phase="plan")
    apply_result = _run(tmp_path, stack="org", phase="apply")

    assert plan_result.returncode == 0, plan_result.stderr
    assert apply_result.returncode == 1
    assert "org apply stack requires reviewed role-scope evidence" in apply_result.stderr


def test_plan_role_trust_policy_cannot_also_trust_the_apply_environment(tmp_path):
    _write_manifest(tmp_path, status="reviewed", phase="plan")
    relative = _evidence_files("org", "plan")[0]
    evidence = tmp_path / "docs/evidence" / relative
    trust = json.loads(evidence.read_text(encoding="utf-8"))
    trust["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] = [
        github_environment_subject("phase3-org-plan"),
        github_environment_subject("phase3-org-apply"),
    ]
    evidence.write_text(json.dumps(trust, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = tmp_path / "docs/evidence/phase3-role-scope.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["roles"]["org"]["plan"]["evidence_sha256"][relative] = hashlib.sha256(
        evidence.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = _run(tmp_path, stack="org", phase="plan")

    assert result.returncode == 1
    assert "not restricted to the protected workflow" in result.stderr


def test_role_evidence_gate_rejects_a_different_configured_role(tmp_path):
    _write_manifest(tmp_path, status="reviewed", stack="control-plane", phase="apply")

    result = _run(
        tmp_path,
        stack="control-plane",
        phase="apply",
        role_arn="arn:aws:iam::123456789012:role/OtherRole",
    )

    assert result.returncode == 1
    assert "does not match the reviewed role" in result.stderr


def test_role_evidence_gate_rejects_missing_policy_artifacts(tmp_path):
    _write_manifest(tmp_path, status="reviewed", include_evidence=False)

    result = _run(tmp_path, stack="org")

    assert result.returncode == 1
    assert "evidence files are missing" in result.stderr


def test_role_evidence_gate_requires_source_hashes_to_name_private_capture_paths(tmp_path):
    _write_manifest(tmp_path, status="reviewed")
    manifest_path = tmp_path / "docs/evidence/phase3-role-scope.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    record = manifest["roles"]["org"]["plan"]
    first_path = next(iter(record["source_evidence_sha256"]))
    first_digest = record["source_evidence_sha256"].pop(first_path)
    record["source_evidence_sha256"][_evidence_files("org", "plan")[0]] = first_digest
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = _run(tmp_path, stack="org")

    assert result.returncode == 1
    assert "raw-source digests are missing or invalid" in result.stderr


def test_role_evidence_gate_rejects_evidence_changed_after_review(tmp_path):
    _write_manifest(tmp_path, status="reviewed")
    evidence = tmp_path / "docs/evidence/terraform-roles/org/plan/attached-policies.json"
    evidence.write_text("[]\n", encoding="utf-8")

    result = _run(tmp_path, stack="org")

    assert result.returncode == 1
    assert "evidence digest does not match" in result.stderr


def test_role_evidence_gate_rejects_empty_or_irrelevant_policy_artifacts(tmp_path):
    _write_manifest(tmp_path, status="reviewed")
    evidence = tmp_path / "docs/evidence/terraform-roles/org/plan/attached-policies.json"
    evidence.write_text('{"Version":"2012-10-17","Statement":[]}\n', encoding="utf-8")
    manifest_path = tmp_path / "docs/evidence/phase3-role-scope.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["roles"]["org"]["plan"]["evidence_sha256"][_evidence_files("org")[1]] = hashlib.sha256(
        evidence.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = _run(tmp_path, stack="org")

    assert result.returncode == 1
    assert "attached policy evidence has an invalid shape" in result.stderr


def test_role_evidence_gate_rejects_wildcards_in_github_trust_subjects(tmp_path):
    _write_manifest(tmp_path, status="reviewed")
    evidence = tmp_path / "docs/evidence/terraform-roles/org/plan/trust-policy.json"
    trust = json.loads(evidence.read_text(encoding="utf-8"))
    trust["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:sub"] = (
        github_environment_subject("phase3-org-*")
    )
    evidence.write_text(json.dumps(trust, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = tmp_path / "docs/evidence/phase3-role-scope.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["roles"]["org"]["plan"]["evidence_sha256"][_evidence_files("org")[0]] = hashlib.sha256(
        evidence.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    result = _run(tmp_path, stack="org")

    assert result.returncode == 1
    assert "not restricted to the protected workflow" in result.stderr


def test_role_evidence_gate_does_not_block_code_managed_demo_stacks(tmp_path):
    result = _run(tmp_path, stack="demo-account")

    assert result.returncode == 0, result.stderr
