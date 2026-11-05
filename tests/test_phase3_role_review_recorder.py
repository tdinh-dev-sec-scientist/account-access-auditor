"""Recording a human role review: capture -> verify -> record -> gate."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from phase3.role_capture import capture_role_evidence
from phase3.role_evidence import validate_role_scope_evidence
from scripts import record_phase3_role_review as recorder
from scripts.render_phase3_org_roles import render_documents
from tests.test_phase3_role_capture import _FakeIam

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/Phase3OrgTerraformPlan"
VALUES = {
    "account_id": ACCOUNT,
    "demo_account_id": "444455556666",
    "organization_id": "o-abcdef1234",
    "root_id": "r-ab12",
    "state_bucket": "vorrin-tfstate-8b39495b",
    "lock_table": "vorrin-tf-locks",
    "region": "us-east-1",
}


def _captured_repository(tmp_path: Path, *, trust=None) -> Path:
    evidence = tmp_path / "docs/evidence"
    evidence.mkdir(parents=True)
    shutil.copy(ROOT / "docs/evidence/phase3-role-scope.json", evidence / "phase3-role-scope.json")
    documents = render_documents(VALUES)
    iam = _FakeIam(role_arn=ROLE_ARN, boundary=False)
    iam.trust = documents["plan-trust"] if trust is None else trust
    iam.policy = documents["plan-permissions"]
    capture_role_evidence(root=tmp_path, stack="org", phase="plan", role_arn=ROLE_ARN, iam_client=iam)
    return tmp_path


def _record(root: Path, **overrides):
    arguments = {
        "root": root,
        "stack": "org",
        "phase": "plan",
        "role_arn": ROLE_ARN,
        "reviewer": "Truong Dinh",
        "reviewed_at": datetime(2026, 11, 5, 17, 0, tzinfo=UTC),
    }
    arguments.update(overrides)
    return recorder.record_review(**arguments)


def test_a_reviewed_rendered_role_passes_the_workflow_gate(tmp_path):
    root = _captured_repository(tmp_path)

    record = _record(root)

    assert record["status"] == "reviewed"
    assert record["reviewed_by"] == "Truong Dinh"
    assert record["reviewed_at"] == "2026-11-05T17:00:00+00:00"
    assert ROLE_ARN not in (root / "docs/evidence/phase3-role-scope.json").read_text(encoding="utf-8")
    validate_role_scope_evidence(root=root, stack="org", phase="plan", role_arn=ROLE_ARN)


def test_only_the_reviewed_role_changes(tmp_path):
    root = _captured_repository(tmp_path)
    before = json.loads((root / "docs/evidence/phase3-role-scope.json").read_text(encoding="utf-8"))

    _record(root)

    after = json.loads((root / "docs/evidence/phase3-role-scope.json").read_text(encoding="utf-8"))
    assert after["roles"]["org"]["apply"] == before["roles"]["org"]["apply"]
    assert after["roles"]["control-plane"] == before["roles"]["control-plane"]


def test_a_role_cannot_be_recorded_twice(tmp_path):
    root = _captured_repository(tmp_path)
    _record(root)

    with pytest.raises(recorder.RecordError, match="already reviewed"):
        _record(root)


def test_a_different_role_arn_is_rejected_before_anything_is_written(tmp_path):
    root = _captured_repository(tmp_path)
    before = (root / "docs/evidence/phase3-role-scope.json").read_bytes()

    with pytest.raises(Exception, match="does not match"):
        _record(root, role_arn=f"arn:aws:iam::{ACCOUNT}:role/SomeOtherRole")
    assert (root / "docs/evidence/phase3-role-scope.json").read_bytes() == before


def test_a_trust_policy_the_gate_rejects_restores_the_manifest(tmp_path):
    trust = render_documents(VALUES)["plan-trust"]
    del trust["Statement"][0]["Condition"]["StringEquals"]["token.actions.githubusercontent.com:ref"]
    root = _captured_repository(tmp_path, trust=trust)
    before = (root / "docs/evidence/phase3-role-scope.json").read_bytes()

    with pytest.raises(recorder.RecordError, match="gate rejected this role"):
        _record(root)
    assert (root / "docs/evidence/phase3-role-scope.json").read_bytes() == before


@pytest.mark.parametrize("reviewer", ["", "   ", "x" * 121])
def test_reviewer_name_is_required(tmp_path, reviewer):
    with pytest.raises(recorder.RecordError, match="reviewer"):
        _record(tmp_path, reviewer=reviewer)


def test_cli_refuses_without_explicit_review_confirmation(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/record_phase3_role_review.py"),
            "--root",
            str(tmp_path),
            "--stack",
            "org",
            "--phase",
            "plan",
            "--role-arn",
            ROLE_ARN,
            "--reviewer",
            "Truong Dinh",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "--confirm-reviewed" in result.stderr


def test_cli_records_a_confirmed_review(tmp_path):
    root = _captured_repository(tmp_path)

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/record_phase3_role_review.py"),
            "--root",
            str(root),
            "--stack",
            "org",
            "--phase",
            "plan",
            "--role-arn",
            ROLE_ARN,
            "--reviewer",
            "Truong Dinh",
            "--confirm-reviewed",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "The role-evidence gate accepts it." in result.stdout
