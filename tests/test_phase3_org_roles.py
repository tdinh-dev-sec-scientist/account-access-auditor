"""Org-stack GitHub OIDC role templates and their renderer."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from phase3.role_evidence import (
    GITHUB_SUBJECT_REPOSITORY,
    _validate_policy_document,
    _validate_trust_policy,
    github_environment_subject,
)
from scripts import render_phase3_org_roles as renderer

ROOT = Path(__file__).resolve().parents[1]
VALUES = {
    "account_id": "111122223333",
    "demo_account_id": "444455556666",
    "organization_id": "o-abcdef1234",
    "root_id": "r-ab12",
    "state_bucket": "vorrin-tfstate-8b39495b",
    "lock_table": "vorrin-tf-locks",
    "region": "us-east-1",
}


def _statements(document):
    return {statement["Sid"]: statement for statement in document["Statement"]}


def _actions(document, effect="Allow"):
    actions = set()
    for statement in document["Statement"]:
        if statement["Effect"] == effect:
            value = statement["Action"]
            actions.update([value] if isinstance(value, str) else value)
    return actions


@pytest.fixture(scope="module")
def documents():
    return renderer.render_documents(VALUES)


def test_github_subject_uses_the_probed_immutable_id_format():
    assert GITHUB_SUBJECT_REPOSITORY == "tdinh-dev-sec-scientist@172205018/Vorrin@1360779179"
    assert github_environment_subject("phase3-org-plan") == (
        "repo:tdinh-dev-sec-scientist@172205018/Vorrin@1360779179:environment:phase3-org-plan"
    )


def test_terraform_subjects_use_the_immutable_id_repository():
    for path in ("infra/phase3/demo-bootstrap/main.tf", "infra/phase3/control-plane/stage1.tf"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert "repo:${var.github_repository}" not in text, path
        assert "repo:${var.github_subject_repository}:environment:" in text, path
    for path in ("infra/phase3/demo-bootstrap/variables.tf", "infra/phase3/control-plane/variables.tf"):
        assert f'default     = "{GITHUB_SUBJECT_REPOSITORY}"' in (ROOT / path).read_text(encoding="utf-8")


def test_rendered_documents_have_no_placeholders(documents):
    assert set(documents) == {"plan-trust", "plan-permissions", "apply-trust", "apply-permissions"}
    assert "${" not in json.dumps(documents)


@pytest.mark.parametrize("phase", ["plan", "apply"])
def test_rendered_trust_passes_the_repository_role_evidence_gate(documents, phase):
    # The capture tool replaces account IDs with <TARGET_ACCOUNT> before the gate sees them.
    projected = json.loads(
        json.dumps(documents[f"{phase}-trust"]).replace(VALUES["account_id"], "<TARGET_ACCOUNT>")
    )
    role_arn = f"arn:aws:iam::{VALUES['account_id']}:role/Phase3OrgTerraform{phase.title()}"

    _validate_trust_policy("org", phase, projected, role_arn=role_arn)


def test_trust_pins_all_four_claims_to_the_protected_environment(documents):
    conditions = documents["plan-trust"]["Statement"][0]["Condition"]["StringEquals"]

    assert conditions == {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": github_environment_subject("phase3-org-plan"),
        "token.actions.githubusercontent.com:workflow": "Phase 3 Terraform",
        "token.actions.githubusercontent.com:ref": "refs/heads/main",
    }
    apply_subject = documents["apply-trust"]["Statement"][0]["Condition"]["StringEquals"]
    assert apply_subject["token.actions.githubusercontent.com:sub"].endswith(":environment:phase3-org-apply")


@pytest.mark.parametrize("name", ["plan-permissions", "apply-permissions"])
def test_permission_documents_satisfy_the_policy_shape_gate(documents, name):
    _validate_policy_document(documents[name], context=name, require_resource=True)


def test_plan_role_cannot_change_the_organization(documents):
    organization_actions = {
        action for action in _actions(documents["plan-permissions"]) if action.startswith("organizations:")
    }

    assert organization_actions
    assert all(re.match(r"organizations:(Describe|List)", action) for action in organization_actions)
    assert "s3:PutObject" not in _actions(documents["plan-permissions"])


def test_apply_role_cannot_attach_policies_to_the_root_or_move_other_accounts(documents):
    statements = _statements(documents["apply-permissions"])
    attach = statements["AttachServiceControlPoliciesToOUsNeverTheRoot"]["Resource"]
    move = statements["MoveOnlyTheDemoAccountBetweenTheRootAndOUs"]["Resource"]

    assert not any(":root/" in arn for arn in attach)
    assert [arn for arn in move if ":account/" in arn] == [
        f"arn:aws:organizations::{VALUES['account_id']}:account/{VALUES['organization_id']}/{VALUES['demo_account_id']}"
    ]


def test_apply_role_explicitly_denies_destructive_organization_changes(documents):
    denied = _actions(documents["apply-permissions"], effect="Deny")

    for action in (
        "organizations:LeaveOrganization",
        "organizations:DeleteOrganization",
        "organizations:RemoveAccountFromOrganization",
        "organizations:CloseAccount",
        "organizations:DetachPolicy",
        "organizations:DeletePolicy",
        "sts:AssumeRole",
    ):
        assert action in denied, action
    assert not (_actions(documents["apply-permissions"]) & denied)


def test_state_access_is_limited_to_the_org_state_object(documents):
    for name in ("plan-permissions", "apply-permissions"):
        statements = documents[name]["Statement"]
        object_arns = {
            statement["Resource"] for statement in statements if "s3:GetObject" in statement["Action"]
        }
        assert object_arns == {f"arn:aws:s3:::{VALUES['state_bucket']}/phase3/org/terraform.tfstate"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_id", "12345"),
        ("organization_id", "org-1"),
        ("root_id", "root"),
        ("state_bucket", "Bad_Bucket"),
        ("demo_account_id", None),
        ("region", "us east 1"),
    ],
)
def test_invalid_inputs_are_rejected(field, value):
    with pytest.raises(renderer.RenderError, match=field):
        renderer.render_documents({**VALUES, field: value})


def test_cli_renders_offline_and_prints_commands(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/render_phase3_org_roles.py"),
            "--account-id",
            VALUES["account_id"],
            "--organization-id",
            VALUES["organization_id"],
            "--root-id",
            VALUES["root_id"],
            "--demo-account-id",
            VALUES["demo_account_id"],
            "--state-bucket",
            VALUES["state_bucket"],
            "--lock-table",
            VALUES["lock_table"],
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "apply-permissions.json",
        "apply-trust.json",
        "plan-permissions.json",
        "plan-trust.json",
    ]
    assert "aws iam create-role --role-name Phase3OrgTerraformPlan" in result.stdout
    assert "aws iam put-role-policy --role-name Phase3OrgTerraformApply" in result.stdout


@mock_aws
def test_discovery_reads_ids_from_the_management_account(monkeypatch):
    organizations = boto3.client("organizations", region_name="us-east-1")
    organizations.create_organization(FeatureSet="ALL")
    status = organizations.create_account(Email="owner+vorrin-demo@example.com", AccountName="vorrin-demo")
    demo_id = organizations.describe_create_account_status(
        CreateAccountRequestId=status["CreateAccountStatus"]["Id"]
    )["CreateAccountStatus"]["AccountId"]
    real_session = boto3.session.Session
    monkeypatch.setattr("boto3.session.Session", lambda **_kwargs: real_session(region_name="us-east-1"))
    discovered = renderer.discover("vorrin-admin", "vorrin-demo")

    assert discovered["demo_account_id"] == demo_id
    assert discovered["organization_id"].startswith("o-")
    assert discovered["root_id"].startswith("r-")
    assert re.fullmatch(r"[0-9]{12}", discovered["account_id"])


@mock_aws
def test_discovery_requires_exactly_one_matching_demo_account(monkeypatch):
    boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
    real_session = boto3.session.Session
    monkeypatch.setattr("boto3.session.Session", lambda **_kwargs: real_session(region_name="us-east-1"))

    with pytest.raises(renderer.RenderError, match="exactly one ACTIVE account named vorrin-demo"):
        renderer.discover("vorrin-admin", "vorrin-demo")


def test_org_stack_can_import_an_existing_demo_account():
    main = (ROOT / "infra/phase3/org/main.tf").read_text(encoding="utf-8")
    variables = (ROOT / "infra/phase3/org/variables.tf").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")

    assert "to       = aws_organizations_account.demo" in main
    assert (
        'for_each = var.existing_demo_account_id == "" ? toset([]) : toset([var.existing_demo_account_id])'
        in main
    )
    assert "ignore_changes = [role_name, iam_user_access_to_billing]" in main
    assert "prevent_destroy = true" in main
    assert 'variable "existing_demo_account_id"' in variables
    assert "TF_VAR_existing_demo_account_id: ${{ vars.PHASE3_EXISTING_DEMO_ACCOUNT_ID || '' }}" in workflow


def test_bootstrap_guide_uses_the_immutable_subject_format():
    guide = (ROOT / "docs/phase3-bootstrap.md").read_text(encoding="utf-8")

    assert "repo:tdinh-dev-sec-scientist/Vorrin:environment:" not in guide
    assert (
        "repo:tdinh-dev-sec-scientist@172205018/Vorrin@1360779179:environment:phase3-demo-bootstrap-plan"
        in guide
    )
    assert "scripts/render_phase3_org_roles.py" in guide
