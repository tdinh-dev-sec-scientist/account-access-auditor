"""Control-plane GitHub OIDC roles and the workload permissions boundary."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from phase3.role_evidence import _validate_policy_document, _validate_trust_policy, github_environment_subject
from scripts import render_phase3_control_plane_roles as renderer
from scripts.render_phase3_org_roles import RenderError

ROOT = Path(__file__).resolve().parents[1]
CONTROL_PLANE = ROOT / "infra/phase3/control-plane"
VALUES = {
    "account_id": "111122223333",
    "demo_account_id": "444455556666",
    "state_bucket": "vorrin-tfstate-8b39495b",
    "lock_table": "vorrin-tf-locks",
    "region": "us-east-1",
    "bucket_prefix": "vorrin",
    "boundary_name": "Phase3ControlPlaneWorkloadBoundary",
}
BOUNDARY_ARN = "arn:aws:iam::111122223333:policy/Phase3ControlPlaneWorkloadBoundary"


@pytest.fixture(scope="module")
def documents():
    return renderer.render_documents(VALUES)


def _statements(document):
    return document["Statement"]


def _actions(statement):
    value = statement.get("Action", [])
    return [value] if isinstance(value, str) else value


def _resources(statement):
    value = statement.get("Resource", statement.get("NotResource", []))
    return [value] if isinstance(value, str) else value


def _allowed(*documents):
    return [s for document in documents for s in _statements(document) if s["Effect"] == "Allow"]


def _write_like(action):
    verb = action.split(":", 1)[1]
    return not verb.startswith(("Describe", "Get", "List", "View")) and action != "apigateway:GET"


@pytest.mark.parametrize("phase", ["plan", "apply"])
def test_trust_pins_the_protected_control_plane_environment(documents, phase):
    projected = json.loads(
        json.dumps(documents[f"{phase}-trust"]).replace(VALUES["account_id"], "<TARGET_ACCOUNT>")
    )
    role_arn = f"arn:aws:iam::{VALUES['account_id']}:role/Phase3ControlPlaneTerraform{phase.title()}"

    _validate_trust_policy("control-plane", phase, projected, role_arn=role_arn)
    subject = documents[f"{phase}-trust"]["Statement"][0]["Condition"]["StringEquals"]
    assert subject["token.actions.githubusercontent.com:sub"] == github_environment_subject(
        f"phase3-control-plane-{phase}"
    )


def test_every_document_is_filled_valid_and_within_iam_size_limits(documents):
    assert set(documents) == {
        "plan-trust",
        "plan-permissions",
        "apply-trust",
        "apply-permissions",
        "apply-manage-1",
        "apply-manage-2",
        "workload-boundary",
    }
    for name, document in documents.items():
        text = json.dumps(document)
        assert "${" not in text, name
        if not name.endswith("-trust"):
            _validate_policy_document(document, context=name, require_resource=True)
    compact = {name: len(json.dumps(doc, separators=(",", ":"))) for name, doc in documents.items()}
    assert compact["apply-permissions"] <= renderer.INLINE_LIMIT
    assert compact["plan-permissions"] <= renderer.INLINE_LIMIT
    assert compact["apply-manage-1"] <= renderer.MANAGED_LIMIT
    assert compact["apply-manage-2"] <= renderer.MANAGED_LIMIT
    assert compact["workload-boundary"] <= renderer.MANAGED_LIMIT


def test_plan_role_allows_no_writes(documents):
    writes = [
        action
        for statement in _allowed(documents["plan-permissions"])
        for action in _actions(statement)
        if _write_like(action)
    ]
    # The S3 backend lock needs these, and only on the lock table.
    assert set(writes) == {"dynamodb:PutItem", "dynamodb:DeleteItem"}
    lock = f"arn:aws:dynamodb:us-east-1:{VALUES['account_id']}:table/vorrin-tf-locks"
    for statement in _allowed(documents["plan-permissions"]):
        if set(_actions(statement)) & set(writes):
            assert _resources(statement) == [lock]


def test_state_access_is_only_the_control_plane_state_object(documents):
    state = f"arn:aws:s3:::{VALUES['state_bucket']}/phase3/control-plane/terraform.tfstate"
    for name in ("plan-permissions", "apply-permissions"):
        objects = {
            resource
            for statement in _allowed(documents[name])
            if set(_actions(statement)) & {"s3:GetObject", "s3:PutObject"}
            for resource in _resources(statement)
        }
        assert objects == {state}, name


def test_data_reads_are_denied_even_where_configuration_reads_are_broad(documents):
    for name in ("plan-permissions", "apply-permissions"):
        denied = {
            action
            for statement in _statements(documents[name])
            if statement["Effect"] == "Deny"
            for action in _actions(statement)
        }
        assert {
            "s3:GetObject",
            "dynamodb:Scan",
            "dynamodb:Query",
            "secretsmanager:GetSecretValue",
            "logs:GetLogEvents",
            "organizations:*",
            "sts:AssumeRole",
            "iam:AttachRolePolicy",
            "iam:CreatePolicyVersion",
            "iam:DeleteRolePermissionsBoundary",
        } <= denied, name


def test_apply_can_create_or_change_roles_only_with_the_owner_boundary(documents):
    apply = (documents["apply-permissions"], documents["apply-manage-1"], documents["apply-manage-2"])
    for statement in _allowed(*apply):
        actions = set(_actions(statement))
        if actions & {"iam:CreateRole", "iam:PutRolePolicy", "iam:PutRolePermissionsBoundary"}:
            assert statement["Condition"] == {"StringEquals": {"iam:PermissionsBoundary": BOUNDARY_ARN}}
        iam_writes = {a for a in actions if a.startswith("iam:") and _write_like(a)}
        if iam_writes - {"iam:CreateServiceLinkedRole"}:
            assert all(
                re.fullmatch(r"arn:aws:iam::111122223333:role/vorrin-(p3|phase3)-\*", resource)
                for resource in _resources(statement)
            ), statement["Sid"]
        if "iam:PassRole" in actions:
            assert statement["Condition"]["StringEquals"]["iam:PassedToService"]
    never = next(
        s
        for s in _statements(documents["apply-permissions"])
        if s["Sid"] == "NeverChangeTheWorkloadBoundaryOrTerraformRoles"
    )
    assert never["Effect"] == "Deny" and never["NotAction"] == ["iam:Get*", "iam:List*"]
    assert BOUNDARY_ARN in never["Resource"]


def test_name_scoped_writes_stay_inside_the_bucket_prefix(documents):
    generated_id_services = (
        "ec2:",
        "cloudfront:",
        "cognito-idp:",
        "ecs:RegisterTaskDefinition",
        "sns:Unsubscribe",
    )
    for statement in _allowed(documents["apply-manage-1"], documents["apply-manage-2"]):
        if statement["Resource"] == "*":
            assert all(
                action.startswith(generated_id_services)
                or action
                in {
                    "iam:CreateServiceLinkedRole",
                    "ecs:DeregisterTaskDefinition",
                    "ecs:DeleteTaskDefinitions",
                    "sns:SetSubscriptionAttributes",
                }
                for action in _actions(statement)
            ), statement["Sid"]
            continue
        for resource in _resources(statement):
            assert (
                "vorrin" in resource
                or "/restapis" in resource
                or "/tags/" in resource
                or ("distribution/*" in resource)
            ), (statement["Sid"], resource)


def test_no_cognito_user_management_from_terraform(documents):
    actions = {
        a for s in _allowed(documents["apply-manage-1"], documents["apply-manage-2"]) for a in _actions(s)
    }
    assert not {a for a in actions if a.startswith("cognito-idp:Admin")}


def test_boundary_is_an_explicit_allowlist_without_iam_writes(documents):
    boundary = documents["workload-boundary"]
    for statement in _statements(boundary):
        assert statement["Effect"] == "Allow"
        assert "NotAction" not in statement
        for action in _actions(statement):
            assert "*" not in action, action
            if action.startswith("iam:"):
                assert action == "iam:PassRole"
        if statement["Resource"] == "*":
            assert _actions(statement) == ["ecr:GetAuthorizationToken"]
    assume = next(s for s in _statements(boundary) if "sts:AssumeRole" in _actions(s))
    assert assume["Resource"] == "arn:aws:iam::444455556666:role/AccountAccessAuditorReadOnly"


def test_every_terraform_workload_role_carries_the_boundary():
    text = "\n".join(path.read_text(encoding="utf-8") for path in sorted(CONTROL_PLANE.glob("*.tf")))
    roles = re.findall(r'resource "aws_iam_role" "([a-z_]+)" \{(.*?)\n\}', text, flags=re.S)
    assert len(roles) == 11
    for name, body in roles:
        assert "permissions_boundary = local.workload_permissions_boundary_arn" in body, name
    assert 'default     = "Phase3ControlPlaneWorkloadBoundary"' in text


def test_every_terraform_role_name_matches_the_apply_role_scope():
    text = "\n".join(path.read_text(encoding="utf-8") for path in sorted(CONTROL_PLANE.glob("*.tf")))
    locals_ = dict(re.findall(r"^\s+([a-z_]+_name)\s+=\s+\"([^\"]+)\"", text, flags=re.M))
    for _name, body in re.findall(r'resource "aws_iam_role" "([a-z_]+)" \{(.*?)\n\}', text, flags=re.S):
        raw = re.search(r"^\s+name\s+=\s+(.+)$", body, flags=re.M).group(1).strip()
        value = locals_.get(raw.removeprefix("local."), raw).strip('"')
        assert re.match(r"\$\{var\.bucket_prefix\}-(p3|phase3)-", value), value


@pytest.mark.parametrize("field", list(VALUES))
def test_invalid_inputs_are_rejected(field):
    with pytest.raises(RenderError, match=field):
        renderer.render_documents({**VALUES, field: "not valid!"})


def test_the_demo_account_must_differ_from_the_control_plane_account():
    with pytest.raises(RenderError, match="differ"):
        renderer.render_documents({**VALUES, "demo_account_id": VALUES["account_id"]})


def test_cli_renders_offline_and_prints_ordered_commands(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/render_phase3_control_plane_roles.py"),
            "--account-id",
            VALUES["account_id"],
            "--demo-account-id",
            VALUES["demo_account_id"],
            "--state-bucket",
            VALUES["state_bucket"],
            "--lock-table",
            VALUES["lock_table"],
            "--bucket-prefix",
            VALUES["bucket_prefix"],
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert len(list(tmp_path.iterdir())) == 7
    out = result.stdout
    order = [
        "--policy-name Phase3ControlPlaneWorkloadBoundary",
        "create-role --role-name Phase3ControlPlaneTerraformPlan",
        "create-role --role-name Phase3ControlPlaneTerraformApply",
        "--policy-name Phase3ControlPlaneTerraformApplyManage1",
        "attach-role-policy --role-name Phase3ControlPlaneTerraformApply",
        "--policy-name Phase3ControlPlaneTerraformApplyManage2",
    ]
    positions = [out.index(marker) for marker in order]
    assert positions == sorted(positions)


@mock_aws
def test_discovery_requires_the_management_account(monkeypatch):
    organizations = boto3.client("organizations", region_name="us-east-1")
    organizations.create_organization(FeatureSet="ALL")
    organizations.create_account(AccountName="vorrin-demo", Email="demo@example.com")
    real_session = boto3.session.Session
    monkeypatch.setattr("boto3.session.Session", lambda **_kwargs: real_session(region_name="us-east-1"))

    found = renderer.discover("vorrin-admin", "vorrin-demo")

    assert re.fullmatch(r"[0-9]{12}", found["account_id"])
    assert re.fullmatch(r"[0-9]{12}", found["demo_account_id"])
    assert found["account_id"] != found["demo_account_id"]
