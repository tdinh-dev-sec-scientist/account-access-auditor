"""Demo-bootstrap GitHub OIDC roles rendered for the demo account."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from phase3.role_evidence import _validate_policy_document, _validate_trust_policy, github_environment_subject
from scripts import render_phase3_demo_bootstrap_roles as renderer
from scripts.render_phase3_org_roles import RenderError

ROOT = Path(__file__).resolve().parents[1]
VALUES = {
    "account_id": "356929397083",
    "state_bucket": "vorrin-demo-tfstate-1a2b3c4d",
    "lock_table": "vorrin-demo-tf-locks",
    "region": "us-east-1",
}


@pytest.fixture(scope="module")
def documents():
    return renderer.render_documents(VALUES)


@pytest.mark.parametrize("phase", ["plan", "apply"])
def test_trust_pins_the_protected_demo_bootstrap_environment(documents, phase):
    projected = json.loads(
        json.dumps(documents[f"{phase}-trust"]).replace(VALUES["account_id"], "<TARGET_ACCOUNT>")
    )
    role_arn = f"arn:aws:iam::{VALUES['account_id']}:role/Phase3DemoBootstrap{phase.title()}"

    _validate_trust_policy("demo-bootstrap", phase, projected, role_arn=role_arn)
    subject = documents[f"{phase}-trust"]["Statement"][0]["Condition"]["StringEquals"]
    assert subject["token.actions.githubusercontent.com:sub"] == github_environment_subject(
        f"phase3-demo-bootstrap-{phase}"
    )


@pytest.mark.parametrize("name", ["plan-permissions", "apply-permissions"])
def test_permissions_are_scoped_to_the_demo_account_state(documents, name):
    text = json.dumps(documents[name])

    _validate_policy_document(documents[name], context=name, require_resource=True)
    assert "${" not in text
    assert f"arn:aws:s3:::{VALUES['state_bucket']}/phase3/demo-bootstrap/terraform.tfstate" in text
    assert f"arn:aws:dynamodb:us-east-1:{VALUES['account_id']}:table/vorrin-demo-tf-locks" in text
    assert f"arn:aws:iam::{VALUES['account_id']}:role/Phase3DemoTerraformPlan" in text


def test_plan_role_cannot_write_state_or_roles(documents):
    actions = {
        action
        for statement in documents["plan-permissions"]["Statement"]
        for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
    }

    assert "s3:PutObject" not in actions
    assert not any(
        action.startswith(("iam:Create", "iam:Put", "iam:Update", "iam:Delete")) for action in actions
    )


def test_role_names_are_the_ones_the_demo_scp_allows():
    org = (ROOT / "infra/phase3/org/main.tf").read_text(encoding="utf-8")

    for role, _environment, _file in renderer.ROLES.values():
        assert f':role/{role}"' in org, role


@pytest.mark.parametrize("field", ["account_id", "state_bucket", "lock_table", "region"])
def test_invalid_inputs_are_rejected(field):
    with pytest.raises(RenderError, match=field):
        renderer.render_documents({**VALUES, field: "not valid!"})


def test_cli_renders_offline_and_prints_demo_account_commands(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/render_phase3_demo_bootstrap_roles.py"),
            "--account-id",
            VALUES["account_id"],
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
    assert "aws iam create-role --role-name Phase3DemoBootstrapPlan" in result.stdout
    assert "Phase 3 demo-bootstrap Terraform plan role" in result.stdout


@mock_aws
def test_discovery_refuses_the_management_account(monkeypatch):
    boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
    real_session = boto3.session.Session
    monkeypatch.setattr("boto3.session.Session", lambda **_kwargs: real_session(region_name="us-east-1"))

    with pytest.raises(RenderError, match="management account"):
        renderer.discover("vorrin-admin")
