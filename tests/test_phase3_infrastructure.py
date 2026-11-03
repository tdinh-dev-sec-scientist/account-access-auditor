from __future__ import annotations

import json
import re
from pathlib import Path

from auditor.permissions import generate_policy

ROOT = Path(__file__).resolve().parents[1]


def _actions(policy: dict) -> set[str]:
    actions = set()
    for statement in policy["Statement"]:
        value = statement["Action"]
        actions.update(value if isinstance(value, list) else [value])
    return actions


def test_demo_target_role_policy_matches_the_auditors_generated_read_only_policy():
    policy_path = ROOT / "infra/phase3/policies/target-readonly.json"
    target_policy = json.loads(policy_path.read_text(encoding="utf-8"))
    expected_actions = _actions(generate_policy()) - {"sts:AssumeRole"}

    assert _actions(target_policy) == expected_actions
    assert all("*" not in action for action in _actions(target_policy))
    assert "arn:aws:iam::*" not in json.dumps(target_policy)
    assert "${demo_account_id}" in json.dumps(target_policy)


def test_phase3_scan_infrastructure_has_no_target_account_write_actions():
    policy_path = ROOT / "infra/phase3/policies/target-readonly.json"
    target_policy = json.loads(policy_path.read_text(encoding="utf-8"))
    forbidden_prefixes = ("iam:Create", "iam:Put", "iam:Update", "iam:Delete", "s3:Put", "s3:Delete")

    assert not any(action.startswith(forbidden_prefixes) for action in _actions(target_policy))


def test_private_snapshot_writer_cannot_write_public_results():
    policy_path = ROOT / "infra/phase3/policies/private-snapshot-writer.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    resources = json.dumps([statement["Resource"] for statement in policy["Statement"]])

    assert "${private_bucket_arn}/snapshots/${demo_account_id}/*" in resources
    assert "${private_table_arn}" in resources
    assert "public-results" not in resources
    assert "${private_table_arn}/index/scan-run-index" in resources


def test_private_snapshot_writer_lock_permissions_are_scoped_to_private_index():
    policy_path = ROOT / "infra/phase3/policies/private-snapshot-writer.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    lock_statements = [
        statement
        for statement in policy["Statement"]
        if set(statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]])
        & {"dynamodb:UpdateItem", "dynamodb:DeleteItem"}
    ]

    assert len(lock_statements) == 1
    assert set(lock_statements[0]["Action"]) == {"dynamodb:UpdateItem", "dynamodb:DeleteItem"}
    assert lock_statements[0]["Resource"] == "${private_table_arn}"
    assert "dynamodb:Scan" not in _actions(policy)


def test_scan_worker_can_only_assume_the_named_read_only_target_role():
    policy_path = ROOT / "infra/phase3/policies/scan-worker-runtime.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))

    assert _actions(policy) == {"sts:AssumeRole"}
    assert policy["Statement"][0]["Resource"] == (
        "arn:aws:iam::${demo_account_id}:role/AccountAccessAuditorReadOnly"
    )


def test_public_api_and_rin_cannot_mutate_aws_or_read_private_snapshots():
    for name in ("public-api-readonly.json", "rin-readonly.json"):
        policy = json.loads((ROOT / "infra/phase3/policies" / name).read_text(encoding="utf-8"))
        actions = _actions(policy)
        assert not any(
            action.startswith(("s3:Put", "s3:Delete", "dynamodb:Put", "dynamodb:Update", "dynamodb:Delete", "iam:"))
            for action in actions
        )
        assert "${private_bucket_arn}" not in json.dumps(policy)
        assert "${private_table_arn}" not in json.dumps(policy)
    rin_policy = json.loads((ROOT / "infra/phase3/policies/rin-readonly.json").read_text(encoding="utf-8"))
    assert "lambda:InvokeFunction" in _actions(rin_policy)


def test_quota_and_kill_switch_write_roles_cannot_touch_other_tables():
    quota = json.loads((ROOT / "infra/phase3/policies/rin-quota-writer.json").read_text(encoding="utf-8"))
    kill_switch = json.loads((ROOT / "infra/phase3/policies/rin-kill-switch.json").read_text(encoding="utf-8"))

    assert _actions(quota) == {"dynamodb:UpdateItem"}
    assert quota["Statement"][0]["Resource"] == "${quota_table_arn}"
    assert _actions(kill_switch) == {"dynamodb:UpdateItem"}
    assert kill_switch["Statement"][0]["Resource"] == "${feature_table_arn}"
    assert kill_switch["Statement"][0]["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == ["PLATFORM"]
    assert set(kill_switch["Statement"][0]["Condition"]["ForAllValues:StringLike"]["dynamodb:Attributes"]) == {
        "pk", "sk", "rin_enabled", "static_mode"
    }


def test_public_publisher_reads_private_only_and_writes_only_isolated_public_results():
    policy = json.loads((ROOT / "infra/phase3/policies/public-publisher-runtime.json").read_text(encoding="utf-8"))
    encoded = json.dumps(policy)
    assert "${private_bucket_arn}/snapshots/${demo_account_id}/*" in encoded
    assert "${public_bucket_arn}/snapshots/*" in encoded
    assert "${public_table_arn}" in encoded
    assert "${private_table_arn}" not in encoded
    assert "public-results" not in encoded


def test_daily_quota_limit_has_a_separate_aggregate_alert_path():
    stage3 = (ROOT / "infra/phase3/control-plane/stage3.tf").read_text(encoding="utf-8")
    stage4 = (ROOT / "infra/phase3/control-plane/stage4.tf").read_text(encoding="utf-8")

    assert '"DailyLimitReached"' in (ROOT / "phase3/quotas.py").read_text(encoding="utf-8")
    assert 'resource "aws_sns_topic" "rin_daily_alert"' in stage3
    assert 'resource "aws_sns_topic_subscription" "rin_daily_alert_email"' in stage3
    assert 'resource "aws_cloudwatch_metric_alarm" "rin_daily_limit"' in stage3
    assert re.search(r'metric_name\s*=\s*"DailyLimitReached"', stage3)
    assert re.search(r'alarm_actions\s*=\s*\[aws_sns_topic\.rin_daily_alert\[0\]\.arn\]', stage3)
    assert 'alarm_actions       = [aws_sns_topic.budget_kill[0].arn]' not in stage4


def test_owner_terraform_state_and_values_are_ignored_by_git():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert ".terraform/" in ignore
    assert "*.tfstate" in ignore
    assert "*.tfvars" in ignore
    assert "!*.tfvars.example" in ignore


def test_cloudfront_rate_limit_counts_api_calls_without_throttling_static_assets():
    stage3 = (ROOT / "infra/phase3/control-plane/stage3.tf").read_text(encoding="utf-8")

    assert re.search(r'search_string\s*=\s*"/api/"', stage3)
    assert "scope_down_statement" in stage3
    assert re.search(r'positional_constraint\s*=\s*"STARTS_WITH"', stage3)


def test_demo_terraform_role_can_read_only_the_provider_required_bucket_and_attachment_state():
    bootstrap = (ROOT / "infra/phase3/demo-bootstrap/main.tf").read_text(encoding="utf-8")

    assert '"iam:ListAttachedRolePolicies"' in bootstrap
    assert 'Sid    = "ReadOnlyNamedDemoBucketTerraformState"' in bootstrap
    for action in (
        "s3:ListBucket",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketCORS",
        "s3:GetBucketWebsite",
        "s3:GetBucketVersioning",
        "s3:GetAccelerateConfiguration",
        "s3:GetBucketRequestPayment",
        "s3:GetBucketLogging",
        "s3:GetLifecycleConfiguration",
        "s3:GetReplicationConfiguration",
        "s3:GetBucketObjectLockConfiguration",
    ):
        assert f'"{action}"' in bootstrap
    assert 's3:::${var.bucket_prefix}-p3-demo-a-${var.demo_account_id}' in bootstrap
    assert 's3:::${var.bucket_prefix}-p3-demo-b-${var.demo_account_id}' in bootstrap


def test_stage1_scan_uses_step_functions_and_an_ecs_fargate_task():
    stage1 = (ROOT / "infra/phase3/control-plane/stage1.tf").read_text(encoding="utf-8")

    assert 'resource "aws_ecs_cluster" "scan"' in stage1
    assert 'resource "aws_ecs_task_definition" "scan"' in stage1
    assert 'states:::ecs:runTask.sync' in stage1
    assert re.search(r'LaunchType\s*=\s*"FARGATE"', stage1)
    assert 'resource "aws_lambda_function" "scan_worker"' not in stage1
    assert 'GetScanReceipt = {' in stage1
    assert re.search(r'kind\s*=\s*"get_receipt"', stage1)
    assert '"receipt.$" = "$.scan_receipt.receipt"' in stage1
    assert 'Name = "PHASE3_PRIVATE_SNAPSHOT_BUCKET"' not in stage1
    assert 'Name = "PHASE3_PRIVATE_RUN_INDEX_TABLE"' not in stage1
    assert 'aws_iam_role_policy" "scan_task_invoke_private_writer"' in stage1
    assert '"iam:PassRole"' in stage1


def test_demo_account_changes_use_protected_github_oidc_terraform_workflow():
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")
    bootstrap = (ROOT / "infra/phase3/demo-bootstrap/main.tf").read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "id-token: write" in workflow
    assert "phase3-demo-account-apply" in workflow
    assert "required reviewers" in workflow.lower() or "environment:" in workflow
    assert "allowed-account-ids" in workflow
    assert "PHASE3_AWS_ACCOUNT_ID" in workflow
    assert "${{ github.run_attempt }}" in workflow
    for stack in ("org", "demo-bootstrap", "demo-account", "control-plane"):
        assert stack in workflow
    assert "terraform plan" in workflow
    assert "terraform apply" in workflow
    assert 'data "aws_iam_openid_connect_provider" "github"' in bootstrap
    assert "sts:AssumeRoleWithWebIdentity" in bootstrap
    assert re.search(r'github_apply_subject\s*=\s*"repo:\$\{var\.github_repository\}:environment:\$\{var\.github_apply_environment\}"', bootstrap)
    assert "token.actions.githubusercontent.com:ref" in bootstrap
    assert 'token.actions.githubusercontent.com:workflow" = "Phase 3 Terraform"' in bootstrap
    assert 'Action   = ["s3:GetObject"]' in bootstrap
    assert 'Action   = ["s3:GetObject", "s3:PutObject"]' in bootstrap
    assert '"s3:DeleteObject"' not in bootstrap


def test_control_plane_workflow_builds_lambda_and_web_assets_before_terraform_plan():
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")

    assert "actions/setup-python@v5" in workflow
    assert 'python-version: "3.12"' in workflow
    assert "python scripts/package_phase3_lambdas.py" in workflow
    assert "python scripts/build_phase3_web.py" in workflow
    assert workflow.index("Build Phase 3 Lambda and web assets") < workflow.index("Plan the selected stack")
    assert workflow.count("phase3-control-plane-assets-${{ github.run_id }}-${{ github.run_attempt }}") == 2
    assert "build/phase3/lambda.zip" in workflow
    assert "build/phase3/web/**" in workflow
    assert "actions/download-artifact@v4" in workflow
    assert "path: build/phase3" in workflow
    assert "sha256sum --check lambda.zip.sha256 web.sha256" in workflow
    assert workflow.index("Verify the exact control-plane assets") < workflow.index("Apply only the reviewed plan")


def test_demo_account_is_cost_guarded_and_cloudtrail_is_protected():
    org_policy = (ROOT / "infra/phase3/org/main.tf").read_text(encoding="utf-8")
    demo_stack = (ROOT / "infra/phase3/demo-account/main.tf").read_text(encoding="utf-8")

    for action in (
        "ec2:RunInstances",
        "ec2:CreateNatGateway",
        "rds:CreateDBInstance",
        "eks:CreateCluster",
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "iam:CreateAccessKey",
        "iam:CreateUser",
        "lambda:CreateFunction",
    ):
        assert action in org_policy
    assert 'resource "aws_cloudtrail" "demo"' in demo_stack
    assert 'resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail"' in demo_stack
    assert 'project = "guardrails-phase3"' in demo_stack
    assert "event_selector" not in demo_stack


def test_scan_image_publisher_can_only_write_the_scan_image_repository():
    stage1 = (ROOT / "infra/phase3/control-plane/stage1.tf").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/phase3-scan-image.yml").read_text(encoding="utf-8")
    publisher_policy = stage1.split('resource "aws_iam_role_policy" "scan_image_publisher"', 1)[1].split(
        'resource "aws_ecs_task_definition" "scan"', 1
    )[0]

    assert re.search(r'image_tag_mutability\s*=\s*"MUTABLE"', stage1)
    assert "scan_container_image" in stage1
    assert "sha-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "ecr:GetAuthorizationToken" in stage1
    assert '"ecr:GetDownloadUrlForLayer"' in publisher_policy
    assert '"ecr:PutImage"' in publisher_policy
    assert '"ecr:BatchGetImage"' in stage1
    assert 'Resource = aws_ecr_repository.scan.arn' in stage1
    assert "sts:AssumeRoleWithWebIdentity" in stage1
    assert 'data "aws_iam_openid_connect_provider" "github"' in stage1
    assert 'resource "aws_iam_openid_connect_provider" "github"' not in stage1
    assert 'token.actions.githubusercontent.com:workflow" = "Phase 3 scan image"' in stage1
    assert "cosign sign --yes" in workflow
    assert "cosign verify" in workflow
    assert "steps.build.outputs.digest" in workflow


def test_bootstrap_stack_uses_a_named_limited_role_instead_of_account_admin():
    bootstrap = (ROOT / "infra/phase3/demo-bootstrap/main.tf").read_text(encoding="utf-8")
    plan_policy = json.loads((ROOT / "infra/phase3/policies/demo-bootstrap-plan.json").read_text(encoding="utf-8"))
    apply_policy = json.loads((ROOT / "infra/phase3/policies/demo-bootstrap-apply.json").read_text(encoding="utf-8"))
    org_policy = (ROOT / "infra/phase3/org/main.tf").read_text(encoding="utf-8")

    assert 'data "aws_iam_openid_connect_provider" "github"' in bootstrap
    assert 'resource "aws_iam_openid_connect_provider" "github"' not in bootstrap
    assert "OrganizationAccountAccessRole" not in bootstrap
    assert "Phase3DemoBootstrapPlan" in org_policy
    assert "Phase3DemoBootstrapApply" in org_policy
    assert _actions(plan_policy) <= {
        "iam:GetOpenIDConnectProvider",
        "iam:CreateRole",
        "iam:GetRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:PutRolePolicy",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetObject",
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
    }
    assert _actions(apply_policy) - _actions(plan_policy) <= {"iam:CreateRole", "iam:UpdateAssumeRolePolicy", "iam:TagRole", "iam:UntagRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "s3:PutObject"}
    assert not (_actions(plan_policy) & {"iam:CreateRole", "iam:PutRolePolicy", "s3:PutObject"})
    plan_resources = [item["Resource"] for item in plan_policy["Statement"]]
    apply_resources = [item["Resource"] for item in apply_policy["Statement"]]
    assert "${bootstrap_state_bucket_arn}" in plan_resources
    assert "${bootstrap_state_object_arn}" in plan_resources
    assert "${bootstrap_state_lock_table_arn}" in plan_resources
    assert "arn:aws:iam::${demo_account_id}:role/Phase3DemoTerraformPlan" in apply_resources[1]
    assert "arn:aws:iam::${demo_account_id}:role/Phase3DemoTerraformApply" in apply_resources[1]
    assert all(resource != "*" for resource in plan_resources + apply_resources)


def test_read_only_scan_target_requires_exact_named_role_and_no_private_store_permissions():
    stage1 = (ROOT / "infra/phase3/control-plane/stage1.tf").read_text(encoding="utf-8")
    scan_task = (ROOT / "phase3/scan_task.py").read_text(encoding="utf-8")

    assert "if not role_match:" in scan_task
    assert '"AssumeOnlyTheDemoReadOnlyRole"' in (ROOT / "infra/phase3/policies/scan-worker-runtime.json").read_text(
        encoding="utf-8"
    )
    assert '"dynamodb:PutItem"' not in stage1.split('resource "aws_iam_role_policy" "scan_task_assume_target"')[1].split("resource")[0]
    assert '"s3:PutObject"' not in stage1.split('resource "aws_iam_role_policy" "scan_task_assume_target"')[1].split("resource")[0]


def test_demo_account_terraform_uses_encrypted_remote_state_and_is_in_ci_validation():
    versions = (ROOT / "infra/phase3/demo-account/versions.tf").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    deploy = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")

    assert 'backend "s3" {}' in versions
    assert 'infra/phase3/demo-account' in workflow
    assert 'backend-config="encrypt=true"' in deploy
    assert 'TF_VAR_scan_task_role_arn' in deploy


def test_scan_image_has_a_human_verifiable_signed_digest_pinned_release_path():
    dockerfile = (ROOT / "Dockerfile.phase3-scan").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/phase3-scan-image.yml").read_text(encoding="utf-8")
    variables = (ROOT / "infra/phase3/control-plane/variables.tf").read_text(encoding="utf-8")

    assert "USER 10001:10001" in dockerfile
    assert "FROM --platform=" not in dockerfile
    assert "scan_container_image" in variables
    assert "sha256:[0-9a-f]{64}" in variables
    assert "id-token: write" in workflow
    assert "allowed-account-ids" in workflow
    assert "cosign sign" in workflow
    assert "cosign verify" in workflow
    assert "ecr:PutImage" in (ROOT / "infra/phase3/control-plane/stage1.tf").read_text(encoding="utf-8")
