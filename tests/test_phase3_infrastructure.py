from __future__ import annotations

import json
import re
from pathlib import Path

from auditor.permissions import generate_policy

ROOT = Path(__file__).resolve().parents[1]


def _actions(policy: dict) -> set[str]:
    actions = set()
    for statement in policy["Statement"]:
        if statement.get("Effect") != "Allow":
            continue
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


def test_target_role_s3_metadata_reads_are_limited_to_the_selected_account():
    policy = json.loads((ROOT / "infra/phase3/policies/target-readonly.json").read_text(encoding="utf-8"))
    bucket_statement = next(
        statement for statement in policy["Statement"] if statement.get("Sid") == "AuditorReadBuckets"
    )

    assert bucket_statement["Condition"]["StringEquals"]["aws:ResourceAccount"] == "${demo_account_id}"


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
            action.startswith(
                ("s3:Put", "s3:Delete", "dynamodb:Put", "dynamodb:Update", "dynamodb:Delete", "iam:")
            )
            for action in actions
        )
        assert "${private_bucket_arn}" not in json.dumps(policy)
        assert "${private_table_arn}" not in json.dumps(policy)
    rin_policy = json.loads((ROOT / "infra/phase3/policies/rin-readonly.json").read_text(encoding="utf-8"))
    assert "lambda:InvokeFunction" in _actions(rin_policy)


def test_rin_bedrock_guardrail_permission_is_exact_and_requires_live_configuration():
    policy = json.loads((ROOT / "infra/phase3/policies/rin-guardrail.json").read_text(encoding="utf-8"))
    statement = policy["Statement"][0]
    stage3 = (ROOT / "infra/phase3/control-plane/stage3.tf").read_text(encoding="utf-8")
    variables = (ROOT / "infra/phase3/control-plane/variables.tf").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")

    assert _actions(policy) == {"bedrock:ApplyGuardrail"}
    assert statement["Resource"] == "${guardrail_arn}"
    assert re.search(r"count\s*=\s*var\.enable_stage3\s*&&\s*var\.rin_enabled\s*\?\s*1\s*:\s*0", stage3)
    assert re.search(r'name\s*=\s*"ApplyOnlyTheApprovedRinGuardrail"', stage3)
    assert 'var.rin_guardrail_arn != ""' in variables
    assert "var.rin_guardrail_version" in variables
    assert "data.aws_caller_identity.current.account_id" in stage3
    assert "var.aws_region" in stage3
    assert "PHASE3_RIN_GUARDRAIL_ARN" in stage3
    assert "PHASE3_RIN_GUARDRAIL_VERSION" in stage3
    assert "TF_VAR_rin_guardrail_arn" in workflow
    assert "TF_VAR_rin_guardrail_version" in workflow


def test_quota_and_kill_switch_write_roles_cannot_touch_other_tables():
    quota = json.loads((ROOT / "infra/phase3/policies/rin-quota-writer.json").read_text(encoding="utf-8"))
    kill_switch = json.loads(
        (ROOT / "infra/phase3/policies/rin-kill-switch.json").read_text(encoding="utf-8")
    )

    assert _actions(quota) == {"dynamodb:UpdateItem"}
    assert quota["Statement"][0]["Resource"] == "${quota_table_arn}"
    assert _actions(kill_switch) == {"dynamodb:UpdateItem"}
    assert kill_switch["Statement"][0]["Resource"] == "${feature_table_arn}"
    assert kill_switch["Statement"][0]["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == [
        "PLATFORM"
    ]
    assert set(
        kill_switch["Statement"][0]["Condition"]["ForAllValues:StringLike"]["dynamodb:Attributes"]
    ) == {"pk", "sk", "rin_enabled", "static_mode"}


def test_public_publisher_reads_private_only_and_writes_only_isolated_public_results():
    policy = json.loads(
        (ROOT / "infra/phase3/policies/public-publisher-runtime.json").read_text(encoding="utf-8")
    )
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
    assert re.search(r"alarm_actions\s*=\s*\[aws_sns_topic\.rin_daily_alert\[0\]\.arn\]", stage3)
    assert "alarm_actions       = [aws_sns_topic.budget_kill[0].arn]" not in stage4


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
    assert "s3:::${var.bucket_prefix}-p3-demo-a-${var.demo_account_id}" in bootstrap
    assert "s3:::${var.bucket_prefix}-p3-demo-b-${var.demo_account_id}" in bootstrap


def test_target_role_apply_permissions_cannot_escalate_its_read_only_boundary():
    bootstrap = (ROOT / "infra/phase3/demo-bootstrap/main.tf").read_text(encoding="utf-8")
    demo_account = (ROOT / "infra/phase3/demo-account/main.tf").read_text(encoding="utf-8")

    assert '"iam:PolicyARN" = local.target_policy_arn' in bootstrap
    assert '"iam:PermissionsBoundary" = local.target_policy_arn' in bootstrap
    assert "permissions_boundary = aws_iam_policy.target_readonly.arn" in demo_account
    for action in ("iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicyVersion"):
        assert action not in bootstrap


def test_target_readonly_boundary_explicitly_denies_every_action_outside_its_read_allowlist():
    policy = json.loads((ROOT / "infra/phase3/policies/target-readonly.json").read_text(encoding="utf-8"))
    deny_statement = next(
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") == "DenyEveryActionOutsideTheExplicitReadOnlyAllowlist"
    )
    allow_actions = set().union(
        *(
            set(statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]])
            for statement in policy["Statement"]
            if statement.get("Effect") == "Allow"
        )
    )

    assert deny_statement["NotAction"] == sorted(allow_actions)
    assert deny_statement["Resource"] == "*"


def test_foreign_s3_resource_policy_grant_is_overridden_by_explicit_resource_account_deny():
    policy = json.loads((ROOT / "infra/phase3/policies/target-readonly.json").read_text(encoding="utf-8"))
    bucket_allow = next(
        statement for statement in policy["Statement"] if statement.get("Sid") == "AuditorReadBuckets"
    )
    foreign_resource_policy_grant = {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetBucketPolicy",
        "Resource": "arn:aws:s3:::foreign-account-bucket",
        "Condition": {
            "ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly"}
        },
    }
    foreign_account_id = "210987654321"
    demo_account_condition = bucket_allow["Condition"]["StringEquals"]["aws:ResourceAccount"]
    demo_account_id = foreign_resource_policy_grant["Condition"]["ArnEquals"]["aws:PrincipalArn"].split(":")[
        4
    ]
    foreign_account_deny = next(
        statement
        for statement in policy["Statement"]
        if statement.get("Sid") == "DenyS3MetadataReadsOutsideDemoAccount"
    )

    assert foreign_resource_policy_grant == {
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetBucketPolicy",
        "Resource": "arn:aws:s3:::foreign-account-bucket",
        "Condition": {
            "ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/AccountAccessAuditorReadOnly"}
        },
    }
    assert foreign_resource_policy_grant["Action"] in bucket_allow["Action"]
    assert demo_account_condition == "${demo_account_id}"
    assert foreign_account_id != demo_account_id
    assert foreign_account_deny["Effect"] == "Deny"
    assert foreign_account_deny["Action"] == sorted(bucket_allow["Action"])
    assert foreign_account_deny["Resource"] == "arn:aws:s3:::*"
    assert foreign_account_deny["Condition"] == {
        "StringNotEquals": {"aws:ResourceAccount": "${demo_account_id}"}
    }


def test_privileged_phase3_workflows_pin_every_external_action_to_a_full_sha():
    for workflow_name in ("phase3-terraform.yml", "phase3-scan-image.yml"):
        workflow = (ROOT / ".github/workflows" / workflow_name).read_text(encoding="utf-8")
        for line in workflow.splitlines():
            if re.search(r"\buses:\s*", line):
                assert re.search(r"uses:\s*[^@\s]+@[0-9a-f]{40}\s+#\s+v\d", line), (
                    f"{workflow_name} has a mutable or undocumented action ref: {line.strip()}"
                )


def test_phase3_terraform_workflow_only_sets_declared_terraform_variables():
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")
    workflow_variables = set(re.findall(r"(?m)^\s+TF_VAR_([A-Za-z_][A-Za-z0-9_]*):", workflow))
    declared_variables = set()
    for terraform_file in (ROOT / "infra/phase3").rglob("*.tf"):
        declared_variables.update(
            re.findall(r'\bvariable\s+"([A-Za-z_][A-Za-z0-9_]*)"', terraform_file.read_text(encoding="utf-8"))
        )

    undeclared_variables = workflow_variables - declared_variables
    assert not undeclared_variables, (
        f"Workflow sets undeclared Terraform variables: {sorted(undeclared_variables)}"
    )


def test_stage_two_provider_input_budget_covers_all_billable_input_tokens():
    variables = (ROOT / "infra/phase3/control-plane/variables.tf").read_text(encoding="utf-8")
    stage3 = (ROOT / "infra/phase3/control-plane/stage3.tf").read_text(encoding="utf-8")

    assert "including the system instructions" in variables
    assert "var.rin_max_input_tokens * coalesce(var.rin_input_cost_per_million_tokens_usd, 0)" in stage3


def test_control_plane_stage_enables_require_checked_in_predecessor_acceptance_evidence():
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")
    control_plane = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "infra/phase3/control-plane").glob("*.tf"))
    )

    assert "validate_phase3_stage_gates.py" in workflow
    assert 'terraform_data" "phase3_stage_acceptance_gate' in control_plane
    assert "docs/evidence/phase3-stage-acceptance.json" in control_plane
    assert "phase3_stage_acceptance.schema_version == 3" in control_plane
    assert "phase3_stage1.evidence_sha256[evidence_path]" in control_plane
    assert "phase3_stage2.evidence_sha256[evidence_path]" in control_plane
    assert "phase3_stage3.evidence_sha256[evidence_path]" in control_plane
    assert "phase3_stage1_evidence_valid" in control_plane
    assert "phase3_stage2_evidence_valid" in control_plane
    assert "phase3_stage3_runtime_evidence_valid" in control_plane
    assert "phase3_stage3_quota_fallbacks.daily_invocation_limit == local.rin_daily_cap" in control_plane
    assert (
        "phase3_stage3_quota_fallbacks.monthly_budget_usd == var.provider_monthly_budget_usd" in control_plane
    )
    assert "phase3_stage1_scans.target_account_id_sha256 == sha256(var.demo_account_id)" in control_plane
    assert "phase3_stage1_scans.schedule_execution_log_sha256 == filesha256" in control_plane
    assert '"stage1/schedule-execution-log.json"' in control_plane
    assert (
        "execution.snapshot_sha256 == local.phase3_stage1_scans.scans[index].snapshot_sha256" in control_plane
    )
    assert "execution.workflow_started_at" in control_plane
    assert (
        "length(distinct([for case in local.phase3_stage3_rin_evaluation.cases : case.case_id]))"
        in control_plane
    )
    assert "contains(local.phase3_stage3_required_rin_categories, case.category)" in control_plane
    assert 'regex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", run.scan_run_id)' in control_plane
    assert 'timeadd(execution.scheduled_at, "1h")' in control_plane
    assert (
        'timeadd(local.phase3_stage1_schedule_log.scheduled_executions[0].scheduled_at, "6h")'
        in control_plane
    )
    assert "length(distinct(local.phase3_stage1_drift.new_finding_ids))" in control_plane
    assert '"kill_switch_static_mode"' in control_plane
    assert "can(tolist(local.phase3_stage1_role.effective_write_actions))" in control_plane
    assert "can(tolist(local.phase3_stage2_redaction.failed_case_ids))" in control_plane
    assert "length(distinct(local.phase3_stage2_redaction.passed_case_categories))" in control_plane
    assert 'can(regex("^\\".*\\"$", jsonencode(category)))' in control_plane
    assert (
        "can(tolist(local.phase3_stage3_privacy_accessibility.unapproved_third_party_requests))"
        in control_plane
    )
    assert "timecmp(local.phase3_stage1_scans.scans[0].completed_at" in control_plane
    assert "published_guardrail_policy_review == true" in control_plane
    assert "bedrock_invocation_logging_review == true" in control_plane
    assert '"stage3/guardrail-policy-review.json"' in control_plane
    assert '"stage3/bedrock-logging-review.json"' in control_plane
    assert '"stage3/transport-security.json"' in control_plane
    assert '"stage3/external-tls-scan.json"' in control_plane
    assert '"stage3/privacy-accessibility.json"' in control_plane
    assert '"stage3/rin-evaluation.json"' in control_plane
    assert '"stage3/quota-fallbacks.json"' in control_plane
    assert '"stage3/failure-banners.json"' in control_plane
    assert '"stage3/guardrail-configuration.json"' in control_plane
    assert '"stage3/guardrail-evaluation.json"' in control_plane
    assert '"stage3/bedrock-logging-settings.json"' in control_plane
    assert '"stage3/external-provider-logging-settings.json"' in control_plane
    assert "phase3_stage3_reviews_valid" in control_plane
    assert "configuration_sha256" in control_plane
    assert "filesha256(" in control_plane
    assert "maximum_prompt_retention_days" in control_plane
    assert "maximum_prompt_retention_days <= 30" in control_plane
    assert "includes_prompt_content" in control_plane
    assert "phase3_stage3_guardrail_configuration.input_controls ==" in control_plane
    assert 'case.observed_action == "BLOCK"' in control_plane
    assert "phase3_stage3_bedrock_logging.includes_prompt_content ==" in control_plane
    assert "phase3_stage3_external_logging.retention_days ==" in control_plane
    assert "phase3_stage3_guardrail_review.guardrail_arn == var.rin_guardrail_arn" in control_plane
    assert "phase3_stage3_guardrail_review.published_version == var.rin_guardrail_version" in control_plane
    assert (
        "exact Guardrail ARN and published version covered by the reviewed Stage 3 evidence" in control_plane
    )
    assert "floor(local.phase3_stage3_guardrail_review.evaluation.case_count)" in control_plane
    assert (
        "logging.includes_prompt_content == true || logging.includes_prompt_content == false" in control_plane
    )
    assert "floor(logging.retention_days) == logging.retention_days" in control_plane


def test_owner_provisioned_role_evidence_is_checked_before_oidc_in_plan_and_apply_jobs():
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")
    plan_job, apply_job = workflow.split("\n  apply:", 1)

    for job in (plan_job, apply_job):
        assert "validate_phase3_role_evidence.py" in job
        assert job.index("validate_phase3_role_evidence.py") < job.index(
            "aws-actions/configure-aws-credentials@"
        )
    assert "--phase plan" in plan_job
    assert "--phase apply" in apply_job


def test_stage1_scan_uses_step_functions_and_an_ecs_fargate_task():
    stage1 = (ROOT / "infra/phase3/control-plane/stage1.tf").read_text(encoding="utf-8")

    assert 'resource "aws_ecs_cluster" "scan"' in stage1
    assert 'resource "aws_ecs_task_definition" "scan"' in stage1
    assert "states:::ecs:runTask.sync" in stage1
    assert re.search(r'LaunchType\s*=\s*"FARGATE"', stage1)
    assert 'resource "aws_lambda_function" "scan_worker"' not in stage1
    assert "GetScanReceipt = {" in stage1
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
    assert re.search(
        r'github_apply_subject\s*=\s*"repo:\$\{var\.github_repository\}:environment:\$\{var\.github_apply_environment\}"',
        bootstrap,
    )
    assert "token.actions.githubusercontent.com:ref" in bootstrap
    assert 'token.actions.githubusercontent.com:workflow" = "Phase 3 Terraform"' in bootstrap
    assert 'Action   = ["s3:GetObject"]' in bootstrap
    assert 'Action   = ["s3:GetObject", "s3:PutObject"]' in bootstrap
    assert '"s3:DeleteObject"' not in bootstrap


def test_control_plane_workflow_builds_lambda_and_web_assets_before_terraform_plan():
    workflow = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")

    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0" in workflow
    assert 'python-version: "3.12"' in workflow
    assert "python scripts/package_phase3_lambdas.py" in workflow
    assert "python scripts/build_phase3_web.py" in workflow
    assert workflow.index("Build Phase 3 Lambda and web assets") < workflow.index("Plan the selected stack")
    assert workflow.count("phase3-control-plane-assets-${{ github.run_id }}-${{ github.run_attempt }}") == 2
    assert "build/phase3/lambda.zip" in workflow
    assert "build/phase3/web/**" in workflow
    assert "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0" in workflow
    assert "path: build/phase3" in workflow
    assert "sha256sum --check lambda.zip.sha256 web.sha256" in workflow
    assert workflow.index("Verify the exact control-plane assets") < workflow.index(
        "Apply only the reviewed plan"
    )


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
    assert 'resource "aws_s3_bucket_versioning" "demo_a"' in demo_stack
    assert 'resource "aws_s3_bucket_versioning" "demo_b"' in demo_stack
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
    assert "Resource = aws_ecr_repository.scan.arn" in stage1
    assert "sts:AssumeRoleWithWebIdentity" in stage1
    assert 'data "aws_iam_openid_connect_provider" "github"' in stage1
    assert 'resource "aws_iam_openid_connect_provider" "github"' not in stage1
    assert 'token.actions.githubusercontent.com:workflow" = "Phase 3 scan image"' in stage1
    assert "cosign sign --yes" in workflow
    assert "cosign verify" in workflow
    assert "steps.build.outputs.digest" in workflow


def test_bootstrap_stack_uses_a_named_limited_role_instead_of_account_admin():
    bootstrap = (ROOT / "infra/phase3/demo-bootstrap/main.tf").read_text(encoding="utf-8")
    plan_policy = json.loads(
        (ROOT / "infra/phase3/policies/demo-bootstrap-plan.json").read_text(encoding="utf-8")
    )
    apply_policy = json.loads(
        (ROOT / "infra/phase3/policies/demo-bootstrap-apply.json").read_text(encoding="utf-8")
    )
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
    assert _actions(apply_policy) - _actions(plan_policy) <= {
        "iam:CreateRole",
        "iam:UpdateAssumeRolePolicy",
        "iam:TagRole",
        "iam:UntagRole",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "s3:PutObject",
    }
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
    assert '"AssumeOnlyTheDemoReadOnlyRole"' in (
        ROOT / "infra/phase3/policies/scan-worker-runtime.json"
    ).read_text(encoding="utf-8")
    assert (
        '"dynamodb:PutItem"'
        not in stage1.split('resource "aws_iam_role_policy" "scan_task_assume_target"')[1].split("resource")[
            0
        ]
    )
    assert (
        '"s3:PutObject"'
        not in stage1.split('resource "aws_iam_role_policy" "scan_task_assume_target"')[1].split("resource")[
            0
        ]
    )


def test_demo_account_terraform_uses_encrypted_remote_state_and_is_in_ci_validation():
    versions = (ROOT / "infra/phase3/demo-account/versions.tf").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    deploy = (ROOT / ".github/workflows/phase3-terraform.yml").read_text(encoding="utf-8")

    assert 'backend "s3" {}' in versions
    assert "infra/phase3/demo-account" in workflow
    assert 'backend-config="encrypt=true"' in deploy
    assert "TF_VAR_scan_task_role_arn" in deploy


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


def test_console_scripts_are_served_as_javascript():
    stage3 = (ROOT / "infra/phase3/control-plane/stage3.tf").read_text(encoding="utf-8")

    for script in ("console.js", "status.js", "knowledge.js", "auth.js"):
        assert re.search(rf'"{re.escape(script)}"\s*=\s*"text/javascript; charset=utf-8"', stage3), script
