data "aws_partition" "current" {}

locals {
  demo_account_id          = aws_organizations_account.demo.id
  trail_bucket_arn         = "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_prefix}-p3-trail-${local.demo_account_id}"
  trail_arn                = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${local.demo_account_id}:trail/${var.bucket_prefix}-phase3-demo-management"
  target_role_arn          = "arn:${data.aws_partition.current.partition}:iam::${local.demo_account_id}:role/AccountAccessAuditorReadOnly"
  target_policy_arn        = "arn:${data.aws_partition.current.partition}:iam::${local.demo_account_id}:policy/AccountAccessAuditorReadOnly"
  terraform_plan_role_arn  = "arn:${data.aws_partition.current.partition}:iam::${local.demo_account_id}:role/Phase3DemoTerraformPlan"
  terraform_apply_role_arn = "arn:${data.aws_partition.current.partition}:iam::${local.demo_account_id}:role/Phase3DemoTerraformApply"
  bootstrap_plan_role_arn  = "arn:${data.aws_partition.current.partition}:iam::${local.demo_account_id}:role/Phase3DemoBootstrapPlan"
  bootstrap_apply_role_arn = "arn:${data.aws_partition.current.partition}:iam::${local.demo_account_id}:role/Phase3DemoBootstrapApply"
}

resource "aws_organizations_organizational_unit" "demo" {
  name      = var.demo_ou_name
  parent_id = var.organization_root_id

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_account" "demo" {
  name                       = var.demo_account_name
  email                      = var.demo_account_email
  parent_id                  = aws_organizations_organizational_unit.demo.id
  role_name                  = "OrganizationAccountAccessRole"
  iam_user_access_to_billing = "DENY"
  close_on_deletion          = false

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_policy" "demo_guardrails" {
  name        = "GuardrailsPhase3DemoS3ExposureGuardrail"
  description = "Restricts demo data exposure, interactive credentials, unmanaged roles, costly services, and CloudTrail changes."
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyBucketPolicyAndAclExposure"
        Effect = "Deny"
        Action = ["s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:PutObjectAcl"]
        NotResource = [
          local.trail_bucket_arn,
          "${local.trail_bucket_arn}/*"
        ]
      },
      {
        Sid    = "DenyUnapprovedCostlyResources"
        Effect = "Deny"
        Action = [
          "ec2:RunInstances",
          "ec2:CreateFleet",
          "ec2:CreateSpotFleet",
          "ec2:RequestSpotInstances",
          "ec2:CreateNatGateway",
          "ec2:AllocateAddress",
          "ec2:CreateVolume",
          "ec2:CreateSnapshot",
          "ec2:CreateSnapshots",
          "rds:CreateDBInstance",
          "rds:CreateDBCluster",
          "eks:CreateCluster",
          "ecs:CreateCluster",
          "ecs:CreateService",
          "ecs:RunTask",
          "elasticache:CreateCacheCluster",
          "elasticache:CreateReplicationGroup",
          "elasticmapreduce:RunJobFlow",
          "redshift:CreateCluster",
          "sagemaker:Create*",
          "opensearch:CreateDomain",
          "batch:CreateComputeEnvironment",
          "batch:SubmitJob",
          "glue:CreateJob",
          "glue:StartJobRun",
          "glue:CreateCrawler",
          "glue:StartCrawler",
          "lambda:CreateFunction",
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream",
          "bedrock:CreateProvisionedModelThroughput"
        ]
        Resource = "*"
      },
      {
        Sid      = "DenyInteractiveUsersAndCredentials"
        Effect   = "Deny"
        Action   = ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
        Resource = "*"
      },
      {
        Sid    = "DenyUnapprovedRoleChanges"
        Effect = "Deny"
        Action = [
          "iam:CreateRole",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy"
        ]
        NotResource = [local.target_role_arn, local.terraform_plan_role_arn, local.terraform_apply_role_arn, local.bootstrap_plan_role_arn, local.bootstrap_apply_role_arn]
      },
      {
        Sid         = "DenyUnapprovedInlineRolePolicies"
        Effect      = "Deny"
        Action      = ["iam:PutRolePolicy", "iam:DeleteRolePolicy"]
        NotResource = [local.terraform_plan_role_arn, local.terraform_apply_role_arn, local.bootstrap_plan_role_arn, local.bootstrap_apply_role_arn]
      },
      {
        Sid         = "DenyRoleTrustChangesOutsideBootstrapRoles"
        Effect      = "Deny"
        Action      = "iam:UpdateAssumeRolePolicy"
        NotResource = [local.terraform_plan_role_arn, local.terraform_apply_role_arn, local.bootstrap_plan_role_arn, local.bootstrap_apply_role_arn]
      },
      {
        Sid      = "DenyRoleDeletion"
        Effect   = "Deny"
        Action   = "iam:DeleteRole"
        Resource = "*"
      },
      {
        Sid    = "DenyUnapprovedPolicyChanges"
        Effect = "Deny"
        Action = [
          "iam:CreatePolicy",
          "iam:CreatePolicyVersion",
          "iam:SetDefaultPolicyVersion",
          "iam:DeletePolicyVersion"
        ]
        NotResource = [local.target_policy_arn]
      },
      {
        Sid      = "DenyManagedPolicyDeletion"
        Effect   = "Deny"
        Action   = "iam:DeletePolicy"
        Resource = "*"
      },
      {
        Sid      = "DenyRoleDelegation"
        Effect   = "Deny"
        Action   = "iam:PassRole"
        Resource = "*"
      },
      {
        Sid         = "DenyUnapprovedCloudTrailCreation"
        Effect      = "Deny"
        Action      = ["cloudtrail:CreateTrail", "cloudtrail:StartLogging"]
        NotResource = [local.trail_arn]
      },
      {
        Sid    = "ProtectDemoAccountCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors"
        ]
        Resource = [local.trail_arn]
      }
    ]
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_organizations_policy_attachment" "demo_guardrails" {
  policy_id = aws_organizations_policy.demo_guardrails.id
  target_id = aws_organizations_organizational_unit.demo.id

  lifecycle {
    prevent_destroy = true
  }
}
