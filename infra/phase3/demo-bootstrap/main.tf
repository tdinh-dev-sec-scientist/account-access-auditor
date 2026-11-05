data "aws_partition" "current" {}

locals {
  github_plan_subject      = "repo:${var.github_subject_repository}:environment:${var.github_plan_environment}"
  github_apply_subject     = "repo:${var.github_subject_repository}:environment:${var.github_apply_environment}"
  github_oidc_provider_arn = "arn:${data.aws_partition.current.partition}:iam::${var.demo_account_id}:oidc-provider/token.actions.githubusercontent.com"
  demo_bucket_arns = [
    "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_prefix}-p3-demo-a-${var.demo_account_id}",
    "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_prefix}-p3-demo-b-${var.demo_account_id}",
    "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_prefix}-p3-trail-${var.demo_account_id}",
  ]
  demo_object_arns  = [for arn in local.demo_bucket_arns : "${arn}/*"]
  target_role_arn   = "arn:${data.aws_partition.current.partition}:iam::${var.demo_account_id}:role/AccountAccessAuditorReadOnly"
  target_policy_arn = "arn:${data.aws_partition.current.partition}:iam::${var.demo_account_id}:policy/AccountAccessAuditorReadOnly"
  trail_arn         = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${var.demo_account_id}:trail/${var.bucket_prefix}-phase3-demo-management"
}

data "aws_iam_openid_connect_provider" "github" {
  arn = local.github_oidc_provider_arn
}

resource "aws_iam_role" "terraform_plan" {
  name = "Phase3DemoTerraformPlan"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "token.actions.githubusercontent.com:aud"      = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub"      = local.github_plan_subject
        "token.actions.githubusercontent.com:ref"      = var.github_ref
        "token.actions.githubusercontent.com:workflow" = "Phase 3 Terraform"
      } }
    }]
  })
  max_session_duration = 3600
}

resource "aws_iam_role" "terraform_apply" {
  name = "Phase3DemoTerraformApply"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "token.actions.githubusercontent.com:aud"      = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub"      = local.github_apply_subject
        "token.actions.githubusercontent.com:ref"      = var.github_ref
        "token.actions.githubusercontent.com:workflow" = "Phase 3 Terraform"
      } }
    }]
  })
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "terraform_plan" {
  name = "ReadDemoTerraformResourcesAndScopedState"
  role = aws_iam_role.terraform_plan.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyNamedDemoBucketTerraformState"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketTagging",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketOwnershipControls",
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
          "s3:GetBucketObjectLockConfiguration"
        ]
        Resource = local.demo_bucket_arns
      },
      {
        Sid      = "ReadOnlyPhase3TargetRole"
        Effect   = "Allow"
        Action   = ["iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"]
        Resource = local.target_role_arn
      },
      {
        Sid      = "ReadOnlyPhase3TargetPolicy"
        Effect   = "Allow"
        Action   = ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"]
        Resource = local.target_policy_arn
      },
      {
        Sid      = "ReadOnlyPhase3CloudTrail"
        Effect   = "Allow"
        Action   = ["cloudtrail:GetTrail", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors", "cloudtrail:GetInsightSelectors", "cloudtrail:ListTags"]
        Resource = local.trail_arn
      },
      {
        Sid      = "ListCloudTrailsForTerraformRefresh"
        Effect   = "Allow"
        Action   = ["cloudtrail:ListTrails", "cloudtrail:DescribeTrails"]
        Resource = "*"
      },
      {
        Sid      = "ReadAccountPublicAccessBlock"
        Effect   = "Allow"
        Action   = "s3:GetAccountPublicAccessBlock"
        Resource = "*"
      },
      {
        Sid      = "UseOnlyOwnerSelectedTerraformStateBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketVersioning"]
        Resource = var.terraform_state_bucket_arn
      },
      {
        Sid      = "UseOnlyDemoTerraformStateObject"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = var.terraform_state_object_arn
      },
      {
        Sid      = "LockOnlyOwnerSelectedTerraformState"
        Effect   = "Allow"
        Action   = ["dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = var.terraform_state_lock_table_arn
      }
    ]
  })
}

resource "aws_iam_role_policy" "terraform_apply" {
  name = "ManageOnlyPhase3DemoResourcesAndScopedState"
  role = aws_iam_role.terraform_apply.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyNamedDemoBucketTerraformState"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetBucketTagging",
          "s3:GetBucketPublicAccessBlock",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketOwnershipControls",
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
          "s3:GetBucketObjectLockConfiguration"
        ]
        Resource = local.demo_bucket_arns
      },
      {
        Sid      = "ReadOnlyPhase3TargetRole"
        Effect   = "Allow"
        Action   = ["iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies"]
        Resource = local.target_role_arn
      },
      {
        Sid      = "ReadOnlyPhase3TargetPolicy"
        Effect   = "Allow"
        Action   = ["iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListPolicyVersions"]
        Resource = local.target_policy_arn
      },
      {
        Sid      = "ReadOnlyPhase3CloudTrail"
        Effect   = "Allow"
        Action   = ["cloudtrail:GetTrail", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors", "cloudtrail:GetInsightSelectors", "cloudtrail:ListTags"]
        Resource = local.trail_arn
      },
      {
        Sid      = "ListCloudTrailsForTerraformRefresh"
        Effect   = "Allow"
        Action   = ["cloudtrail:ListTrails", "cloudtrail:DescribeTrails"]
        Resource = "*"
      },
      {
        Sid      = "ReadAccountPublicAccessBlock"
        Effect   = "Allow"
        Action   = ["s3:GetAccountPublicAccessBlock", "s3:PutAccountPublicAccessBlock"]
        Resource = "*"
      },
      {
        Sid    = "CreateAndSecureNamedDemoBuckets"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:PutBucketTagging",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketOwnershipControls",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutBucketVersioning",
          "s3:PutLifecycleConfiguration",
          "s3:PutBucketPolicy"
        ]
        Resource = concat(local.demo_bucket_arns, local.demo_object_arns)
      },
      {
        Sid      = "CreateTargetRoleWithReadOnlyPermissionsBoundary"
        Effect   = "Allow"
        Action   = "iam:CreateRole"
        Resource = local.target_role_arn
        Condition = {
          ArnEquals = {
            "iam:PermissionsBoundary" = local.target_policy_arn
          }
        }
      },
      {
        Sid      = "TagOnlyTargetReadonlyRole"
        Effect   = "Allow"
        Action   = ["iam:TagRole", "iam:UntagRole"]
        Resource = local.target_role_arn
      },
      {
        Sid      = "AttachOnlyTargetReadonlyPolicy"
        Effect   = "Allow"
        Action   = ["iam:AttachRolePolicy", "iam:DetachRolePolicy"]
        Resource = local.target_role_arn
        Condition = {
          ArnEquals = {
            "iam:PolicyARN" = local.target_policy_arn
          }
        }
      },
      {
        Sid    = "CreateOnlyNamedTargetReadonlyPolicy"
        Effect = "Allow"
        Action = [
          "iam:CreatePolicy",
          "iam:TagPolicy",
          "iam:UntagPolicy"
        ]
        Resource = local.target_policy_arn
      },
      {
        Sid      = "CreateAndStartOnlyDemoManagementTrail"
        Effect   = "Allow"
        Action   = ["cloudtrail:CreateTrail", "cloudtrail:StartLogging", "cloudtrail:AddTags"]
        Resource = local.trail_arn
      },
      {
        Sid      = "UseOnlyOwnerSelectedTerraformStateBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:GetBucketVersioning"]
        Resource = var.terraform_state_bucket_arn
      },
      {
        Sid      = "UseOnlyDemoTerraformStateObject"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = var.terraform_state_object_arn
      },
      {
        Sid      = "LockOnlyOwnerSelectedTerraformState"
        Effect   = "Allow"
        Action   = ["dynamodb:DescribeTable", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = var.terraform_state_lock_table_arn
      }
    ]
  })
}
