variable "aws_region" {
  description = "Region for the demo-account bootstrap role."
  type        = string
  default     = "us-east-1"
}

variable "demo_account_id" {
  description = "Dedicated account ID output by the Phase 3 Organizations stack."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.demo_account_id))
    error_message = "demo_account_id must be a 12-digit AWS account ID."
  }
}

variable "bucket_prefix" {
  description = "Same globally unique prefix used in the control-plane stack."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,20}$", var.bucket_prefix))
    error_message = "bucket_prefix must be 3-21 lowercase letters, numbers, or hyphens."
  }
}

variable "github_repository" {
  description = "Exact GitHub repository allowed by the deployment OIDC trust policies."
  type        = string
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be an exact owner/repository pair."
  }
}

variable "github_ref" {
  description = "Only this protected branch may obtain Phase 3 demo Terraform credentials."
  type        = string
  default     = "refs/heads/main"
}

variable "github_plan_environment" {
  description = "GitHub environment used by the read-only plan job."
  type        = string
  default     = "phase3-demo-account-plan"
}

variable "github_apply_environment" {
  description = "GitHub environment with required reviewers for applying demo-account Terraform."
  type        = string
  default     = "phase3-demo-account-apply"
}

variable "terraform_state_bucket_arn" {
  description = "Owner-selected encrypted remote state bucket ARN for the demo-account stack."
  type        = string
  validation {
    condition     = can(regex("^arn:[^:]+:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.terraform_state_bucket_arn))
    error_message = "terraform_state_bucket_arn must identify one S3 bucket."
  }
}

variable "terraform_state_object_arn" {
  description = "Exact state object ARN under the owner-selected bucket."
  type        = string
  validation {
    condition     = can(regex("^arn:[^:]+:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/phase3/demo-account/terraform.tfstate$", var.terraform_state_object_arn))
    error_message = "terraform_state_object_arn must be the fixed demo-account state object."
  }
}

variable "terraform_state_lock_table_arn" {
  description = "Exact DynamoDB lock-table ARN for the owner-selected Terraform state."
  type        = string
  validation {
    condition     = can(regex("^arn:[^:]+:dynamodb:[^:]+:[0-9]{12}:table/[A-Za-z0-9_.-]+$", var.terraform_state_lock_table_arn))
    error_message = "terraform_state_lock_table_arn must identify one DynamoDB table."
  }
}
