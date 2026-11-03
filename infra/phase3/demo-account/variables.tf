variable "aws_region" {
  description = "Region for the demo account's Terraform resources and CloudTrail home region."
  type        = string
  default     = "us-east-1"
}

variable "bucket_prefix" {
  description = "Owner-selected globally unique lowercase prefix used by Phase 3 demo resources."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,20}$", var.bucket_prefix))
    error_message = "bucket_prefix must be 3-21 lowercase letters, numbers, or hyphens."
  }
}

variable "scan_task_role_arn" {
  description = "Exact control-plane ECS task role allowed to assume the named read-only target role."
  type        = string
  validation {
    condition     = can(regex("^arn:[^:]+:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$", var.scan_task_role_arn))
    error_message = "scan_task_role_arn must be a valid IAM role ARN."
  }
}
