variable "aws_region" {
  description = "Region used for the management-plane Organizations API calls."
  type        = string
  default     = "us-east-1"
}

variable "demo_account_name" {
  description = "Display name of the isolated Phase 3 demo account."
  type        = string
  default     = "guardrails-phase3-demo"
}

variable "demo_account_email" {
  description = "Unique AWS Organizations account email supplied by the owner."
  type        = string
  sensitive   = true
}

variable "demo_ou_name" {
  description = "Name of the dedicated organizational unit for the demo account."
  type        = string
  default     = "GuardrailsPhase3Demo"
}

variable "bucket_prefix" {
  description = "Owner-selected lowercase prefix used to narrowly exempt the private CloudTrail log bucket from bucket-policy SCP denial."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,20}$", var.bucket_prefix))
    error_message = "bucket_prefix must be 3-21 lowercase letters, numbers, or hyphens."
  }
}

variable "organization_root_id" {
  description = "AWS Organizations root ID supplied after checking the target organization."
  type        = string
  validation {
    condition     = can(regex("^r-[a-z0-9]{4,32}$", var.organization_root_id))
    error_message = "organization_root_id must be a valid Organizations root ID."
  }
}
