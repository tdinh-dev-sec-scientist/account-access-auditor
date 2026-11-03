variable "aws_region" {
  description = "Control-plane region and default scan region."
  type        = string
  default     = "us-east-1"
}

variable "demo_account_id" {
  description = "Account ID output by the protected Phase 3 Organizations stack."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.demo_account_id))
    error_message = "demo_account_id must be a 12-digit AWS account ID."
  }
}


variable "bucket_prefix" {
  description = "Globally unique lowercase prefix used for the private and public result buckets."
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,20}$", var.bucket_prefix))
    error_message = "bucket_prefix must be 3-21 lowercase letters, numbers, or hyphens."
  }
}

variable "github_repository" {
  description = "Exact GitHub owner/repository allowed to publish a signed Phase 3 scan image."
  type        = string
  default     = "tdinh-dev-sec-scientist/account-access-auditor"
  validation {
    condition     = can(regex("^[a-z0-9_.-]+/[a-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must be a lowercase owner/repository pair."
  }
}

variable "github_image_environment" {
  description = "Protected GitHub environment used by the scan image publishing job."
  type        = string
  default     = "phase3-scan-image"
  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,64}$", var.github_image_environment))
    error_message = "github_image_environment must be a valid exact environment name."
  }
}

variable "lambda_package_path" {
  description = "Path to the Python 3.12 ZIP built by scripts/package_phase3_lambdas.py."
  type        = string
  default     = "../../../build/phase3/lambda.zip"
}

variable "web_asset_dir" {
  description = "Directory produced by scripts/build_phase3_web.py; contains only the sanitized console bundle."
  type        = string
  default     = "../../../build/phase3/web"
}

variable "scan_schedule_enabled" {
  description = "Enable the six-hour scan schedule after the Stage 1 target is reviewed."
  type        = bool
  default     = false
  validation {
    condition     = !var.scan_schedule_enabled || var.enable_scan_pipeline
    error_message = "The scan schedule cannot be enabled until the Fargate scan pipeline is enabled."
  }
}

variable "enable_scan_pipeline" {
  description = "Create Step Functions and EventBridge scan resources after the signed image is available."
  type        = bool
  default     = false
}

variable "scan_container_image" {
  description = "Exact ECR image digest from the verified Phase 3 scan image release workflow."
  type        = string
  default     = ""
  validation {
    condition = !var.enable_scan_pipeline || can(regex(
      "^[0-9]{12}[.]dkr[.]ecr[.][a-z0-9-]+[.]amazonaws[.]com/${var.bucket_prefix}/phase3-scan@sha256:[0-9a-f]{64}$",
      var.scan_container_image
    ))
    error_message = "Enabling scans requires an immutable ECR URI pinned to a SHA-256 digest in the configured repository."
  }
}

variable "monthly_budget_usd" {
  description = "Owner-set monthly AWS budget. Required to enable Phase 4 budget alerts."
  type        = number
  default     = null
  nullable    = true
  validation {
    condition     = var.monthly_budget_usd == null || var.monthly_budget_usd > 0
    error_message = "monthly_budget_usd must be positive when supplied."
  }
}

variable "aws_pricing_estimate_monthly_usd" {
  description = "Monthly AWS estimate recorded from the AWS Pricing Calculator before enabling Stage 2."
  type        = number
  default     = null
  nullable    = true
}

variable "aws_pricing_estimate_reference" {
  description = "Owner-reviewed calculator export or evidence reference for the Phase 3 AWS estimate."
  type        = string
  default     = ""
}

variable "provider_monthly_budget_usd" {
  description = "Owner-set external model budget tracked separately from AWS spend."
  type        = number
  default     = null
  nullable    = true
  validation {
    condition     = var.provider_monthly_budget_usd == null || var.provider_monthly_budget_usd > 0
    error_message = "provider_monthly_budget_usd must be positive when supplied."
  }
}

variable "budget_alert_email" {
  description = "Owner-managed recipient for the 50%, 80%, and 100% actual monthly AWS budget alerts."
  type        = string
  default     = ""
  validation {
    condition     = !var.enable_stage4 || can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.budget_alert_email))
    error_message = "Stage 4 requires a valid budget_alert_email for monthly spend notifications."
  }
}

variable "rin_enabled" {
  description = "Enable live provider-backed Rin only after secret, model, quotas, and budgets are configured."
  type        = bool
  default     = false
  validation {
    condition = !var.rin_enabled || (
      var.enable_stage3 && var.enable_stage4 && var.monthly_budget_usd != null &&
      var.provider_monthly_budget_usd != null && var.rin_model != "" &&
      var.rin_input_cost_per_million_tokens_usd != null && var.rin_output_cost_per_million_tokens_usd != null &&
      var.rin_input_cost_per_million_tokens_usd > 0 && var.rin_output_cost_per_million_tokens_usd > 0
    )
    error_message = "Live Rin requires Stage 3/4, owner AWS/provider budgets, an approved model, and explicit provider token rates."
  }
}

variable "rin_model" {
  description = "Explicit owner-approved external provider model identifier."
  type        = string
  default     = ""
}

variable "rin_input_cost_per_million_tokens_usd" {
  description = "Owner-verified current external model input token price used for conservative cost caps."
  type        = number
  default     = null
  nullable    = true
}

variable "rin_output_cost_per_million_tokens_usd" {
  description = "Owner-verified current external model output token price used for conservative cost caps."
  type        = number
  default     = null
  nullable    = true
}

variable "rin_max_input_tokens" {
  description = "Maximum estimated input-token budget for one evidence-only answer."
  type        = number
  default     = 4096
  validation {
    condition     = var.rin_max_input_tokens >= 512 && var.rin_max_input_tokens <= 8192
    error_message = "rin_max_input_tokens must be between 512 and 8192."
  }
}

variable "rin_max_output_tokens" {
  description = "Hard response-token cap for each Rin answer."
  type        = number
  default     = 600
  validation {
    condition     = var.rin_max_output_tokens >= 128 && var.rin_max_output_tokens <= 1200
    error_message = "rin_max_output_tokens must be between 128 and 1200."
  }
}

variable "enable_stage2" {
  description = "Create public redaction, publication, and read-only API resources after Stage 1 acceptance."
  type        = bool
  default     = false
  validation {
    condition = !var.enable_stage2 || (
      var.enable_scan_pipeline &&
      var.monthly_budget_usd != null &&
      var.aws_pricing_estimate_monthly_usd != null &&
      var.aws_pricing_estimate_monthly_usd > 0 &&
      var.monthly_budget_usd >= var.aws_pricing_estimate_monthly_usd &&
      trimspace(var.aws_pricing_estimate_reference) != ""
    )
    error_message = "Stage 2 requires an owner AWS cap that covers a recorded AWS Pricing Calculator estimate."
  }
}

variable "enable_stage3" {
  description = "Create CloudFront and Rin resources after Stage 2 acceptance."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_stage3 || var.enable_stage2
    error_message = "Stage 3 requires the Stage 2 public schema, publisher, and API resources."
  }
}

variable "enable_stage4" {
  description = "Create budget alarms and the kill-switch integration after launch inputs are set."
  type        = bool
  default     = false
  validation {
    condition     = !var.enable_stage4 || (var.enable_stage2 && var.enable_stage3 && var.monthly_budget_usd != null)
    error_message = "Stage 4 requires Stages 2/3 and an owner-set monthly AWS budget."
  }
}

variable "domain_name" {
  description = "Optional custom domain. Leave empty to use the CloudFront default domain."
  type        = string
  default     = ""
  validation {
    condition     = var.domain_name == "" || (var.hosted_zone_id != "" && can(regex("^arn:[^:]+:acm:us-east-1:[0-9]{12}:certificate/.+$", var.certificate_arn)))
    error_message = "A custom domain requires its hosted zone and an ACM certificate ARN in us-east-1."
  }
}

variable "hosted_zone_id" {
  description = "Required only when a custom domain is configured."
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ACM certificate in us-east-1. Not required for the CloudFront default domain."
  type        = string
  default     = ""
}
