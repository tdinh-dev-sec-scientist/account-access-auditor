data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

locals {
  demo_a_bucket_name = "${var.bucket_prefix}-p3-demo-a-${data.aws_caller_identity.current.account_id}"
  demo_b_bucket_name = "${var.bucket_prefix}-p3-demo-b-${data.aws_caller_identity.current.account_id}"
  trail_bucket_name  = "${var.bucket_prefix}-p3-trail-${data.aws_caller_identity.current.account_id}"
  trail_name         = "${var.bucket_prefix}-phase3-demo-management"
  trail_s3_prefix    = "management"
  trail_arn          = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/${local.trail_name}"
}

resource "aws_s3_account_public_access_block" "demo" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_iam_role" "target_readonly" {
  name = "AccountAccessAuditorReadOnly"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "OnlyThePhase3FargateTaskMayAssumeThisRole"
      Effect    = "Allow"
      Principal = { AWS = var.scan_task_role_arn }
      Action    = "sts:AssumeRole"
    }]
  })
  max_session_duration = 3600

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_policy" "target_readonly" {
  name = "AccountAccessAuditorReadOnly"
  policy = templatefile("${path.module}/../policies/target-readonly.json", {
    demo_account_id = data.aws_caller_identity.current.account_id
  })

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_iam_role_policy_attachment" "target_readonly" {
  role       = aws_iam_role.target_readonly.name
  policy_arn = aws_iam_policy.target_readonly.arn
}

resource "aws_s3_bucket" "demo_a" {
  bucket        = local.demo_a_bucket_name
  force_destroy = false

  tags = { project = "guardrails-phase3" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "demo_b" {
  bucket        = local.demo_b_bucket_name
  force_destroy = false

  tags = { project = "guardrails-phase3" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "demo_a" {
  bucket = aws_s3_bucket.demo_a.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "demo_b" {
  bucket = aws_s3_bucket.demo_b.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "demo_a" {
  bucket = aws_s3_bucket.demo_a.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_ownership_controls" "demo_b" {
  bucket = aws_s3_bucket.demo_b.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

# Intentional but non-exposing drift: account-level protection remains on,
# bucket A has two disabled controls, and the SCP prevents public ACL/policy writes.
resource "aws_s3_bucket_public_access_block" "demo_a" {
  bucket                  = aws_s3_bucket.demo_a.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = false
  restrict_public_buckets = false
  depends_on              = [aws_s3_account_public_access_block.demo]
}

resource "aws_s3_bucket_public_access_block" "demo_b" {
  bucket                  = aws_s3_bucket.demo_b.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
  depends_on              = [aws_s3_account_public_access_block.demo]
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.trail_bucket_name
  force_destroy = false
  tags          = { project = "guardrails-phase3" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    id     = "ExpireManagementLogsAndOldVersions"
    status = "Enabled"
    filter { prefix = "${local.trail_s3_prefix}/" }
    expiration { days = 30 }
    noncurrent_version_expiration { noncurrent_days = 7 }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudTrailToVerifyLogBucket"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "AllowCloudTrailToWriteOnlyThisAccountLogs"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/${local.trail_s3_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      }
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}

resource "aws_cloudtrail" "demo" {
  # Without explicit selectors CloudTrail defaults to read/write management
  # events and no data events; the OU policy blocks later selector changes.
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.bucket
  s3_key_prefix                 = local.trail_s3_prefix
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  lifecycle {
    prevent_destroy = true
  }
}
