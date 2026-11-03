output "target_readonly_role_arn" {
  description = "Read-only target role assumed by the dedicated Phase 3 Fargate scan task."
  value       = aws_iam_role.target_readonly.arn
}

output "demo_bucket_names" {
  description = "Empty demo buckets containing intentionally incomplete per-bucket public-access settings."
  value       = [aws_s3_bucket.demo_a.bucket, aws_s3_bucket.demo_b.bucket]
}

output "cloudtrail_log_bucket_name" {
  description = "Private, encrypted CloudTrail log bucket with 30-day retention."
  value       = aws_s3_bucket.cloudtrail.bucket
}
