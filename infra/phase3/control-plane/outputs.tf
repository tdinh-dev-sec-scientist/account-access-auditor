output "scan_task_role_arn" {
  description = "Fargate task role trusted by the dedicated demo account's read-only target role."
  value       = aws_iam_role.scan_task.arn
}

output "scan_ecr_repository_uri" {
  description = "Immutable ECR repository for signed Phase 3 Fargate scan images."
  value       = aws_ecr_repository.scan.repository_url
}

output "scan_image_publisher_role_arn" {
  description = "GitHub OIDC role scoped to publishing only the Phase 3 scan image."
  value       = aws_iam_role.scan_image_publisher.arn
}

output "private_snapshot_bucket" {
  description = "Private report-only storage bucket."
  value       = aws_s3_bucket.private_snapshots.bucket
}

output "private_run_index_table" {
  description = "Private account-scoped run index table."
  value       = aws_dynamodb_table.private_runs.name
}

output "scan_workflow_arn" {
  description = "Scheduled, read-only scan workflow ARN."
  value       = var.enable_scan_pipeline ? aws_sfn_state_machine.scan[0].arn : null
}
