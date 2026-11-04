output "terraform_plan_role_arn" {
  description = "Read-only AWS Terraform plan role used by the protected GitHub plan environment."
  value       = aws_iam_role.terraform_plan.arn
}

output "terraform_apply_role_arn" {
  description = "Resource-scoped AWS Terraform apply role used only after GitHub environment approval."
  value       = aws_iam_role.terraform_apply.arn
}
