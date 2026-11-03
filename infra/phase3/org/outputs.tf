output "demo_account_id" {
  description = "New account ID to pass to the control-plane stack."
  value       = aws_organizations_account.demo.id
}

output "demo_ou_id" {
  description = "Dedicated OU protected by the Phase 3 demo SCP."
  value       = aws_organizations_organizational_unit.demo.id
}
