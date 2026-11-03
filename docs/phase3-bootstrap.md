# Phase 3 GitHub OIDC bootstrap

The Terraform workflow uses GitHub OIDC. Its first trusted role and the
owner-selected remote state must exist before the workflow can run. These are
one-time identity prerequisites; the routine workflow does not assume
OrganizationAccountAccessRole or personal administrator credentials.

## Demo-account bootstrap roles

Before dispatching the demo-bootstrap stack:

1. In the dedicated demo account, create the GitHub OIDC provider for
   https://token.actions.githubusercontent.com with audience
   sts.amazonaws.com. Limit the setup permission to that provider ARN.
2. Create Phase3DemoBootstrapPlan and Phase3DemoBootstrapApply with trust
   conditions matching all of the following:

   | Claim | Plan role | Apply role |
   | --- | --- | --- |
   | aud | sts.amazonaws.com | sts.amazonaws.com |
   | sub | repo:tdinh-dev-sec-scientist/account-access-auditor:environment:phase3-demo-bootstrap-plan | repo:tdinh-dev-sec-scientist/account-access-auditor:environment:phase3-demo-bootstrap-apply |
   | ref | refs/heads/main | refs/heads/main |
   | workflow | Phase 3 Terraform | Phase 3 Terraform |

3. Replace the placeholders in demo-bootstrap-plan.json and
   demo-bootstrap-apply.json with the dedicated account ID, state bucket ARN,
   exact phase3/demo-bootstrap/terraform.tfstate object ARN, and exact lock
   table ARN. Attach the corresponding policy to each role. The plan role can
   read the two Terraform roles and selected OIDC provider; its only writes are
   the state lock. The apply role can write the bootstrap state and create or
   update only Phase3DemoTerraformPlan and Phase3DemoTerraformApply.
4. Set each protected GitHub environment's PHASE3_TERRAFORM_ROLE_ARN to its
   corresponding role ARN. Require a reviewer in the apply environment and
   restrict both environments to main.

The demo-bootstrap Terraform root reads the pre-existing OIDC provider and
creates only the later demo-account Terraform roles. Its plan and apply roles
do not have permissions to create target-account data resources, pass roles,
create users, or assume the account administrator role.

## Organizations and control-plane roles

The org and control-plane roots also need separate plan and apply GitHub OIDC
roles in their respective AWS accounts. Configure each role to trust only the
exact repository, its matching protected environment, refs/heads/main, and
the Phase 3 Terraform workflow. Attach the minimum AWS permissions for that
root and its single remote-state object. The plan role may read the resources
that Terraform manages and write only its state lock. The apply role may
change only the resources in that root. Store their ARNs in the matching
environment as PHASE3_TERRAFORM_ROLE_ARN.

The demo-account plan and apply roles are created by the demo-bootstrap root.
Use those role ARNs for the phase3-demo-account-plan and
phase3-demo-account-apply environments after that stack is reviewed.

The image publishing workflow uses a different protected phase3-scan-image
environment and a role created by the control-plane stack. That role can push
and verify only the Phase 3 scan image repository.

Do not put account IDs, state paths, role ARNs, or external provider secrets in
tracked Terraform variable files. Keep apply approval and live stage evidence
separate: a successful workflow run alone does not pass a Phase 3 stage gate.
