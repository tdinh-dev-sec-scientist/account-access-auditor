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
   | sub | repo:tdinh-dev-sec-scientist@172205018/Vorrin@1360779179:environment:phase3-demo-bootstrap-plan | repo:tdinh-dev-sec-scientist@172205018/Vorrin@1360779179:environment:phase3-demo-bootstrap-apply |
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

## GitHub OIDC subject format

This repository's OIDC tokens use GitHub's immutable-ID subject format,
`repo:tdinh-dev-sec-scientist@172205018/Vorrin@1360779179:...`, not
`repo:tdinh-dev-sec-scientist/Vorrin:...`. A trust policy with the short form
never matches. A live probe on 2026-11-05 confirmed this and also confirmed
that AWS evaluates the `workflow` and `ref` claims: a role whose `workflow`
condition did not match was denied. `phase3.role_evidence.GITHUB_SUBJECT_REPOSITORY`
and the Terraform variable `github_subject_repository` hold the value.

## Org stack roles

Create the org plan and apply roles in the management account from the
reviewed templates `infra/phase3/policies/github-oidc-trust.json`,
`org-terraform-plan.json`, and `org-terraform-apply.json`:

```sh
python scripts/render_phase3_org_roles.py --profile vorrin-admin --state-bucket <state-bucket> --lock-table <lock-table> --demo-account-name vorrin-demo
```

The script discovers the account, organization, root, and demo account IDs
with read-only calls, writes the filled documents to the gitignored
`build/phase3/roles/org/`, and prints the `aws iam create-role` and
`put-role-policy` commands. The plan role can only read the organization and
lock the org state. The apply role can create organizational units under the
root, move only the demo account, create, update, and attach service control
policies to organizational units (never the root), and write only the org
state object; it explicitly denies leaving or deleting the organization,
closing or removing accounts, detaching or deleting policies, and
`sts:AssumeRole`.

To adopt a demo account that already exists, set the repository variable
`PHASE3_EXISTING_DEMO_ACCOUNT_ID`, and make `PHASE3_DEMO_ACCOUNT_NAME` and the
`PHASE3_DEMO_ACCOUNT_EMAIL` secret match it exactly. The org stack then imports
the account instead of creating a second one.

## Organizations and control-plane roles

The org and control-plane roots also need separate plan and apply GitHub OIDC
roles in their respective AWS accounts. Configure each role to trust only the
exact repository, its matching protected environment, refs/heads/main, and
the Phase 3 Terraform workflow. Attach the minimum AWS permissions for that
root and its single remote-state object. The plan role may read the resources
that Terraform manages and write only its state lock. The apply role may
change only the resources in that root. Store their ARNs in the matching
environment as PHASE3_TERRAFORM_ROLE_ARN.

**Current audit limitation:** exact org and control-plane trust/policy
documents are not checked into this repository. The configured
`audit-readonly` profile can identify its caller but AWS denies `iam:ListRoles`;
the `default` profile resolves to the account root and must not be used for
policy capture. No role policies have been captured. Treat all four roles as
unverified. The plan and apply workflow blocks those stacks before requesting
OIDC credentials until
schema-3 records independently identify the exact plan and apply role
fingerprints in `docs/evidence/phase3-role-scope.json`. Each role requires four
AWS captures: trust policy, attached policies, inline policies, and permissions
boundary. The capture tool writes exact source JSON to the gitignored
`docs/evidence/.private-role-captures/{org|control-plane}/{plan|apply}/` with
owner-only file permissions. A private metadata file binds the capture to the
SHA-256 fingerprint of the exact role ARN without storing that ARN. It also
writes sanitized projections under
`docs/evidence/terraform-roles/{org|control-plane}/{plan|apply}/` for checked-in
review. Projections replace account IDs, external IDs, resource and policy
names, statement IDs, custom condition keys, and condition values. Only
allowlisted standard condition keys and exact public GitHub OIDC claims remain
visible. Permission actions, resource types, and wildcard scope remain visible.
Exact policy names and values stay in owner-only source files for the human
reviewer. The tool stops if it detects credential-like values, unapproved
GitHub claims, or unsupported policy shapes. Schema-3 records
contain both source-file and sanitized-file SHA-256 digests. The gate validates the checked-in projections,
requires only the matching protected GitHub environment in each trust policy,
and checks the exact workflow role ARN against its fingerprint. It does not
read the gitignored source files in CI or recompute effective permissions.
Keep all four records pending until the offline source/projection check passes,
each real AWS policy set has been reviewed, and the protected environment
approval has been inspected.

To capture a role, use a named non-root profile for that same AWS account with
only `sts:GetCallerIdentity`, `iam:GetRole`,
`iam:ListAttachedRolePolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`,
`iam:ListRolePolicies`, and `iam:GetRolePolicy`. Obtain the exact ARN from the
matching protected GitHub environment locally; do not paste it into chat or
tracked config. Run once for each stack and phase, for example:

The four environment names are `phase3-org-plan`, `phase3-org-apply`,
`phase3-control-plane-plan`, and `phase3-control-plane-apply`. On macOS, install
GitHub CLI if needed and authenticate interactively:

```sh
brew install gh
gh auth login --hostname github.com --git-protocol https --web
gh auth status --hostname github.com
```

The GitHub CLI supports reading a named environment variable with
`gh variable get --env` ([command reference](https://cli.github.com/manual/gh_variable_get)).
For a fine-grained token, GitHub requires repository `Environments: read`
permission; a classic personal access token requires `repo` scope ([API
permission requirements](https://docs.github.com/en/rest/actions/variables#get-an-environment-variable)).
Load each value into a local shell variable without printing it:

```sh
repo=tdinh-dev-sec-scientist/Vorrin
export ORG_PLAN_ROLE_ARN="$(gh variable get PHASE3_TERRAFORM_ROLE_ARN --env phase3-org-plan --repo "$repo" --json value --jq .value)"
export ORG_APPLY_ROLE_ARN="$(gh variable get PHASE3_TERRAFORM_ROLE_ARN --env phase3-org-apply --repo "$repo" --json value --jq .value)"
export CONTROL_PLANE_PLAN_ROLE_ARN="$(gh variable get PHASE3_TERRAFORM_ROLE_ARN --env phase3-control-plane-plan --repo "$repo" --json value --jq .value)"
export CONTROL_PLANE_APPLY_ROLE_ARN="$(gh variable get PHASE3_TERRAFORM_ROLE_ARN --env phase3-control-plane-apply --repo "$repo" --json value --jq .value)"
test -n "$ORG_PLAN_ROLE_ARN" && test -n "$ORG_APPLY_ROLE_ARN"
test -n "$CONTROL_PLANE_PLAN_ROLE_ARN" && test -n "$CONTROL_PLANE_APPLY_ROLE_ARN"
```

Use one named non-root AWS profile for each target account, and scope the IAM
read actions above to the exact Terraform role ARNs and their attached managed
policy ARNs. `iam:ListRoles` is not used by the capture tool; a denial for that
action alone does not prevent capture. The tool rejects a profile whose account
does not match the role ARN. If the existing `audit-readonly` profile matches
the Organizations account and has the listed exact-role permissions, use it
for the `org` captures; configure a separate read-only profile for the
control-plane account.

Capture and verify all four roles with the corresponding account profile:

```sh
./.venv/bin/python scripts/capture_phase3_role_evidence.py --profile org-audit-readonly --stack org --phase plan --role-arn "$ORG_PLAN_ROLE_ARN"
./.venv/bin/python scripts/capture_phase3_role_evidence.py --profile org-audit-readonly --stack org --phase apply --role-arn "$ORG_APPLY_ROLE_ARN"
./.venv/bin/python scripts/capture_phase3_role_evidence.py --profile control-plane-audit-readonly --stack control-plane --phase plan --role-arn "$CONTROL_PLANE_PLAN_ROLE_ARN"
./.venv/bin/python scripts/capture_phase3_role_evidence.py --profile control-plane-audit-readonly --stack control-plane --phase apply --role-arn "$CONTROL_PLANE_APPLY_ROLE_ARN"

./.venv/bin/python scripts/verify_phase3_role_capture.py --stack org --phase plan --role-arn "$ORG_PLAN_ROLE_ARN"
./.venv/bin/python scripts/verify_phase3_role_capture.py --stack org --phase apply --role-arn "$ORG_APPLY_ROLE_ARN"
./.venv/bin/python scripts/verify_phase3_role_capture.py --stack control-plane --phase plan --role-arn "$CONTROL_PLANE_PLAN_ROLE_ARN"
./.venv/bin/python scripts/verify_phase3_role_capture.py --stack control-plane --phase apply --role-arn "$CONTROL_PLANE_APPLY_ROLE_ARN"
```

Replace the two profile names with the named profiles available on this
machine. Capture and verification do not mark any role reviewed; keep all four
manifest records pending until a human has reviewed the genuine source policy
captures.

The single-role example below is useful when recapturing one role:

```sh
./.venv/bin/python scripts/capture_phase3_role_evidence.py \
  --profile org-audit-readonly \
  --stack org \
  --phase plan \
  --role-arn "$ORG_PLAN_ROLE_ARN"
```

The capture tool rejects root or cross-account identities, refuses to overwrite
existing evidence, prints both source and sanitized hashes, and never changes
the manifest's review status. Run the offline verifier while the manifest is
pending to prove that the tracked projection is the exact deterministic
redaction of the owner-only source capture:

```sh
./.venv/bin/python scripts/verify_phase3_role_capture.py \
  --stack org \
  --phase plan \
  --role-arn "$ORG_PLAN_ROLE_ARN"
```

The verifier prints hashes only, checks source and projection paths and file
permissions, and never updates review status. After it passes, the human
reviewer must evaluate the actual permissions and trust scope in the private
source. Only after that review should the reviewer record the exact ARN hash,
reviewer, timestamp, and both digest sets. Run the verifier again afterward; it
will also compare the reviewed manifest digests with the source and projection
files. The configured `audit-readonly` profile
currently denies `iam:ListRoles`, so it cannot enumerate role names; it may
still capture a role when supplied its exact ARN and the required read
permissions.

The demo-account plan and apply roles are created by the demo-bootstrap root.
Use those role ARNs for the phase3-demo-account-plan and
phase3-demo-account-apply environments after that stack is reviewed.
The demo-account apply role cannot create or select a new target-policy version
or remove the target role's permissions boundary. Changing that policy therefore
requires a separate owner-controlled review and apply path.

The image publishing workflow uses a different protected phase3-scan-image
environment and a role created by the control-plane stack. That role can push
and verify only the Phase 3 scan image repository.

Do not put account IDs, state paths, role ARNs, or external provider secrets in
tracked Terraform variable files. Keep apply approval and live stage evidence
separate: a successful workflow run alone does not pass a Phase 3 stage gate.
Later-stage control-plane plans also require the corresponding predecessor
stage to be marked passed in `docs/evidence/phase3-stage-acceptance.json`, with
the required non-empty evidence files checked in under that stage's evidence
directory. Every passed stage record must list every evidence path and the
SHA-256 digest of its exact checked-in bytes in `evidence_sha256`; changing a
file after review blocks the stage. The reviewer must inspect real run output,
not a test fixture or placeholder, before setting its criterion to `true`.

Use these evidence paths for the plan's stage exit criteria:

| Stage | Required evidence files |
| --- | --- |
| 1 | `stage1/scheduled-scan-results.json`, `stage1/schedule-execution-log.json`, `stage1/drift-review.json`, `stage1/read-only-role-review.json` |
| 2 | `stage2/redaction-test-results.json`, `stage2/publisher-failure.json`, `stage2/public-api-methods.json` |
| 3 | `stage3/transport-security.json`, `stage3/external-tls-scan.json`, `stage3/source-reports/external-tls.json`, `stage3/privacy-accessibility.json`, `stage3/source-reports/browser-network.json`, `stage3/source-reports/lighthouse.json`, `stage3/source-reports/accessibility.json`, `stage3/rin-evaluation.json`, `stage3/quota-fallbacks.json`, `stage3/failure-banners.json`, `stage3/guardrail-policy-review.json`, `stage3/bedrock-logging-review.json`, `stage3/guardrail-configuration.json`, `stage3/guardrail-evaluation.json`, `stage3/bedrock-logging-settings.json`, `stage3/external-provider-logging-settings.json` |
| 4 | `stage4/budget-cutoff.json`, `stage4/kill-switch-recovery.json`, `stage4/load-resilience.json`, `stage4/source-reports/load-test.json`, `stage4/actual-monthly-cost.json`, `stage4/source-reports/aws-cost-explorer.json`, `stage4/source-reports/provider-cost.json`, `stage4/launch-evidence.json` |

Each evidence directory contains reviewed artifacts, not the manifest. After
review, record the exact reviewer and timezone-qualified timestamp, set only
the criteria supported by those artifacts, and calculate the SHA-256 values
for all listed files. The validator rejects incomplete paths, changed bytes,
missing files, and stages marked passed before their predecessors. Stage 3
also validates criterion-specific HTTPS/header, Rin evaluation, quota,
failure-banner, Guardrail, and logging evidence. When live Rin is enabled,
Terraform requires the reviewed Guardrail ARN and version to match the
configured ARN and version exactly. Keep the checked-in manifest pending until
real live evidence has been reviewed; local test output alone does not pass a
stage.

Stage evidence JSON uses `schema_version: 1` and carries the same `reviewed_by`
and timezone-qualified `reviewed_at` as the stage record. Stage 1 records two
completed scheduled scans, snapshot hashes, a Terraform change, new/resolved
finding IDs, and a read-only role review with no effective write actions. The
scan artifact also identifies the demo account by a fixed label and records
the execution-log digest used to review scan consecutiveness. The retained
schedule log must show the complete export window, two events exactly six hours
apart, and matching workflow/scan IDs, timestamps, and snapshot digests. The
Step Functions execution must start within one hour of its schedule event,
matching the configured Scheduler retry age; the scan container must start
after the workflow begins. Its account-ID digest must match the configured
`demo_account_id`; the workflow checks that binding before requesting AWS
credentials.
Stage 2 records required redaction cases with zero leaks/unapproved fields, a
forced publisher failure that preserves the prior snapshot hash, and GET/HEAD
success with other standard methods rejected. Stage 3 records required
headers, a dated external TLS scan, browser-network and accessibility report
digests for the dashboard/finding/Rin pages, passing Rin test categories,
fixture responses at session/daily/monthly limits, and all failure banners.
Stage 4 records the 50/80/100% budget alerts, kill-switch recovery, load tests
at multiple traffic levels, actual AWS and provider costs against their
separate budgets, and every final release criterion. Report digests must match
their corresponding retained source-report files. The pre-credential workflow
also binds Stage 3 quota evidence to configured provider prices, token caps,
monthly budget, and derived daily cap. Generic `checked: true` files do not
satisfy these schemas.

## Rin Bedrock Guardrail

The A2-false model path uses the selected external model provider and an
owner-managed Bedrock Guardrail. Terraform does not create or edit the
Guardrail. Before live Rin can be enabled:

1. Configure and publish a numeric Guardrail version. It must block prompt
   attacks, deny off-scope topics, and detect or block sensitive data for both
   input and output. Review the [Guardrails content and topic policies](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)
   and [prompt attack filter requirements](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-prompt-attack.html).
2. Set `PHASE3_RIN_GUARDRAIL_ARN` and
   `PHASE3_RIN_GUARDRAIL_VERSION` in the protected control-plane environment.
   The ARN must belong to the same AWS account and region as the Rin Lambda;
   `DRAFT` is rejected.
3. Review the captured Rin role policy. When Rin is enabled, it receives only
   `bedrock:ApplyGuardrail` on that exact Guardrail ARN. It does not receive
   `bedrock:InvokeModel`. Rin sends the bounded redacted question and selected
   finding to `ApplyGuardrail` with `source=INPUT` before calling the external
   model, then checks the validated answer with `source=OUTPUT` before
   returning it. A block, invalid response, or service error selects the
   fixture fallback. See AWS's [independent ApplyGuardrail API](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-use-independent-api.html).
4. Verify Guardrail and model invocation logging settings. This service does
   not log prompt text; account-level Bedrock invocation logging must not
   persist Rin messages beyond the approved retention boundary.
5. Include both Guardrail evaluations per live question in the AWS estimate.
   Record the published ARN/version, reviewed filters, adversarial test results,
   logging settings, and cost evidence before passing the Rin acceptance gate.
   Stage 3 cannot pass until reviewed records exist at
   `docs/evidence/stage3/guardrail-policy-review.json` and
   `docs/evidence/stage3/bedrock-logging-review.json`; the manifest keeps both
   criteria false until those artifacts are captured and reviewed. The policy
   record must identify the published ARN/version, the checked-in
   `stage3/guardrail-configuration.json` export and its matching SHA-256,
   input/output prompt-attack and sensitive-data filters, off-scope topics, and
   a passing adversarial-suite digest with its case count, matching the
   checked-in `stage3/guardrail-evaluation.json` export. The logging record
   must identify the same Guardrail version, checked-in Bedrock and
   external-provider settings exports at `stage3/bedrock-logging-settings.json`
   and `stage3/external-provider-logging-settings.json`, and matching SHA-256
   values for both. The same reviewer and timestamp must cover all four source
   exports and both review records. Prompt-content retention is capped at 30
   days to implement the plan's short-retention requirement. Generic
   `reviewed: true` files, unattached digests, and prompt retention beyond 30
   days fail both Python and Terraform validation. Keep the Stage 3 manifest
   pending until these are actual AWS/provider captures and have been reviewed;
   test fixtures are not acceptance evidence.
   The four capture files use the validator's canonical JSON shape: the
   Guardrail configuration carries its ARN, published version, and reviewed
   input/output control objects; evaluation carries the same ARN/version,
   case count, overall result, and per-case expected/observed action; each
   logging capture carries the settings version, enabled state, prompt-content
   flag, and retention days (plus provider name for external logging). The
   evaluator requires passing cases for input/output prompt attacks, sensitive
   data, off-scope topics, and a safe in-scope request. Review summaries must
   equal these captured fields, and each digest is SHA-256 over the exact bytes
   of its corresponding checked-in JSON file.
