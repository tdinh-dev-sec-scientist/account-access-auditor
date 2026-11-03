# Phase 3 status

**Local implementation for all four stages is prepared. No live stage gate has passed.**
The checked-in [Phase 3 plan](plans/AWS_Cloud_Security_Guardrails_Phase_3_Plan.docx)
is the source of truth. Local tests and Terraform code do not count as live
acceptance.

## Stage status

| Stage | Local implementation | Live acceptance |
| --- | --- | --- |
| Stage 1 — Demo account and scans | OU/SCP, guarded low-cost demo resources, read-only ECS Fargate scanner, scheduler, private snapshots, and drift history are implemented. | **Not passed.** No demo account or role has been provisioned, no scheduled scan has run, and the new/resolved drift evidence is absent. |
| Stage 2 — Redaction, publication, and API | Versioned public schema, allowlist redaction, private-to-public publisher, last-good behavior, and GET/HEAD API are implemented and locally tested. | **Not passed.** Stage 1 has not passed. An owner-recorded AWS Pricing Calculator estimate and a monthly cap covering that estimate are also required before enablement. |
| Stage 3 — Website and Rin | Sanitized bundle, same-origin API client, failure banners, fixture fallback, external-provider Rin path, session/daily quotas, and CloudFront/WAF/TLS Terraform are implemented. | **Not passed.** Stages 1–2, provider selection, current provider rates, secret rotation, and live browser/TLS/header/accessibility checks remain pending. Rin and hosting are disabled by default. |
| Stage 4 — Harden, document, and launch | AWS budget alerts, a separate daily-limit alert, atomic static-mode kill switch, and operational documentation are implemented. | **Not passed.** No deployment, actual cost record, external security scan, load test, or end-to-end kill-switch recovery measurement exists. |

Later-stage code was prepared before the earlier live stage gates were met. This
is an implementation-sequencing deviation; it is not stage acceptance. The
Terraform flags remain false until the previous gate and its evidence are
reviewed. No Phase 3 AWS resources have been created, and no AWS profile was
used for this work.

## Confirmed assumptions and permission boundary

- **A1 is false:** Phase 2 has local drift history and a fixture-backed static
  site, not an S3 snapshot store or DynamoDB index. Phase 3 implements those
  missing components.
- **A2 is false:** Rin is not backed by Bedrock. The implementation follows the
  plan's external-provider contingency. It stays disabled until the owner
  selects a provider/model, configures its secret and rotation process, and
  supplies a provider budget and current token rates.
- The scan worker assumes only the named target read-only role. The public API
  and Rin can read only sanitized public results; Rin can invoke only the
  separate quota function and read its provider secret. The private snapshot
  writer, sanitized publisher, quota writer, kill switch, and Terraform roles
  are separate, resource-scoped plan-authorized write paths.
- Stage flags, the six-hour schedule, and live Rin default to disabled. See
  [the cost record](costs.md) and [the operations runbook](operations-runbook.md)
  before any live plan.

## Inputs and evidence still required

1. Designated AWS Organizations management/control-plane accounts and the
   dedicated demo account, plus the pre-scoped GitHub OIDC providers and
   plan/apply roles for those accounts. The one-time identity setup is
   documented in [the OIDC bootstrap guide](phase3-bootstrap.md). Do not put
   account-specific values in tracked files.
2. An owner-generated AWS Pricing Calculator estimate, its evidence reference,
   and a monthly AWS cap at least as high as the estimate. An encrypted,
   access-controlled Terraform state location must also be selected before
   applying.
3. A budget-alert email, external provider/model, current provider input and
   output rates, separate provider monthly cap, and a managed provider secret.
   Provider values are not invented here.
4. After deployment: two scheduled scans, reviewed Terraform drift evidence,
   read-only permission evidence, public redaction/failure evidence, TLS and
   header results, browser/accessibility checks, load/resilience results,
   kill-switch/recovery timing, and actual AWS/provider spend.

The default CloudFront domain is the planned choice when no custom domain is
provided. That does not remove the other stage gates.
