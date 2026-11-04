# Phase 3 status

**Local implementation for all four stages is prepared. No live stage gate has passed.**
The checked-in [Phase 3 plan](plans/AWS_Cloud_Security_Guardrails_Phase_3_Plan.docx)
is the source of truth. Local tests and Terraform code do not count as live
acceptance.

Terraform 1.9.8 `fmt -check -recursive infra/phase3` passed, and
`terraform validate` passed in the `org`, `demo-bootstrap`, `demo-account`,
and `control-plane` roots. Each root was initialized with `-backend=false` and
`-lockfile=readonly`; no AWS credentials were used. These local checks do not
count as live acceptance.

The README now gives visitors a short console walkthrough and links each view
to its source report and JSON evidence. The embedded demo GIF remains omitted
at the owner's request; a recording artifact is still outstanding.

## Stage status

| Stage | Local implementation | Live acceptance |
| --- | --- | --- |
| Stage 1 — Demo account and scans | OU/SCP, guarded low-cost demo resources, read-only ECS Fargate scanner, scheduler, private snapshots, and drift history are implemented. | **Not passed.** No demo account or role has been provisioned, no scheduled scan has run, and the new/resolved drift evidence is absent. |
| Stage 2 — Redaction, publication, and API | Versioned public schema, allowlist redaction, private-to-public publisher, last-good behavior, and GET/HEAD API are implemented and locally tested. | **Not passed.** Stage 1 has not passed. An owner-recorded AWS Pricing Calculator estimate and a monthly cap covering that estimate are also required before enablement. |
| Stage 3 — Website and Rin | Sanitized bundle, same-origin API client, failure banners, fixture fallback, external-provider Rin path, input/output Bedrock Guardrail checks, session/daily quotas, and CloudFront/WAF/TLS Terraform are implemented. | **Not passed.** Stages 1–2, provider selection, current provider rates, secret rotation, a published and reviewed Guardrail version, logging review, and live browser/TLS/header/accessibility checks remain pending. Rin and hosting are disabled by default. |
| Stage 4 — Harden, document, and launch | AWS budget alerts, a separate daily-limit alert, atomic static-mode kill switch, and operational documentation are implemented. | **Not passed.** No deployment, actual cost record, external security scan, load test, or end-to-end kill-switch recovery measurement exists. |

Later-stage code was prepared before the earlier live stage gates were met. This
is an implementation-sequencing deviation; it is not stage acceptance. The
checked-in acceptance manifest is pending for every stage, and both CI and
Terraform preconditions block later-stage enablement until reviewed evidence
files are present. No Phase 3 AWS resources have been created. The configured
`audit-readonly` profile can obtain an identity but AWS denies `iam:ListRoles`;
the `default` profile resolves to account root and was not used for policy
capture. No actual AWS role policies were captured. The version-3 role manifest
keeps the org and control-plane plan/apply roles separate and pending.
Stage 3's versioned acceptance manifest explicitly requires reviewed published
Guardrail-policy and Bedrock invocation-logging records at
`stage3/guardrail-policy-review.json` and
`stage3/bedrock-logging-review.json`, plus the four source exports whose exact
bytes those records hash: the Guardrail configuration, adversarial evaluation,
Bedrock logging settings, and external-provider logging settings. The gate
enforces a 30-day maximum for prompt-content retention. The source paths are
`stage3/guardrail-configuration.json`, `stage3/guardrail-evaluation.json`,
`stage3/bedrock-logging-settings.json`, and
`stage3/external-provider-logging-settings.json`. These actual captures are
absent, so Stage 3 remains pending.

The version-3 stage gate requires named evidence artifacts and a SHA-256 digest
for every reviewed file. A file changed after review blocks the gate. Stage 3
also validates that its review summaries match the captured Guardrail and
logging records. This hardens the evidence gate; it does not replace live
acceptance activity or mark a stage passed.

## Confirmed assumptions and permission boundary

The public snapshot shape is versioned as 2.0.0 because evidence summaries and
affected-service status are required fields. The repository contains no 1.0.0
public snapshot. No profile with access to the Phase 3 public-results store is
configured, so remote objects remain unverified; before launch, publish a
2.0.0 snapshot and verify that no older object can remain behind the latest
pointer.

- **A1 is false:** Phase 2 has local drift history and a fixture-backed static
  site, not an S3 snapshot store or DynamoDB index. Phase 3 implements those
  missing components.
- **A2 is false:** Rin model generation follows the plan's external-provider
  contingency. An owner-managed Bedrock Guardrail independently checks the
  redacted input and validated output. Rin stays disabled until the owner
  selects a provider/model, configures its secret and rotation process,
  publishes and reviews the Guardrail, and supplies provider rates and a
  separate provider budget.
- The scan worker assumes only the named target read-only role. The public API
  reads sanitized scan results and its feature flag, and writes its own logs.
  Rin reads sanitized scan results, its feature flag and provider secret,
  invokes the separate quota function, writes its own logs, and applies only
  the approved Bedrock Guardrail when enabled. Neither can change target
  resources or scan results. The private snapshot writer, publisher, quota
  writer, and kill switch have separate runtime roles.
  The Organizations and control-plane Terraform role policies are owner-created
  prerequisites and have not been independently verified; see the bootstrap
  guide before using them.
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
   output rates, separate provider monthly cap, managed provider secret, and
   owner-managed published Bedrock Guardrail with reviewed input/output
   policies and invocation-logging settings. Provider values are not invented
   here.
4. After deployment: two scheduled scans, reviewed Terraform drift evidence,
   read-only permission evidence, public redaction/failure evidence, TLS and
   header results, browser/accessibility checks, load/resilience results,
   kill-switch/recovery timing, and actual AWS/provider spend.

The default CloudFront domain is the planned choice when no custom domain is
provided. That does not remove the other stage gates.
