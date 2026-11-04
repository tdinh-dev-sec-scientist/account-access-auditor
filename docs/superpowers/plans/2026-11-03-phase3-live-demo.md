# Phase 3 Live Demo Implementation Plan

> **For agentic workers:** Execute inline, stage by stage. The Phase 3 release
> gates remain binding; never report a stage complete from local simulation.

**Goal:** Replace the static fixture-only Phase 2 showcase with a public,
sanitized live AWS demo while preserving read-only scans, evidence-grounded Rin,
and bounded cost.

**Architecture:** Reuse `run_fleet_scan`, existing versioned `ScanRun` and
`Finding` contracts, and the current console. Add a private scheduled scan and
snapshot path because Phase 2 has only host scheduling and local SQLite; place
an allowlist redactor between private snapshots and the public store/API. Keep
the public API and Rin read-only, and publish the UI behind CloudFront, OAC,
TLS, security headers, and WAF.

**Tech Stack:** Existing Python 3.11+ and boto3, pinned Terraform AWS provider,
EventBridge Scheduler, Step Functions, ECS Fargate for the scanner, narrowly
scoped Lambda adapters for private storage, publication, API, Rin, quotas, and
the kill switch, private S3, DynamoDB, API Gateway REST, CloudFront, WAF, AWS
Budgets, GitHub OIDC, and the existing static HTML/CSS/JavaScript console. Do
not add dependencies unless the implementation proves they are needed.

**Spec:** `docs/plans/AWS_Cloud_Security_Guardrails_Phase_3_Plan.docx`

## Global Constraints

- Target-account collection uses the existing operation allowlist; the assumed
  target role has no AWS write actions.
- Only plan-scoped Terraform, private snapshot-writer, public publisher, quota,
  and kill-switch roles may write, each to named resources. The target assumed
  role, scanner runtime role, public API role, and Rin role do not mutate AWS
  resources or scan state.
- Public output is schema-versioned and allowlist-only; unknown fields are
  dropped, identifiers are pseudonymized or removed, and any validation or
  redaction failure leaves the last good public snapshot active.
- Public data API routes accept only `GET` and `HEAD`; the separate Rin chat
  route accepts `POST`. The public API role reads only the public store; Rin
  reads only public evidence and cannot call GitHub or scanners.
- Preserve `PASS`, `FAIL`, `UNKNOWN`, and `ERROR`; incomplete, stale, failed, or
  publication-paused data must never render as clean.
- No secret, message body, raw evidence, or private snapshot reaches browser
  assets, public output, or ordinary operational logs.
- Rin is disabled or fixture-backed unless provider secret, exact model,
  per-session limit, daily cap, and monthly spend configuration are present.
- Do not deploy, create AWS resources, commit, or push until the required target
  account, budget, and live-deployment gates are satisfied.

## Review Focus

1. Unknown or newly added Phase 2 fields must never cross the publisher boundary.
2. Resource identifiers with malformed, mixed-case, or embedded secret forms
   must not leak through keys, values, errors, or citations.
3. Concurrent publication or a mid-write failure must not replace the latest
   good pointer with an incomplete snapshot.
4. Direct API-origin requests must still meet method and rate limits; CloudFront
   must not become the only security check.
5. Partial scans, stale snapshots, unavailable providers, and budget exhaustion
   must retain explicit banners and fixture fallback behavior.

---

### Task 1: Stage 1 — Managed read-only scans and private history

**Files:**
- Create: `phase3/scan_task.py`, `phase3/snapshot_writer.py`
- Create: `infra/phase3/` Terraform for the demo account, OU/SCP, read-only
  target role, scheduled Step Functions/ECS Fargate workflow, private snapshot
  bucket, and run index
- Create: a protected GitHub OIDC Terraform workflow for the four Phase 3 roots
- Test: `tests/test_phase3_scan_pipeline.py`,
  `tests/test_phase3_infrastructure.py`
- Update: `docs/phase3-status.md`, `docs/least-privilege.md`

**Interfaces:**
- Consumes: `FleetConfig`, `run_fleet_scan`, `HistoryStore.record_scan`, and
  the Phase 2 `contract.scan_run`/`contract.findings` records.
- Produces: `phase3.scan_task.run_scan_task(...)` runs as an ECS Fargate task,
  assumes only the named demo read-only role, and invokes the separate private
  snapshot writer with the complete report. The writer validates and stores
  the private report and drift view, then returns a bounded receipt; Step
  Functions retrieves that receipt by scan-run ID. The scan task itself cannot
  write S3 or DynamoDB state.

- [ ] Test a successful one-account scan and preservation of `UNKNOWN`/`ERROR`.
- [ ] Prove the target role has only declared read actions and cannot call a
  write operation; prove the Fargate scan task has no direct private/public S3
  or DynamoDB write permission.
- [ ] Provision only low-cost demo resources from Terraform; no credentials,
  user access keys, compute, NAT, or data-bearing public buckets.
- [ ] Add scheduled orchestration, private versioned snapshots, and comparable
  coverage-aware drift history without changing scan rules.
- [ ] Run unit, IaC, and full Phase 2 regression suites. Do not pass Stage 1
  until two scheduled scans, reviewed-change new/resolved drift, and live
  read-only role evidence are checked in.

### Task 2: Stage 2 — Public contract, redaction, publisher, and GET API

**Files:**
- Create: `phase3/public_schema.py`, `phase3/redaction.py`,
  `phase3/publisher.py`, `phase3/public_api.py`
- Create: `schemas/public-snapshot-v2.schema.json`
- Create: public-results S3/DynamoDB resources and scoped Lambda roles in
  `infra/phase3/`
- Test: `tests/test_phase3_redaction.py`, `tests/test_phase3_publisher.py`,
  `tests/test_phase3_public_api.py`

**Interfaces:**
- Consumes: Task 1 private snapshots and the Phase 2 contracts.
- Produces: `redact_snapshot(report, hmac_key) -> dict`,
  `publish_snapshot(snapshot, store) -> publication_result`, and
  `public_api.lambda_handler(event, context) -> API Gateway response`.

- [ ] Enforce the explicit public allowlist, fixed demo-account label, stable
  keyed resource pseudonyms; retain only approved rule/control, severity,
  status, lifecycle/drift, scan metadata, remediation, and references; remove
  IPs, hosts, endpoints, IAM principals, e-mails, access keys, exception owners,
  and raw evidence; show only exception existence/expiry; reject account-ID,
  ARN, and access-key patterns.
- [ ] Validate against the separately versioned public schema; reject malformed
  input and output without changing the last-good pointer.
- [ ] Record the required AWS Pricing Calculator estimate and a hard owner-set
  monthly cap before Stage 2 deployment; do not substitute a guessed cap.
- [ ] Expose only `GET`/`HEAD` routes for latest scan, runs, findings, and drift;
  return status/freshness metadata and safe cache headers.
- [ ] Verify the API role cannot read private snapshots or write any AWS state.
- [ ] Run seeded-secret, unknown-field, stable-pseudonym, failure-atomicity,
  method, and Phase 2 regression tests before the Stage 2 gate.

### Task 3: Stage 3 — CloudFront site, live console, and guarded Rin

**Files:**
- Modify: `scripts/console/console.js`, `scripts/console/index.html`,
  `scripts/console/console.css`, and `scripts/build_site.py`
- Create: `phase3/rin_service.py`, `phase3/quotas.py`,
  `tests/test_phase3_rin.py`, `tests/test_phase3_console.py`
- Create: private web bucket, OAC, CloudFront, TLS/security headers, WAF, API
  origin, provider-secret reference, and static fixture bundle in `infra/phase3/`

**Interfaces:**
- Consumes: Task 2 GET API and public evidence schema; existing local Rin
  fixture behavior remains the fallback.
- Produces: same-origin console data loading; `rin.lambda_handler(event,
  context)` accepts a bounded question and finding ID and returns validated
  cited JSON. Rin receives only the selected redacted finding and approved
  references.

- [ ] Render live overview, finding detail, drift, scan time/status, and explicit
  states for failed scans (last good plus banner), partial scans, stale data
  (>2 scan intervals), paused publication, unavailable API (labeled fixtures),
  paused Rin (fixture answers), and static kill-switch mode.
- [ ] Include a user-facing Security and Limitations view that clearly
  separates static fixture behavior, read-only AWS collection, sanitized public
  data, and live acceptance gates that remain unverified.
- [ ] Restrict API methods to GET/HEAD and apply WAF rate rules at CloudFront and
  the API origin so a direct origin request cannot bypass rate control. Keep
  `/api/rin` as a separate POST-only route.
- [ ] Apply the plan defaults: 100 requests per IP per 5 minutes, maximum
  500-character questions, 10 questions per browser session, a configured
  answer-token cap, and a daily invocation cap derived from the monthly budget.
  Keep quota writes in a separate role limited to the quota table; Rin itself
  remains read-only.
- [ ] Add input/output validation, citation allowlisting, prompt-attack tests,
  secret-free logs that exclude message text by default, and fixture fallback
  for errors, Guardrails/moderation blocks, quotas, or budget cutoff.
- [ ] Keep Rin disabled unless an external provider secret reference, approved
  model, and spend-rate configuration are explicitly supplied.
- [ ] Verify HTTP-to-HTTPS redirect, HSTS, CSP, X-Content-Type-Options,
  Referrer-Policy, frame-ancestors, and no unapproved third-party requests.

### Task 4: Stage 4 — Budget, kill switch, evidence, and launch readiness

**Files:**
- Create: budget alarms, invocation/cost metrics, and a narrowly scoped
  kill-switch Lambda in `infra/phase3/`
- Create/update: `docs/phase3-status.md`, `docs/costs.md`,
  `docs/threat-model.md`, `docs/operations-runbook.md`, `README.md`, and
  `docs/evidence/`
- Test: `tests/test_phase3_kill_switch.py`, release/HTTP acceptance scripts,
  documentation links, and full Phase 2 suite

- [ ] At the configured cap, disable live Rin and return the site to static
  fixtures without removing the last good redacted scan results.
- [ ] Send AWS budget alerts at 50%, 80%, and 100%; test automatic Rin cutoff
  at 100% and keep the public scan-results path available from its cached copy.
- [ ] Tag demo resources `project=guardrails-phase3`; record monthly actual AWS
  spend and provider spend separately because A2 selects an external provider.
- [ ] Exercise switch-off/switch-on recovery, budget alarms, load/rate limits,
  provider outage, stale/partial/failed snapshots, and publisher failure.
- [ ] Record measured AWS estimate, configured owner cap, actual spend when
  available, TLS/header scan, Lighthouse/accessibility, and kill-switch timings.
- [ ] Update public claims to match checked-in evidence and label unverified
  live acceptance as pending.
- [ ] Pass every Phase 3 release criterion before calling Phase 3 complete.

## Execution notes

- Stage 1 assumptions A1/A2 are false in the repository: managed scan storage
  and the Phase 2 dashboard do not exist, and Rin uses OpenAI rather than
  Bedrock. Build the missing private dashboard data path first. The external
  provider path requires an owner-managed secret and explicit spend settings.
- Terraform and a Phase 3 AWS profile are absent in the current environment.
  Add CI validation for pinned Terraform; live acceptance remains pending until
  the owner supplies the dedicated target, OIDC role/environment, remote state,
  and budget configuration.
- Work in this order. A stage's infrastructure may be authored and locally
  tested ahead of live evidence, but do not claim its exit gate or enable the
  next deployment stage until the preceding gate has passed.
