# Operations runbook

This runbook covers the Phase 2 local/read-only paths and the Phase 3
deployment design. Phase 3 infrastructure is code-only today: no Phase 3 AWS
resources have been created. Check [Phase 2 status](implementation-status.md)
and [Phase 3 status](phase3-status.md) for verified evidence and open gates.

## 1. Install and reproduce the offline demo

Use Python 3.11 or newer. From a clean checkout:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pytest --cov=auditor --cov-report=term-missing \
  --cov-report=json:results/coverage.json --cov-fail-under=86
python -m lab.run_benchmark
python scripts/collect_metrics.py
python scripts/build_site.py
python -m http.server --directory site 8000
```

Open `http://localhost:8000`. The benchmark provisions only an in-process moto
account, scores expected findings, and regenerates the reports under `results/`.
The static site replays those artifacts; it is not a live AWS dashboard. Metrics
are generated from the test, coverage, benchmark, mapping, and policy artifacts.
CI uses `python scripts/collect_metrics.py --check` to detect a stale README
metrics block.

Do not run `lab.provision --backend aws` as part of this quickstart. That
separate fixture-provisioning path creates deliberately misconfigured
resources, requires both explicit live-account confirmations, and must only be
used against a dedicated account you own. Ordinary demo and test commands use
moto and do not contact AWS.

Optional Checkov and Conftest binaries enable the external scanner integration
tests and `scan-iac`. Their installation and checksums are documented in
[`iac-scanning.md`](iac-scanning.md). Without them, those tests skip and IaC
scans return an error rather than a clean pass.

## 2. Run AWS posture scans

Install a scoped role following [`least-privilege.md`](least-privilege.md),
configure a named profile, then run:

```bash
python -m auditor.cli validate-policy
python -m auditor.cli audit --profile audit-readonly --region us-east-1 \
  --output json,html --output-dir reports --redact --fail-on high
```

Use `fleet-scan` only with an approved target-role file and source profile; it
assumes configured read-only roles and stores history locally. See
[`fleet-scanning.md`](fleet-scanning.md) for trust policies, local scheduling,
history permissions, and backup considerations. The scheduler runs on a
Unix-like host and skips overlap with a lock.

Do not interpret `UNKNOWN` or `ERROR` as clean. `UNKNOWN` means incomplete AWS
coverage or unavailable vulnerability data; inspect collection details and
resolve the permission, throttling, region, or data-source failure before
acting on absence of findings. See [`contracts.md`](contracts.md) for exit
codes and status precedence.

## 3. Run CI and Kubernetes guardrails

The pull-request workflow scans without AWS credentials. Configure the
repository variable `IAC_FAIL_ON` for the desired threshold. Fork PRs receive
annotations/artifacts but no SARIF upload. Same-repository PR SARIF is uploaded
by a separate trusted `workflow_run`; the scanning workflow has no
`security-events: write` permission. IaC failure and tool errors remain
non-green; do not add AWS credentials or OIDC to either workflow.

For admission testing, follow [`../deploy/gatekeeper/README.md`](../deploy/gatekeeper/README.md)
on the dedicated `kind-account-access-auditor-demo` cluster. The smoke test
uses dry-run Pods and refuses a nonlocal/unnamed context. It is not part of the
default suite; it was exercised separately on 2026-11-02.

## 4. Exceptions, remediation, and AI

- Keep exception owners, reasons, scopes, and expiry dates current. Expired
  exceptions re-expose the finding; exceptions do not remove evidence. See
  [`iac-scanning.md`](iac-scanning.md#thresholds-and-exceptions).
- Preview remediation and review the patch before opening a PR. The supported
  sandbox runs only on a temporary local copy and requires a passing rescan.
  AWS sandbox apply is not implemented or claimed. The user-approved
  [Stage 6 amendment](phase2-stage6-amendment.md) governs repository acceptance;
  see [`remediation.md`](remediation.md).
- Use `ai-analyze` only after reviewing the redacted data boundary. It is
  optional, has no AWS access, and never controls the gate. An explicit call
  can incur provider usage charges and provider retention settings apply; see
  [`ai-analyst.md`](ai-analyst.md).

## 5. Supply-chain release

For the local signed release, install the documented pinned Syft, Grype, and
Cosign versions. Generate the Cosign key outside the source tree, restrict
private-key permissions, keep its password out of shell history, and use a
fresh Grype database. Follow [`supply-chain.md`](supply-chain.md). The local
path signs and verifies files but skips transparency-log verification; obtain
the public key through a separate trusted channel. Do not describe this as an
identity-bound production release.

## 6. Cost, data retention, and recovery

- The offline benchmark and static site use no AWS account. Live audits make
  AWS API calls; review current AWS service pricing and organizational logging
  policies. The recorded moto request count is not a live cost estimate.
- GitHub Actions consumes the organization's runner/artifact allowance. IaC
  artifacts are configured for 14-day retention.
- AI is never called automatically. An explicit OpenAI request may incur model
  usage charges; `store: false` is not a promise of zero provider-side abuse
  monitoring retention.
- Local history, reports, exception files, and Cosign keys require host-level
  access control and backups. Protect backups to the same standard as the
  original data. If a credential or key may be exposed, revoke/rotate it using
  your organization's process, inspect audit logs, invalidate affected signed
  artifacts, and rebuild from a trusted checkout.

## 7. Phase 3 live operations

**Do not enable a later stage until the previous stage's live exit evidence is
reviewed.** Phase 3 AWS resources have not been deployed. The owner has
authorized only the plan-scoped write roles in [Phase 3 status](phase3-status.md);
the target scan role, public API, and Rin remain read-only toward AWS.

### Preflight and deployment sequence

1. Create or select an encrypted, versioned, access-controlled S3 state bucket
   and DynamoDB lock table before running Terraform. All four Terraform roots
   use an S3 backend with no default bucket or local-state fallback. Set
   PHASE3_TF_STATE_BUCKET, PHASE3_TF_STATE_REGION, and
   PHASE3_TF_STATE_LOCK_TABLE in each protected GitHub environment. Restrict
   state bucket and lock-table access separately from application roles.
2. Create the protected GitHub environments
   phase3-org-plan/apply, phase3-demo-bootstrap-plan/apply,
   phase3-demo-account-plan/apply, and
   phase3-control-plane-plan/apply. Each environment must set its
   PHASE3_TERRAFORM_ROLE_ARN and only the owner-approved stack values. Apply
   environments must require a reviewer and restrict deployments to main.
   Trust policies must match the exact repository, environment, main ref, and
   Phase 3 Terraform workflow. Follow [the OIDC bootstrap guide](phase3-bootstrap.md)
   for the one-time identity prerequisites and exact bootstrap role policies.
   The demo bootstrap roles have access only to their Terraform state and the
   two named deployment roles; the workflow does not assume
   OrganizationAccountAccessRole.
3. Fill only owner-approved account, state, estimate, cap, alert, and provider
   values in protected environment variables or secrets. Never store those
   values in tracked files. Keep scan, API, and Rin roles read-only toward AWS.
4. Build and inspect the sanitized web bundle and Lambda ZIP locally:

       python scripts/build_phase3_web.py
       python scripts/package_phase3_lambdas.py

   The public bundle contains only the allowlisted fixture profile and console
   assets. Do not copy raw reports or private scan output into the public
   bucket.
5. Dispatch Phase 3 Terraform from main, choose one stack under
   infra/phase3/, and leave apply unchecked for the first run. The roots are
   infra/phase3/org, infra/phase3/demo-bootstrap, infra/phase3/demo-account,
   and infra/phase3/control-plane. Review the saved human-readable plan artifact
   and its account/resource boundary. The apply job uses the same run's
   checksum-verified saved plan and waits for the apply environment reviewer.
   Terraform 1.9.8 and the S3 backend are pinned; the workflow has no local
   state fallback.
6. Apply stacks in order: org creates the demo OU/account/SCP; demo-bootstrap
   creates the demo-account scan plan/apply roles; demo-account creates the
   empty demo resources, CloudTrail, and read-only target role; control-plane
   creates the Fargate control plane. The scan schedule, public stages, and Rin
   remain disabled by default. After the control-plane stack creates ECR, run
   the protected Phase 3 scan image workflow and review its verified digest.
   Enable the scan pipeline and schedule only after the image and Stage 1 plan
   are reviewed. Enable each later stage only after the preceding live gate,
   cost estimate, and evidence are reviewed. Do not fill missing values with
   guesses.

CI runs pinned Terraform formatting and backend-disabled validation without
AWS credentials. It does not replace protected AWS plan review or live
acceptance.

### Provider key and Rin controls

- Rin is disabled unless the platform flag, provider secret, approved model,
  current input/output rates, monthly provider budget, positive daily cap, and
  a numeric published Guardrail ARN/version are configured. A2 is false, so
  model generation uses an external-provider path with Bedrock Guardrails.
- Enter or rotate the provider key through the approved Secrets Manager
  interface. Do not put it in Terraform variables, source files, shell
  arguments, logs, or browser code. Confirm provider retention, billing, and
  key-rotation requirements before enabling Rin.
- Publish and adversarially test the exact Bedrock Guardrail version before
  enabling Rin. It must assess redacted input and validated output for prompt
  attacks, off-scope topics, and sensitive data. The Rin role may call only
  `bedrock:ApplyGuardrail` on that ARN; it cannot invoke a Bedrock model.
- Review Bedrock invocation logging before launch. The Rin service does not
  log prompts or answers; account-level logging must not retain message text
  beyond the approved retention boundary. Include two Guardrail evaluations
  per request in the AWS estimate.
- The request path rechecks the kill-switch flag before reading the provider
  secret. It sends one selected public finding and a bounded question to the
  input Guardrail, calls the external model only after a pass, and filters the
  validated answer through the output Guardrail. It has no raw scan evidence
  or target-account scanning tools.
- A daily-limit alert reports aggregate usage only. At the monthly AWS 100%
  notification, the budget topic atomically disables Rin and marks the console
  static. Budget delivery can be delayed and is not a hard spend limit.

### Kill switch and recovery

1. Check the alert and confirm the feature table has rin_enabled=false and
   static_mode=true. Verify the public API still serves its last-good
   sanitized scan and reports static mode; verify the website shows fixture
   mode and Rin does not call the provider.
2. Rehearse with an isolated Phase 3 stack and the owner-approved publisher for
   the exact budget SNS topic. The kill-switch handler ignores message content
   and accepts only the configured topic. Do not rehearse by changing the
   public production cap or modifying the target scan role.
3. Before recovery, review AWS and provider actuals, resolve the cause, verify
   key/model/budget settings, and re-run the security and resilience checks.
   Re-enable only through a reviewed Terraform replacement of the platform
   configuration item. Routine plans ignore item changes so a normal apply
   cannot silently undo a kill switch. Keep the schedule, Rin, and public
   stages disabled if cost or evidence is uncertain.

The kill-switch update is atomic. A request already inside the external
provider call cannot be canceled; its maximum input and output are bounded.
Record the measured switch and recovery times in docs/evidence after a live
rehearsal. No live kill-switch test or timing is claimed yet.

## 8. Unsupported scope

The AWS auditor does not resolve permissions boundaries, SCPs, or session
policies; inspect root account controls, IAM password policy, S3 object-level
settings, CloudTrail event selectors or log contents; or scan more than the
documented services. IaC scanning does not render Helm templates or accept
Terraform `.tf.json`. Supply-chain scanning accepts local saved artifacts, not
live registry images. There is no hosted multi-tenant service or AWS
remediation apply. Phase 3 managed history, scheduled scans, and a public
dashboard are implemented in Terraform but have not been deployed or accepted;
see [`phase3-status.md`](phase3-status.md).
