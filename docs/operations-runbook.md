# Operations runbook

This runbook covers the supported local and read-only AWS paths. It does not
provision cloud infrastructure, deploy production changes, or turn the
read-only auditor into an AWS writer. Check [Phase 2 status](implementation-status.md)
for criteria that remain unmet.

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
  The plan's AWS sandbox apply remains unmet by design; see
  [`remediation.md`](remediation.md).
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

## 7. Unsupported scope

The AWS auditor does not resolve permissions boundaries, SCPs, or session
policies; inspect root account controls, IAM password policy, S3 object-level
settings, CloudTrail event selectors or log contents; or scan more than the
documented services. IaC scanning does not render Helm templates or accept
Terraform `.tf.json`. Supply-chain scanning accepts local saved artifacts, not
live registry images. There is no hosted multi-tenant service, AWS-managed
history/dashboard, AWS scheduled orchestration, or AWS remediation apply.
