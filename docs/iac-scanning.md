# Local IaC and policy scanning

`auditor scan-iac` scans local files and directories without creating a Boto3
session or using AWS credentials. It combines Checkov's selected upstream
checks, the project's Conftest/Rego policy pack, and the existing IAM wildcard
rules. Reports use the versioned finding and scan-run contracts.

## Run

Install Checkov in an isolated tool environment using
[`requirements-scanners.txt`](../requirements-scanners.txt), and install
[Conftest v0.71.1](https://github.com/open-policy-agent/conftest/releases/tag/v0.71.1)
for your platform. Verify the downloaded archive against the `checksums.txt`
file published with that release. Put both tools on `PATH`. The implementation
is tested with Checkov 3.4.3 and Conftest 0.71.1 (OPA 1.21.1). Reports record
the versions actually invoked.

The default Docker image does not bundle either optional scanner executable.
Install them in the image or run `scan-iac` from an environment where both are
on `PATH`.

```bash
python -m auditor.cli scan-iac infra/ iam/policy.json
python -m auditor.cli scan-iac charts/rendered.yaml --helm-rendered --output reports/iac.json
python -m auditor.cli scan-iac infra/ --fail-on HIGH --sarif-output reports/iac.sarif
```

Use `--helm-rendered` when the YAML files are rendered Helm output. Helm chart
templates are not rendered by this command. Direct files support Terraform
`.tf` HCL, IAM policy JSON, Kubernetes YAML/JSON, and rendered Helm
YAML. Terraform JSON syntax is currently rejected because this adapter has not
validated the Checkov configuration parser for `.tf.json` input. Directory
scans recurse through supported files and ignore unrelated file extensions. A
malformed supported file or unavailable scanner is an `ERROR`, never a clean
pass.
Pass a directory when Terraform resources are split across files so Checkov's
graph checks can evaluate their relationships. A direct `.tf` file scan uses
only that file's Terraform context.

Checkov supports file/framework selection and JSON output; this adapter invokes
it with `--skip-download`, `--skip-results-upload`, and `--soft-fail`, then
applies this project's own gate and exit codes. See the [Checkov CLI reference](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html).
Conftest runs the bundled Rego pack locally with JSON output and no policy
updates; see [Conftest documentation](https://www.conftest.dev/).

## Controls in this release

Checkov is intentionally limited to the reviewed baseline IDs below. A finding
from any selected Checkov or project policy control is retained in the report.
The default `--fail-on INFO` preserves the Stage 2 behavior and fails on every
finding; choose `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` to set a less
strict gate. The selected threshold and per-finding gate result are recorded in
the report.

| Input | Checkov controls | Project controls |
| --- | --- | --- |
| Terraform | `CKV_AWS_20` public-read ACL, `CKV_AWS_21` versioning, `CKV_AWS_145` KMS encryption, `CKV2_AWS_6` public-access block | `IAC-TF-001` public-read S3 ACL |
| Kubernetes / rendered Helm | `CKV_K8S_20` privilege escalation, `CKV_K8S_29` security context, `CKV_K8S_43` image digest | `IAC-K8S-001` privileged containers, `IAC-K8S-002` `latest` image tag, `IAC-K8S-003` host network/process/IPC namespaces |
| IAM policy JSON | — | Existing `IAM-004` and `IAM-005` wildcard policy rules |

The Kubernetes Rego checks cover Pods and common workload pod templates
(Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob). Other resource
kinds still receive the selected Checkov checks. Raw Helm templates and
container image/SBOM scanning are outside this stage.

## Normalization and failures

Project severity mapping is deterministic:

- A recognized Checkov or Rego severity maps case-insensitively to the same
  project tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- Missing or unrecognized scanner severity maps to `MEDIUM`; the original
  scanner severity remains in `source_severity` when supplied.
- IAM findings keep the existing IAM rule severity.

Findings retain scanner name, upstream rule/query ID, canonical control ID,
resource reference where available, relative source file and line when
available, and scanner evidence. Checkov source evidence includes check name,
evaluated keys, and result state; raw code blocks and evaluated resource bodies
are omitted so a hard-coded credential in input is not copied into the report.
Conftest evidence includes the policy message, namespace, and query.

Fingerprints use canonical control ID, source type, and a stable resource
reference; when no resource reference exists they use source file and optional
line. Only duplicates from the same scanner, control, source type, and identity
are merged. Their evidence observations are retained. Terraform, Kubernetes,
Helm, and IAM records remain separate source types.

The local gate fails on findings at or above `--fail-on` (exit 1). Missing
tools, invalid scanner output, malformed inputs, invalid exception files, and
policy evaluation errors produce `ERROR` (exit 2). A complete scan with no
gating findings passes (exit 0). AWS collection is not part of this command;
scanner subprocesses have AWS credentials/configuration removed and EC2
metadata lookup disabled.

## Thresholds and exceptions

`--exceptions exceptions.yaml` applies exact, time-bounded exceptions. Each
record needs an owner, reason, creation time, expiry time, and one exact scope:
a 16-character finding fingerprint, or a control ID plus an exact resource
reference or source file. Wildcards, path traversal, unknown fields, duplicate
IDs, and timestamps without a timezone are rejected. An invalid file makes the
scan `ERROR` and cannot suppress a finding.

```yaml
exceptions:
  - id: EXC-2026-014
    control_id: IAC-K8S-001
    source_file: workloads/vendor-api.yaml
    owner: platform-team
    approver: security-lead
    reason: Vendor runtime requires this setting during migration.
    created_at: "2026-10-01T00:00:00Z"
    expires_at: "2026-12-01T00:00:00Z"
```

Active exceptions lower only their matching finding's gate result. Findings
and evidence remain in JSON and SARIF. Expired and unmatched exceptions also
remain in the report; expired records do not suppress findings. Review
`contract.exceptions` and each finding's `exceptions` array.

## Pull request and admission enforcement

The [IaC guardrails workflow](../.github/workflows/iac-guardrails.yml) runs
credential-free scans on pull requests. It emits escaped annotations, retains
JSON and SARIF artifacts, and uses a separate trusted `workflow_run` to upload
SARIF for same-repository pull requests. The scanning workflow has no
`security-events: write` token permission and uses no AWS credentials or OIDC
role. Fork pull requests still receive annotations and artifacts; they do not
receive SARIF upload.
Set the repository variable `IAC_FAIL_ON` to adjust the workflow threshold;
the default is `MEDIUM`. `--exclude` patterns are applied to discovery and
Checkov's directory scan, so the deliberately vulnerable scanner fixture and
Gatekeeper admission sample are excluded from the repository scan.

The Gatekeeper demo is documented in
[`deploy/gatekeeper/README.md`](../deploy/gatekeeper/README.md). It is limited
to a named local demo cluster and denies privileged Pods or Pods using the
`latest` image tag. The auditor receives no Kubernetes credentials. Its
admission smoke test uses server-side dry runs and refuses any context other
than `kind-account-access-auditor-demo`.

`annotate-iac REPORT.json` emits GitHub workflow annotations, and
`gate-iac REPORT.json` returns the scan exit code stored in the report. These
commands let CI publish feedback even when the scan itself fails.

## Fixture coverage

`tests/fixtures/iac/` contains clean and vulnerable cases for Terraform, IAM,
Kubernetes, and rendered Helm. The integration tests invoke real Checkov and
Conftest when installed; they skip only when either external binary is absent.
