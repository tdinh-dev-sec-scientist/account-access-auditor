# The controlled misconfigured test environment

## What it is, precisely

`lab/` provisions an AWS account containing deliberately broken IAM, S3, and
CloudTrail configuration, then the auditor scans it and the result is scored
against a manifest of what *should* have been found.

**The account is emulated in-process by [moto](https://github.com/getmoto/moto),
not a live AWS account.** That distinction matters, so it is stated in the report
metadata itself:

```json
"environment": "lab/misconfigured (moto emulated account, not a live AWS account)"
```

What is real: the auditor's own session, its boto3 clients, botocore's request
signing and response parsing, the paginators, the AWS error codes
(`NoSuchEntity`, `NoSuchBucketPolicy`, `ServerSideEncryptionConfigurationNotFoundError`),
and every line of collection, normalization, rule evaluation, and reporting.
What is emulated is the service behind the endpoint.

The same provisioning code runs against a real AWS test account
(`--backend aws`), behind two independent confirmations, because it creates
public buckets and over-permissioned principals.

## The account, and why each resource is there

Every resource name starts with `lab-` so it is unmistakable as test material.
The account ID is `123456789012`, AWS's documentation placeholder. No real
credentials, account identifiers, or data appear anywhere.

### IAM

| Resource | Deliberate misconfiguration | Rules it should trigger |
| --- | --- | --- |
| `lab-admin-console-nomfa` | Console login profile, no MFA, inline `Action: "*"` on `Resource: "*"` | IAM-001 (HIGH), IAM-004 (CRITICAL) |
| `lab-svc-stale-keys` | Programmatic only, key aged 400 days, never used | IAM-006 (INFO), IAM-002 (HIGH), IAM-003 (MEDIUM) |
| `lab-svc-rotating` | Programmatic only, key aged 120 days, used 5 days ago | IAM-006 (INFO), IAM-002 (MEDIUM) — and **not** IAM-003 |
| `lab-contractor-offboarded` | Console **with** MFA, leftover Inactive key | IAM-003 (LOW) — and **not** IAM-001 |
| `lab-developers` (group) | Customer-managed policy with `s3:*`, `ec2:*` on `*`, two members | IAM-005 (HIGH) once, at the group |
| `lab-ci-deploy-role` (role) | Inline `iam:*` on `*` | IAM-005 (HIGH) |
| `lab-clean-user` | **Negative control**: MFA, no keys, scoped policy containing a `Deny` | nothing |
| `lab-readonly-role` | **Negative control**: scoped inline policy | nothing |

### S3

| Bucket | Deliberate misconfiguration | Rules it should trigger |
| --- | --- | --- |
| `lab-public-assets` | No Public Access Block, public-read ACL, unconditional public policy, no encryption config | S3-001, S3-002 (CRITICAL), S3-003 (CRITICAL), S3-004 |
| `lab-partner-share` | Public principal narrowed by `aws:SourceIp` | S3-001, S3-003 (**MEDIUM**) |
| `lab-tls-only-public` | Public principal with only `aws:SecureTransport` | S3-001, S3-003 (**CRITICAL**) |
| `lab-latent-acl` | Public ACL, but `IgnorePublicAcls` on | S3-001, S3-002 (**LOW**) |
| `lab-blocked-public-policy` | Public policy, all four PAB settings on | S3-003 (**LOW**) |
| `lab-unencrypted-logs` | Correct public-access posture, no encryption config | S3-004 only |
| `lab-clean-data` | **Negative control**: PAB on, SSE-S3, private | nothing |
| `lab-trail-logs` | **Negative control**: CloudTrail delivery policy with a *Service* principal | nothing |

The three S3 severity cases are the point of the design. A scanner that reports
every public bucket policy as CRITICAL is unusable in a real account; one that
downgrades any *conditional* public policy misses `lab-tls-only-public`, which
is open to the internet with a condition that restricts nothing but the
protocol. The lab contains both traps.

### CloudTrail

| Resource | Deliberate misconfiguration | Rules |
| --- | --- | --- |
| `lab-single-region-trail` | Single-region, log file validation off, created but never started | CT-002, CT-003, CT-004 |

### The second profile

CT-001 ("no trail configured") cannot coexist with CT-002/003/004, which all
require a trail to exist. Rather than leave one rule unexercised against a live
API, the lab provisions a second account, `no-trail`, containing one locked-down
bucket and no trail at all. Across the two profiles, **all 14 rules fire**.

## Time travel

An access key aged 400 days cannot be created on demand. Under the moto backend
the provisioner backdates the emulator's stored timestamp directly. That is a
property of the fixture, not of the auditor: the key's age still reaches the
rules through `iam:ListAccessKeys` like any other key.

Against a real account there is no equivalent, so the provisioner logs a warning
saying the age-dependent expectations will not hold until enough time has
passed, rather than pretending they will.

## Running it

```bash
python -m lab.run_benchmark
```

Provisions both profiles, audits each, scores the result, and writes:

| Artifact | Contents |
| --- | --- |
| `results/aws_audit_results.json` | Full report, primary profile |
| `results/aws_audit_results.csv` | The same findings, flat |
| `results/aws_audit_tickets.txt` | The same findings as ticket bodies |
| `results/aws_audit_results_no-trail.json` | Full report, `no-trail` profile |
| `results/expected_vs_actual.json` | TP / FN / FP per profile |
| `results/benchmark_report.md` | The human-readable version |

The committed artifacts are written with access key IDs masked
(`auditor/redaction.py`), because they live in a repository. Redaction runs
after detection and changes nothing that was found.

**The exit code is non-zero if any expected finding was missed.** That is
deliberate: a missed expectation is a scanner defect, and the fix is to improve
the rule and re-run, never to delete the expectation.

## Against a real AWS test account

Only ever point this at a dedicated, empty account you own.

```bash
export AUDITOR_LAB_ALLOW_REAL_AWS=yes
python -m lab.provision --backend aws --profile misconfigured \
    --suffix "$(openssl rand -hex 4)" --i-own-this-account
python -m auditor.cli audit --profile my-test-account --redact
```

The `--suffix` is required because S3 bucket names are globally unique. Both the
environment variable and the flag are needed; either alone refuses to run.
