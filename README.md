# AWS Account & Access Configuration Auditor

A read-only Python tool that inspects an AWS account's IAM, S3, and CloudTrail
configuration through Boto3 and reports prioritized findings as JSON, CSV, a
terminal summary, and ticket-ready text.

The tool reports **observed configuration**. It does not attempt to prove
exploitability, and it does not modify anything in the account — a property
enforced by tests and by a runtime guard, not just promised here.

**Python 3.11+ · Boto3 · pytest · 14 rules · 5-tier severity model · CIS AWS Foundations Benchmark v3.0.0**

---

## Measured, not asserted

Every number below comes from an artifact in `results/`, produced by the
commands named beside it. `python scripts/collect_metrics.py` regenerates the
table from those artifacts; nothing here is typed in by hand.

| Metric | Value | Evidence |
| --- | ---: | --- |
| Security rules | 14 | `auditor/rules/registry.py` |
| Findings against the deliberately misconfigured test account | **25** | `results/aws_audit_results.json` |
| Detection rate (expected vs actual) | **100%** — 25 TP / 0 FN / 0 FP | `results/expected_vs_actual.json` |
| Offline fixture cases | **98** | `results/fixture_manifest.json` |
| Tests passing | **579 / 579** | `pytest` |
| Detection-code coverage (branch-inclusive) | **99.87%** | `results/coverage.json` |
| Whole-package coverage (branch-inclusive) | 99.61% | `results/coverage.json` |
| Rules with a defensible CIS mapping | **11 / 14** (v3.0.0) | `compliance/cis_mapping.json` |
| Self-audit of the tool's own IAM policy | **PASS** | `python -m auditor.cli validate-policy` |
| API calls for a full scan of the test account | 101 in 0.28s | `results/aws_audit_results.json` |

> **What the test account is.** The deliberately misconfigured account is
> emulated in-process by [moto](https://github.com/getmoto/moto), not a live AWS
> account, and the report says so in its own metadata. Everything on the
> auditor's side of the endpoint is real: real boto3 clients, real botocore
> signing and parsing, real paginators, real AWS error codes. The same
> provisioning code targets a real test account with `--backend aws`.
> See [docs/test-environment.md](docs/test-environment.md).

---

## The 14 rules

| ID | Rule | Service | Severity | CIS v3.0.0 |
| --- | --- | --- | --- | --- |
| IAM-001 | Console-enabled user lacks MFA | IAM | HIGH | 1.10 |
| IAM-002 | Active access key past the rotation threshold | IAM | HIGH / MEDIUM | 1.14 |
| IAM-003 | Dormant or disabled access key | IAM | MEDIUM / LOW | 1.12 |
| IAM-004 | Policy allows `Action: "*"` on `Resource: "*"` | IAM | CRITICAL | 1.16 |
| IAM-005 | Policy allows service-wide wildcards on all resources | IAM | HIGH / LOW | *partial* |
| IAM-006 | Programmatic-only user without MFA (inventory) | IAM | INFO | — |
| S3-001 | Public Access Block not fully enabled | S3 | MEDIUM | 2.1.4 |
| S3-002 | Bucket ACL grants a global group | S3 | CRITICAL / LOW | 2.1.4 |
| S3-003 | Bucket policy allows an anonymous principal | S3 | CRITICAL / MEDIUM / LOW | 2.1.4 |
| S3-004 | No explicit bucket encryption configuration | S3 | MEDIUM | *partial* |
| CT-001 | No CloudTrail trail configured | CloudTrail | HIGH | 3.1 |
| CT-002 | No multi-region trail | CloudTrail | MEDIUM | 3.1 |
| CT-003 | Log file validation disabled | CloudTrail | MEDIUM | 3.2 |
| CT-004 | Trail not logging, or reporting a delivery error | CloudTrail | HIGH | 3.1 |

```bash
python -m auditor.cli list-rules          # the table above, with titles
python -m auditor.cli list-rules --json   # full metadata for every rule
```

Severity is this project's own prioritization model, not a CVSS score or an AWS
risk rating. It is deterministic by construction: each rule declares in the
registry which tiers it may emit, and `Finding.build` raises if a rule tries to
emit any other. See [docs/cis-mapping.md](docs/cis-mapping.md) for the mapping
rationale, control by control.

---

## Install and run

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m auditor.cli audit                       # scan everything, JSON + CSV
python -m auditor.cli audit --services s3 --output json
python -m auditor.cli audit \
    --services iam,s3,cloudtrail \
    --output json,csv,tickets \
    --output-dir reports/ \
    --severity high \
    --exclude-rules IAM-006 \
    --profile audit-readonly \
    --region us-east-1 \
    --redact \
    --fail-on critical
```

| Command | Purpose |
| --- | --- |
| `audit` | Scan an account and write reports |
| `list-rules` | The rule catalogue, with severities and CIS mappings |
| `list-permissions` | The code → IAM action → policy statement inventory |
| `validate-policy` | Self-audit: run the wildcard rules against an IAM policy |
| `generate-policy` | Regenerate the least-privilege policy from the code |

Exit codes: `0` success, `1` findings at or above `--fail-on` (or a failed
`validate-policy`), `2` the scan could not run.

### Terminal output

```
AWS Account & Access Configuration Auditor
==========================================

Account: 123456789012
Region:  us-east-1
Caller:  arn:aws:sts::123456789012:assumed-role/auditor-readonly/session

Scanning IAM..................DONE
Scanning S3...................DONE
Scanning CloudTrail...........DONE

Findings
--------
CRITICAL   4
HIGH       5
MEDIUM     11
LOW        3
INFO       2
TOTAL      25

SEVERITY   RULE      CIS     RESOURCE                           TITLE
CRITICAL   IAM-004   1.16    user:lab-admin-console-nomfa/lab-… IAM policy grants unrestricted actions on all resources
CRITICAL   S3-002    2.1.4   lab-public-assets                  Bucket ACL grants public access
CRITICAL   S3-003    2.1.4   lab-public-assets                  Bucket policy grants access to a public principal
CRITICAL   S3-003    2.1.4   lab-tls-only-public                Bucket policy grants access to a public principal
HIGH       CT-004    3.1     lab-single-region-trail            CloudTrail trail exists but is not currently logging
...

Resources scanned: cloudtrail_trails=1, iam_access_keys=3, iam_groups=1, iam_policies=5, iam_roles=2, iam_users=5, s3_buckets=8
API calls: 101   Duration: 0.282s
```

---

## Architecture

```
AWS ──► collectors ──► normalization ──► rule engine ──► findings ──► reporters
        (boto3 only)   (pure functions)   (no boto3)      (+severity,   json / csv
                                                           evidence,    tickets /
                                                           CIS mapping) terminal
```

```
auditor/
├── cli.py            subcommands, orchestration, exit codes
├── config.py         YAML merged over defaults, with validation
├── aws_session.py    session construction, credential errors, retry config
├── readonly.py       botocore hook that blocks undeclared operations
├── permissions.py    the API inventory the IAM policy is generated from
├── severity.py       the 5-tier model, in one place
├── compliance.py     loads compliance/cis_mapping.json
├── redaction.py      optional masking of identifiers in a finished report
├── collectors/       which API calls to make, and how to survive their failures
├── normalize/        what a response *means* as data (pure, no boto3)
├── rules/            registry.py (metadata) + the detection logic (no boto3)
├── models/           Finding, report assembly
└── reporters/        json, csv, tickets, terminal
```

Four separations do the work:

**Collection is separate from evaluation.** Collectors import boto3; rules do
not. That is what lets all 14 rules run against 98 fixture cases with no AWS
access, and it is asserted by a test rather than left as a convention.

**Fetching is separate from interpreting.** Collectors decide which calls to make
and how to handle their failures; `normalize/` decides what a response means.
The awkward parts of the real API — a null `LocationConstraint` meaning
`us-east-1`, a missing `LastUsedDate` meaning "never used", an empty-string
delivery error meaning "no error yet" — are pinned in tests as pure functions.

**Static rule metadata is separate from per-finding data.** Title, rationale,
remediation, allowed severities, and CIS mapping live once in
`rules/registry.py`. A rule supplies only the resource, the chosen tier, the
evidence, and a description written from that evidence.

**Detection is separate from publishing.** `redaction.py` masks access key IDs in
a finished report for sharing; it runs after evaluation and cannot change what
was found.

---

## Judgement calls worth explaining

**Unknown is not clean.** A denied `GetLoginProfile` leaves console access
`None`, and the MFA rules stay silent rather than guessing. A denied
`DescribeTrails` sets `trails_readable: False`, and CT-001 does *not* fire —
absence of data is not evidence of absence of a trail. Collection errors are
reported in their own section, with the permission likely missing, so a scan
that read nothing cannot look like a clean account.

**A condition is not automatically a mitigation.** A public bucket policy
conditioned on `aws:SourceIp` is downgraded to MEDIUM for review. One
conditioned only on `aws:SecureTransport` stays CRITICAL — requiring HTTPS
restricts the protocol, not the caller. The lab contains both cases
(`lab-partner-share`, `lab-tls-only-public`) so the distinction is tested rather
than argued.

**Blocked is not absent.** A public ACL that `IgnorePublicAcls` currently
neutralises is LOW, not silence: it becomes live the moment that setting is
removed. Likewise a public policy under `BlockPublicPolicy`.

**`Deny` is not a grant.** `Deny "*" on "*"` is one of the safest statements a
policy can contain, and reporting it as an over-permission would be a false
positive on good practice.

**Policy shape, not effective permissions.** IAM-004 says the document grants
unrestricted actions. It does not say the principal can use them: the tool does
not evaluate SCPs, permissions boundaries, or session policies, and the wording
reflects that.

**Configuration state and operational state are different questions.** A trail
existing is not a trail logging (CT-003 vs CT-004). A key existing is not a key
being used (IAM-002 vs IAM-003).

**Missing encryption configuration is not "unencrypted."** S3 has applied SSE-S3
by default since January 2023, so S3-004 reports the absence of an explicit,
auditable configuration rather than claiming objects are in plaintext — and it
is recorded as `partial` in the CIS mapping for the same reason.

**AWS-managed breadth is not customer misconfiguration.** A `s3:*` grant in an
inline policy is HIGH; the same shape in an AWS-managed policy is LOW, because
its contents are AWS-maintained and reviewable. `AdministratorAccess` is still
CRITICAL under IAM-004 either way, which is what CIS 1.16 asks for.

---

## Read-only, proven

Three independent controls, each with a test behind it:

**1. No write call exists in the source.** The set of write operations is derived
from **botocore's own service models** — every operation of `iam`, `s3`,
`cloudtrail`, and `sts` that is not a Get/List/Describe/Head — and no file under
`auditor/` references one. Not a hand-written list of bad words that goes stale.

**2. The IAM policy grants no write action.**
`policies/auditor-readonly-policy.json` is generated from `auditor/permissions.py`
and a test fails if the committed file drifts from the code. It contains 30
explicit read actions, no `"*"`, no `service:*`, and six of its ten statements
are scoped to a resource pattern rather than `*`.

**3. A runtime guard blocks anything undeclared.** `auditor/readonly.py` registers
a botocore `before-call` hook that rejects any operation missing from the
inventory, before the request is signed and sent:

```python
>>> session.client("iam").create_user(UserName="x")
ReadOnlyViolation: Blocked 'iam:CreateUser': the auditor is read-only ...
```

It is an allowlist, not a verb heuristic, so it also catches a *read* call the
project never declared. The guard doubles as the API-call counter in the report.

Also checked by the suite: no credential material is committed (access key ID
patterns, secret-key assignments, private keys), the auditor never imports the
`lab/` package that does make write calls, and no permission is granted that no
collector needs.

### Self-audit

```console
$ python -m auditor.cli validate-policy
Self-audit of policies/auditor-readonly-policy.json
  statements:                  10
  IAM-004 (Action * on *):     PASS
  IAM-005 (service-wide on *): PASS
  declared calls read-only:    PASS (All declared API operations are read-only.)

RESULT: PASS
```

The result means something only because the detector was not weakened to get it.
Two tests feed the same checker policies that *should* fail — an
`AdministratorAccess`-shaped one and a `service:*` one — and assert that they do.
The policy passes because it is genuinely least-privilege. Details in
[docs/least-privilege.md](docs/least-privilege.md).

---

## Testing

**579 tests, 98 offline fixture cases, 99.87% branch coverage of the detection
code.** No test makes a network call; the AWS environment is neutralised for the
whole session in `tests/conftest.py`.

The fixture suite is the centre of it. A *case* in `tests/cases/` is normalized
AWS state plus the **complete** set of findings the engine must produce from it —
rule, resource, and tier for each, and nothing else. Asserting the whole output
rather than "at least one finding fired" is what catches a rule that fires twice,
fires on the wrong resource, or fires at the wrong tier.

| Category | Cases | What it pins |
| --- | ---: | --- |
| `clean` | 17 | Correct configuration produces silence |
| `vulnerable` | 19 | The misconfiguration the rule exists to find |
| `severity` | 6 | The same issue at a different tier |
| `edge` | 39 | Threshold boundaries, unknown state, absent optional fields |
| `malformed` | 8 | Responses that are wrong, not merely bad |
| `multi` | 9 | Several resources at once, for per-resource attribution |

By service: 48 IAM, 35 S3, 15 CloudTrail. Every rule has at least three cases,
and the suite fails if any rule lacks both a case that fires it and a case that
must keep it silent. `results/fixture_manifest.json` is generated from the
registry, which is where the count comes from.

Beyond the fixture cases: collector failure paths under stubbed clients
(AccessDenied, throttling, pagination, malformed responses), the happy path
through real boto3 clients against an emulated account, reporter schemas,
configuration validation, every config toggle, CLI parsing and exit codes, the
security properties above, and the end-to-end lab benchmark.

---

## Reproducing the numbers

From a clean checkout, offline:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

pytest -q                                             # 579 tests
pytest --cov=auditor --cov-report=term-missing \
       --cov-report=json:results/coverage.json        # coverage
python -m lab.run_benchmark                           # the 25-finding benchmark
python -m auditor.cli validate-policy                 # self-audit
python scripts/collect_metrics.py                     # the evidence table
```

`lab/run_benchmark.py` exits non-zero if any expected finding was missed. That is
deliberate: a missed expectation is a scanner defect, and the fix is to improve
the rule and re-run, never to delete the expectation.

Against a real, dedicated test account (creates public buckets and
over-permissioned principals — never point this at anything you care about):

```bash
export AUDITOR_LAB_ALLOW_REAL_AWS=yes
python -m lab.provision --backend aws --suffix "$(openssl rand -hex 4)" --i-own-this-account
python -m auditor.cli audit --profile my-test-account --redact
```

CI runs the whole offline workflow on every push, with no AWS credentials
configured anywhere in the workflow.

---

## Configuration

Thresholds live in `config.yaml`, not in rule source, and every key is validated
on load — an unknown key or a threshold written as `"90"` is reported rather
than silently ignored, because a typo'd threshold is a rule that quietly stops
firing.

```yaml
iam:
  access_key_max_age_days: 90        # CIS 1.14
  access_key_critical_age_days: 180  # project escalation tier
  access_key_unused_days: 45         # CIS 1.12
  require_mfa_for_console_users: true
```

Use `--strict-config` to fail on a bad configuration instead of warning. Anything
omitted falls back to `auditor/config.py`.

---

## Known limitations

These are gaps in scope, stated rather than hidden:

- **Permissions boundaries, SCPs, and session policies are not resolved.** The
  tool reports policy shape, not effective permissions.
- **Root-account checks are absent** (CIS 1.4–1.6). They need
  `iam:GetAccountSummary` and the credential report, which are not in the
  permission inventory.
- **The IAM password policy is not inspected** (CIS 1.8–1.9).
- **Service-linked roles are skipped.** Their policies are AWS-defined and not
  editable, so flagging them would be noise; the count skipped is reported.
- **Object-level S3 configuration is out of scope** — per-object ACLs, object
  lock, MFA Delete.
- **CloudTrail coverage stops at trail configuration and status** — not event
  selectors, CloudWatch metric filters, or log content.
- **Single region per run.** CloudTrail is queried in the session's region;
  multi-region posture is inferred from `IsMultiRegionTrail`.

Adding any of these means adding its read permission to
`auditor/permissions.py`, which regenerates the IAM policy — which is why the
scope is deliberate rather than accidental.

---

## Security notes for this repository

Reports contain account IDs, usernames, and bucket names, so `reports/` is
gitignored along with `.env`, `.aws/`, and credential files. The committed
artifacts under `results/` are written with access key IDs masked, and a test
scans the whole repository for credential material on every run. Committed
samples use AWS's documentation placeholder account, `123456789012`.

Never commit access keys, secret keys, session tokens, or real account data.

## License

MIT — see [LICENSE](LICENSE).
