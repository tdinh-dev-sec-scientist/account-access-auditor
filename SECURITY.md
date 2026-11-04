# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/tdinh-dev-sec-scientist/Vorrin/security/advisories/new)
rather than in a public issue. Include:

- the affected file, command, or workflow;
- steps to reproduce, using the emulated lab account where possible;
- the impact you expect (for example, a write call to AWS, a credential or
  account identifier reaching a report, or a bypassed gate).

Do not include real AWS credentials, account IDs, or scan output from an
account you do not own.

## Supported versions

Only the latest commit on `main` is supported.

## Security model in brief

- **Read-only AWS access.** Collectors call only `Get*`, `List*`, and
  `Describe*` operations, plus `sts:GetCallerIdentity` and, for fleet scans,
  `sts:AssumeRole` into read-only target roles. A runtime guard blocks any
  undeclared operation, `tests/test_security_properties.py` checks the source
  for write calls, and CI fails if `policies/auditor-readonly-policy.json`
  drifts from the permissions the code declares.
- **No stored credentials.** The tool uses the standard boto3 credential chain.
  No long-lived AWS keys are stored in the repository or CI: the test and
  benchmark jobs run against an in-process Moto emulation, and the Phase 3
  deployment workflows use short-lived GitHub OIDC role credentials.
- **Untrusted input.** AWS responses, IaC files, remediation plans, and saved
  reports are treated as untrusted and validated before use.
- **Redaction.** `--redact` and `--redact-account-id` mask access key IDs and
  account IDs before reports leave the account. The public demo publishes only
  allowlisted, redacted fields.

The full threat model is in [docs/threat-model.md](docs/threat-model.md) and
the IAM permissions are explained in
[docs/least-privilege.md](docs/least-privilege.md).
