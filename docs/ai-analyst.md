# Optional AI analyst

`ai-analyze` is an advisory sidecar for an already-saved scan report. It is
never part of the scan path: a normal AWS or IaC scan remains deterministic and
offline with respect to AI providers. The command creates no AWS session and
does not change the report, its findings, severity, scan status, gate status, or
the original scan exit code.

## Explicit provider call

OpenAI is the only provider currently implemented. A request is made only when
the user explicitly runs `ai-analyze` and supplies a model and
`OPENAI_API_KEY`:

```bash
export OPENAI_API_KEY="<provider key>"
export AUDITOR_AI_MODEL="<model name>"
python -m auditor.cli ai-analyze --report reports/iac-report.json
```

`--model` overrides `AUDITOR_AI_MODEL`; `OPENAI_MODEL` is the final model
fallback. The key is read from the environment and is not included in the
prompt, output, or logs. The implementation uses the fixed HTTPS Responses API
endpoint, disables redirects, sends no tools, requests strict structured JSON,
sets `store` to `false`, and bounds the request, response, and timeout. There is
no automatic provider call or retry. See OpenAI's [Responses API
reference](https://developers.openai.com/api/reference/resources/responses/methods/create)
and [structured outputs guide](https://developers.openai.com/api/docs/guides/structured-outputs?api-mode=responses).

`store: false` disables Responses API storage for the request. It is not a
promise that provider-side abuse monitoring retains no data; consult the
provider's current [data controls](https://developers.openai.com/api/docs/guides/your-data)
and account terms before sending reports. The operator should review the
redacted data boundary below before enabling the command in an environment.

## Data sent and redaction

The request is built from the versioned contract, not a serialized copy of the
whole report. It includes bounded scanner and policy-pack versions, finding
fingerprints, control and scanner-rule IDs, source type and location, severity,
title, and a citation catalog containing the finding's description, sanitized
evidence, remediation, and compliance references. It omits report metadata,
AWS account references, and each finding's resource reference.

Before sending, the analyst redacts AWS account IDs, access-key IDs, private
keys, bearer and hosted-service tokens, common secret assignments, resource
names/IDs/ARNs in structured evidence, inline ARNs, and email addresses. It
limits findings, nesting, item counts, text lengths, and total prompt bytes.
Treat any new evidence format as untrusted and extend the tests when adding
fields that can contain credentials or resource identifiers.

## Evidence-bound output

The provider must return exactly one analysis per finding, with a non-empty
explanation, an explicit uncertainty statement, citations, and an optional
patch proposal. Local validation rejects missing or extra findings, unknown or
duplicate citation IDs, unsupported fields (including severity or gate
fields), malformed output, and sensitive output. Citations must refer to the
catalog supplied for that same finding; arbitrary URLs and unsupported claims
are not accepted as citations.

Finding text is marked as untrusted input in the model instructions. The
provider receives no tools and cannot call AWS. Its output cannot affect scan
status or gate evaluation. A provider outage produces `UNAVAILABLE`; invalid or
unsafe output produces `REJECTED`. Both return an empty analysis list and
preserve the saved scan and gate statuses. Missing provider configuration is a
non-blocking `UNAVAILABLE` result. These sidecar states do not alter the
original scan's exit code.

## Patch proposals

An AI proposal is not an applied change. Without `--source`, it is marked
`BLOCKED` and no patch is returned. With a source tree, the implementation
accepts only exact text replacements in supported IaC files, applies them to a
temporary local copy, and runs the normal IaC scanner against that copy. A
patch is returned only when the rescan is local-only, complete, gate-passing,
and no longer contains the targeted finding. A failed or unsafe rescan returns
no patch. The original source tree is not modified; Terraform, AWS APIs, and
cloud apply commands are never run.

For example:

```bash
python -m auditor.cli ai-analyze \
  --report reports/iac-report.json \
  --source infra \
  --fail-on HIGH
```

The provider path is tested with deterministic local fakes. No live API call is
made by the test suite; deployment-specific provider retention settings and
model behavior remain external to this repository.
