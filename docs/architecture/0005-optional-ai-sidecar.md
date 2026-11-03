# ADR 0005: optional AI sidecar

- Status: Accepted
- Date: 2026-11-02

## Context

Explanations may help review findings, but model output is untrusted and must
not become an enforcement or cloud-access path.

## Decision

Invoke the configured provider only through the separate `ai-analyze` command.
Send bounded redacted contract data, request strict structured output, validate
finding identity and citations locally, and give the model no tools. Preserve
the original scan/gate fields on outage or invalid output. Return a patch only
after a local temporary-copy IaC rescan passes.

## Consequences

Normal scans remain independent of provider availability. An explicit request
transmits redacted finding context to the configured service; account-specific
provider data controls still apply. The current provider implementation is
OpenAI only. See [`docs/ai-analyst.md`](../ai-analyst.md).
