# ADR 0001: versioned findings and deterministic gates

- Status: Accepted
- Date: 2026-11-02

## Context

AWS, IaC, fleet, and optional policy-validation scans need a stable interface
that preserves scanner provenance while existing v1 AWS report fields remain
usable. Scanner and provider output is untrusted and must not determine
severity or gate state.

## Decision

Use versioned `Finding`, `ScanRun`, and `ArtifactResult` records alongside the
legacy AWS report. Preserve upstream scanner IDs and source severity, map
findings into canonical control IDs, and compute deterministic gates in local
code. Scanner errors and incomplete collection produce explicit `ERROR` or
`UNKNOWN` outcomes. AI output is advisory and cannot mutate either record.

## Consequences

Adapters and reporters can evolve independently while consumers validate the
contract version. Supply-chain results retain their detailed release manifest
and now embed shared `ScanRun` and `ArtifactResult` records. Vulnerability
matches remain in the raw Grype reports rather than being converted into
shared `Finding` records.
