# ADR 0002: preserve AWS read-only and use local state

- Status: Accepted
- Date: 2026-11-02

## Context

The Phase 2 plan proposes AWS-hosted scheduling/storage and a disposable AWS
remediation sandbox. The project requirement is to preserve AWS read-only
behavior and never add AWS write operations.

## Decision

Keep target-account sessions behind the read-only operation guard. Run
scheduled scans from a host scheduler and store drift history in a private
local SQLite database. Test remediation patches only in a temporary local
copy. Do not add EventBridge, Step Functions, S3, DynamoDB, or a remediator role
to this repository's AWS execution path.

## Consequences

The user-approved [Stage 6 amendment](../phase2-stage6-amendment.md) supersedes
the plan's direct AWS apply criterion for this repository. AWS sandbox apply
remains unimplemented and is not claimed; the local simulation is not
equivalent to AWS remediation. Local scheduling and history also do not provide
managed AWS availability or backups. See the [capability status page](../implementation-status.md)
for acceptance evidence and limitations.
