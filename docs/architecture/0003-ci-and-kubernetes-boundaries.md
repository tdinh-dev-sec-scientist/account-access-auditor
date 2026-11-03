# ADR 0003: credential-free CI and isolated Kubernetes admission

- Status: Accepted
- Date: 2026-11-02

## Context

Pull-request content can be hostile. Static scans need to report actionable
results without granting fork code AWS access. Kubernetes admission is a
separate runtime boundary from cloud account auditing.

## Decision

Run IaC scans in GitHub Actions without AWS credentials, OIDC, or write-capable
tokens. Publish annotations and artifacts, then upload SARIF for same-repository
pull requests in a separate trusted `workflow_run`. Keep Gatekeeper as a
separately installed demo/authorized-cluster policy; the auditor receives no
Kubernetes credentials. The trusted remediation workflow is manual and creates
a review PR only.

## Consequences

Forks do not receive cloud or remediation authority. A live Gatekeeper demo
requires the named local cluster and explicit smoke test; repository manifests
alone do not prove an admission controller is operating.
