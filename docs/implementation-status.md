# Phase 2 implementation status

**Phase 2 is not release-complete.** This page records what the repository
implements against the final development plan. “Implemented” means the code and
automated tests exist; live checks are stated where verified. No live AWS
account or GitHub pull request was exercised in this environment; the local
signed-release acceptance is recorded below.

| Plan area | Status | Evidence and remaining gap |
| --- | --- | --- |
| Stage 1: baseline and contracts | Implemented for AWS, IaC, fleet, and supply-chain findings and artifacts | `docs/contracts.md`, `schemas/`; Grype findings use shared versioned `Finding` records, while raw reports remain available as detailed evidence. |
| Stage 2: IaC and policy scanning | Implemented for documented controls; real scanner fixtures and Gatekeeper admission verified | `docs/iac-scanning.md`; Checkov 3.4.3 and Conftest 0.71.1 fixture tests passed with both real binaries. The named local Gatekeeper demo accepted a clean Pod and denied a violating Pod on 2026-11-02. Raw Helm templates and Terraform `.tf.json` are unsupported. |
| Stage 3: GitHub and Kubernetes guardrails | Partially verified | PR workflow and Gatekeeper demo assets exist. No live GitHub PR was exercised; the separate local admission result is recorded under Stage 2. |
| Stage 4: AWS drift | Local read-only path implemented; managed AWS path deferred | Cross-account/region scans use read-only roles; a host scheduler and private local SQLite history provide drift. EventBridge, Step Functions, S3, and DynamoDB are not provisioned. |
| Stage 5: supply-chain controls | Local signed-release acceptance passed on 2026-11-03 | Syft 1.55.0, Grype 0.121.0, and Cosign 3.1.4 produced source and image SBOMs and vulnerability reports; the `HIGH` gate passed with 0 source findings and 16 image findings (13 medium, 2 low, 1 negligible), and all five artifact signatures verified. The manifest embeds shared `ScanRun`, `Finding`, and `ArtifactResult` records. Signatures are local and transparency-log verification is disabled. |
| Stage 6: exceptions and remediation | Partial; approved read-only deviation | Expiring exceptions, deterministic previews, reviewed PRs, and a temporary local-copy rescan exist. Disposable-account AWS apply remains unmet by the user-approved read-only decision; see `docs/remediation.md`. |
| Stage 7: AI analyst | Implemented as an optional sidecar | Redacted, cited explanations and rescanned local patch proposals; no AWS access or gate authority. See `docs/ai-analyst.md`. |
| Stage 8: hardening and release documentation | Implemented in this stage | Threat model, ADRs, operational runbook, generated README metrics, and reproducible demo instructions are provided. The live Gatekeeper demo and local signed-release acceptance were exercised; no live GitHub pull request or public signing identity was tested. |

## Release acceptance disposition

- AWS assessment remains read-only, and the original v1 benchmark is retained.
- Terraform, IAM, Kubernetes, rendered Helm, live AWS scans, and supply-chain
  release artifacts use shared versioned contracts. Grype matches become
  shared `Finding` records in `contract.findings`; signed raw reports retain
  the detailed scanner output.
- The real Checkov and Conftest scanner integrations passed on their pinned
  versions, including the clean and vulnerable IaC fixtures.
- Local signed-release acceptance passed on 2026-11-03 with Syft 1.55.0,
  Grype 0.121.0, and Cosign 3.1.4. The valid 21-hour-old Grype database
  produced 0 source findings and 16 image findings, none at the configured
  `HIGH` threshold or above; Cosign verified all five signed release artifacts.
  The image uses Python 3.12 Alpine and runs as non-root. No AWS session or
  image push was used.
- GitHub PR feedback is deterministic and has no AWS credentials. Gatekeeper
  live admission acceptance passed on 2026-11-02 on
  `kind-account-access-auditor-demo`: the clean Pod was accepted and the
  violating Pod was denied using server-side dry runs. The live test remains
  opt-in in the standard suite; no live GitHub PR was exercised.
- Scheduled drift runs and history are local. Managed AWS orchestration and
  storage are not included.
- Exceptions expire and remain visible. Remediation previews and local rescans
  are implemented, but the plan's disposable-account apply criterion remains
  unmet and is not represented as complete.
- Supply-chain signing uses a temporary local key and skips the transparency
  log. A production trust identity and public verification channel are outside
  this demo.
- The benchmark measures the labeled moto fixture corpus only. It does not
  estimate general real-world precision or recall.
- The original 90% branch-inclusive CI floor failed on the expanded Phase 2
  package at 86.23%. CI now requires 86% across all auditor modules; the latest
  artifact reports 87.36%. Raising the floor back to 90% remains a test coverage
  objective. The tradeoff is a lower gate while those missing branches remain.

Do not report Phase 2 complete while any release acceptance item above remains
unmet. Phase 3 has not started.
