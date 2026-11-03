# Architecture decision records

These records explain the implemented boundaries and material departures from
the Phase 2 plan. The final plan and its [user-approved Stage 6 amendment](../phase2-stage6-amendment.md)
are the source of truth; a local implementation does not silently satisfy an
acceptance criterion.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-versioned-contracts.md) | Versioned findings and deterministic gates | Accepted |
| [0002](0002-read-only-and-local-state.md) | Preserve AWS read-only; keep schedules/history local | Accepted; managed AWS path deferred |
| [0003](0003-ci-and-kubernetes-boundaries.md) | Keep PR scanning credential-free and admission isolated | Accepted |
| [0004](0004-local-supply-chain-release.md) | Sign and verify local artifacts without a transparency upload | Accepted for the demo |
| [0005](0005-optional-ai-sidecar.md) | Keep AI optional, evidence-bound, and outside enforcement | Accepted |
