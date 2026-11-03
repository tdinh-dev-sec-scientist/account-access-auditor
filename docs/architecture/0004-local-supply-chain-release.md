# ADR 0004: local supply-chain release and verification

- Status: Accepted for the demo
- Date: 2026-11-02

## Context

Release SBOMs, vulnerability reports, images, and signatures need verifiable
provenance without adding AWS access or an image-registry dependency.

## Decision

Use pinned local Syft, Grype, and Cosign CLIs. Record tool/database provenance,
scan saved source and image SBOMs, sign exact artifact bytes with a local key,
verify signatures before the manifest reports `PASS`, and embed the shared
`ScanRun`/`ArtifactResult` contract in the detailed release manifest. Skip
transparency-log upload and verification for the local demonstration.

## Consequences

The output is verifiable against the included public key, but the demo does not
establish a public signer identity or transparency record. Artifact results
record a local public-key file digest and signature verification; builder
provenance remains unverified because the demo creates no attestation. Grype
findings remain in raw reports and are not normalized into shared `Finding`
records. Dependency resolution, Docker base images, and vulnerability
databases can change between runs, so the semantic SBOM digest is not a promise
of byte-identical full releases.
