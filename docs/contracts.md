# Scan record contracts

The v1 audit report remains available at its existing top-level keys:
`metadata`, `summary`, `collection_errors`, and `findings`. A new `contract`
object is additive and contains the versioned records used by future scanner
adapters:

- [`finding-v1.schema.json`](../schemas/finding-v1.schema.json)
- [`scan-run-v1.schema.json`](../schemas/scan-run-v1.schema.json)
- [`artifact-result-v1.schema.json`](../schemas/artifact-result-v1.schema.json)

All records use schema version `1.0.0`. Schema versions identify the record
shape; scanner and policy-pack versions are recorded separately. The current
AWS auditor does not have an independently versioned policy pack, so
`policy_pack_version` is `null` rather than an invented version.

The local supply-chain release embeds a `contract` with a `ScanRun`, normalized
Grype `Finding` records, and `ArtifactResult` records beside its detailed
release manifest. Grype findings preserve the source vulnerability ID and
source severity while using the project's severity scale. Each artifact record
names a safe relative location, format, SHA-256 digest, producing scanner and
version, and vulnerability database provenance when applicable.
`signature_identity` is the SHA-256 digest of the local public-key file;
`signature_verified` is true only when Cosign verification succeeded for the
recorded artifact digest. `provenance_verified` is `null` because this demo
does not produce or verify a builder attestation. A local key digest is not a
trusted external signer identity; consumers still need a separately trusted
key-distribution channel.

## Artifact results

`ArtifactResult` is defined by
[`artifact-result-v1.schema.json`](../schemas/artifact-result-v1.schema.json).
It records a relative artifact location and format, content digest, producing
scanner/version, optional vulnerability database provenance, signature
identity and verification state, and build-provenance verification state.
Unobserved provenance remains `null`; it is not treated as verified.

## Finding identity

The existing AWS rule IDs (`IAM-*`, `S3-*`, and `CT-*`) remain the stable
`control_id` values. For native AWS findings, `scanner_rule_id` is the same ID,
`scanner` is `account-access-auditor`, and `source_type` is `aws`. External
adapters can preserve their original rule ID while mapping it to a canonical
control ID.

`severity` is the project's normalized tier. `source_severity` is optional and
retains the upstream tier when the scanner supplied one. A source location
always includes a file and may omit the line when the scanner has no line data.

The contract fingerprint is the first 16 lowercase hex characters of SHA-256
over canonical JSON containing `control_id`, `source_type`, and
`resource_reference`. If no stable resource reference exists, the source file
and optional line form the identity instead. Titles, descriptions, and evidence do not
change identity. The legacy finding's existing `fingerprint` remains untouched
in the v1 report; the contract record carries the source-aware fingerprint.
Current AWS findings use lifecycle state `open`. Reference entries preserve
mapped compliance framework/control identifiers; unmapped findings use an
empty list.

## Run status and exit codes

`status` describes whether the configured scan/gate produced a usable result.
`gate_status` says whether a threshold was configured and whether it passed.
An observe-only scan can have findings and still have `PASS` with
`NOT_CONFIGURED`; that means the scan completed, not that the account is clean.

| Status | Meaning | CLI exit code |
| --- | --- | ---: |
| `PASS` | Collection completed; no configured gate threshold was crossed. | 0 |
| `FAIL` | Collection completed and the configured `--fail-on` threshold was crossed. | 1 |
| `ERROR` | A collector failed as a component, or a fatal setup/configuration error prevented a usable scan. | 2 |
| `UNKNOWN` | AWS data could not be fully read, including AccessDenied and exhausted throttling. Treat the result as incomplete. | 3 |

Incomplete coverage takes precedence over a gate result: if a known finding
crosses `--fail-on` while other AWS data is unavailable, `status` is
`UNKNOWN`, `gate_status` remains `FAIL`, and the CLI exits 3. Fatal setup
errors still return exit 2 before a report can be written. Error entries retain
their specific `category`, operation, resource, and AWS error code.

## Component ownership

- AWS collectors own Boto3 calls, pagination, retries, and collection errors.
- The IaC adapter owns Checkov and Conftest invocation/parsing and preserves
  upstream scanner IDs and locations. The supply-chain adapter normalizes
  Grype matches to shared `Finding` records and emits shared `ScanRun` and
  `ArtifactResult` records while retaining signed raw reports in its manifest.
- Normalizers map scanner outputs into finding and scan-run records.
- The deterministic policy evaluator owns severity, gate thresholds, and exit
  status. Exceptions and AI output do not alter this contract's evidence.
- Reporters render records; they do not change scan state or contact AWS.

The contract contains only references and evidence supplied by the scanner.
It does not claim effective-permission analysis, compliance certification, or
historical drift that has not been computed.

## IaC gate and exception fields

IaC `scan_run` records include `gate_threshold` for the configured severity
threshold. Each IaC finding carries a `gate` boolean and an `exceptions` list;
an active matching exception changes only `gate`, while the finding and its
evidence remain present. The contract-level `exceptions` list records every
configured exception as matched or unmatched and active or expired.
