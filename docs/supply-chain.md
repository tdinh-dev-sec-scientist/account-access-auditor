# Local supply-chain release

The Stage 5 release command catalogs the source tree and a saved container
image, scans both CycloneDX SBOMs with Grype, applies a severity gate, then
signs and verifies the release image archive, SBOMs, and vulnerability reports.
It uses only local files and local tool CLIs. It does not create an AWS session,
push an image, or upload a signature to a registry or transparency log.

## Pinned tools

The command accepts only the versions recorded in
[`auditor/supply_chain.py`](../auditor/supply_chain.py): Syft 1.55.0, Grype
0.121.0, and Cosign 3.1.4. Install each binary from its official project
release and verify the release checksum or signature before use:

- [Syft releases](https://github.com/anchore/syft/releases)
- [Grype releases](https://github.com/anchore/grype/releases)
- [Cosign releases](https://github.com/sigstore/cosign/releases)

The program checks the exact versions before creating the release. Grype's
database must be valid and no older than 120 hours. A missing, stale, or
unavailable vulnerability database produces `UNKNOWN` and exit code 3; it
never produces a clean scan. The manifest records the database schema, build
time, age, and checksum when available.

Each `release-manifest.json` and `supply-chain-status.json` also embeds the
shared [`ScanRun`, `Finding`, and `ArtifactResult` contracts](contracts.md).
Each source and image Grype match becomes a `contract.findings` record; the
original vulnerability reports remain signed artifacts for detailed scanner
evidence. A verified local signature uses the SHA-256 digest of `release.pub`
as its local key identity; `provenance_verified` is `null` because this demo
does not produce or verify build attestations. This digest is not a public
trust identity.

Grype severity maps to the project scale as follows:

| Grype source severity | Project severity |
| --- | --- |
| `NEGLIGIBLE` | `INFO` |
| `LOW` | `LOW` |
| `MEDIUM` | `MEDIUM` |
| `HIGH` | `HIGH` |
| `CRITICAL` | `CRITICAL` |

The contract keeps the original Grype tier in `source_severity`. Package
references are hashed into stable resource references; package name, version,
and type remain as evidence, while arbitrary PURL qualifiers are not copied
into normalized findings.

## Build and sign a demo release

Create a local Cosign key pair outside the repository. Start from the
repository root, protect the private key, and keep its password out of shell
history and logs:

```bash
REPO_ROOT="$PWD"
KEY_DIR="$HOME/.config/account-access-auditor/cosign"
mkdir -m 700 -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
cd "$KEY_DIR"
cosign generate-key-pair
chmod 600 cosign.key
cd "$REPO_ROOT"
printf 'Cosign key password: '
read -r -s COSIGN_PASSWORD
printf '\n'
export COSIGN_PASSWORD
export COSIGN_KEY="$KEY_DIR/cosign.key"
export COSIGN_PUBLIC_KEY="$KEY_DIR/cosign.pub"
scripts/build_signed_release.sh "${TMPDIR:-/tmp}/account-access-auditor-release"
unset COSIGN_PASSWORD
```

The output directory must be outside the source tree and must not already
contain release files. Docker, Syft, Grype, and Cosign must be available in
`PATH`. The release CLI runs with host Python, so that interpreter also needs
the project's runtime dependencies. For a clean checkout, create a virtual
environment and point `PYTHON` at it before running the script:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
export PYTHON="$PWD/.venv/bin/python"
```

The script checks that Python can import the CLI before starting the Docker
build. The Docker build context and source catalog exclude AWS credentials,
dotenv files, credential files, private-key files, agent instruction files,
and the plan document.

The script builds the Dockerfile locally, saves the image as an archive, and
runs the release command. It does not push the image. Output includes:

- `source.sbom.cdx.json` and `image.sbom.cdx.json`
- Source and image Grype JSON vulnerability reports
- `release-image.tar` and public verification key `release.pub`
- One detached Cosign signature per signed file, plus `release-manifest.json`

If the vulnerability gate fails, the output contains the SBOMs, scan reports,
and failing manifest, but it does not copy the image archive or public key into
the release directory.

The SBOM files retain Syft's standard generation timestamp and serial number.
The manifest also records a semantic reproducibility digest that excludes
those generator-assigned fields, along with the source tree digest, image
archive digest, and exact scanner versions.

## Reproducibility boundary

The procedure and tool versions are pinned, and the semantic SBOM digest
ignores Syft's run-specific timestamp and serial number. This does not promise
a byte-identical release archive across runs: the Docker build uses the latest
base image (`--pull`), Python dependency requirements are minimum-version
constraints, and Grype's vulnerability database changes over time. The manifest
binds each result to its source/image digest, tool versions, and database
provenance so one particular release can be reproduced and verified. Re-run the
benchmark to reproduce the labeled detection result; do not interpret these
artifacts as a general vulnerability rate.

Cosign signs the exact bytes of the saved image archive and each report using
the supplied local key, then verifies every detached signature before the
manifest can say `PASS`. The locally pinned Cosign 3.x command uses its
backward-compatible detached-signature flags and skips transparency-log
upload and verification so it can run locally. This verifies the signature
against the included public key, but does not provide public transparency or
auditability. Consumers must obtain and trust that key through a separate
trusted channel. For production releases, use an identity-bound CI signing
policy and registry-native image signatures.

Verify an artifact independently before loading or using it:

```bash
cosign verify-blob \
  --key release.pub \
  --new-bundle-format=false \
  --insecure-ignore-tlog \
  --signature release-image.tar.sig \
  release-image.tar
```

Exit codes are `0` for a verified release that passes its vulnerability gate,
`1` when a finding meets the configured `--fail-on` tier, `2` for setup or
tool errors, and `3` when vulnerability scan data is unknown. A failing
vulnerability gate still writes reports and a manifest, but does not sign the
release artifacts.
