#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
OUTPUT_ARGUMENT="${1:?Usage: scripts/build_signed_release.sh OUTPUT_DIR}"
mkdir -p -- "$OUTPUT_ARGUMENT"
OUTPUT_DIR="$(cd -- "$OUTPUT_ARGUMENT" && pwd -P)"

case "$OUTPUT_DIR/" in
  "$PROJECT_ROOT/"*)
    printf '%s\n' "Output must be outside the source tree: $PROJECT_ROOT" >&2
    exit 2
    ;;
esac

: "${COSIGN_KEY:?Set COSIGN_KEY to a protected local Cosign private-key path}"
: "${COSIGN_PUBLIC_KEY:?Set COSIGN_PUBLIC_KEY to its matching public-key path}"

if [[ ! -f "$COSIGN_KEY" || ! -f "$COSIGN_PUBLIC_KEY" ]]; then
  printf '%s\n' "Cosign key files must exist and be regular files." >&2
  exit 2
fi
COSIGN_KEY="$(cd -- "$(dirname -- "$COSIGN_KEY")" && pwd -P)/$(basename -- "$COSIGN_KEY")"
COSIGN_PUBLIC_KEY="$(cd -- "$(dirname -- "$COSIGN_PUBLIC_KEY")" && pwd -P)/$(basename -- "$COSIGN_PUBLIC_KEY")"

IMAGE_TAG="${SUPPLY_CHAIN_IMAGE_TAG:-account-access-auditor:release-demo}"
BUILD_TMP="$(mktemp -d "${TMPDIR:-/tmp}/account-access-auditor-release.XXXXXX")"
trap 'rm -rf "$BUILD_TMP"' EXIT
IMAGE_ARCHIVE="$BUILD_TMP/container-input.tar"
for name in \
  source.sbom.cdx.json image.sbom.cdx.json \
  source.vulnerabilities.json image.vulnerabilities.json \
  release-image.tar release.pub release-manifest.json supply-chain-status.json \
  source.sbom.cdx.json.sig image.sbom.cdx.json.sig \
  source.vulnerabilities.json.sig image.vulnerabilities.json.sig release-image.tar.sig; do
  if [[ -e "$OUTPUT_DIR/$name" || -L "$OUTPUT_DIR/$name" ]]; then
    printf '%s\n' "Refusing to overwrite existing release file: $OUTPUT_DIR/$name" >&2
    exit 2
  fi
done

cd -- "$PROJECT_ROOT"
env -u COSIGN_PASSWORD docker build --pull --file "$PROJECT_ROOT/Dockerfile" --tag "$IMAGE_TAG" "$PROJECT_ROOT"
env -u COSIGN_PASSWORD docker image save --output "$IMAGE_ARCHIVE" "$IMAGE_TAG"

"${PYTHON:-python3}" -m auditor.cli supply-chain-release \
  --source "$PROJECT_ROOT" \
  --image-archive "$IMAGE_ARCHIVE" \
  --image-format docker-archive \
  --output-dir "$OUTPUT_DIR" \
  --signing-key "$COSIGN_KEY" \
  --public-key "$COSIGN_PUBLIC_KEY" \
  --fail-on "${SUPPLY_CHAIN_FAIL_ON:-HIGH}"
