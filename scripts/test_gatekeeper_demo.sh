#!/usr/bin/env bash
set -euo pipefail

expected_context="kind-account-access-auditor-demo"
actual_context="$(kubectl config current-context 2>/dev/null || true)"
if [[ "$actual_context" != "$expected_context" ]]; then
  echo "Refusing Gatekeeper demo test: current context must be $expected_context." >&2
  exit 2
fi
server="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)"
case "$server" in
  https://127.0.0.1:*|https://localhost:*|https://\[::1\]:*) ;;
  *)
    echo "Refusing Gatekeeper demo test: the named context must point to a local cluster." >&2
    exit 2
    ;;
esac

kubectl apply --dry-run=server -f deploy/gatekeeper/samples/clean-pod.yaml >/dev/null
if kubectl apply --dry-run=server -f deploy/gatekeeper/samples/violating-pod.yaml >/dev/null 2>&1; then
  echo "Gatekeeper accepted the violating Pod; admission guardrail did not deny it." >&2
  exit 1
fi

echo "Gatekeeper accepted the clean Pod and denied the violating Pod."
