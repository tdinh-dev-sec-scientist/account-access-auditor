# Gatekeeper demo admission guardrails

This demo enforces two Kubernetes controls at admission: Pods may not run
privileged containers, and container images may not use the mutable `latest`
tag. It is scoped to a dedicated local demo cluster. The auditor itself does
not connect to Kubernetes or receive cluster credentials.

## Install on the dedicated demo cluster

1. Create and select the named local cluster. Kubernetes 1.33.2 is in the
   [Gatekeeper v3.23.1 test matrix](https://github.com/open-policy-agent/gatekeeper/blob/v3.23.1/.github/workflows/workflow.yaml):

   ```bash
   kind create cluster --name account-access-auditor-demo --image kindest/node:v1.33.2
   kubectl config use-context kind-account-access-auditor-demo
   ```

2. Install the pinned Gatekeeper release and wait for its controller:

   ```bash
   kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.23.1/deploy/gatekeeper.yaml
   kubectl wait --for=condition=Available deployment/gatekeeper-controller-manager \
     -n gatekeeper-system --timeout=180s
   ```

3. Install the demo template and deny constraint:

   ```bash
   kubectl apply -f deploy/gatekeeper/template.yaml
   kubectl wait --for=condition=Established crd/k8sdenyprivilegedlatest.constraints.gatekeeper.sh \
     --timeout=60s
   kubectl apply -f deploy/gatekeeper/constraint.yaml
   ```

4. Verify admission without storing either Pod:

   ```bash
   scripts/test_gatekeeper_demo.sh
   ```

The script refuses any Kubernetes context other than
`kind-account-access-auditor-demo`. It uses server-side dry runs, so the sample
Pods are not persisted. The clean Pod must be accepted; the violating Pod must
be denied. Use a dedicated demo cluster only. The auditor's AWS role remains
read-only and does not need Kubernetes permissions or cluster-admin access.
