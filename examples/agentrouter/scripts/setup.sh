#!/usr/bin/env bash

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/common.sh"
REPO_ROOT="$(cd "$DEMO_DIR/../.." && pwd)"
AUTHZ_IMAGE=ko.local/github.com/kyverno/kyverno-authz:agentrouter-demo
require_tools docker kind kubectl helm go ko python3
docker info >/dev/null

# A policy file that fails to compile is skipped by the authorizer, so check before deploying.
printf 'Checking that every demo policy compiles before deploying it...\n'
(cd "$REPO_ROOT" && go test ./examples/agentrouter/tests -count=1)

if ! kind get clusters | grep -Fxq "$CLUSTER_NAME"; then
  kind create cluster --name "$CLUSTER_NAME" --image kindest/node:v1.35.1 --wait 120s
fi

diagnostics() {
  local status=$?
  if ((status != 0)); then
    k get pods -A -o wide >&2
    k get events -A --sort-by=.lastTimestamp | tail -30 >&2
  fi
  exit "$status"
}
trap diagnostics EXIT

printf '\nInstalling Envoy Gateway v1.9.2, Agent Router v1.2.0, and Kyverno v1.19.1...\n'
helm upgrade --install eg oci://docker.io/envoyproxy/gateway-helm \
  --version v1.9.2 --kube-context "$CONTEXT" \
  --namespace envoy-gateway-system --create-namespace \
  --values "$DEMO_DIR/install/envoy-gateway-values.yaml" --wait --timeout 5m
helm upgrade --install aieg-crd oci://docker.io/envoyproxy/ai-gateway-crds-helm \
  --version v1.2.0 --kube-context "$CONTEXT" \
  --namespace envoy-ai-gateway-system --create-namespace --wait --timeout 3m
helm upgrade --install aieg oci://docker.io/envoyproxy/ai-gateway-helm \
  --version v1.2.0 --kube-context "$CONTEXT" \
  --namespace envoy-ai-gateway-system --wait --timeout 5m
helm upgrade --install kyverno kyverno --repo https://kyverno.github.io/kyverno/ \
  --version 3.9.1 --kube-context "$CONTEXT" \
  --namespace kyverno --create-namespace \
  --values "$DEMO_DIR/install/kyverno-values.yaml" --wait --timeout 5m
printf '\nBuilding Kyverno Authz from this checkout...\n'
(
  cd "$REPO_ROOT"
  KO_DOCKER_REPO=ko.local ko build . --preserve-import-paths \
    --tags=agentrouter-demo --platform="linux/$(go env GOARCH)"
)
kind load docker-image "$AUTHZ_IMAGE" --name "$CLUSTER_NAME"

k apply -f "$DEMO_DIR/install/openreports.io_reports.yaml"
k wait crd/reports.openreports.io --for=condition=Established --timeout=60s
k apply -f "$DEMO_DIR/manifests/namespaces.yaml"
k create configmap mcp-server -n "$NAMESPACE" \
  --from-file=server.py="$DEMO_DIR/apps/mcp-server/server.py" --dry-run=client -o yaml | k apply -f -
k create configmap llm-backend -n "$NAMESPACE" \
  --from-file=server.py="$DEMO_DIR/apps/llm-backend/server.py" --dry-run=client -o yaml | k apply -f -
k create configmap demo-policies -n "$NAMESPACE" \
  --from-file="$DEMO_DIR/policies/authz" --dry-run=client -o yaml | k apply -f -

# Keep the generated demo password stable across setup reruns without writing it to disk.
if ! k get secret demo-identity -n "$NAMESPACE" >/dev/null 2>&1; then
  python3 "$DEMO_DIR/apps/identity/realm.py" | k apply -f -
fi
k apply -f "$DEMO_DIR/manifests/services.yaml"
k apply -f "$DEMO_DIR/manifests/rbac.yaml"
k apply -f "$DEMO_DIR/manifests/alice-scale.yaml"
k apply -f "$DEMO_DIR/manifests/workloads.yaml"

printf '\nInstalling platform guardrails before any Agent Router route is admitted...\n'
k apply -f "$DEMO_DIR/policies/admission/kyverno-rbac.yaml"
k apply -f "$DEMO_DIR/policies/admission/mcproute-guardrails.yaml"
k apply -f "$DEMO_DIR/policies/admission/aigatewayroute-guardrails.yaml"
for policy in agentrouter-mcproute-guardrails agentrouter-model-route-guardrails; do
  k wait "validatingpolicy/$policy" --for=jsonpath='{.status.conditionStatus.ready}'=true --timeout=120s
done

# ConfigMap files and the locally built image may have changed since the previous setup.
k rollout restart -n "$NAMESPACE" \
  deployment/kyverno-authz deployment/kube-tools deployment/runbooks deployment/llm-backend
for deployment in keycloak kyverno-authz kube-tools runbooks llm-backend; do
  k rollout status -n "$NAMESPACE" "deployment/$deployment" --timeout=5m
done
k rollout status -n team-b-dev deployment/checkout --timeout=3m
k apply -f "$DEMO_DIR/manifests/gateway.yaml"
k apply -f "$DEMO_DIR/manifests/models.yaml"
k wait -n "$NAMESPACE" gateway/agentrouter --for=condition=Programmed --timeout=180s
k wait -n "$NAMESPACE" mcproute/operations --for=condition=Accepted --timeout=180s
k wait -n "$NAMESPACE" aigatewayroute/models --for=condition=Accepted --timeout=180s
# Agent Router rolls the Envoy proxy to add its model-routing sidecar; let that settle
# because a port-forward to a terminating proxy pod would fail.
for _ in 1 2; do
  sleep 5
  k rollout status -n envoy-gateway-system deployment \
    -l gateway.envoyproxy.io/owning-gateway-name=agentrouter --timeout=180s
done

printf '\nChecking the public MCP and model endpoints...\n'
python3 "$DEMO_DIR/client/demo.py" --check
printf '\nReady. Follow the README Demo runbook, or run the full suite: %s/scripts/run.sh\n' "$DEMO_DIR"
