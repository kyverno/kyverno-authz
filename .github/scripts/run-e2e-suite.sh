#!/usr/bin/env bash
set -euo pipefail

suite="${1:?suite is required}"
source_dir="${2:?source directory is required}"
helm_path="${3:?helm path is required}"
cd "$source_dir"

install_vpol_and_polex() {
  make install-vpol
  make install-polex
}

setup_cert_manager() {
  HELM="$helm_path" make install-cert-manager install-cluster-issuer
}

wait_for_validation() {
  local policy_file="$1"
  kubectl rollout status deployment/kyverno-authz-server-validation -n kyverno --timeout=180s
  for attempt in $(seq 1 36); do
    if kubectl create --dry-run=server --request-timeout=5s -f "$policy_file"; then
      return 0
    fi
    echo "validation webhook admission attempt $attempt failed; retrying" >&2
    sleep 5
  done
  echo "validation webhook did not accept a server-side dry-run" >&2
  kubectl get pods,svc,endpoints -n kyverno >&2 || true
  exit 1
}

case "$suite" in
  authz-server-envoy)
    KYVERNO_AUTHZ_SERVICE=kyverno-authz-server.kyverno.svc.cluster.local HELM="$helm_path" make install-istio
    setup_cert_manager
    install_vpol_and_polex
    HELM="$helm_path" make deploy-kyverno-envoy-server
    kubectl create ns app
    kubectl label namespace app istio-injection=enabled
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.24/samples/httpbin/httpbin.yaml -n app
    chainsaw test tests/e2e/authz-server/envoy
    ;;
  authz-server-http)
    setup_cert_manager
    install_vpol_and_polex
    HELM="$helm_path" make deploy-kyverno-http-server
    kubectl create ns app
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.24/samples/httpbin/httpbin.yaml -n app
    chainsaw test tests/e2e/authz-server/http
    ;;
  sidecar-injector)
    KYVERNO_AUTHZ_SERVICE=kyverno-authz-server.local HELM="$helm_path" make install-istio install-service-entry
    install_vpol_and_polex
    HELM="$helm_path" make deploy-kyverno-sidecar-injector
    kubectl create ns app
    kubectl label namespace app istio-injection=enabled
    kubectl label namespace app kyverno-injection=enabled
    kubectl apply -f https://raw.githubusercontent.com/istio/istio/release-1.24/samples/httpbin/httpbin.yaml -n app
    chainsaw test tests/e2e/sidecar-injector
    ;;
  validation-webhook-envoy)
    setup_cert_manager
    install_vpol_and_polex
    HELM="$helm_path" make deploy-kyverno-envoy-server
    wait_for_validation tests/e2e/validation-webhook/envoy/validation/valid/policy.yaml
    chainsaw test tests/e2e/validation-webhook/envoy
    ;;
  validation-webhook-http)
    setup_cert_manager
    install_vpol_and_polex
    HELM="$helm_path" make deploy-kyverno-http-server
    wait_for_validation tests/e2e/validation-webhook/http/validation/valid/policy.yaml
    chainsaw test tests/e2e/validation-webhook/http
    ;;
  *)
    echo "Unknown E2E suite: $suite" >&2
    exit 2
    ;;
esac
