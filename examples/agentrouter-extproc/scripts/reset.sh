#!/usr/bin/env bash

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/common.sh"
require_tools kubectl
require_cluster
rm -f "$DEMO_DIR/.state/session.json"
k delete policyexceptions.policies.kyverno.io break-glass-inc-1234 --ignore-not-found
if k get configmap demo-exceptions -n "$NAMESPACE" >/dev/null 2>&1; then
  k delete configmap demo-exceptions -n "$NAMESPACE"
  k rollout restart deployment/kyverno-authz -n "$NAMESPACE"
fi
k apply -f "$DEMO_DIR/manifests/alice-scale.yaml"
k scale -n "$NAMESPACE" deployment/kyverno-authz --replicas=1
k rollout status -n "$NAMESPACE" deployment/kyverno-authz --timeout=120s
k scale -n team-a-dev deployment/checkout --replicas=0
k scale -n team-b-dev deployment/checkout --replicas=1
k rollout status -n team-b-dev deployment/checkout --timeout=120s
printf 'Reset complete: Alice can scale; team A has 0 replicas; team B has 1.\n'
