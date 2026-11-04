#!/usr/bin/env bash

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEMO_DIR
CLUSTER_NAME=kyverno-agentrouter
CONTEXT="kind-$CLUSTER_NAME"
NAMESPACE=agentrouter-demo

k() {
  kubectl --context "$CONTEXT" "$@"
}

require_tools() {
  local tool
  for tool in "$@"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      printf 'Required tool not found: %s\n' "$tool" >&2
      exit 1
    fi
  done
}

require_cluster() {
  k get namespace "$NAMESPACE" >/dev/null
}
