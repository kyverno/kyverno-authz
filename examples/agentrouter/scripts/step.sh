#!/usr/bin/env bash
set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/common.sh"
case "${1:-}" in
  status|read|revoke|denied|restore|scale|models|reports|guardrails|fail-closed)
    [[ $# == 1 ]] || { printf 'Provide exactly one step name.\n' >&2; exit 1; } ;;
  *) printf 'Usage: %s {status|read|revoke|denied|restore|scale|models|reports|guardrails|fail-closed}\n' "$0" >&2; exit 1 ;;
esac
require_tools kubectl python3
require_cluster
umask 077
python3 "$DEMO_DIR/client/demo.py" --step "$1"
