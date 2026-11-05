#!/usr/bin/env bash

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/common.sh"
require_tools kubectl python3
require_cluster
usage() {
  printf 'Usage: %s [--check|--scenario N|--help]\nUse scripts/step.sh for isolated presenter actions.\n' "$0" >&2
  exit 1
}
log="last-run.log"
case "$#:${1:-}" in
  0:|1:--check|1:--help) ;;
  2:--scenario)
    [[ "$2" =~ ^[1-7]$ ]] || usage
    log="scenario-$2.log"
    ;;
  *) usage ;;
esac
mkdir -p "$DEMO_DIR/.state"
chmod 700 "$DEMO_DIR/.state"
umask 077
python3 -u "$DEMO_DIR/client/demo.py" "$@" 2>&1 | tee "$DEMO_DIR/.state/$log"
