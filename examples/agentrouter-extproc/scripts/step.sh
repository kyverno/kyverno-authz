#!/usr/bin/env bash

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/common.sh"
require_tools kubectl python3
require_cluster
if [[ $# != 1 ]]; then
  printf 'Usage: %s {reset|list|revoke|list-hidden|direct-denied|bob-list|grant|list-visible|scale|exception-activate|exception-allow|exception-narrow|exception-revoke|reports}\n' "$0" >&2
  exit 1
fi
umask 077
python3 -u "$DEMO_DIR/client/demo.py" --step "$1"
