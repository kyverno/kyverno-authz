#!/usr/bin/env bash

set -euo pipefail
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/common.sh"
require_tools kubectl python3
require_cluster
exec python3 "$DEMO_DIR/client/demo.py" --token "${1:-alice}"
