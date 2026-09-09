#!/usr/bin/env bash
# T-11 guarded entrypoint. --lab or read-only --replay is mandatory.
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -I -B "$SCRIPT_DIR/trial_runner.py" "$@"
