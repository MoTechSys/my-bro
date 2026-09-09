#!/bin/bash
# Purpose: bounded loopback-only lab listener; owner [ASTRA]; 2026-09-09.
# Status: syntax checked, nc variant/live Wazuh pending. Source: UC-05/08.
set -euo pipefail
export PATH=/usr/bin:/bin
[[ ${1:-} == --lab && $# == 1 ]] || { echo 'Usage: netcat_tests.sh --lab' >&2; exit 2; }
command -v nc >/dev/null || { echo 'Install and verify nc separately' >&2; exit 2; }
# Help may exit nonzero; this is an execve policy probe, not a network action.
nc -h >/dev/null 2>&1 || true
pid=''
cleanup() {
  if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# No shell execution, no public bind, no timeout wrapper with a misleading match.
nc -l -p 4444 -s 127.0.0.1 </dev/null >/dev/null 2>&1 &
pid=$!
sleep 1
kill -0 "$pid" 2>/dev/null || { echo 'Listener failed: check nc options/port collision' >&2; exit 1; }
echo "Listener child PID $pid, loopback port 4444; verify socket with ss."
sleep 44
# Cleanup owns only this child; no broad pkill. A client can end nc early.
echo 'Observation window ended; verify actual lifetime and rule 100051; respect ignore=900.'
