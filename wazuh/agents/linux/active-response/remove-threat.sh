#!/bin/bash
# Purpose: guarded Linux VT response; owner [ASTRA]; updated 2026-09-09.
# Status: local regression tests; live lab/peer review pending (T-15).
# Source: Wazuh 4.14 custom AR protocol, ISSUE-036.
# Deploy as /var/ossec/active-response/bin/remove-threat.exe (Linux shebang)
# AND deploy soc_ar.py beside it, both root:wazuh 0750.
# Only soc_ar.main('remove') on command=add may unlink an approved file.
set -euo pipefail
export PATH=/usr/bin:/bin
HERE=$(cd -- "$(dirname -- "$0")" && pwd -P)
exec /usr/bin/python3 -I "$HERE/soc_ar.py" remove
