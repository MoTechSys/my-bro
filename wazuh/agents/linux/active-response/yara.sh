#!/bin/bash
# Purpose: bounded, allowlisted YARA AR; owner [ASTRA]; updated 2026-09-09.
# Status: local tests; live YARA/Wazuh verification pending (T-15).
# Source: Wazuh 4.14 YARA PoC; deploy soc_ar.py alongside this wrapper.
# Targets: root:wazuh 0750 under /var/ossec/active-response/bin/.
set -euo pipefail
export PATH=/usr/bin:/bin
HERE=$(cd -- "$(dirname -- "$0")" && pwd -P)
exec /usr/bin/python3 -I "$HERE/soc_ar.py" yara
