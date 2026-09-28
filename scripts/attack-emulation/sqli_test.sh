#!/bin/bash
# Purpose: harmless SQL-injection *pattern* requests for UC-09; owner [CLAUDE]; 2026-09-28.
# Expected: 31103 (attempt, non-2xx) or 31106 (web attack returned 200) - Wazuh 4.14.7 built-in,
#           verified with tests/test_wazuh_engine.py. Requires log_format apache (ISSUE-059).
# No database is touched: the target only needs Apache serving any page.
set -euo pipefail
export PATH=/usr/bin:/bin
[[ ${1:-} == --lab && $# == 2 ]] || { echo 'Usage: sqli_test.sh --lab PRIVATE_IPV4 (approved Apache target)' >&2; exit 2; }
TARGET=$2
python3 - "$TARGET" <<'PY'
import ipaddress, sys
ip = ipaddress.IPv4Address(sys.argv[1])
if not any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
    raise SystemExit('Only explicitly approved RFC1918 lab addresses are accepted')
PY
# URL-encoded patterns that match <url> of rule 31103 (union+select, %20from%20, null,null ...)
PAYLOADS=(
  "/index.php?id=1%20union%20select%201,2,3"
  "/index.php?id=1+union+select+null,null"
  "/login.php?user=admin'%20or%201=1%20from%20users--"
)
for p in "${PAYLOADS[@]}"; do
  code=$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' \
         --connect-timeout 5 --max-time 10 -A 'SOC_SQLI_TEST' "http://${TARGET}${SQLI_PORT:+:$SQLI_PORT}${p}" || true)
  echo "sent ${p} -> HTTP ${code}"
done
echo "Verify rule 31103/31106 (level 6-7, MITRE T1190) on the Dashboard; this is detection of the pattern, not exploit success."
