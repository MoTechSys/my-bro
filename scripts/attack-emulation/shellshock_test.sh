#!/bin/bash
# Purpose: harmless Shellshock-pattern lab request; owner [ASTRA]; 2026-09-09.
# Status: syntax checked, lab pending. Source: UC-06, Wazuh 4.14 PoC.
set -euo pipefail
export PATH=/usr/bin:/bin
[[ ${1:-} == --lab && $# == 2 ]] || { echo 'Usage: shellshock_test.sh --lab PRIVATE_IPV4 (approved non-CGI target)' >&2; exit 2; }
TARGET=$2
python3 - "$TARGET" <<'PY'
import ipaddress, sys
ip = ipaddress.IPv4Address(sys.argv[1])
if not any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
    raise SystemExit('Only explicitly approved RFC1918 lab addresses are accepted')
PY
curl --noproxy '*' --fail --silent --show-error --connect-timeout 5 --max-time 10 \
  -H 'User-Agent: () { :; }; /bin/echo SOC_SHELLSHOCK_TEST' \
  "http://${TARGET}/" > /dev/null
echo "Request completed; verify rule 31168 and the source log (not exploit success)."
