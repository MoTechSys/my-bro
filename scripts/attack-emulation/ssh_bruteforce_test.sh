#!/bin/bash
# Purpose: bounded SSH brute-force emulation for UC-11 (firewall-drop AR); owner [CLAUDE]; 2026-09-28.
# Expected on the target agent: 5710 x7 -> 5712 (L10) -> AR firewall-drop -> 651, unblock after 300 s.
# Verified end-to-end on wazuh-manager 4.14.7 (iptables DROP added and removed).
# Uses only invalid usernames so no real account can be locked or guessed.
set -euo pipefail
export PATH=/usr/bin:/bin
[[ ${1:-} == --lab && ( $# == 2 || $# == 3 ) ]] || { echo 'Usage: [SSH_PORT=22] ssh_bruteforce_test.sh --lab PRIVATE_IPV4 [ATTEMPTS=10]' >&2; exit 2; }
TARGET=$2; N=${3:-10}; PORT=${SSH_PORT:-22}
[[ $PORT =~ ^[0-9]+$ && $PORT -ge 1 && $PORT -le 65535 ]] || { echo 'SSH_PORT invalid' >&2; exit 2; }
[[ $N =~ ^[0-9]+$ && $N -ge 8 && $N -le 30 ]] || { echo 'ATTEMPTS must be 8..30' >&2; exit 2; }
python3 - "$TARGET" <<'PY'
import ipaddress, sys
ip = ipaddress.IPv4Address(sys.argv[1])
if not any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
    raise SystemExit('Only explicitly approved RFC1918 lab addresses are accepted')
PY
command -v ssh >/dev/null || { echo 'ssh client required' >&2; exit 2; }
for i in $(seq 1 "$N"); do
  timeout 8 ssh -p "$PORT" -o BatchMode=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no -o ConnectTimeout=4 \
      -o NumberOfPasswordPrompts=1 "socbf_invalid_${i}@${TARGET}" true </dev/null >/dev/null 2>&1 || true
  echo "attempt ${i}/${N}"
done
echo "Now: ping/ssh ${TARGET} should time out (blocked) until the 300 s timeout expires."
echo "Evidence: rule 5712 + 651 in alerts, 'iptables -S INPUT' on the target."
