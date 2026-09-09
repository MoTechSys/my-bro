#!/bin/bash
# Purpose: bounded approved lab scan; owner [ASTRA]; updated 2026-09-09.
# Status: syntax checked, lab pending. Source: UC-04, T-15 review.
set -euo pipefail
export PATH=/usr/bin:/bin
[[ ${1:-} == --lab && $# == 2 ]] || { echo 'Usage: sudo bash nmap_scan.sh --lab PRIVATE_IPV4' >&2; exit 2; }
TARGET=$2
python3 - "$TARGET" <<'PY'
import ipaddress, sys
ip = ipaddress.IPv4Address(sys.argv[1])
if not any(ip in ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
    raise SystemExit('Only an approved RFC1918 lab host is accepted')
PY
command -v nmap >/dev/null || { echo 'Install nmap separately after review' >&2; exit 2; }
[[ $EUID == 0 ]] || { echo 'SYN scan requires an explicitly privileged lab session' >&2; exit 2; }
timeout --kill-after=5 120 nmap -n -sS -T4 --host-timeout 90s "$TARGET"
echo 'Scan completed; verify the specific Suricata signature and Wazuh event.'
