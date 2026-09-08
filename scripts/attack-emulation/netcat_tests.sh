#!/bin/bash
# UC-05 + UC-08: trigger the auditd red-list rule (100210) and the netcat listener rule (100051).
# Source: S2 p.36, S5 img12/img31.  Package on Kali: netcat-traditional or netcat-openbsd (ISSUE-012).
command -v nc >/dev/null || sudo apt -y install netcat-traditional
echo "[1] executing 'nc -h' -> expect 100210 (audit red)"; nc -h >/dev/null 2>&1
echo "[2] starting listener for 45s on :4444 -> expect 100051 within one 30s process-list cycle"
timeout 45 nc -l -p 4444 >/dev/null 2>&1 &
echo "check dashboard: data.audit.command:nc  |  rule.id:100051"
