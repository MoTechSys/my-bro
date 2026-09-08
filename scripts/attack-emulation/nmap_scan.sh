#!/bin/bash
# UC-04: generate Suricata alerts (NMAP SYN scan) — seen in the lab as rule 86601 (S5 img18).
TARGET="${1:-192.168.100.108}"
command -v nmap >/dev/null || sudo apt -y install nmap
sudo nmap -sS -T4 "$TARGET"
echo "check dashboard: rule.groups:suricata"
