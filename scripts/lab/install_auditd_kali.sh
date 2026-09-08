#!/bin/bash
# UC-05: install auditd and load the Wazuh execve rules. Source: S2 pp.32-33, S5 img01-02
set -e
sudo apt -y install auditd
sudo systemctl enable --now auditd
sudo cp "$(dirname "$0")/../../wazuh/auditd/wazuh.rules" /etc/audit/rules.d/wazuh.rules
sudo augenrules --load
sudo auditctl -l
echo "wazuh group GID (ISSUE-031): $(getent group wazuh)"
