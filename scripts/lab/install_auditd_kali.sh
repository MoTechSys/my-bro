#!/bin/bash
# Purpose: approved auditd lab setup; owner [ASTRA]; updated 2026-09-09.
# Status: syntax checked; live service/rollback test pending. Sources: UC-05, ISSUE-031.
set -euo pipefail
export PATH=/usr/bin:/bin
[[ ${1:-} == --lab && $# == 1 ]] || { echo 'Usage: install_auditd_kali.sh --lab (changes audit policy)' >&2; exit 2; }
[[ $EUID != 0 ]] || { echo 'Run as the lab user; only installation uses sudo' >&2; exit 2; }
getent group wazuh >/dev/null || { echo 'Install Wazuh agent first' >&2; exit 2; }
GID=$(getent group wazuh | cut -d: -f3)
[[ $GID =~ ^[0-9]+$ ]] || exit 2
SOURCE=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)/wazuh/auditd/wazuh.rules
umask 077
STAGED=$(mktemp "$PWD/.audit-rules.XXXXXX")
trap 'rm -f -- "$STAGED"' EXIT
sed "s/egid!=994/egid!=$GID/g" "$SOURCE" > "$STAGED"
sudo apt -y install auditd
sudo systemctl enable --now auditd
DEST=/etc/audit/rules.d/wazuh.rules
if sudo test -e "$DEST"; then
  BACKUP=$(sudo mktemp /etc/audit/rules.d/wazuh.backup.XXXXXX)
  sudo cp --preserve=mode,ownership,timestamps -- "$DEST" "$BACKUP"
  echo "Previous policy backed up at $BACKUP (not a .rules file)"
fi
sudo install -o root -g root -m 600 -- "$STAGED" "$DEST"
sudo augenrules --load
sudo auditctl -l
echo "Configured wazuh GID: $GID. Verify login AUID and rules; no success-rate claim."
