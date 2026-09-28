#!/bin/bash
# Deploy this repository's manager-side content into a local wazuh-manager 4.14.x
# (sandbox/lab). Idempotent. Owner [CLAUDE] 2026-09-28.
# Usage: sudo bash scripts/lab/deploy_manager_local.sh [--restart]
set -euo pipefail
cd "$(dirname "$0")/../.."
W=/var/ossec
[[ -x $W/bin/wazuh-control ]] || { echo "wazuh-manager not installed" >&2; exit 2; }
install -o wazuh -g wazuh -m 660 wazuh/manager/rules/local_rules.xml wazuh/manager/rules/local_rules_network.xml $W/etc/rules/
install -o wazuh -g wazuh -m 660 wazuh/manager/decoders/local_decoder.xml wazuh/manager/decoders/mikrotik_decoders.xml $W/etc/decoders/
for l in suspicious-programs known-devices; do install -o wazuh -g wazuh -m 660 wazuh/manager/lists/$l $W/etc/lists/$l; done
install -o root -g wazuh -m 750 wazuh/manager/integrations/custom-telegram wazuh/manager/integrations/custom-telegram.py $W/integrations/
install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/soc_ar.py $W/active-response/bin/soc_ar.py
install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/remove-threat.sh $W/active-response/bin/remove-threat.exe
install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/yara.sh $W/active-response/bin/yara.sh
python3 - "$W/etc/ossec.conf" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
for l in ('etc/lists/suspicious-programs','etc/lists/known-devices'):
    tag=f'<list>{l}</list>'
    if tag not in s:
        s=s.replace('<list>etc/lists/audit-keys</list>', '<list>etc/lists/audit-keys</list>\n    '+tag, 1)
open(p,'w').write(s)
PY
$W/bin/wazuh-analysisd -t
echo "deployed; analysisd config test OK"
[[ ${1:-} == --restart ]] && $W/bin/wazuh-control restart >/dev/null && echo restarted
exit 0
