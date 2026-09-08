# scripts/lab — تثبيت المكونات على Kali (kali1)

| سكربت | UC | ماذا يفعل |
|-------|----|-----------|
| `install_auditd_kali.sh` | 05 | يثبت auditd ويضيف قواعد execve (من `wazuh/auditd/wazuh.rules`) |
| `install_yara_kali.sh` | 07 | يبني YARA 4.5.5 من المصدر، يصلح libyara، ينزّل قواعد VALHALLA إلى `/var/ossec/etc/yara/rules/` (ISSUE-020) |

بعد كل سكربت: انسخ مقاطع `wazuh/agents/linux/ossec.conf.d/` وأعد تشغيل `wazuh-agent`.
