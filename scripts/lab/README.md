# scripts/lab — تثبيت المكونات على Kali (kali1)
| سكربت | UC | الوظيفة |
|-------|----|---------|
| `install_auditd_kali.sh --lab` | 05 | auditd + قواعد execve من `wazuh/auditd/wazuh.rules` |
| `install_yara_kali.sh --lab SOURCE_SHA256 RULES_SHA256` | 07 | بناء YARA 4.5.5، إصلاح libyara، قواعد VALHALLA إلى `/var/ossec/etc/yara/rules/` |

شغّل كمستخدم المعمل غير root؛ sudo لخطوات التثبيت المعلنة فقط. البصمات مستقلة موثوقة؛ snapshot وrollback قبل أي تغيير. لم تختبر هذه المثبتات أصلياً هنا؛ راجع SECURITY_REVIEW §5–7.
