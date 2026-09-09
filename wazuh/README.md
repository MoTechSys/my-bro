# `wazuh/` — Clean, corrected, deployable configuration

This directory combines source-derived lab configurations with newly authored T-15 hardening (#14). Local tests are not native deployment acceptance. Follow tests/SECURITY_REVIEW.md for gates, backup and rollback; never copy all files blindly.

```
wazuh/
├── manager/
│   ├── rules/local_rules.xml          -> /var/ossec/etc/rules/local_rules.xml
│   ├── decoders/local_decoder.xml     -> /var/ossec/etc/decoders/local_decoder.xml
│   ├── lists/suspicious-programs      -> /var/ossec/etc/lists/suspicious-programs
│   ├── lists/audit-keys               (reference; shipped with Wazuh)
│   └── ossec.conf.d/*.xml             snippets to merge into /var/ossec/etc/ossec.conf
├── agents/
│   ├── linux/ossec.conf.d/*.xml       snippets for kali1 /var/ossec/etc/ossec.conf
│   ├── linux/active-response/*.sh     -> /var/ossec/active-response/bin/  (root:wazuh 750)
│   ├── windows/ossec.conf.d/*.xml     snippets for win1 ossec.conf
│   └── windows/active-response/       yara.bat, remove-threat.py (-> .exe via PyInstaller)
├── suricata/suricata.yaml.patch.md
└── auditd/wazuh.rules
```

## Linux and Windows deployment contract
Linux: install remove-threat.sh as /var/ossec/active-response/bin/remove-threat.exe, with soc_ar.py beside it; install yara.sh with that same helper. All root:wazuh 0750 in protected parents. Never copy the Windows binary to Linux. Windows needs verified allowlists, native PyInstaller builds and ACL testing. The manager uses one local remove-threat dispatch; current VT integration does not automatically cover Windows. See docs/lab/UC-03 and UC-07.

## Apply order (manager)
1. `lists/suspicious-programs` → then add `<list>` line (`ossec.conf.d/10-*`).
2. `decoders/local_decoder.xml`
3. `rules/local_rules.xml`
4. Merge `ossec.conf.d/20-*`, `30-*`, `40-*` into `<ossec_config>` (set the VirusTotal key).
5. `sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager`

## Validate before commit
```bash
bash scripts/validate/validate_all.sh
```

## Rule-ID namespace
See `docs/02_ARCHITECTURE.md §5`. Reserved for extensions: 100400–100499 (network/syslog), 100500–100599 (AI/reporting).
