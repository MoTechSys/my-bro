# `wazuh/` — Clean, corrected, deployable configuration

Everything in this directory is **extracted from the team's lab sources (S2, S5) and corrected** according to `docs/04_ISSUES_LOG.md`. Nothing here is invented; every file header cites its source page/screenshot.

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
