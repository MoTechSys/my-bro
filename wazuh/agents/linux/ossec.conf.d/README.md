# Linux agent (kali1) — ossec.conf snippets

Add each block **inside** the existing `<ossec_config>` of `/var/ossec/etc/ossec.conf`, then
`sudo systemctl restart wazuh-agent`.

| File | Use case | Source |
|------|----------|--------|
| `10-syscheck-dirs.xml` | UC-02/03/07 FIM directories | S2 pp.7-8, 12, 43 |
| `20-localfile-audit.xml` | UC-05 auditd log | S2 p.33, S5 img04 |
| `30-localfile-apache.xml` | UC-06 Apache access log | S2 p.38, S5 img16 |
| `40-localfile-suricata.xml` | UC-04 Suricata eve.json | S2 p.30 |
| `50-command-process-list.xml` | UC-08 process list every 30 s | S5 img30 |
