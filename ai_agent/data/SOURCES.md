# Data provenance

- `mitre_techniques.json`: extracted 18 techniques from MITRE ATT&CK Enterprise STIX (github.com/mitre-attack/attack-stix-data), collection version 19.2, fetched 2026-09-28. Only IDs referenced by our rules/built-in rules.
- `builtin_rules.json`: descriptions/levels/MITRE copied from `/var/ossec/ruleset/rules/*.xml` of wazuh-manager 4.14.7 (installed package), 2026-09-28.
- Wazuh 4.14.7 rules still emit T1562.001/T1562.004, which ATT&CK v19 revoked (-> T1685/T1686). Both old and new IDs are kept; the old entry carries `revoked_by`.
