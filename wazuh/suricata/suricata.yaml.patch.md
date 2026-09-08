# Suricata 8.0.6 — required changes to `/etc/suricata/suricata.yaml` (UC-04)

Source: S2 pp.28–29 + screenshots `p29_0..p29_3.png`, `p30_0.png`.
Fixes: ISSUE-009 (no chmod 777), ISSUE-021 (duplicate HOME_NET), ISSUE-022 (rule path).

```yaml
vars:
  address-groups:
    # ONE HOME_NET line only (the lab had two -> "Configuration node 'HOME_NET' redefined")
    HOME_NET: "[192.168.100.0/24,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

default-rule-path: /var/lib/suricata/rules     # path used by `suricata-update` (matches screenshot p29_1)
rule-files:
  - "*.rules"

stats:
  enabled: yes

af-packet:
  - interface: eth0                              # verify with `ip a`; the lab VM uses eth0
```

## Rules install (pick ONE)

```bash
# A) recommended
sudo suricata-update
# B) manual ET Open
cd /tmp && curl -LO https://rules.emergingthreats.net/open/suricata-8.0.6/emerging.rules.tar.gz \
 && tar -xvzf emerging.rules.tar.gz && sudo mkdir -p /var/lib/suricata/rules \
 && sudo mv rules/*.rules /var/lib/suricata/rules/ && sudo chmod 644 /var/lib/suricata/rules/*.rules
```

## Validate + run
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml      # must print "Configuration provided was successfully loaded"
sudo systemctl enable --now suricata
sudo systemctl status suricata                        # expect: "This is Suricata version 8.0.6 RELEASE running in SYSTEM mode"
```

## Troubleshooting (from S2 p.31)
`Unable to find iface eth0: No such device` → wrong interface name; fix `af-packet.interface`.
