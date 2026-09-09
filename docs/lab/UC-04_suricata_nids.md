# UC-04 — تكامل Suricata NIDS مع Wazuh

**المصدر:** S2 ص26–31، لقطات `p27_0`, `p28_0`, `p28_1`, `p29_0..3`, `p30_0`, `p30_1`; S5 `img18` (NMAP SYN Scan alert).

## الهدف
كشف هجمات الشبكة (فحص منافذ، توقيعات ET Open) على `kali1` وإرسالها كأحداث JSON إلى Wazuh.

## التثبيت (kali1)
```bash
sudo apt-get update && sudo apt-get install suricata -y     # Kali repo → 8.0.6 (p30_0)
# add-apt-repository ppa:oisf/... غير موجود على Kali (p27_0: command not found) — لا حاجة له.
sudo suricata-update                                          # قواعد ET Open → /var/lib/suricata/rules
```

## الإعداد `/etc/suricata/suricata.yaml`
انظر `wazuh/suricata/suricata.yaml.patch.md`. الجوهر:
- `HOME_NET: "[192.168.100.0/24,10.0.0.0/8,172.16.0.0/12]"` **مرة واحدة** (ISSUE-021).
- `default-rule-path: /var/lib/suricata/rules` + `rule-files: - "*.rules"` (ISSUE-022).
- `af-packet: - interface: eth0`.
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml && sudo systemctl enable --now suricata
```

## ربط الوكيل
`wazuh/agents/linux/ossec.conf.d/40-localfile-suricata.xml`:
```xml
<localfile><log_format>json</log_format><location>/var/log/suricata/eve.json</location></localfile>
```
`sudo systemctl restart wazuh-agent`. لا حاجة لقواعد مخصصة — Wazuh يملك decoder وقواعد Suricata (86600+).

## المحاكاة
```bash
sudo bash scripts/attack-emulation/nmap_scan.sh --lab 192.168.100.108     # من جهاز آخر
# لا يعتبر ping دليلاً بديلاً على اكتشاف المسح؛ تحقق من التوقيع الفعلي في PILOT.
```

## النتيجة الفعلية
- `p30_0.png`: `suricata.service active (running)` — **Suricata 8.0.6 RELEASE, SYSTEM mode**.
- S5 `img18`: `rule.id 86601 — Suricata: Alert - NMAP SYN Scan Detected` على `kali1`.

## الأخطاء المعروفة
- ISSUE-009 `chmod 777` على القواعد — استخدم 644.
- ISSUE-021 `Configuration node 'HOME_NET' redefined`.
- S2 ص31: `Unable to find iface eth0` → اسم الواجهة خطأ.

## استعلام اللوحة
Threat Hunting → `rule.groups:suricata`.
