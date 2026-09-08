# UC-06 — كشف هجوم Shellshock (CVE-2014-6271)

**المصدر:** S2 ص36–39 (`p37_0`, `p38_0`, `p38_1`, `p39_1`); S5 القسم الثاني (`img13`–`img19`).

## الهدف
كشف نمط Shellshock `() { :; };` في ترويسات HTTP الواردة إلى Apache على `kali1` عبر مراقبة `access.log`، وربطه بـ MITRE ATT&CK.

## سلسلة الأحداث
طلب HTTP بترويسة User-Agent خبيثة → `/var/log/apache2/access.log` → logcollector (syslog) → decoder apache → **`31168` Shellshock attack detected (L15)** → MITRE `T1068` + `T1190`.

## الضحية (kali1)
```bash
sudo apt update && sudo apt install apache2 -y       # 2.4.68-1 (img13)
sudo ufw allow 'Apache' && sudo ufw enable && sudo ufw status
sudo systemctl status apache2                          # active (img15)
```
`wazuh/agents/linux/ossec.conf.d/30-localfile-apache.xml` → داخل ossec.conf → `sudo systemctl restart wazuh-agent`.

## المحاكاة (من جهاز المهاجم)
```bash
bash scripts/attack-emulation/shellshock_test.sh 192.168.100.108
```
استجابة Apache الافتراضية ("It works") **طبيعية** — الخادم غير مصاب فعلياً (لا CGI)، لكن الطلب