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
bash scripts/attack-emulation/shellshock_test.sh --lab 192.168.100.108
```
استجابة Apache الافتراضية ("It works") **طبيعية** — الخادم غير مصاب فعلياً (لا CGI)، لكن الطلب يُسجَّل في access.log وهذا كل ما يحتاجه Wazuh للكشف.

## النتيجة الفعلية
- S5 `img17`: أمر curl بالحمولة إلى `192.168.0.186` وإرجاع صفحة Apache الافتراضية.
- S5 `img19`: **rule 31168 — Shellshock attack detected — Level 15** على `kali1` مع MITRE T1068/T1190 (2026-08-30)، إضافة إلى `rule 506 Wazuh agent stopped` (T1562.001).

## الأخطاء المعروفة
- ISSUE-004: IP الهدف في S5 (`192.168.0.186`) من شبكة مختلفة عن المعمل الحالي.
- ISSUE-007: عنوان القسم في S2 يذكر "SQL Injection" بلا محتوى → مقترح UC-09 (قواعد 31103/31104 بنفس الإعداد).

## استعلام اللوحة
Threat Hunting → `rule.description:Shellshock attack detected` أو `rule.id:31168`; MITRE ATT&CK → T1190.
