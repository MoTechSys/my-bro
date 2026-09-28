# UC-09 — كشف حقن SQL عبر سجلات Apache

**الحالة:** ✅ مُثبت حياً 2026-09-28 على wazuh-manager 4.14.7 (sandbox، `SANDBOX_LAB.md`). يُغلق ISSUE-007 وISSUE-059.

## الهدف
كشف أنماط SQL Injection في طلبات HTTP (MITRE T1190) من `access.log` دون قاعدة بيانات حقيقية.

## السلسلة
طلب HTTP → `/var/log/apache2/access.log` → logcollector **`log_format apache`** → decoder `web-accesslog` →
- **31103** SQL injection attempt (L7) عند رمز غير 2xx
- **31106** A web attack returned code 200 (L6) عند النجاح (أخطر: الطلب قُبل)

> ⚠️ مع `log_format syslog` (الإعداد القديم) لا يضمن Wazuh فك الحقول؛ لذلك `wazuh/agents/linux/ossec.conf.d/30-localfile-apache.xml` صار `apache` (ISSUE-059). Shellshock 31168 يبقى يعمل.

## الإعداد
Agent: `30-localfile-apache.xml` داخل ossec.conf ثم `systemctl restart wazuh-agent`. لا قواعد مخصصة (built-in `0245-web_rules.xml`).

## المحاكاة
```bash
bash scripts/attack-emulation/sqli_test.sh --lab 192.168.100.108          # SQLI_PORT=8081 لمنفذ آخر
```
يرسل 3 أنماط (`union select`, `+union+select+null,null`, `' or 1=1 from users--`) بـUser-Agent `SOC_SQLI_TEST`.

## الدليل الحي (2026-09-28)
```
2026-09-28T16:50:45.407+0000 31103 7 SQL injection attempt. ['T1190'] /index.php?id=1%20union%20select%201,2,3
2026-09-28T16:50:45.407+0000 31103 7 SQL injection attempt. ['T1190'] /login.php?user=admin'%20or%201=1%20from%20users--
2026-09-28T16:50:45.407+0000 31103 7 SQL injection attempt. ['T1190'] /index.php?id=1+union+select+null,null
```
اختبارات المحرك: `tests/test_wazuh_engine.py::EngineRules::test_uc09_*`.

## استعلام اللوحة
`rule.id:(31103 OR 31106)`

## حدود
كشف نمط في URL فقط (لا POST body)؛ لا يثبت نجاح الاستغلال. ترميزات مزدوجة/تهرّب قد تفلت (يُذكر في الفصل 5).
