# Lab Runbooks — حالات الاستخدام (Use Cases)

كل runbook يتبع القالب: **الهدف → المكونات → الإعداد (agent / manager) → محاكاة الهجوم → النتيجة المتوقعة → الأدلة الفعلية من المعمل → الأخطاء المعروفة → استعلام اللوحة**.

| UC | العنوان | الحالة | القواعد الرئيسية | آخر تحقق حي (Wazuh 4.14.7 sandbox) |
|----|---------|:------:|------------------|------------------|
| [UC-01](UC-01_agent_deployment.md) | نشر وكلاء Windows + Linux | ✅ Linux / ⚠️ Windows | 503/504 | 2026-09-28: kali1 (001) active؛ Windows تاريخي فقط (S2 p04_0) |
| [UC-02](UC-02_fim.md) | File Integrity Monitoring | ✅ | 550/553/554, 100200/100201 | 2026-09-28: FIM realtime → 100201 |
| [UC-03](UC-03_virustotal_active_response.md) | VirusTotal + Active Response | ✅ (VT محقون) | 87105, 100092/100093 | 2026-09-28: حذف خلال 1.6 ث؛ 4 مدخلات خبيثة رُفضت |
| [UC-04](UC-04_suricata_nids.md) | Suricata NIDS | ✅ قاعدة | 86601 | logtest؛ Suricata غير مثبت هنا |
| [UC-05](UC-05_auditd_malicious_commands.md) | الأوامر الخبيثة (auditd + CDB) | ✅ قاعدة | 80792 → 100210 | logtest؛ auditd غير مثبت هنا |
| [UC-06](UC-06_shellshock.md) | Shellshock | ✅ | 31168 | Apache حقيقي |
| [UC-07](UC-07_yara.md) | YARA + AR | ✅ قاعدة / ⚠️ Windows | 100300/100301, 100303/100304, 108001 | logtest + FIM queue لـWindows |
| [UC-08](UC-08_process_monitoring_netcat.md) | Netcat listener | ✅ | 100050/100051 | logtest 9 صيغ + 6 سلبية |
| [UC-09](UC-09_sql_injection.md) | SQL Injection | ✅ | 31103/31106 | Apache حقيقي + sqli_test.sh |
| [UC-10](UC-10_telegram.md) | إشعار Telegram L≥12 | ✅ (mock) | integratord | integrator → mock API |
| [UC-11](UC-11_ssh_bruteforce_ar.md) | SSH brute force + firewall-drop | ✅ | 5712/5763 → 651/652 | sshd حقيقي، iptables، فك 300 ث |
| [UC-12](UC-12_mikrotik_network_devices.md) | أجهزة الشبكة MikroTik | ✅ (محاكي) | 100400–100411 | UDP 514 → remoted |
| [UC-13](UC-13_mobile_network_visibility.md) | رؤية الهواتف/الأجهزة من الشبكة | ✅ (محاكي) | 100420–100422 | UDP 514 → remoted |
| [UC-14](UC-14_ai_analyst.md) | المحلل بالذكاء الاصطناعي L1/L2/L3 | ✅ | — | gpt-5-mini + Wazuh API على kali1 |

المعمل الحي وطريقة إعادة بنائه: [`SANDBOX_LAB.md`](SANDBOX_LAB.md). مصفوفة التغطية: [`COVERAGE_MATRIX.md`](COVERAGE_MATRIX.md).

**أدلة اللقطات:** `docs/sources/screenshots/wazuh_guide/` (S2) و`docs/sources/screenshots/wazuh_report/` (S5). لقطات جديدة تُوضع في `docs/lab/evidence/UC-0X/`.
