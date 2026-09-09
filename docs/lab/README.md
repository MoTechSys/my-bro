# Lab Runbooks — حالات الاستخدام (Use Cases)

كل runbook يتبع القالب: **الهدف → المكونات → الإعداد (agent / manager) → محاكاة الهجوم → النتيجة المتوقعة → الأدلة الفعلية من المعمل → الأخطاء المعروفة → استعلام اللوحة**.

| UC | العنوان | الحالة | القواعد الرئيسية | الدليل المعملي |
|----|---------|:------:|------------------|----------------|
| [UC-01](UC-01_agent_deployment.md) | نشر وكلاء Windows + Linux | ✅ | — | S2 p04_0 |
| [UC-02](UC-02_fim.md) | File Integrity Monitoring | ✅ | 550/553/554 | S2 p09_1, p18_1 |
| [UC-03](UC-03_virustotal_active_response.md) | VirusTotal + Active Response | ✅ | 100200/100201, 87105, 100092/100093 | S2 p17_0, p18_1 |
| [UC-04](UC-04_suricata_nids.md) | Suricata NIDS | ✅ | 86600–86601 | S2 p30_0, S5 img18 |
| [UC-05](UC-05_auditd_malicious_commands.md) | مراقبة الأوامر الخبيثة (auditd + CDB) | ✅ | 80792 → 100210 | S5 img01–img12, S2 p36_0 |
| [UC-06](UC-06_shellshock.md) | كشف Shellshock | ✅ | 31168 | S5 img13–img19 |
| [UC-07](UC-07_yara.md) | YARA + Active Response | ✅ Linux / ⚠️ Windows | 100300/100301, 108000/108001 | S5 img20–img29 |
| [UC-08](UC-08_process_monitoring_netcat.md) | مراقبة العمليات (Netcat listener) | ✅ | 100050/100051 | S5 img30–img31 |
| UC-09 | SQL Injection (مقترح، ISSUE-007) | ☐ | 31103/31104 | — |
| UC-10 | إشعارات Email/Telegram (مقترح، ISSUE-016) | ☐ | — | — |
| UC-11 | SSH brute-force + firewall-drop (مقترح) | ☐ | 5710/5712 + AR | — |
| UC-12 | أجهزة الشبكة عبر Syslog (رؤية المستخدم) | ☐ | 100400+ | — |

**أدلة اللقطات:** `docs/sources/screenshots/wazuh_guide/` (S2) و`docs/sources/screenshots/wazuh_report/` (S5). لقطات جديدة تُوضع في `docs/lab/evidence/UC-0X/`.
