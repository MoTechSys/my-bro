# الرسالة الأكاديمية — الهيكل والحالة

> المصدر الحالي: `docs/sources/originals/04_thesis_ch1_ch3_latest_REPAIRED.docx` (S4). كل فصل يُكتب هنا كـ Markdown ثم يُحوَّل إلى DOCX بـ pandoc (`scripts/thesis/build_docx.sh` — يُنشأ في P2).
> **قاعدة:** أي مكوّن يُذكر في الرسالة يجب أن يكون في `02_ARCHITECTURE.md` أو موصوفاً صراحةً كـ "عمل مستقبلي".

## حالة الفصول

| الفصل | العنوان | الحالة | المصدر/الملاحظات |
|-------|---------|:------:|------------------|
| 1 | المقدمة (1.1–1.7) | ✅ مكتمل في S4 | يحتاج تصحيح جدول 1.1: حذف Zeek/Filebeat/Elasticsearch/Kibana → Wazuh Indexer/Dashboard؛ Windows 11 → 10 (ISSUE-001/002/003/015) |
| 2 (✅ v1 `ch2_literature_review.md`) | الإطار النظري والدراسات السابقة | ❌ غير موجود | SOC، SIEM، IDS/NIDS، FIM، Active Response، Threat Intelligence (VirusTotal/YARA)، MITRE ATT&CK؛ مقارنة Wazuh vs OSSEC/ELK/Splunk/Security Onion؛ ≥10 مراجع (Wazuh docs، Suricata docs، NIST SP 800-61، MITRE) |
| 3 | منهجية التصميم | ◐ §3.6 فقط | إضافة 3.1 المنهجية (تجريبية/تطبيقية)، 3.2 تحليل المتطلبات (وظيفية/غير وظيفية)، 3.3 حالات الاستخدام (UC-01..08)، 3.4 تصميم المعمل (المخطط من 02_ARCHITECTURE §1)، 3.5 تصميم القواعد (ID registry)؛ إكمال DFD Level 1/2 كأشكال |
| 4 | التنفيذ | ❌ غير موجود كفصل | المادة الخام جاهزة: S5 (4 أقسام) + runbooks UC-01..08 + لقطات المعمل الحقيقية (ليس لقطات توثيق Wazuh — ISSUE-005) |
| 5 | الاختبار والنتائج والخاتمة | ❌ | جدول النتائج المُقاسة من `tests/RESULTS.md` (ISSUE-019)، التحديات (DNS، HOME_NET، yum على Kali…)، الأعمال المستقبلية: Zeek، TheHive، AI analyzer، Email/Telegram، network devices syslog، mobile (ISSUE-027) |
| — | المراجع | ❌ | APA/IEEE حسب قالب الجامعة (Q6) |
| — | الملاحق | ❌ | أ: local_rules.xml كامل؛ ب: سكربتات AR؛ ج: أوامر التثبيت |

## ملفات العمل (تُنشأ في P2)
```
docs/thesis/
├── ch1_introduction.md          (مستخرج من S4 + تصحيحات)
├── ch2_literature_review.md
├── ch3_methodology.md
├── ch4_implementation.md
├── ch5_results_conclusion.md
├── references.md
└── figures/                     (المخططات: topology, DFD L0/L1/L2, data flow)
```

## قواعد الكتابة
- عربية فصحى؛ المصطلح الإنجليزي بين قوسين عند أول ذكر.
- كل لقطة شاشة تُرقَّم "شكل (X.Y)" وتُذكر في النص قبلها.
- كل ادعاء "تم الكشف" يُسند إلى rule.id + level + لقطة.
