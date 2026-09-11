# SOC Graduation Project — Open-Source Security Operations Center with Wazuh SIEM

> 🧠 **للوكلاء/المطوّرين الجدد:** ابدأ بـ [`CONTEXT_RESUME.md`](CONTEXT_RESUME.md) — ذاكرة المشروع الكاملة في ملف واحد.

> **مشروع تخرّج:** تصميم وتنفيذ مركز عمليات أمنية (SOC) يعتمد على أدوات مفتوحة المصدر — Wazuh 4.14.7 + Suricata 8.0.6 + YARA + VirusTotal + auditd — في معمل افتراضي يراقب Windows 10 وKali Linux.

> CI: [validation workflow](.github/workflows/validate.yml) · [actual runs](https://github.com/MoTechSys/my-bro/actions/workflows/validate.yml) · [activation history](.github/workflows-pending/README.md). CI does not deploy or certify the SOC lab.

## 🤖 للوكلاء الآليين (AI agents)
**ابدأ من [`AI_AGENT_START_HERE.md`](AI_AGENT_START_HERE.md)** ثم [`docs/00_PROJECT_STATE.md`](docs/00_PROJECT_STATE.md). لا تعمل قبل قراءتهما.

## 👥 للفريق (البشر)

| أريد أن… | اذهب إلى |
|----------|----------|
| أفهم ما هو موجود وما هو ناقص | [`docs/00_PROJECT_STATE.md`](docs/00_PROJECT_STATE.md) |
| أرى الخطة والمراحل | [`docs/03_ROADMAP.md`](docs/03_ROADMAP.md) |
| أعرف الأخطاء التي يجب تصحيحها في الرسالة/المعمل | [`docs/04_ISSUES_LOG.md`](docs/04_ISSUES_LOG.md) |
| أعرف حقائق المعمل (IPs، إصدارات، قواعد) | [`docs/02_ARCHITECTURE.md`](docs/02_ARCHITECTURE.md) |
| أعيد تنفيذ حالة استخدام خطوة بخطوة | [`docs/lab/`](docs/lab/) |
| أنسخ إعدادات Wazuh النظيفة إلى السيرفر | [`wazuh/README.md`](wazuh/README.md) |
| أكتب فصلاً من الرسالة | [`docs/thesis/README.md`](docs/thesis/README.md) |
| أفهم رؤية التوسعة (أجهزة الشبكة/الهواتف) | [`extension/VISION_AND_FEASIBILITY.md`](extension/VISION_AND_FEASIBILITY.md) |

## حالات الاستخدام الموثقة تاريخياً — تحتاج إعادة تحقق حي

| UC | الوصف | قاعدة/مستوى التنبيه |
|----|-------|---------------------|
| 01 | نشر وكلاء Windows/Linux | — |
| 02 | File Integrity Monitoring (realtime) | 550/553/554 |
| 03 | VirusTotal + حذف تلقائي (Active Response) | 87105 → 100092 (L12) |
| 04 | Suricata NIDS → Wazuh | 86601 |
| 05 | auditd + CDB list للأوامر الخبيثة | 100210 (L12) |
| 06 | كشف Shellshock عبر Apache logs | 31168 (L15) + MITRE T1068/T1190 |
| 07 | YARA scan on file change (Active Response) | 108001 (L12) |
| 08 | مراقبة العمليات — Netcat listener | 100051 (L7) |

## دراسة النية والمخطط المقترح
[دراسة الأصول والصوتيات والمخطط](docs/INTENT_STUDY_AND_BLUEPRINT.md) — مصفوفة الأدلة والمتطلبات، حدود مراقبة الهواتف والشبكة، بوابات التسليم، وبحث Fable/Astra الرسمي. مقترح ينتظر قرارات صاحب المشروع؛ ليس إعلان اكتمال أو تغيير نطاق تلقائي.

## خطة الاستكمال والتدقيق
[الخطة الموحدة](docs/03_ROADMAP.md) · [سجل تغطية التدقيق](docs/TAKEOVER_AUDIT.md). لا تمثل اللقطات القديمة اعتماداً للكود الحالي؛ Windows AR والقياسات الفعلية معلقة.

## ✅ التحقق
```bash
bash scripts/validate/validate_all.sh
```

## 📁 الهيكل
```
AI_AGENT_START_HERE.md   بروتوكول الوكلاء       docs/        التوثيق والخطة والمصادر
wazuh/                   إعدادات نظيفة قابلة للنشر   scripts/     تحقق + محاكاة هجمات
extension/               رؤية التوسعة              tests/       خطة ونتائج الاختبار (P2)
```

## ⚠️ الأمان
لا مفاتيح API حقيقية في المستودع. استبدل `<YOUR_VIRUS_TOTAL_API_KEY>` محلياً فقط.

## الترخيص
سكربتات Active Response مشتقة من توثيق Wazuh (GPLv2). باقي المحتوى © فريق المشروع.
