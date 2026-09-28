# SOC Graduation Project — Open-Source Security Operations Center with Wazuh SIEM

> 🧠 **للوكلاء/المطوّرين الجدد:** ابدأ بـ [`CONTEXT_RESUME.md`](CONTEXT_RESUME.md) — ذاكرة المشروع الكاملة في ملف واحد.

> **مشروع تخرّج:** تصميم وتنفيذ مركز عمليات أمنية (SOC) يعتمد على أدوات مفتوحة المصدر — Wazuh 4.14.7 + Suricata + YARA + VirusTotal + auditd + MikroTik syslog + محلل AI — يراقب Windows/Linux وأجهزة الشبكة ورؤية الهواتف من الشبكة.

> CI: see `.github/workflows-pending/README.md` to enable the validation workflow.

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

## حالات الاستخدام (مُتحقَّق منها على Wazuh 4.14.7 حقيقي — 2026-09-28)

| UC | الوصف | القواعد | التحقق |
|----|-------|---------|--------|
| 01 | نشر الوكلاء | 503/504 | kali1 active (Windows تاريخي) |
| 02 | FIM realtime | 550/553/554, 100200/100201 | حي |
| 03 | VirusTotal + حذف آلي مُحصَّن | 87105 → 100092/100093 | حي (1.6 ث) |
| 04 | Suricata NIDS | 86601 | محرك |
| 05 | auditd + CDB أوامر خبيثة | 100210 (L12) | محرك |
| 06 | Shellshock | 31168 (L15) | حي |
| 07 | YARA + AR | 108001 (L12) | محرك |
| 08 | Netcat listener | 100051 | محرك (9 صيغ) |
| 09 | SQL Injection | 31103/31106 | حي |
| 10 | Telegram L≥12 | integratord | حي (mock) |
| 11 | SSH brute force + حظر آلي | 5712/5763 → 651 | حي |
| 12 | راوتر MikroTik (syslog) | 100400–100411 | حي (محاكي) |
| 13 | رؤية الهواتف/الأجهزة من الشبكة | 100420–100422 | حي (محاكي) |
| 14 | محلل AI (شرح/ترابط/رد بموافقة) | — | حي (gpt-5-mini) |

التفاصيل: [`docs/lab/README.md`](docs/lab/README.md) · المعمل: [`docs/lab/SANDBOX_LAB.md`](docs/lab/SANDBOX_LAB.md) · التغطية: [`docs/lab/COVERAGE_MATRIX.md`](docs/lab/COVERAGE_MATRIX.md) · AI: [`ai_agent/README.md`](ai_agent/README.md)

## دراسة النية والمخطط المقترح
[دراسة الأصول والصوتيات والمخطط](docs/INTENT_STUDY_AND_BLUEPRINT.md) — مصفوفة الأدلة والمتطلبات، حدود مراقبة الهواتف والشبكة، بوابات التسليم، وبحث Fable/Astra الرسمي. مقترح ينتظر قرارات صاحب المشروع؛ ليس إعلان اكتمال أو تغيير نطاق تلقائي.

## خطة الاستكمال والتدقيق
[الخطة الموحدة](docs/03_ROADMAP.md) · [سجل تغطية التدقيق](docs/TAKEOVER_AUDIT.md). لا تمثل اللقطات القديمة اعتماداً للكود الحالي؛ Windows AR والقياسات الفعلية معلقة.

## ✅ التحقق
```bash
bash scripts/validate/validate_all.sh                  # بنية + معرّفات + أسرار
python3 -m pytest tests -q                             # 178 اختباراً (+28 تُتخطّى بلا Wazuh)
sudo python3 -m pytest tests/test_wazuh_engine.py -q   # 28 على محرك Wazuh الحقيقي
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
