# 🤖 AI AGENT — START HERE (اقرأ هذا أولاً)

> **هذا الملف هو نقطة الدخول الإلزامية لأي جلسة AI جديدة تعمل على هذا المستودع.**
> لا تبدأ أي عمل قبل قراءة الملفات المذكورة أدناه بالترتيب.

---

## 0. ما هو هذا المشروع؟ (30 ثانية)

مشروع تخرّج جامعي (4 طلاب) بعنوان:

> **تصميم وتنفيذ منصة مركز عمليات أمنية (SOC) باستخدام أدوات مفتوحة المصدر — Wazuh SIEM**
> *Design & Implementation of an Open-Source Security Operations Center Platform*

- **الأداة المركزية:** Wazuh **v4.14.7** (Manager + Indexer + Dashboard) على Ubuntu Server.
- **نقاط النهاية المُراقبة:** Kali Linux 2025.4 (`kali1`) + Windows 10 Education (`win1`).
- **ما تم تنفيذه فعلياً في المعمل** (مؤكَّد بلقطات شاشة): نشر الوكلاء، FIM، VirusTotal + Active Response، Suricata NIDS، auditd + CDB lists، Shellshock detection، YARA + Active Response، مراقبة Netcat.
- **المرحلة الحالية:** الجزء العملي الأساسي مكتمل ~90%. المتبقي: توثيق أكاديمي (الفصول 2، 4، 5)، اختبارات مُقاسة، وتوسعة الرؤية (مراقبة أجهزة الشبكة والهواتف — انظر الرؤية في `docs/01_SOURCE_ANALYSIS.md §7`).

---

## 1. ترتيب القراءة الإلزامي

| # | الملف | لماذا |
|---|-------|-------|
| 1 | `AI_AGENT_START_HERE.md` | (هذا الملف) البروتوكول |
| 1b | `COLLABORATION_PROTOCOL.md` | **إلزامي** — يعمل أكثر من وكيل AI على المستودع (Claude + Astra): الفروع، الحجز، الملكية |
| 1c | `docs/TASKBOARD.md` + `docs/SESSIONS_LOG.md` | المهام المتاحة/المحجوزة + آخر ما فعله الوكلاء الآخرون |
| 2 | `docs/05_PROJECT_INTENT_UNIFIED_VISION.md` | **النية الموحَّدة — المرجع الأعلى**؛ عند أي تعارض هذه هي الحاكمة |
| 3 | `docs/00_PROJECT_STATE.md` | **الحالة الحالية بالضبط** — ما تم، ما المتبقي، آخر تحديث |
| 4 | `docs/03_ROADMAP.md` | الخطة الكاملة بالمراحل ومعايير القبول |
| 5 | `docs/04_ISSUES_LOG.md` | الأخطاء المكتشفة في المصادر + حالتها |
| 6 | `docs/02_ARCHITECTURE.md` | حقائق المعمل (IPs، الإصدارات، أسماء الوكلاء، معرّفات القواعد) |
| 7 | `docs/01_SOURCE_ANALYSIS.md` | التحليل العميق للمصادر السبعة التي رفعها المستخدم |
| 8 | `docs/DECISIONS.md` | القرارات المعمارية ولماذا اتُّخذت (ADR) |
| 9 | `CHANGELOG.md` | سجل التغييرات |

ثم حسب المهمة:
- تعديل قواعد/إعدادات Wazuh → `wazuh/README.md`
- كتابة فصول الرسالة → `docs/thesis/README.md`
- تشغيل سيناريو معملي → `docs/lab/`

---

## 2. القواعد الصارمة (Non-negotiable)

### 2.1 دقة صفرية-هلوسة
- **لا تخترع** عناوين IP، إصدارات، أسماء ملفات، أو معرّفات قواعد. كل الحقائق موثّقة في `docs/02_ARCHITECTURE.md` مع مصدرها (رقم الصفحة/لقطة الشاشة).
- إذا كانت المعلومة غير مؤكدة، اكتبها هكذا: `⚠️ UNVERIFIED: ...` وأضفها إلى `docs/04_ISSUES_LOG.md` كـ "Open Question".
- أي حقيقة مستقاة من لقطة شاشة يجب الإشارة إلى مسارها في `docs/sources/screenshots/`.

### 2.2 Wazuh Rule ID Namespace (ممنوع التعارض)
| النطاق | الاستخدام | الحالة |
|--------|-----------|--------|
| `100050–100051` | مراقبة العمليات (process list / netcat) | مستخدم |
| `100092–100093` | VirusTotal Active Response results | مستخدم |
| `100200–100201` | FIM على `/home/kali/SOCfile` (VirusTotal trigger) | مستخدم |
| `100210` | Audit: red-list command executed | مستخدم |
| `100300–100301` | FIM على `/tmp/yara/malware` (YARA trigger, Linux) | مستخدم |
| `100303–100304` | FIM على `C:\Users\<USER>\Downloads` (YARA trigger, Windows) | مستخدم |
| `108000–108001` | YARA decoder grouping + positive match | مستخدم |
| `100400–100499` | **محجوز** لتوسعات المشروع (network devices / syslog) | حر |
| `100500–100599` | **محجوز** لتكامل AI / التقارير | حر |

قبل إضافة أي قاعدة: شغّل `python3 scripts/validate/check_rule_ids.py`.

### 2.3 سير عمل Git (إلزامي بعد كل تعديل)
الفرع المشترك `genspark_ai_developer` يُعاد ضبطه على `origin/main` في بداية كل جلسة؛ التمييز بين الوكلاء بـ **بادئة الـ commit** `[CLAUDE]`/`[ASTRA]` وبالحجز في TASKBOARD. التفاصيل في `COLLABORATION_PROTOCOL.md §1.1`.
```bash
git add -A && git commit -m "[ME] type(scope): description"
git fetch origin main && git rebase origin/main   # حل التعارضات لصالح remote
git push --force-with-lease origin genspark_ai_developer
# ثم حدّث/أنشئ الـ PR إلى main وشارك الرابط
```
أنواع الـ commit: `docs`, `feat`, `fix`, `refactor`, `test`, `chore`.

### 2.4 تحديث الحالة قبل انتهاء الجلسة
قبل أن تُغلق أي جلسة، **يجب** تحديث:
1. `docs/00_PROJECT_STATE.md` → قسم "آخر جلسة" + "المهمة التالية بالضبط".
2. `CHANGELOG.md` → ما أُنجز.
3. `docs/04_ISSUES_LOG.md` → أي خطأ جديد اكتُشف أو أُغلق.

### 2.5 اللغة
- التوثيق الأكاديمي: **عربية فصحى** مع المصطلح الإنجليزي بين قوسين عند أول ذكر.
- الكود، أسماء الملفات، رسائل الـ commit، تعليقات الإعدادات: **إنجليزي**.
- لا تُترجم أسماء الأدوات (Wazuh, Suricata, YARA…).

### 2.6 الأمان
- **لا تُخزّن أي API key حقيقي** في المستودع (VirusTotal, VALHALLA…). استخدم `<YOUR_VIRUS_TOTAL_API_KEY>` placeholder. الملف `.gitignore` يمنع `*.key`, `secrets*`.
- لقطة الشاشة `docs/sources/screenshots/wazuh_guide/p17_0.png` تحتوي على مفتاح VirusTotal مطموس جزئياً — لا تحاول قراءته.

---

## 3. كيف تتحقق من صحة عملك

```bash
# تحقق XML لكل قواعد/decoders Wazuh + عدم تكرار الـ IDs + placeholders
bash scripts/validate/validate_all.sh
```
يجب أن يمر بـ `ALL CHECKS PASSED` قبل أي commit يلمس `wazuh/`.

---

## 4. قدرات مطلوب استخدامها بأقصى دقة
- **قراءة لقطات الشاشة** قبل الاعتماد على نص الـ PDF (نص الـ PDF العربي معكوس/مكسور في أماكن كثيرة بسبب استخراج RTL).
- **مقارنة المصادر ببعضها** (الدليل المعملي vs التقرير vs الرسالة) — التعارضات مسجّلة في `docs/04_ISSUES_LOG.md`.
- **الرجوع لتوثيق Wazuh الرسمي** (`documentation.wazuh.com/4.14/`) عند أي شك في صياغة قاعدة.

---

## 5. فهرس المستودع

```
.
├── AI_AGENT_START_HERE.md      ← أنت هنا
├── COLLABORATION_PROTOCOL.md   ← تعاون وكلاء متعددين (Claude + Astra)
├── README.md                   ← نظرة عامة عامة للبشر
├── CHANGELOG.md
├── docs/
│   ├── 00_PROJECT_STATE.md     ← الحالة الحية
│   ├── 01_SOURCE_ANALYSIS.md   ← تحليل المصادر السبعة
│   ├── 02_ARCHITECTURE.md      ← حقائق المعمل + المخططات
│   ├── 03_ROADMAP.md           ← الخطة والمراحل
│   ├── 04_ISSUES_LOG.md        ← الأخطاء والتعارضات
│   ├── 05_PROJECT_INTENT_UNIFIED_VISION.md ← النية الموحَّدة (المرجع الأعلى)
│   ├── TASKBOARD.md            ← لوحة المهام المشتركة (احجز قبل أن تلمس)
│   ├── SESSIONS_LOG.md         ← سجل الجلسات (append-only)
│   ├── DECISIONS.md            ← ADRs
│   ├── lab/                    ← runbooks لكل حالة استخدام (UC-01..UC-08)
│   ├── thesis/                 ← هيكل الرسالة وحالة كل فصل
│   └── sources/                ← المصادر الأصلية + النص المستخرج + لقطات الشاشة + الصوتيات
├── wazuh/                      ← إعدادات نظيفة ومُصحَّحة قابلة للنشر
│   ├── manager/{rules,decoders,lists,ossec.conf.d}
│   ├── agents/{linux,windows}/{active-response,ossec.conf.d}
│   ├── suricata/
│   └── auditd/
├── scripts/
│   ├── validate/               ← فحوصات آلية
│   ├── lab/                    ← سكربتات تثبيت/إعداد
│   └── attack-emulation/       ← محاكاة الهجمات للعرض أمام اللجنة
├── extension/                  ← تصميم توسعة الرؤية (أجهزة الشبكة/الهواتف)
└── tests/
```
