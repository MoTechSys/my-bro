# 01 — تحليل المصادر (Source Analysis)

> تحليل دقيق للمصادر السبعة التي رفعها المستخدم في 2026-09-08. كل استنتاج هنا مربوط بمصدره.
> المصادر الأصلية محفوظة في `docs/sources/originals/`، والنص المستخرج في `docs/sources/extracted_text/`، ولقطات الشاشة في `docs/sources/screenshots/`.

---

## 0. جدول المصادر

| # | الملف الأصلي | النسخة في المستودع | النوع | الحجم | الحالة |
|---|--------------|---------------------|-------|-------|--------|
| S1 | `مشروع_التخرج__تصميم_وتنفيذ_منصة_مركز_عمليات_أمنية_.pdf` | `originals/01_proposal_ai_soc_ar.pdf` | مقترح أولي (8 صفحات) | 366 KB | مقروء |
| S2 | `2شرح ال Wazuh.pdf` | `originals/02_wazuh_lab_guide_ar.pdf` | دليل معملي (55 صفحة، 61 صورة) | 7.3 MB | مقروء — النص العربي مكسور (RTL) لكن الأوامر والإعدادات سليمة |
| S3 | `SOC.docx` | `originals/03_thesis_chapter1_v1.docx` | الفصل الأول — نسخة قديمة | 19 KB | مقروء |
| S4 | `مشروع_SOC_اخر نسخة.docx` | `originals/04_thesis_ch1_ch3_latest_REPAIRED.docx` | الفصل 1 + جزء من الفصل 3 — **أحدث نسخة** | 2.7 MB | **كان معطوباً** (CRC خاطئ في `word/media/image1.png`) — **تم إصلاحه** بإعادة تجميع الـ ZIP؛ النص كامل، 3 صور |
| S5 | `تقرير_مشروع_Wazuh_SIEM_المنظم.docx` | `originals/05_wazuh_siem_report_4_usecases.docx` | تقرير تنفيذ 4 حالات استخدام (31 صورة) | 2.4 MB | مقروء |
| S6 | `WhatsApp Ptt 2026-09-07 at 7.50.00 AM.ogg` | `voice_notes/voice_01_..._vision.ogg` | صوتي 3:32 دقيقة | 478 KB | مُفرَّغ نصياً (§7) |
| S7 | `WhatsApp Ptt 2026-09-07 at 11.48.39 PM.ogg` | `voice_notes/voice_02_..._platform.ogg` | صوتي 0:28 ثانية | 66 KB | مُفرَّغ نصياً (§7) |

---

## 1. S1 — المقترح الأولي "AI-Powered SOC"

**طبيعته:** وثيقة تسويقية/تخطيطية للفكرة قبل التنفيذ. غالباً مُولَّدة بمساعدة AI (فيها كلمة `mermaid` كنص خام في ص1، ومخطط لم يُعرض).

**ما يقترحه:**
- المكونات: Wazuh + Suricata + Elasticsearch + Kibana + TheHive + Python + LLM (GPT/Llama) + MITRE ATT&CK.
- مثال تحليل AI: `Rule 5710, SSH Brute Force, Severity 10` → تقرير مقترح بالحظر وMFA.
- ميزات إضافية مقترحة: Chatbot للمحلل، تلخيص الحوادث، تقليل False Positives، إشعارات Telegram/Email، تقرير PDF لكل حادثة.
- سيناريو العرض أمام اللجنة (7 خطوات): Kali → هجوم → Wazuh/Suricata تكشف → Kibana → AI يحلل → TheHive case → إشعار → تقرير.
- تقسيم العمل على 4 طلاب: (1) SIEM/Infra، (2) Network/Attacks + Suricata، (3) AI + Python، (4) Dashboard + TheHive + توثيق.
- مواصفات الأجهزة: الحد الأدنى i5/16GB/512GB SSD، الموصى به i7/32GB/1TB.
- تقدير الذاكرة: Wazuh 6–8GB، Elasticsearch 4–8GB، Kali 4GB، Windows 4–8GB.
- نصيحة مهمة في §18: **لا تبدأ بعنوان ضخم "SOC ذاتي بالكامل بالـ AI"**؛ العنوان الواقعي المقترح:
  > "تصميم وتنفيذ Mini AI-SOC باستخدام Wazuh وSuricata لتحليل الحوادث الأمنية وتقليل التنبيهات الكاذبة"

**تقييمي:** هذا المقترح **أوسع** من ما نُفِّذ فعلاً. الفريق (بحكمة) نفّذ Wazuh كاملاً وأجّل TheHive/AI. الرسالة الحالية (S4) **أزالت** الـ AI من العنوان وأبقته كـ "أساس يمكن تطويره مستقبلاً" (§1.5 آخر نقطة). هذا قرار صحيح ومتوافق مع نصيحة §18.

**ملاحظة تقنية مهمة:** المقترح يذكر Elasticsearch + Kibana منفصلين. **الواقع:** Wazuh 4.x يأتي بـ **Wazuh Indexer** (fork من OpenSearch) و**Wazuh Dashboard** (fork من OpenSearch Dashboards) مدمجين. لقطات الشاشة كلها تُظهر Wazuh Dashboard وليس Kibana. → مسجَّل كـ ISSUE-003.

---

## 2. S2 — الدليل المعملي "شرح الـ Wazuh" (المصدر الأغنى)

**طبيعته:** دليل خطوة-بخطوة بأسلوب طالب يشرح لزملائه، بلهجة يمنية عامية، مبني على توثيق Wazuh الرسمي (PoC guides) مع تكييفه على معمل الفريق. يحتوي 61 لقطة شاشة حقيقية من المعمل.

### 2.1 الحقائق المؤكدة من لقطات الشاشة

| الحقيقة | القيمة | المصدر |
|---------|--------|--------|
| Wazuh Server IP | `192.168.100.105` | ص1، ص5، `screenshots/wazuh_guide/p01_1.png`, `p05_3.png` |
| Wazuh Dashboard login | `admin` / (كلمة مرور مخفية) | ص1 |
| إصدار الوكلاء | **v4.14.7** | `p04_0.png` (عمود Version)، `p05_3.png` (msi filename `wazuh-agent-4.14.7-1.msi`)، `p06_1.png` (`wazuh-agent_4.14.7-1_amd64.deb`) |
| Agent 001 | `win1` — `192.168.100.106` — Microsoft Windows 10 Education 10.0.19045.2006 — group `default` — كان `disconnected` وقت اللقطة | `p04_0.png` |
| Agent 002 | `kali1` — `192.168.100.108` — Kali GNU/Linux 2025.4 — group `default` — `active` | `p04_0.png` |
| Cluster node | `node01` | `p04_0.png` |
| اسم وكيل ثاني ظهر في الأمثلة | `win2` | ص5 (أثناء الشرح، اسم مثال) |
| مستخدم Kali | `kali` (hostname `kaliabdualrahman`) | `p06_1.png`, `p08_1.png` |
| مستخدم Wazuh server | `wazuh-user@wazuh-server` (OVA الرسمية) | `p01_0.png`, `screenshots/wazuh_report/img06.png` |
| Server IP بديل ظهر مرة | `192.168.8.5` | `p18_1.png` (شريط عنوان المتصفح) → ISSUE-004 |
| Suricata HOME_NET | `192.168.100.0/24, 10.0.0.0/8, 172.16.0.0/12` | `p29_0.png` |
| Suricata version | 8.0.6 (رابط القواعد) ثم `suricata-update` | ص27 |
| Apache version | 2.4.68-1 | `screenshots/wazuh_report/img13.png` |
| YARA version | 4.5.5 | ص40 |
| مسار الملف المراقب (Linux FIM) | `/home/kali/abdul` ثم `/home/kali/SOCfile` | ص8، ص12 |
| مسار الملف المراقب (Windows FIM) | `C:\Users\Lenovo\Desktop\abdul` | ص9–10 |

### 2.2 حالات الاستخدام المُغطاة (بترتيب الدليل)

| UC | العنوان | صفحات | الحالة |
|----|---------|-------|--------|
| UC-01 | Deploy Windows + Linux Agents | 1–6 | ✅ منفَّذ (لقطة p04_0) |
| UC-02 | File Integrity Monitoring (Linux + Windows) | 6–11 | ✅ منفَّذ (p09_1: أحداث 550/554 على kali1) |
| UC-03 | VirusTotal integration + Active Response (remove-threat) | 11–26 | ✅ منفَّذ (p18_1: eicar.com deleted؛ p19_0, p26_0 لقطات من توثيق Wazuh **ليست من المعمل** — ISSUE-005) |
| UC-04 | Suricata NIDS integration | 26–31 | ✅ منفَّذ (p30_0: suricata active، p31_0 من توثيق Wazuh) |
| UC-05 | Monitoring malicious commands (auditd + CDB) | 32–36 | ✅ منفَّذ (p36_0: rule 100210 level 12 على kali1) |
| UC-06 | Shellshock detection | 36–39 | ✅ منفَّذ (تقرير S5 img19: rule 31168 level 15) |
| UC-07 | YARA integration (Linux + Windows) | 39–55 | ✅ Linux منفَّذ (S5)؛ Windows **غير مؤكد** — ISSUE-006 |
| — | "SQL Injection Attack" مذكور في عنوان القسم 6 (ص36) | — | ❌ **لم يُنفَّذ** — العنوان فقط بلا محتوى — ISSUE-007 |

### 2.3 الإعدادات الكاملة المستخرجة
كلها منسوخة ومُنظَّفة في `wazuh/` (انظر `wazuh/README.md`). أهمها:
- `remove-threat.sh` (Linux AR) — ص13–14
- `remove-threat.py` (Windows AR → PyInstaller) — ص20–23
- `yara.sh` (Linux AR) — ص42–43
- `yara.bat` (Windows AR) — ص51–52
- `malware_downloader.sh` — ص47–48
- `local_rules.xml` مقاطع — ص15، 17، 35، 44–45، 53
- `local_decoder.xml` — ص45–46، 53
- `suspicious-programs` CDB — ص34
- `audit.rules` — ص32–33
- `suricata.yaml` مقتطفات — ص28

### 2.4 أخطاء اكتُشفت في الدليل
مفصَّلة في `04_ISSUES_LOG.md`. أبرزها:
- ISSUE-008: `sudo nano var/ossec/etc/rules/local_rules.xml/` — مسار بدون `/` في البداية ومع `/` زائدة في النهاية (ص15، 17).
- ISSUE-009: `chmod 777` على قواعد Suricata (ص27) — صلاحيات مفرطة؛ الأمر البديل في نفس الصفحة يستخدم `644` (صحيح).
- ISSUE-010: تكرار القواعد 100300/100301 و108000/108001 مرتين في `local_rules.xml` (ص44–45) بمسارين مختلفين (`/tmp/yara/malware/` و`/home/kali/abdul`) → **Wazuh manager سيرفض التشغيل** بسبب Rule ID مكرر إذا نُسخ كما هو.
- ISSUE-011: تعارض قوائم `rules_id` في VirusTotal AR: `<rules_id>87105</rules_id>` صحيح (87105 = VirusTotal positive match)، لكن الفلتر في ص19 يذكر `553,100092,87105,100201`.
- ISSUE-012: في ص36 أمر `sudo apt -y install netcat` — في Kali 2025 الحزمة اسمها `netcat-openbsd` أو `netcat-traditional`.
- ISSUE-013: سكربت `malware_downloader.sh` ص47: regex `^[Yy]$` انكسر في استخراج النص فقط (النسخة في لقطة الشاشة صحيحة).
- ISSUE-014: لقطة `p06_1.png` تُظهر فشل `wget` بسبب `Temporary failure in name resolution` — مشكلة DNS في Kali وقت التثبيت (تم تجاوزها لاحقاً لأن الوكيل ظهر active).

---

## 3. S3 — الفصل الأول (نسخة قديمة `SOC.docx`)

**طبيعته:** مسودة أولى للفصل الأول. عناوين مكررة (فهرس ثم محتوى). لا توجد صور.

**المحتوى:** 1.1 مقدمة → 1.7 الأدوات. جدول الأدوات (12 صف).

**فروقات عن S4 (الأحدث):**
- S3 فيه **Zeek** في جدول الأدوات ولا يذكر Suricata. S4 يذكر **Suricata وZeek** معاً في §3.6.2.
- S4 أصلح تنسيق القوائم (List Paragraph) وأزال العناوين المكررة.
- S4 أضاف "الفصل الثالث: منهجية تصميم النظام" (§3.6 فقط).

→ **S3 مُتجاوَز (superseded)**؛ نحتفظ به للتاريخ فقط.

---

## 4. S4 — أحدث نسخة من الرسالة (الفصل 1 + جزء الفصل 3)

**طبيعته:** النسخة الأكاديمية الأحدث. **كان الملف معطوباً** (checksum failure في `image1.png`) — أصلحته بإعادة بناء أرشيف ZIP متجاوزاً فحص CRC؛ كل النص و3 الصور استُخرجت بنجاح. النسخة المُصلَحة في `originals/04_thesis_ch1_ch3_latest_REPAIRED.docx`.

### 4.1 الفصل الأول (مكتمل)
- 1.1 مقدمة، 1.2 تعريف المشروع، 1.3 مشكلة الدراسة، 1.4 الأهداف (عام + 10 خاصة)، 1.5 الأهمية (8 نقاط)، 1.6 الحدود (In/Out of Scope)، 1.7 الأدوات (جدول 1.1).
- **العنوان الفعلي للمشروع** (من 1.2): "تصميم وتنفيذ مركز عمليات أمنية (SOC) يعتمد على أدوات مفتوحة المصدر".
- **لا ذكر للـ AI** إلا كتطوير مستقبلي في 1.5. ✅ قرار سليم.

### 4.2 الفصل الثالث (جزئي — §3.6 فقط)
- 3.6.1 نمذجة سير العمل: **6 طبقات** (جدول 3.1): مصادر البيانات → الجمع (Wazuh Agent + Suricata + Zeek) → المعالجة والربط (تطبيع، ربط، MITRE ATT&CK، تقييم خطورة) → القرار → الاستجابة والتخزين → الإخراج (Kibana + Email/Telegram/Syslog + تقارير).
- 3.6.2 DFD: 3 مستويات (Context، Level 1، Level 2). الشكل 3.3 (Context Diagram) موجود كصورة. Level 1 مذكور نصياً بلا صورة بعد.

### 4.3 تعارضات مع الواقع المُنفَّذ
| ما تقوله الرسالة | الواقع في المعمل | ISSUE |
|------------------|-------------------|-------|
| Zeek لتحليل الشبكة (جدول 1.1) + Suricata وZeek معاً (§3.6) | **Suricata فقط** منفَّذ؛ لا دليل على Zeek إطلاقاً | ISSUE-001 |
| Elasticsearch + Kibana + Filebeat | Wazuh Indexer + Wazuh Dashboard (مدمجة في Wazuh 4.x؛ Filebeat موجود داخلياً في Manager فقط) | ISSUE-003 |
| Windows 11 (جدول 1.1) | **Windows 10 Education 10.0.19045** (لقطة p04_0) | ISSUE-002 |
| Ubuntu Server | صحيح — لكن الأدق: **Wazuh OVA 4.14** (المستخدم `wazuh-user@wazuh-server` يدل على الـ OVA الرسمية) | ISSUE-015 |
| Email/Telegram/Syslog للإشعارات (§3.6 الطبقة 6) | لم يُنفَّذ أي منها | ISSUE-016 |

### 4.4 ما ينقص الرسالة
- الفصل 2 (الدراسات السابقة / الإطار النظري) — **غير موجود**.
- الفصل 3: §3.1–3.5 غائبة (منهجية البحث، تحليل المتطلبات، حالات الاستخدام…) و§3.6.2.2+ ناقصة الأشكال.
- الفصل 4 (التنفيذ) — **غير موجود** كفصل، لكن مادته الخام موجودة في S5.
- الفصل 5 (الاختبار والنتائج والخاتمة) — **غير موجود**.
- المراجع، الملاحق.

---

## 5. S5 — تقرير تنفيذ 4 حالات استخدام على Wazuh SIEM

**طبيعته:** تقرير تنفيذي منظَّم (31 لقطة شاشة حقيقية) يوثّق 4 محاور على Kali Linux. هذا **أفضل مادة خام للفصل الرابع**.

### 5.1 المحاور
| القسم | الموضوع | القواعد | الدليل |
|-------|---------|---------|--------|
| 1 | مراقبة الأوامر الخبيثة (auditd + CDB `suspicious-programs`) | 80792 (base), **100210** (level 12) | img01–img12: تثبيت auditd على kali بالمستخدم `omar`، `auditctl -l` يُظهر القاعدتين b32/b64، لوحة Wazuh تُظهر "Highly Suspicious Command executed: /usr/bin/nc" level 12 |
| 2 | كشف Shellshock (Apache access.log) | **31168** (level 15) | img13–img19: apache2 2.4.68، ufw، curl بالـ payload `() { :; }; /bin/cat /etc/passwd` إلى `192.168.0.186`، MITRE T1068 + T1190 |
| 3 | دمج YARA (FIM → AR → yara.sh) | 100300/100301, 108000/**108001** (level 12) | img20–img29: بناء YARA 4.5.5 من المصدر، قواعد VALHALLA demo (1.23 MB)، `yara.sh`، decoder |
| 4 | مراقبة العمليات (Netcat listener) | **100050** (level 0), **100051** (level 7, ignore=900) | img30–img31: `<localfile>` بـ `full_command` + `ps -e -o pid,uname,command` كل 30 ثانية |

### 5.2 حقائق إضافية من هذا التقرير
- المستخدم على Kali هنا `omar` (UID 1000) — بينما في S2 المستخدم `kali`. يدل على **جهازَي Kali مختلفين أو أعضاء فريق مختلفين**. → ISSUE-017 (توضيح مطلوب).
- IP الهدف في Shellshock: `192.168.0.186` — **شبكة مختلفة** عن `192.168.100.x`. → ISSUE-004.
- في `local_rules.xml` (img27): مسار FIM هنا `/tmp/home/kali/omar` (خطأ إملائي محتمل — كان المقصود `/home/kali/omar` أو `/tmp/yara/malware`). → ISSUE-018.
- ظهر في الأحداث `rule.id 86601 — Suricata: Alert - NMAP SYN Scan Detected` (img18) → يؤكد أن Suricata + Wazuh تعمل معاً فعلاً.
- ظهر `rule.id 506 — Wazuh agent stopped` مصنَّف تحت T1562.001 Defense Evasion.
- الجدول الختامي يقول "تم اختبار النظام بنجاح 100%" — **ادعاء غير مقاس**؛ يجب تحويله لمقاييس فعلية (عدد التنبيهات، زمن الكشف) في الفصل 5. → ISSUE-019.

### 5.3 أخطاء في التقرير
- §1.3 "شرح المعلمات": `-F auid!=-1` شُرحت كـ "8106+1(Unset UID)" — نص مشوَّه؛ الصحيح: `-1` = 4294967295 = unset AUID.
- §3.2 "أولاً": يذكر خطأ `yum: command not found` على Kali — هذا **ليس خطأ في النظام** بل الطالب نفّذ أوامر RHEL على Debian؛ التقرير يشرحه صحيحاً لكن يجب ألا يُقدَّم كـ "معالجة خطأ".
- استخدام VALHALLA demo API key (`1111…`) — مجموعة القواعد التجريبية محدودة؛ للعرض الأكاديمي يُفضَّل ذكر ذلك صراحة.

---

## 6. المقارنة بين المصادر — مصفوفة المطابقة

| البند | S1 مقترح | S3 ch1 v1 | S4 ch1+3 أحدث | S2 دليل معملي | S5 تقرير تنفيذ | **الواقع المعتمد** |
|-------|:-:|:-:|:-:|:-:|:-:|---|
| SIEM | Wazuh | Wazuh | Wazuh | Wazuh 4.14.7 | Wazuh | **Wazuh 4.14.7** |
| NIDS | Suricata | Zeek | Suricata + Zeek | Suricata 8.0.6 | Suricata (ضمني) | **Suricata 8.0.x** فقط |
| التخزين/العرض | Elasticsearch + Kibana | Elasticsearch + Kibana | Elasticsearch + Kibana | Wazuh Dashboard | Wazuh Dashboard | **Wazuh Indexer + Dashboard** |
| Windows | Victim (غير محدد) | Win 11 | Win 11 | **Win 10 Education** | — | **Windows 10 Education** |
| Linux endpoint | Kali | Kali | Kali | Kali 2025.4 | Kali (omar) | **Kali 2025.4** |
| Incident Response | TheHive | — | — | — | — | **غير منفَّذ** |
| AI/LLM | نعم (مركزي) | لا | تطوير مستقبلي | لا | لا | **غير منفَّذ** |
| MITRE ATT&CK | نعم | — | نعم (§3.6) | ضمني | نعم (T1068/T1190/T1562) | **منفَّذ** (مدمج في Wazuh) |
| Active Response | — | — | "إجراءات الاستجابة" | VirusTotal + YARA | YARA | **منفَّذ** |
| إشعارات | Telegram/Email | — | Email/Telegram/Syslog | — | — | **غير منفَّذ** |

---

## 7. S6 + S7 — الرسائل الصوتية (تفريغ نصي + تحليل)

> **ملاحظة:** اللهجة يمنية. التفريغ بالنموذج `gemini-3-flash-preview` بعد تحويل OGG→MP3 (فشل التفريغ المباشر لملف OGG).

### 7.1 S7 — الرسالة القصيرة (28 ث) — "المنصة جاهزة"
> "هذا عبارة عن تطبيق… منصة الـ Wazuh هذه، أول شيء تترك رابط تنزّل عندك الـ Agent حقها، الـ Agent يرتبط بالـ Wazuh الرئيسي (الـ Management)، نربطها وجاهزة. موجود الـ Management، موجود الـ Agent، موجود كل شيء، باقي بس نربط… قد ربطنا وفعّلنا كل شيء."

**الاستنتاج:** تأكيد أن البنية الأساسية (Manager + Agents) **مكتملة ومربوطة**.

### 7.2 S6 — الرسالة الطويلة (3:32) — "الرؤية والتوسعة"
ملخص أمين لما قاله:
1. **وصف النظام الحالي:** مركز SOC يتصل بعدة أجهزة، يحمي ويراقب الترافيك والشبكة والجهاز (فيروسات)، ويرسل Alerts للسيرفر الرئيسي. يراقب ملفاً/مساراً محدداً: إذا أحد عدّل/أنشأ/حذف ملفاً → Alert فوري. (= FIM + VirusTotal + YARA ✅ متطابق مع المُنفَّذ).
2. **الأداة:** Wazuh — "أداة جاهزة تحتاج إعدادات"، Manager على السيرفر، Agents على الأجهزة.
3. **القيد الذي يراه:** "Wazuh محدود في بعض المصادر: Windows وLinux والماك".
4. **الرؤية للتطوير (الطلب الفعلي):**
   - أن يراقب **الهواتف** (كل أنظمتها).
   - أن يربط **السويتشات والراوترات** ويراقب ترافيك الشبكة منها.
   - أن يكون "قاعدة بيانات كبيرة" تُجمَّع فيها كل الأحداث، "ندري بكل شيء".
   - أن تكون الـ Agents **دفاعية تلقائياً**: "إذا لقيت كذا وكذا تفعّل كذا وكذا، تشتغل طوالي" (= توسيع Active Response).
   - يقول: "نشتي نطوّر الـ Wazuh إنه يكون أداة ثانية وأقوى منها".

### 7.3 تحليلي التقني للرؤية (بدون هلوسة)
| الطلب | هل يدعمه Wazuh 4.14 أصلاً؟ | الطريقة الواقعية | الجهد |
|-------|:-:|------------------|-------|
| راوترات/سويتشات | ✅ **نعم** — عبر **Syslog** (`<remote><connection>syslog</connection>`) + decoders (Cisco IOS، MikroTik، pfSense… مدعومة أو قابلة للإضافة) | تفعيل remote syslog على Manager (UDP/TCP 514)، توجيه الأجهزة إليه، كتابة/تفعيل decoders + قواعد 100400+ | **متوسط** — 1–2 أسبوع |
| هواتف Android/iOS | ❌ **لا يوجد Wazuh agent رسمي للهواتف** | خيارات: (أ) مراقبة ترافيك الهواتف عبر Suricata على الـ gateway (بدون agent)؛ (ب) MDM/EDR مفتوح المصدر يُرسل syslog؛ (ج) حل مخصص يُرسل أحداث عبر Wazuh API — **بحثي/خارج نطاق التخرج غالباً** | **عالٍ** |
| "قاعدة بيانات كبيرة" | ✅ موجودة بالفعل = **Wazuh Indexer** (OpenSearch) | لا شيء إضافي؛ فقط توسيع المصادر | — |
| Agents دفاعية تلقائية | ✅ **Active Response** موجود ومُستخدم (remove-threat, yara) | إضافة استجابات: `firewall-drop` لـ brute force، `host-deny`، عزل الجهاز، قتل عملية | **منخفض–متوسط** |
| "أداة أقوى من Wazuh" | ⚠️ غير واقعي لمشروع تخرج | إعادة صياغة: "**توسعة Wazuh** بطبقة تكامل مخصصة (Python) لأجهزة الشبكة + استجابة آلية" | — |

**التوصية:** تُثبَّت الرؤية في `extension/VISION_AND_FEASIBILITY.md` وتُدرج كمرحلة **P3 (اختيارية)** في الخارطة، مع توصية للرسالة بذكرها في "الأعمال المستقبلية" وتنفيذ الجزء الواقعي منها (syslog من راوتر/سويتش واحد + Active Response إضافية) إذا سمح الوقت.

---

## 8. خلاصة التحليل — ما هو المشروع الحقيقي الآن؟

**مشروع تخرج SOC مفتوح المصدر مبني على Wazuh 4.14.7**، منفَّذ في معمل افتراضي (VMware) بثلاث أجهزة على شبكة `192.168.100.0/24`:
- `wazuh-server` 192.168.100.105 (OVA)
- `win1` 192.168.100.106 (Windows 10 Education)
- `kali1` 192.168.100.108 (Kali 2025.4)

مع **7 حالات استخدام منفَّذة** ومُثبَتة بلقطات شاشة، ورسالة أكاديمية مكتمل منها الفصل الأول وجزء من الثالث، وتقرير تنفيذي يصلح كنواة للفصل الرابع.

**الفجوات الرئيسية:** (1) توحيد الرسالة مع الواقع (Zeek/Kibana/Win11)، (2) الفصول 2، 4، 5، (3) اختبارات مُقاسة بدل "100%"، (4) تنظيف الأخطاء في الإعدادات (IDs مكررة، مسارات)، (5) الرؤية التوسعية (syslog لأجهزة الشبكة) كعمل مستقبلي أو P3.
