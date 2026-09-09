# CONTEXT_RESUME — ذاكرة المشروع الكاملة لأي وكيل جديد

> **اقرأ هذا الملف أولاً وكاملاً. بعده ستعرف كل ما يعرفه الوكيل السابق.**
> كُتب 2026-09-09 ~08:30 UTC بواسطة CLAUDE (Claude Fable 5.1) بطلب المستخدم صراحةً: "كأنك تُرجع ذاكرتك للوكيل الثاني — لا تنسَ صغيرة ولا كبيرة".
> **الترتيب بعد هذا الملف:** `AI_AGENT_START_HERE.md` → `docs/00_PROJECT_STATE.md` → `docs/TASKBOARD.md` → `docs/MASTER_PLAN_v3_DETAILED.md` → `docs/lab/CLOUD_ENV_ACCESS.md` → ثم حسب مهمتك.

---

## 0. في 60 ثانية — إذا لم تقرأ غير هذا

- **المشروع:** رسالة تخرّج (4 طلاب، جامعة، اللغة عربية) — **منصة SOC مفتوحة المصدر على Wazuh 4.14 + Suricata مع استجابة آلية للتهديدات**. صاحب الفكرة **أخو المستخدم**؛ المستخدم هو من يتحدّث معنا.
- **ما هو مُنجَز فعلياً:** 8 حالات استخدام على المعمل (2026-08، لقطات)، مستودع كامل (309 ملف) بإعدادات مُصحَّحة، الفصول 1–3 من الرسالة، خطة اختبار مُقاسة، أداة قياس (`mttd.py`) بـ145 اختباراً (+63 subtests)، AR مُحصَّن (`soc_ar.py`)، Demo Script، **وبيئة سحابية حيّة** (Wazuh 4.14.1 Docker + وكيل Linux active).
- **ما هو ناقص:** قياسات فعلية (صفر حتى الآن)، الفصلان 4 و5، UC-09..13، Windows AR native، ربط المعمل المحلي (WireGuard)، DOCX نهائي، قرارات المستخدم D1–D7، موعد المناقشة (Q5).
- **الوكلاء:** CLAUDE (مخطّط/مراجع/بيئة) + ASTRA (GPT-6 Astra — المنفّذ الرئيسي: كود، اختبارات، ch4/5). يعملان على نفس المستودع بفروع مختلفة.
- **أهم 3 قواعد:** (1) **Zero-Skip**: لا ✅ بدون دليل حي؛ (2) **commit+push كل 15 دقيقة** (الجلسات تنقطع); (3) **لا أسرار في Git** أبداً.
- **الخطوة التالية بالضبط:** `docs/lab/CLOUD_ENV_ACCESS.md §8` — PILOT أول محاولات على البيئة السحابية.

---

## 1. مَن هم الأشخاص وماذا يريدون

| الشخص | الدور | ما يريد | كيف يتكلم |
|---|---|---|---|
| **المستخدم** (يكتب لنا) | وسيط ومدير | أن يخلص المشروع **بجودة عالية** بأقل تعب له؛ يكره التفاصيل الطويلة إلا إذا طلبها؛ يريد "باختصار: ماذا عُمل / ماذا بقي / روابط" | لهجة يمنية/خليجية، عامية، مباشر، يغضب من الاستخفاف بقدرات الوكلاء، يريد "تدقيق تدقيق" |
| **أخو المستخدم** | صاحب المشروع الفعلي، طالب | رؤيته في الصوتية S6: "نراقب كل الأجهزة (Windows/Linux/راوترات/سويتشات/هواتف) والوكلاء يدافعون تلقائياً، وأداة أقوى من Wazuh" | لم نتحدث معه مباشرة؛ نفهمه من 7 مصادر رفعها المستخدم |
| **الفريق** (4 طلاب) | المنفّذون البشريون | — | يشغّلون المعمل المحلي (192.168.100.x) |
| **وكيل السحابة** (وكيل Genspark آخر على Cloud Computer) | أعدّ الـVM ورکّب Docker وأضاف مفتاحنا | متعاون، دقيق، أمين (أعطى بصمات المضيف) | قد لا يكون متاحاً دائماً — لذلك حزمة Bootstrap |
| **ASTRA** | المنفّذ الرئيسي | ينفّذ ما في TASKBOARD؛ يكتب بأسلوب مُقتضَب جداً وحذِر؛ **صادق ومنهجي** — كل ما ادّعاه تحقّقتُ منه وكان صحيحاً | يُوثّق كل شيء في SESSIONS_LOG بصيغة `| تاريخ | [ASTRA] | ما فعل | @CLAUDE رسالة |` |

**⚠️ سياق مهم عن المستخدم:** طلب مني سابقاً "تسليم كامل لأسترا" ثم عاد وطلب مني العودة كمخطّط؛ اشترك في **Cloud Computer** ($39.99/شهر، 16 GB) لأجل بيئة تنفيذ؛ يريد **البرومبتات في الشات فقط لا في التوثيق** (إلا SIDE_TASK_01 الذي طلبه أولاً كملف). يريد أن "ينسخ ويلصق" ويمشي.

## 2. تاريخ المشروع الكامل — كل PR وماذا فعل

| PR | من | ماذا | الحالة |
|---|---|---|---|
| #1–#4 | CLAUDE | تأسيس المستودع من 7 مصادر (S1–S7)، وثيقة النية الموحَّدة (`docs/05`)، بروتوكول التعاون v1→v2 | ✅ مدموج |
| #5–#6 | ASTRA | حجز T-10 + `tests/TEST_PLAN.md` + ISSUEs 034–037 | ✅ |
| #7–#8 | CLAUDE | الفصل 2 (15 مرجعاً IEEE مُتحقَّقاً عبر Crossref) | ✅ |
| #9–#10 | CLAUDE | الفصل 3 (DFD، UC matrix، AR sequences) | ✅ |
| #11 | CLAUDE | `AGENT_CAPABILITIES_AND_ALLOCATION.md` + قاعدة Zero-Skip | ✅ |
| #12, #14 | ASTRA | T-15 مراجعة أمنية → `soc_ar.py` (AR مُحصَّن)، `SECURITY_REVIEW.md`، 19 اختباراً | ✅ |
| #13, #15 | CLAUDE | الفصل 1 v2 (مُوحَّد مع الواقع، 9 تصحيحات) | ✅ |
| #16, #17 | CLAUDE | T-30 Demo Script + `HANDOFF_CLAUDE_TO_ASTRA.md` (مراجعة PR14 = APPROVE) | ✅ |
| #18–#20 | ASTRA | T-16 `TAKEOVER_AUDIT.md` + نواة T-11 `mttd.py` (34 اختباراً) | ✅ |
| #21–#22 | ASTRA | **T-17 `INTENT_STUDY_AND_BLUEPRINT.md`** — قرأ S1–S7 الأصلية مباشرة، فرّغ الصوتيات بأداتين، مصفوفة نية I-01..I-10، **7 قرارات D1–D7 تنتظر المستخدم** | ✅ |
| #23, #25 | CLAUDE | **`MASTER_PLAN_v3_DETAILED.md`** (الخطة الحاكمة) + `plan_math.py` + تدقيق ذاتي §9 | ✅ |
| #24 | ASTRA | T-11 v3.1: عقد JSONL بـ7 طوابع، 8 مقاييس، Wilson/Poisson/MWU، `trial_runner.py` محمي بـ`--lab`، **145 اختباراً (+63 subtests)** | ✅ |
| **#26** | CLAUDE | **بيئة سحابية حيّة** + `CLOUD_ENV_ACCESS.md` + استرجاع v2/SIDE_TASK/T-50-52 | **🟡 مفتوح — يُدمَج أولاً** |

**⚠️ حادثة مهمة:** عند squash PR #23 ضاعت 3 ملفات (`MASTER_PLAN_v2.md`، `SIDE_TASK_01_references.md`، صفوف T-50/51/52) — **استُرجعت في PR #26**. درس: تحقّق من `git show --stat` بعد كل squash.

## 3. النية — ما يريده أخو المستخدم فعلاً (خلاصة T-17 + docs/05)

**الجملة المعتمَدة (MASTER_PLAN_v3 §1):**
> طبقة تكامل وتشغيل فوق Wazuh تُوحِّد إشارات الأجهزة الطرفية (Windows/Linux) وأجهزة الشبكة (router/switch عبر syslog) وحركة الشبكة (Suricata) في خط أنابيب واحد — كشف → قرار محكوم بسياسة → استجابة آلية محدودة وآمنة → عرض — مُثبَتة بسيناريوهات هجوم مُقاسة منهجياً، وقابلة لإضافة مصدر جديد (بما فيه رؤية الهواتف من الشبكة) دون تغيير المعمارية.

**العنوان:** Design and Implementation of an Open-Source SOC Platform with Automated Threat Response using Wazuh and Suricata.

**الأربعة نماذج المتضاربة في رأس الفريق (docs/05 §1)** — احفظها لأنها تفسّر كل التعارضات: A "AI-SOC" (المقترح S1 — لم يُنفَّذ)، B "أكاديمي" (الرسالة S3/S4 — تذكر Zeek/Kibana/Win11 غير الموجودة)، C "معمل Wazuh" (S2/S5 — الأقوى تنفيذاً)، D "نراقب كل شيء" (الصوتية S6 — الرؤية).

**الإضافات الثلاث القابلة للقياس (v3 §3) — جواب "أليس هذا مجرد Wazuh؟":**
- **C1** AR مُحصَّن بسياسة: السكربت الرسمي `remove-threat.sh` (Wazuh PoC) فيه `rm -f $FILENAME` **خارج** شرط `add`، غير مقتبس، بلا hash/allowlist/symlink check → **6 عيوب V1–V6** قابلة للإثبات؛ نسختنا `soc_ar.py` ترفضها.
- **C2** بروتوكول تقييم كمّي: 6 طوابع زمنية t0–t6 → 8 مقاييس؛ Manzoor 2024 (أشهر تقييم Wazuh) **لم يقس** MTTD/AR/FP.
- **C3** عقد إدخال مصدر شبكي (MikroTik غير مدعوم out-of-box في Wazuh) + M0 رؤية هاتف من الشبكة (لا وكيل هاتف رسمي — issue #32881).

**خارج النطاق صراحةً (لا تعِد فتحها):** AI/LLM في التشغيل، وكيل داخل الهاتف، Zeek، TheHive، Kibana، اختبار السعة، "أقوى من Wazuh" كشعار.

## 4. القرارات المعلَّقة عند المستخدم (لا تتجاوزها)

| # | القرار | التوصية الافتراضية إن قال "خذ الافتراضيات" |
|---|---|---|
| D1 | "أقوى من Wazuh" = ماذا؟ | طبقة تكامل (C1+C2+C3)، لا fork |
| D2 | جهاز شبكة | MikroTik CHR (VM مجاني) إن لم يتوفر فعلي |
| D3 | الهاتف | M0 (رؤية شبكية فقط) |
| D4 | واجهة | Dashboard الحالية |
| D5 | AI | للتطوير فقط، لا في التشغيل |
| D6 | تصحيحات FR/NFR في ch3 (ISSUE-047) | اعتماد |
| D7 | **Q5 موعد المناقشة** + Q6 قالب الجامعة + جرد المعمل | **مجهول — يحدّد كل الأولويات** |

## 5. حالة كل مكوّن — بدقة

### 5.1 الكود
| الملف | ماذا | الحالة | اختبارات |
|---|---|---|---|
| `wazuh/manager/rules/local_rules.xml` | قواعد 100050–108001 لـUC-03/05/07/08 (+ 100200/201 FIM، 100092/093 AR result) | ✅ مُطبَّقة على السحابة؛ `<USER_NAME>` placeholder يجب استبداله (فعلنا→Lenovo) | logtest ✅ |
| `wazuh/manager/decoders/local_decoder.xml`, `lists/` | decoder yara + CDB `suspicious-programs`/`malicious-ioc` | ✅ على السحابة | — |
| `wazuh/manager/ossec.conf.d/*.xml` | كتل AR/VT/list — **تحوي تعليقات XML متعددة الأسطر؛ استخدم `re.sub(r'<!--.*?-->','',s,flags=re.S)` قبل الإلحاق** (كسرت ossec.conf مرة) | ✅ على السحابة | `wazuh-analysisd -t` |
| `wazuh/agents/linux/active-response/soc_ar.py` + `remove-threat.sh` | AR مُحصَّن (ASTRA T-15). **عقد النشر:** Linux يُثبَّت الغلاف باسم `remove-threat.exe` (shebang) + `soc_ar.py` بجانبه، root:wazuh 0750 | ✅ كود؛ ❌ لم يُنشر على kali1 بعد | 19 |
| `wazuh/agents/windows/active-response/*.py` | نسخة Windows (PyInstaller) | ❌ لم تُبنَ ولم تُختبَر native | — |
| `scripts/measure/mttd.py` | أداة القياس v2 (ASTRA): Wilson، Poisson، MWU، sample_size floor 30، رفض offset>100ms | ✅ كود | 111+30 |
| `scripts/measure/trial_runner.py/.sh` | يكتب t0، يُطلق الهجمة، يجمع t1–t6؛ **لا ينفّذ بدون `--lab`** | ✅ كود؛ ❌ لم يُشغَّل على بيئة | ضمن الـ141 |
| `scripts/measure/plan_math.py` | يُعيد إنتاج كل رقم في الخطة (Wilson/Poisson/MWU/ميزانية) | ✅ | — |
| `scripts/attack-emulation/*.sh` | eicar (أسماء فريدة)، nmap، shellshock، netcat، malware_downloader — كلها محمية بـ`--lab` وmanifest | ✅ كود | — |
| `scripts/validate/validate_all.sh` | فاحص المستودع | **يجب أن يطبع ALL CHECKS PASSED قبل كل commit** | — |
| `tests/test_security.py`, `tests/test_measure.py` | 19 + 122 | ✅ | `python3 -m pytest tests/ -q` |

### 5.2 الوثائق
| الملف | ماذا | ملاحظة |
|---|---|---|
| `docs/05_PROJECT_INTENT_UNIFIED_VISION.md` | **المرجع الأعلى** للنية؛ MoSCoW | تعديله يحتاج ADR؛ **يحتاج ADR-013 لرفع UC-12/M0 إلى SHOULD** (T-52) |
| `docs/INTENT_STUDY_AND_BLUEPRINT.md` | دراسة ASTRA للمصادر الأصلية + D1–D7 | لا تُسقط شيئاً منها |
| `docs/MASTER_PLAN_v3_DETAILED.md` | **الخطة الحاكمة** (290 سطر): §0 ما غيّرته الرياضيات، §2 جدول 13 UC، §3 H1–H6، §5 نموذج الزمن، §6 بوابات G0–G8، §9 تدقيق ذاتي (6 أخطاء صُحِّحت) | v2 = ملخص تنفيذي |
| `docs/TASKBOARD.md` | لوحة المهام — **احجز قبل أن تلمس** | حالات: FREE/🔒/◐/✅/⛔ |
| `docs/SESSIONS_LOG.md` | سجل الجلسات — **أضف صفاً قبل إغلاق أي جلسة** | آخر صف = آخر ما حدث |
| `docs/04_ISSUES_LOG.md` | 62 ISSUE؛ ~29 OPEN | **⚠️ أُعيد ترقيم بنودي عند دمج PR24:** 050→059، 051→060، 052→061 (CLOSED)، 053→062 |
| `docs/thesis/ch1–ch3` | مسودات كاملة | ch3 يحتاج تصحيح ISSUE-047 |
| `docs/DEMO_SCRIPT.md` | عرض 15 دقيقة، 4 هجمات | يحتاج dry-run بشري ×2 |
| `docs/lab/UC-01..08` | runbooks | UC-06 يستخدم `log_format syslog`؛ UC-09 يتطلب `apache` → ISSUE-059 |
| `docs/lab/CLOUD_ENV_ACCESS.md` | **كيف تتصل بالبيئة + ما هو منشور + الخطوة التالية** | حدّث §3 و§7 بعد أي تغيير على السيرفر |
| `tests/TEST_PLAN.md`, `tests/README.md` | بروتوكول القياس + عقد JSONL v2 | مطابق لـv3.1 |
| `docs/prompts/SIDE_TASK_01_references.md` | برومبت وكيل ثالث: 30–40 مرجعاً IEEE | لم يُنفَّذ بعد |
| `docs/sources/**` | **الأصول — لا تُعدَّل أبداً** | S1 مقترح، S2 دليل المعمل (55 ص)، S3/S4 الرسالة، S5 تقرير 4 UC، S6/S7 صوتيات |

### 5.3 البيئة السحابية (التفاصيل الكاملة في `CLOUD_ENV_ACCESS.md`)
- Azure VM `20.196.217.36`, user `work`, SSH بمفتاح فقط، sudo بلا كلمة مرور، **لا nested virt → Docker فقط**.
- **منشور:** Wazuh 4.14.1 (manager/indexer/dashboard على 8444) + حاوية `kali1` = agent 001 **active** + FIM realtime + قواعدنا.
- **كلمات المرور:** `~/soc/.secrets.env` على السيرفر (600). **الافتراضية مرفوضة.**
- **حزمة Bootstrap** عند المستخدم (ملف خاص خارج Git) — يلصقها لأي وكيل → `ssh cloudlab` يعمل.
- **مُتحقَّق:** `alert.timestamp` بدقة **ms** (ISSUE-061 CLOSED).
- **لم يُنشر بعد:** AR scripts داخل kali1، VT key، YARA، auditd (يحتاج `--privileged`)، Suricata، Windows، MikroTik.

## 6. الأرقام التي يجب أن تعرفها (كلها مُشتقّة في `plan_math.py`)

| الرقم | القيمة | لماذا |
|---|---|---|
| n لكل UC | **30** | 29/30 → Wilson lower 0.833 ≥ 0.80 (يتحمّل خطأً واحداً); 19/20 → 0.764 يفشل |
| baseline | **12 ساعة/OS** | 1 FP في 12h → Poisson upper 0.39 < 0.5; 6h تفشل عند أول FP (0.79) |
| PILOT | n=5 أولاً | لتقدير σ ثم n = max(30, ⌈(1.96σ/1)²⌉) |
| MWU 30/30 | يكشف Δ ≥ **0.75σ** | لا 0.5σ (كان خطأً صحّحته) |
| UC-08 | ≥930 ث بين المحاولات | `ignore=900` على 100051 → 30 محاولة = 7.75 ساعة متداخلة |
| UC-03 VT | 4 طلبات/دقيقة، 500/يوم | 60 محاولة بفاصل 90 ث = 90 دقيقة؛ **أسماء ملفات فريدة** (AR keys dedup — ISSUE-060) |
| ذاكرة المكدّس | ~2.3 GB فعلي | indexer 1.5 + manager 0.5 + dashboard 0.2 + kali1 0.1 |
| ميزانية G6 | 460 محاولة ≈ 15 ساعة + 24 ساعة baseline ليلية | 4–5 أيام عمل |
| رفض جلسة | \|NTP offset\| > 100 ms على أي جهاز | INVALID تلقائياً |
| AR trigger UC-11 | قاعدة **5763** (لا 5712) | Wazuh AR use-case الرسمي؛ تأكيد = 651 |
| SQLi | 31103 محاولة / 31106 نجاح | يتطلب `log_format apache` |

## 7. الأخطاء التي وقعنا فيها (لا تكرّرها)

1. **squash يُضيع ملفات** إن كانت في commits مختلفة ولم تُدمج في الـsoft reset — تحقّق بـ`git show --stat HEAD`.
2. **XML comments متعددة الأسطر** في `ossec.conf.d/*.xml` — `grep -v '^<!--'` يكسرها؛ استخدم Python `re.sub` بـ`re.S`.
3. **Python regex replacement مع `\"`** كتب علامات اقتباس مهرَّبة في YAML → OpenSearch security init فشل بصمت (كل كلمات المرور 401). الحل: lambda في `re.sub` + `securityadmin.sh -cd config/opensearch-security/ -cacert config/certs/root-ca.pem ...`.
4. **`<USER_NAME>`** في `local_rules.xml` ليس XML صالحاً — استبدله قبل النشر.
5. **GitHub API token** (installation) ينتهي بسرعة؛ `git push` يعمل لكن `curl api.github.com` يرد 401 — أعد `setup_github_environment` أو أنشئ PR من الرابط الذي يطبعه `git push`.
6. **ترقيم ISSUEs يتصادم** عند دمج فرعين — تحقّق من `grep ISSUE-0XX` قبل الإشارة.
7. **n=10 أو 20 غير كافٍ إحصائياً** — لا تعد إليها.
8. **لا تفترض** مدة `ps` 60 ث (هي 30) أو أن Suricata ترى كل الشبكة (ترى الـVM فقط بدون mirror).
9. **الجلسات تنقطع** — إن كتبت أكثر من 15 دقيقة بدون push فأنت تخاطر.

## 8. ما يجب فعله الآن — بالترتيب (لمن يستأنف)

### إن كنت **أي وكيل** يستأنف من هنا:
1. `git fetch && git checkout main && git pull` — تأكد PR #26 مدموج (وإلا ادمجه: فيه `CLOUD_ENV_ACCESS.md` والملفات المُسترجَعة).
2. اقرأ `CLOUD_ENV_ACCESS.md §2` واتصل (بحزمة Bootstrap من المستخدم أو مفتاحك). شغّل §4.
3. احجز مهمتك في TASKBOARD (T-60 إن كنت تكمل البيئة).
4. **الخطوة الفنية التالية (T-60 المتبقي):**
   a. نشر `soc_ar.py` + غلاف `remove-threat.exe` داخل `kali1` (`docker cp` → `/var/ossec/active-response/bin/`, `chown root:wazuh; chmod 750`).
   b. اطلب VT API key من المستخدم → `<integration>` في manager ossec.conf (**لا في Git**).
   c. PILOT UC-02: `docker exec kali1 sh -c 'echo x > /home/kali/SOCfile/p_$(date +%s)'` → اقرأ `alerts.json` → سجّل JSONL حسب `tests/README.md`.
   d. PILOT UC-06: حاوية ثانية `curl -H "User-Agent: () { :; }; echo" http://kali1/` → 31168.
   e. PILOT UC-08: `docker exec kali1 nc -l -p 8000 &` → 100051 خلال ≤30 ث.
   f. قرار auditd (UC-05): `--privileged` للحاوية أو auditd على المضيف.
   g. حدّث `CLOUD_ENV_ACCESS.md §3/§7` + SESSIONS_LOG + commit+push.
5. **بالتوازي (ASTRA):** T-13 (SSH brute-force → 5763 → firewall-drop، sshd داخل kali1 + hydra من حاوية)، T-12 (SQLi، وحّد `log_format apache` — ISSUE-059).
6. **يحتاج المستخدم:** D1–D7، Q5، VT key، WireGuard للمعمل (T-61) لفتح Windows/MikroTik/هاتف.

### إن كنت **CLAUDE** في جلسة جديدة:
دورك: مراجعة PRs أسترا، T-52 ADR-013 بعد D1–D7، تدقيق ch1–3 في G7، الدفاع الأكاديمي. **لا تنفّذ ما هو محجوز لأسترا** إلا بطلب.

### إن كنت **ASTRA**:
ابدأ من TASKBOARD T-11 المتبقي (PILOT على السحابة) ثم T-13 → T-12 → T-14 → T-31 → T-22.

## 9. كيف تُبلِغ المستخدم (أسلوبه المفضّل)

- **قصير**: جدول "ماذا عُمل / ماذا بقي / روابط PR". لا فقرات طويلة.
- **صادق**: إن لم تتحقق من شيء قل "لم أتحقق". هو يقدّر "وجدت خطأً عندي وصحّحته" أكثر من الادعاء.
- **لا تستخف** بقدرات الوكلاء أو البيئة — اكتشف الأدوات (`gsk help`، `gsk mesh`) قبل أن تقول "لا أستطيع".
- **البرومبتات** التي يطلبها لوكلاء آخرين: **في الشات**، لا كملفات (إلا إذا طلب).
- عند انقطاع الجلسة: كل شيء مُلتزَم ومرفوع — هذا ما يريده.

## 10. الملفات الخاصة خارج Git (عند المستخدم فقط)
- `CLOUD_LAB_BOOTSTRAP_PRIVATE.txt` — المفتاح الخاص + بصمة + config (3 KB). إن تسرّب: احذف `claude-lab-agent` من `authorized_keys` على السيرفر.
- `~/soc/.secrets.env` على السيرفر — كلمات مرور Wazuh.
- VT API key — لم يُزوَّد بعد.
- Telegram token — لم يُزوَّد بعد.

---
*آخر تحديث: 2026-09-09 08:35 UTC — CLAUDE. حدّث هذا الملف عند كل معلَم كبير (بوابة G تُغلق، قرار D يُحسم، بيئة تتغيّر). هو ليس بديلاً لـSESSIONS_LOG بل خلاصته.*
