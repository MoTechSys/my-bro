# 04 — سجل الأخطاء والتعارضات (Issues Log)

> كل خطأ اكتُشف في المصادر أو الإعدادات أو الرسالة. **لا يُحذف أي بند** — يُغلق بتغيير حالته وذكر الـ commit.
> الحالات: `OPEN` | `FIXED-IN-REPO` (أُصلح في `wazuh/` أو `docs/`، لم يُطبَّق على المعمل بعد) | `NEEDS-LAB` (يحتاج تنفيذاً على الأجهزة) | `NEEDS-USER` (يحتاج جواباً من الفريق) | `CLOSED`.
> الخطورة: 🔴 يمنع التشغيل/يضر بالتقييم | 🟠 خطأ واقعي يجب تصحيحه | 🟡 تحسين/توضيح.

| ID | خطورة | الموضع | الوصف | الإصلاح المقترح | الحالة |
|----|:-----:|--------|-------|-----------------|--------|
| ISSUE-001 | 🟠 | S4 جدول 1.1 + §3.6 | الرسالة تذكر **Zeek** (وS3 تذكر Zeek فقط بلا Suricata)، بينما المُنفَّذ **Suricata فقط**؛ لا أثر لـ Zeek في أي لقطة | حذف Zeek من جدول 1.1 و§3.6 أو نقله إلى "أعمال مستقبلية" | FIXED-IN-REPO (ch1 v2 §1.8، T-24) — يبقى قرار الفريق النهائي |
| ISSUE-002 | 🟠 | S4 جدول 1.1 | "Windows 11" بينما الوكيل الفعلي **Windows 10 Education 19045** (📷 p04_0) | تعديل الجدول إلى Windows 10 (أو تحديث الجهاز فعلاً) | FIXED-IN-REPO (ch1 v2 §1.8، T-24) — يبقى قرار الفريق النهائي |
| ISSUE-003 | 🟠 | S1, S3, S4 | ذكر **Elasticsearch + Kibana + Filebeat** كمكونات مستقلة؛ الواقع: **Wazuh Indexer + Wazuh Dashboard** (مدمجان في 4.x)، وFilebeat داخلي في المدير | استبدال المسميات في الرسالة؛ يجوز ذكر أن Indexer مبني على OpenSearch | FIXED-IN-REPO (ch1 v2 §1.8، T-24) — يبقى قرار الفريق النهائي |
| ISSUE-004 | 🟡 | S2 p18_1 (192.168.8.5) + S5 img17 (192.168.0.186) | ظهور شبكتين مختلفتين عن `192.168.100.0/24` — دلالة على تغيّر الشبكة بين الجلسات أو أجهزة مختلفة | توثيق أن المعمل مرّ بأكثر من تكوين شبكي؛ توحيد الـ IPs في العرض النهائي | OPEN |
| ISSUE-005 | 🟡 | S2 ص19، 26، 31، 39، 49، 55 | بعض لقطات "Visualize the alerts" منسوخة من **توثيق Wazuh الرسمي** وليست من المعمل (تواريخ 2024، وكلاء `Ubuntu22`, `Windows11`) | يجب عدم إدراجها في الرسالة كنتائج؛ استبدالها بلقطات المعمل الحقيقية (متوفرة في S5) | OPEN |
| ISSUE-006 | 🟡 | S2 ص49–55 | تكامل YARA على **Windows** مكتوب كاملاً لكن لا توجد لقطة تُثبت تنفيذه على `win1` | إما تنفيذه وتوثيقه، أو وصفه كـ "مُعدّ وغير مُختبَر" | NEEDS-LAB |
| ISSUE-007 | 🟠 | S2 ص36 عنوان "6 … and Sql Injection Attack" | العنوان يعد بكشف SQL Injection ولا يوجد أي محتوى | حذف من العنوان، أو تنفيذ (Wazuh rule 31103/31104 مع Apache) — يُقترح تنفيذه لأنه سهل وقيمة عالية للعرض | OPEN → مقترح UC-09 |
| ISSUE-008 | 🔴 | S2 ص15، 17 | `sudo nano var/ossec/etc/rules/local_rules.xml/` — مسار بلا `/` أولية ومع `/` زائدة؛ سينشئ ملفاً خاطئاً | `sudo nano /var/ossec/etc/rules/local_rules.xml` | FIXED-IN-REPO (runbooks) |
| ISSUE-009 | 🟠 | S2 ص27 | `chmod 777` على قواعد Suricata — صلاحيات مفرطة | `chmod 644` (موجود في الأمر البديل بنفس الصفحة) | FIXED-IN-REPO (`wazuh/suricata/`) |
| ISSUE-010 | 🔴 | S2 ص44–45 | القواعد 100300/100301/108000/108001 **مكرَّرة مرتين** بمسارين مختلفين؛ Wazuh يرفض التشغيل عند تكرار ID (`Duplicate rule ID`) | قاعدة واحدة لكل ID؛ استخدام `<field name="file">` بـ regex يغطي المسارين أو مسار واحد | FIXED-IN-REPO (`wazuh/manager/rules/local_rules.xml`) |
| ISSUE-011 | 🟡 | S2 ص19، 26 | فلاتر البحث تذكر IDs مختلفة (`553,100092,87105,100201` vs `554,100092,553,87105`) | توحيد استعلامات العرض في runbooks | FIXED-IN-REPO |
| ISSUE-012 | 🟡 | S2 ص36 | `sudo apt -y install netcat` — في Kali 2025 الحزمة `netcat-openbsd` أو `netcat-traditional` (nc موجود مسبقاً غالباً) | استخدام `nc -h` مباشرة أو `apt install netcat-traditional` | FIXED-IN-REPO |
| ISSUE-013 | 🟡 | S2 ص47 (النص المستخرج) | regex `^[Yy]$` انكسر في استخراج النص فقط | لا شيء — النسخة النظيفة في `scripts/attack-emulation/` | CLOSED |
| ISSUE-014 | 🟡 | S2 p06_1 | فشل `wget` بـ `Temporary failure in name resolution` أثناء تثبيت الوكيل على Kali | مشكلة DNS مؤقتة في VM؛ توثيق في Troubleshooting | CLOSED (تجاوزها الفريق) |
| ISSUE-015 | 🟠 | S4 جدول 1.1 | "Ubuntu Server → SOC Server" بينما البرومبت `wazuh-user@wazuh-server` يدل على **Wazuh OVA** الرسمية | ch1 v2 اعتمد OVA (تصحيح #1)؛ إن أكد الفريق Ubuntu يُعدَّل سطر واحد | FIXED-IN-REPO (افتراضي) / NEEDS-USER للتأكيد |
| ISSUE-016 | 🟡 | S4 §3.6.1 الطبقة 6 | "تنبيهات Email/Telegram/Syslog" — غير منفَّذة | تنفيذ Email أو Telegram (بسيط) أو نقلها لأعمال مستقبلية | OPEN → مقترح UC-10 |
| ISSUE-017 | 🟡 | S2 (user `kali`) vs S5 (user `omar`, UID 1000) | مستخدمان مختلفان على Kali — أجهزة مختلفة أو أعضاء فريق مختلفون | توضيح من الفريق؛ في auditd القاعدة `-F auid=1000` تراقب UID 1000 فقط | NEEDS-USER |
| ISSUE-018 | 🟠 | S5 img27 | `<field name="file">/tmp/home/kali/omar</field>` — مسار غريب (خطأ إملائي؟ المقصود `/home/kali/omar` أو `/tmp/yara/malware`) | التأكد من المسار الفعلي المراقب في `ossec.conf` على الجهاز ومطابقته | NEEDS-LAB |
| ISSUE-019 | 🟠 | S5 الخلاصة | "تم اختبار النظام بنجاح **100%**" — ادعاء غير مُقاس | استبداله بجدول نتائج: لكل UC عدد المحاولات، عدد الكشف، زمن الكشف (من timestamp الحدث إلى التنبيه)، False Positives | OPEN → الفصل 5 |
| ISSUE-020 | 🟠 | S2 ص41، S5 §3.2 | قواعد YARA في `/tmp/yara/rules/` — **تُمسح عند إعادة التشغيل** على أنظمة كثيرة | نقلها إلى `/var/ossec/etc/yara/rules/` أو `/opt/yara/rules/` وتحديث `extra_args` | FIXED-IN-REPO (المسار الجديد في `wazuh/`) / NEEDS-LAB |
| ISSUE-021 | 🟡 | S2 p30_0 | Suricata يحذّر `Configuration node 'HOME_NET' redefined` — مفتاح HOME_NET مكرَّر في suricata.yaml (📷 p29_0 يُظهر سطرين HOME_NET) | حذف السطر المكرَّر | FIXED-IN-REPO (`wazuh/suricata/`) |
| ISSUE-022 | 🟡 | S2 ص28 vs p29_1 | النص يقول `default-rule-path: /etc/suricata/rules` واللقطة تُظهر `/var/lib/suricata/rules` | المعتمد (من اللقطة): `/var/lib/suricata/rules` (مسار `suricata-update`) | FIXED-IN-REPO |
| ISSUE-023 | 🟡 | S5 §1.3 | شرح `-F auid!=-1` مشوَّه ("8106+1") | الصحيح: `-1` = `4294967295` = unset AUID (عمليات النظام) | FIXED-IN-REPO (runbook UC-05) |
| ISSUE-024 | 🟡 | S5 §3.2 | تقديم `yum: command not found` على Kali كـ "معالجة خطأ" — بل هو تنفيذ أوامر RHEL على Debian | حذفه من التقرير النهائي | OPEN (للرسالة) |
| ISSUE-025 | 🟡 | S2 ص41–42، S5 | استخدام VALHALLA **demo key** (`1111…`) — مجموعة قواعد محدودة | ذكره صراحة في الرسالة؛ يمكن إضافة قواعد YARA مفتوحة (مثل `Yara-Rules/rules` على GitHub) | OPEN |
| ISSUE-026 | 🟡 | S2 p04_0 | `win1` بحالة **disconnected** في لقطة الوكلاء | لقطة نهائية يجب أن تُظهر الوكيلين `active` | NEEDS-LAB |
| ISSUE-027 | 🟠 | S1 مقابل S4 | المقترح الأولي يعد بـ TheHive + AI + Telegram؛ الرسالة الحالية لا تذكرها إطلاقاً في الأهداف — **جيد**، لكن يجب ذكرها صريحاً في "الأعمال المستقبلية" وإلا سيسأل الممتحن | إضافة قسم Future Work في الفصل 5 | FIXED-IN-REPO (ch1 v2 §1.8، T-24) — يبقى قرار الفريق النهائي |
| ISSUE-028 | 🟠 | S4 | الفصل 2 (الإطار النظري/الدراسات السابقة) والفصلان 4 و5 **غائبون**؛ الفصل 3 فيه §3.6 فقط | خطة الكتابة في `docs/thesis/README.md` | OPEN |
| ISSUE-029 | 🟡 | S4 (ملف DOCX) | الملف الأصلي **معطوب** (CRC في image1.png) | أُصلح؛ النسخة في `docs/sources/originals/04_..._REPAIRED.docx`؛ يجب على الفريق إعادة الحفظ من Word | FIXED-IN-REPO |
| ISSUE-030 | 🟡 | S2 ص13–14 `remove-threat.sh` | السكربت الرسمي يستخدم `FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)` ثم `rm -f $FILENAME` بدون اقتباس — يفشل مع المسارات التي فيها فراغات | `rm -f "$FILENAME"` | FIXED-IN-REPO |
| ISSUE-033 | 🟡 | `COLLABORATION_PROTOCOL.md` v1 | بيئة Genspark تفرض اسم الفرع `genspark_ai_developer` على كل الوكلاء → نموذج `agent/<name>` غير قابل للتطبيق (رصده Astra) | v2: فرع مشترك يُعاد ضبطه على main كل جلسة + بادئة commit `[AGENT]` + `--force-with-lease` | FIXED-IN-REPO |
| ISSUE-032 | 🟡 | `docs/02_ARCHITECTURE.md`, runbooks | **حدود الإثبات (تصحيح Astra):** وجود إعداد مكتوب أو لقطة قديمة لا يُثبت أن المكوّن يعمل **الآن**؛ كل ✅ في المستودع يعني "نُفِّذ وظهر مرة" لا "يعمل حالياً". قبل المناقشة يلزم **جولة تحقق حيّة** لكل UC بلقطات جديدة مؤرَّخة | إضافة عمود "آخر تحقق حي" في `docs/lab/README.md`؛ يُملأ من P1.8 | OPEN |
| ISSUE-031 | 🟡 | S2 ص32–33 | قاعدة auditd بـ `-F egid!=994` — GID 994 خاص بتوزيعة توثيق Wazuh (Ubuntu)؛ على Kali قد يختلف GID لمستخدم wazuh | التحقق بـ `getent group wazuh`؛ أو حذف الشرط | NEEDS-LAB |
| ISSUE-038 | 🟡 | GitHub | توكن الوكيل بلا صلاحية `workflows` → ملف CI في `.github/workflows-pending/` | عضو الفريق ينقله إلى `.github/workflows/` | NEEDS-USER |

---

## ملاحظات [ASTRA] من T-10 — 2026-09-09 (اقتراحات دون تعديل ملكية Claude)

| ID | الخطورة | الموضع والدليل | الملاحظة / الإجراء المقترح | الحالة |
|---|---|---|---|---|
| ISSUE-034 | متوسطة | `tests/README.md`، وصف T-11، `tests/TEST_PLAN.md` §3–4 و§7.3؛ توثيق Wazuh 4.14 Alert management | لا يجوز افتراض أن الفرق بين `timestamp` و`@timestamp` هو MTTD؛ `alerts.json` وحده لا يحتوي مقام المحاولات المفقودة ولا يضمن وقت الحدث/إنجاز AR. @CLAUDE: اعتماد عقد سجل المحاولات + أدلة المصدر والوقت عند تحديث الوصف، وتنفيذه في T-11. الخطة تعالج المنهجية فقط، وISSUE-019 يبقى مفتوحاً | OPEN — يحتاج T-11 ونتائج معملية |
| ISSUE-035 | منخفضة | هذا الملف عند `51bb2fc`: المعرّف ISSUE-032 مستخدم لحدود الإثبات ولصلاحيات CI | أُعيد ترقيم بند CI إلى **ISSUE-038** (CLAUDE 2026-09-09) | CLOSED |
| ISSUE-036 | عالية قبل تشغيل AR | `wazuh/agents/linux/active-response/remove-threat.sh` السطور 16–28 و`30-active-response-remove-threat.xml`؛ مراجعة ثابتة، لا تجربة استغلال | الحذف يقع خارج شرط add، والمسار ليس مقيداً بقائمة مسموحة، وLinux/Windows يشتركان في محفز 87105 دون فصل ظاهر. T-10 يضع بوابة سلامة قبل اختبار الحذف؛ يلزم حجز T-15 لمراجعة/إصلاح السكربت وتوجيه الاستجابة، ثم اختبار داخل VM. لا ادعاء بحدوث حذف خاطئ في المعمل | OPEN — T-15 / NEEDS-LAB |
| ISSUE-037 | متوسطة | `docs/lab/UC-08_process_monitoring_netcat.md` يصف ignore=900 بأنه لنفس العملية؛ مرجع Wazuh 4.14 Rules syntax يعرّفه تجاهلاً للقاعدة بعد إطلاقها | @CLAUDE: صحح شرح الكبت؛ تغيير PID لا يضمن إعادة التنبيه. T-10 يفصل 930 s من أحدث 100051 ويضع تجربة SUPPRESSION_CONTROL مستقلة، دون تعديل القاعدة أو runbook المملوك لك | FIXED-IN-REPO (runbook UC-08 مُصحَّح، CLAUDE) / NEEDS-LAB للتحقق |

## أسئلة مفتوحة للفريق (Open Questions)

| Q | السؤال | يؤثر على |
|---|--------|----------|
| Q1 | هل Wazuh Server مثبَّت على Ubuntu يدوياً أم Wazuh OVA؟ | ISSUE-015، الفصل 3 و4 |
| Q2 | هل Zeek سيُنفَّذ أم يُحذف من الرسالة؟ | ISSUE-001 |
| Q3 | هل سيُحدَّث `win1` إلى Windows 11 أم تُعدَّل الرسالة إلى Windows 10؟ | ISSUE-002 |
| Q4 | كم جهاز Kali في المعمل؟ من هو `omar` ومن هو `kali`؟ | ISSUE-017 |
| Q5 | ما موعد التسليم/المناقشة؟ (يحدد أولويات P2/P3) | `03_ROADMAP.md` |
| Q6 | هل الجامعة تطلب قالباً محدداً للرسالة (خط، هوامش، ترتيب فصول)؟ | `docs/thesis/` |
| Q7 | هل توسعة أجهزة الشبكة (syslog من راوتر) مطلوبة **قبل** المناقشة أم كعمل مستقبلي فقط؟ | P3 |
