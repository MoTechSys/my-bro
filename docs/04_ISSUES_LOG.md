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
| ISSUE-036 | عالية قبل تشغيل AR | `wazuh/agents/linux/active-response/remove-threat.sh` السطور 16–28 و`30-active-response-remove-threat.xml`؛ مراجعة ثابتة، لا تجربة استغلال | الحذف يقع خارج شرط add، والمسار ليس مقيداً بقائمة مسموحة، وLinux/Windows يشتركان في محفز 87105 دون فصل ظاهر. T-10 يضع بوابة سلامة قبل اختبار الحذف؛ يلزم حجز T-15 لمراجعة/إصلاح السكربت وتوجيه الاستجابة، ثم اختبار داخل VM. لا ادعاء بحدوث حذف خاطئ في المعمل | IN-PROGRESS — T-15 PR #14: حراسة add ومسارات/بصمة واستجابة local واحدة؛ اختبارات محلية فقط. مراجعة Claude مكتملة #17؛ يحتاج Windows/المعمل؛ ليس CLOSED |
| ISSUE-037 | متوسطة | `docs/lab/UC-08_process_monitoring_netcat.md` يصف ignore=900 بأنه لنفس العملية؛ مرجع Wazuh 4.14 Rules syntax يعرّفه تجاهلاً للقاعدة بعد إطلاقها | @CLAUDE: صحح شرح الكبت؛ تغيير PID لا يضمن إعادة التنبيه. T-10 يفصل 930 s من أحدث 100051 ويضع تجربة SUPPRESSION_CONTROL مستقلة، دون تعديل القاعدة أو runbook المملوك لك | FIXED-IN-REPO (runbook UC-08 مُصحَّح، CLAUDE) / NEEDS-LAB للتحقق |

## متابعة [ASTRA] لـ T-15 — PR #14، 2026-09-09

| ID | الخطورة | الموضع | الإجراء / ما بقي | الحالة |
|---|---|---|---|---|
| ISSUE-039 | عالية خارج المعمل | `soc_ar.py:remove_file` و`soc_windows_ar.py:main` | حماية الروابط/بصمة/هوية الملف لا تلغي سباق استبدال الاسم الأخير، خصوصاً Windows؛ يلزم ACL/تصميم مقابض أصلي ومراجعة مستقلة قبل نشر إنتاجي. التفاصيل في `tests/SECURITY_REVIEW.md` §4؛ لا حادثة فعلية مُدّعاة | OPEN — T-15 |
| ISSUE-040 | متوسطة | واجهات سكربتات المعمل وتوزيع AR في PR #14 | أصبح --lab وmanifest/bصمات مطلوباً؛ Linux يوزَّع remove-threat.sh باسم remove-threat.exe مع soc_ar.py، وWindows يبني exe أصلياً مع allowlists صريحة. @CLAUDE: تحديث runbooks/F4 وتصديق عقد التوزيع في التقرير §3 و§6؛ لا تستخدم الأوامر القديمة بلا تعديل | OPEN — مراجعة وتحديث أدلة |
| ISSUE-041 | متوسطة | Windows/YARA/installer verification | نجحت 19 حالة محلية والـvalidator؛ لم تُنفّذ PyInstaller/ACL/Wazuh/YARA/مثبتات أو تنزيلات حقيقية. يلزم تنفيذ نقاط التقرير §7 وجمع الأدلة؛ لا يُستبدل ذلك بنجاح syntax | NEEDS-LAB — T-15 |

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

## تدقيق الاستلام T-16 — 2026-09-09

| ID | الخطورة | الملاحظة | الإجراء والحالة |
|---|---|---|---|
| ISSUE-042 | متوسطة | roadmap/STATE/protocol راكدة: نسب بلا اشتقاق، نطاق توسعات مخالف للنية، reset تلقائي | FIXED-IN-REPO في T-16: ADR-011/012 وخطة بوابات؛ لا تغيير للنطاق الحاكم |
| ISSUE-043 | متوسطة | DEMO: CLI قديم، Netcat 60 بدلاً من 30، أزمنة غير مقاسة، 100200 للإضافة بدل 100201 | FIXED-IN-REPO توثيقياً في T-16؛ dry-run مرتان ما زال NEEDS-LAB |
| ISSUE-044 | متوسطة | أسماء النماذج/benchmarks في وثيقة القدرات ليست موثقة بمصادر أولية هنا | OPEN للتحقق أو التنقيح التاريخي؛ وُضع تحذير بعدم استخدامها كحقائق أو معيار قبول |
| ISSUE-045 | متوسطة | prompt لا يثبت أن الخادم OVA؛ بعض الوثائق تعرض الافتراض كحقيقة | OPEN: يلزم جرد حي وتصحيح شامل للرسالة/المعمارية؛ START_HERE وDEMO يوضحان عدم اليقين |
| ISSUE-046 | متوسطة | تدقيق المصادر الأصلية وFR/NFR والفصول ما زال غير مكتمل لدى ASTRA | OPEN: سجل التغطية في TAKEOVER_AUDIT؛ لا ادعاء تدقيق كل حرف أو إعادة تحقق المراجع |

ISSUE-040: تحديث الواجهات وR1/R3 في T-16 = FIXED-IN-REPO للتوثيق فقط؛ اختبار الأوامر الإيجابي في المعمل باقٍ ضمن ISSUE-041. ISSUE-019/032/036/039 لا تُغلق بهذا التدقيق.

متابعة ISSUE-034 في PR #20: نواة سجل المحاولات والوقت الصحيح منفذة محلياً، لكن AR/baseline/UC-01/visibility وsource adapters متبقية؛ الحالة IN-PROGRESS لا CLOSED. اختبارات 33 fixture لا تغلق ISSUE-019.

## مراجعة الأصول والنية T-17 — PR #22

| ID | الخطورة | الدليل/المشكلة | الحالة والخطوة التالية |
|---|---|---|---|
| ISSUE-047 | متوسطة | ch3: كل مكون عامل، FR-08 listener/reverse shell، FR-09 كل تنبيه MITRE، NFR timing/FP/16GB/أمان مطلق، AR sequences قديمة وOVA | OPEN؛ مصفوفة كل FR/NFR في INTENT_STUDY_AND_BLUEPRINT §8؛ تصحيحات الدلالة/النطاق للموافقة ADR-013 ثم تعديل الفصل واختباره |
| ISSUE-048 | متوسطة | docs/05 وADR-010 يضعان الهواتف Future Work ويفسران أقوى من Wazuh؛ S6 يطلب التوسع صراحة وS4 يستبعد محركاً من الصفر | NEEDS-USER؛ D1–D7 في الدراسة، لا مساواة scope الوكلاء بنيّة الأخ؛ لا تغيير تنفيذي تلقائي |
| ISSUE-049 | متوسطة | تحليل الصوت الأول أعطى أزمنة خارج الملف؛ فحص الصور خمن provenance واعتبر سبتمبر 2026 مستقبلاً واختلف OCR لإصدار Kali | OPEN لحدود الأدلة؛ رُفضت الأزمنة/الاستنتاجات، Scribe داخل مدد ffprobe لكنه غير مصدق بشرياً؛ لا تعديل إصدار Kali اعتماداً على OCR؛ يلزم تأكيد المتحدث/صورة أوضح أو جرد حي |

ISSUE-044: FIXED-IN-REPO في #22: مصادر Anthropic/OpenAI أولية، تصحيح Fable $10/$50 وAstra Terminal-Bench 57.9؛ منع مقارنة OSWorld غير المتكافئة ونقل نتائج بلا حواجز إلى قدرات الإنتاج؛ حذف ترتيب قوة غير مثبت من وثيقة القدرات الحالية مع بقاء التاريخ في Git. ليس اختباراً مستقلاً للنموذجين.

ISSUE-046 يبقى OPEN: قرئت نصوص S1–S5 وch3 والصوتيات مع فحص صور مختارة؛ الفصول 1–2 والمراجع وبقية الصور لم يكتمل تدقيقها. ISSUE-005 لا يغلق بالتخمين من أسماء الوكلاء والتواريخ.
| ISSUE-059 | متوسطة | `wazuh/agents/linux/ossec.conf.d` localfile لـaccess.log: UC-06 يستخدم `log_format syslog`؛ Wazuh PoC لـSQLi (UC-09) يتطلّب `apache`. قد لا تُطلَق 31103 تحت syslog | OPEN — T-12: توحيد على `apache` وإعادة اختبار 31168 (MASTER_PLAN_v3 §9) | CLAUDE 2026-09-09 |
| ISSUE-060 | متوسطة | `soc_ar.py:180` keys=[agent,file,md5] → execd قد يرفض (`abort`) محاولات UC-03 المتكررة بنفس المسار خلال timeout؛ يهدّد n=30 | OPEN — أسماء ملفات فريدة لكل محاولة في `eicar_test.sh`؛ اختبار PILOT أولاً | CLAUDE 2026-09-09 |
| ISSUE-061 | عالية للقياس | دقّة `alert.timestamp` في `alerts.json` (ثانية أم ms) غير مُتحقَّقة؛ تحدّد دقّة t2 وكل مقاييس MTTD | **CLOSED 2026-09-09** — مُتحقَّق على Wazuh 4.14.1 حيّ (CLOUD_ENV_ACCESS §5): `2026-09-09T07:56:41.333+0000` = **ميلي ثانية** ✅ | CLAUDE 2026-09-09 |
| ISSUE-062 | منخفضة | UC-08 `ignore=900` → n=30 يستغرق 7.75 ساعة؛ يجب أن يدعم `trial_runner.sh` جدولة متداخلة | OPEN — T-11 | CLAUDE 2026-09-09 |


## عقد T-11 وفق طلب المستخدم وMASTER_PLAN v3 §5 — قبل التنفيذ

| ID | التعارض/الفجوة | الإجراء المعلن (لا حسم صامت) | الحالة |
|---|---|---|---|
| ISSUE-050 | §5.1 والطلب يقولان 6 طوابع لكن يسردان t0..t6 = سبعة؛ t2-prime لـVT إضافي | تطبيق الأسماء السبعة كلها مع t2_prime منفصل، UTC epoch milliseconds أو null مع السبب؛ لا حذف t3 | OPEN للتوضيح؛ واجهة v2 موثقة |
| ISSUE-051 | TEST_PLAN عشرة/PILOT واحد/baseline ساعة وNTP غير المتحقق يبقي الكشف؛ v3 خمسة PILOT و20/30 وست ساعات ورفض جلسة offset>100 | طلب المستخدم يحكم العقد الجديد: رفض كل session عند أي جهاز يتجاوز الحد، مع حفظ كل المحاولات؛ ترحيل v2 صريح مع إبقاء v1 للقراءة التاريخية لا قبول جديد | IN-PROGRESS |
| ISSUE-052 | §5.3 يعد الاستبعادات في المقام؛ TEST_PLAN يقسم على DETECTED+MISSED فقط | إخراج معدل محسوب على كل MEASURED كما في v3 ومعدل conditional على الصالح منفصلاً، Wilson لكل مقام مسمى؛ عدم حذف المحاولات | IN-PROGRESS |
| ISSUE-053 | v3 MTTD=t2-t1 لكل UC، بينما TEST_PLAN يسمي Suricata integration؛ UC03 t2=FIM لا87105، L_AR_trigger=t4-t2 يشملVT رغم تسميته نقل؛ UC07 final YARA بعد AR وليس محفزه | تطبيق صيغ §5.2 حرفياً وتسميات حدودها، stage selectors صريحة؛ عدم استبدال t2 بـ87105 أو نتيجة YARA عند حساب trigger؛ حفظ final detection مستقلاً | IN-PROGRESS |
| ISSUE-054 | H4 median overhead≤1s ليست مكافئة لعدم رفض MWU؛ اتجاه الاختبار وطريقة ties/quantiles غير محددين، plan_math لا ينفذ MWU أو Poisson k>0 | اختبار أحادي greater: hardened أبطأ، exact permutation ranks للعينات الصغيرة مع ties، تقريب مصحح للكبير؛ عرض Δmedian وp دون ادعاء non-inferiority؛ type7 quantiles وPoisson CDF inversion موثقان | OPEN منهجياً؛ تنفيذ حسابات لا إثبات H4 |
| ISSUE-055 | t1 FIM/t4 Starting/t5 independent/t3 polling ليست كلها سجلات موجودة في الكود الحالي؛ storage بدقةms لا يخلق دقة فعلية | runner يجمع الأدلة المتاحة ويترك null وسبباً عند غياب المراقب/الحقل، لا يختلق وقتاً؛ حدود الربط وnative adapters/PILOT تبقى معلقة | NEEDS-LAB |
| ISSUE-056 | خارج §5: v3 V5 يقول rm على symlink يحذف الهدف، وهذا غير صحيح لحذف symlink النهائي؛ موارد/Suricata7/DefenderOFF وتعميم الأمان تحتاج مراجعة | لا تنفيذ للـPoC الخطر أو تعطيل Defender أو تعديل النشر في T-11؛ سجل للمراجع، merge وثيقة الخطة لا اعتماد هذه الادعاءات | OPEN |


## مراجعة مرشح T-11 — PR #24

| ID | التعارض/القرار المعلن | الحالة |
|---|---|---|
| ISSUE-057 | §5 يحدد رفض offset>100؛ التطبيق يحتاط أيضاً برفض uncertainty>100. ساعات t2/t2_prime/t6 موحدة، t6 يحتاج selector خام، وغياب Netcat lookback يصنف INVALID في v2 بدلاً من NOT_EVALUATED القديم. هذه قيود قبول صريحة لا نتائج native ولا تغيير صامت لـv1 | OPEN للمراجعة المنهجية؛ قيود مرشح v2 موثقة في TEST_PLAN/README واختبارات PR #24 |

ISSUE-051/052/053: FIXED-IN-REPO في PR #24 من جهة العقد والتوثيق: PILOT5 و20/30 وbaseline6h، session rejection، المقامان مسميان، ثمانية مقاييس وD_VT وselectors منفصلة. لا إغلاق للقبول المعملي. ISSUE-050 يحتفظ بتعارض العدد الأصلي، والتنفيذ يحفظ السبعة كلها. ISSUE-054 OPEN: حساب MWU لا يثبت non-inferiority أو ادعاءات power. ISSUE-055 NEEDS-LAB: runner يستورد مراقبي t1/t3/t4/t5 ولا ينشرهم؛ AR الحالي بلا Starting معتمد، وnative clocks/causality/rotation يحتاج PILOT. ISSUE-056 خارج نطاق هذه التغييرات ويبقى OPEN.


ISSUE-058 — NEEDS-USER: تفويض GitHub رفض آخر push وgh api user بـ401 خلال تسليم PR #24، بعد push ناجح للكود حتى af61ebf. استعادة الربط/التفويض مطلوبة؛ سجل التسليم committed محلياً، وsquash/update/merge معلقة دون إعادة كتابة remote.

تصادم الترقيم عند دمج v3.1: بنود CLAUDE §9 القديمة050/051/052/053 أصبحت059/060/061/062 على الترتيب؛ بنود PR24 الأصلية050..058 محفوظة. EICAR المطلوب باسم ISSUE-051 في رسالة المستخدم = ISSUE-060 الحالي؛ دقة timestamp باسم ISSUE-052 = ISSUE-061. لا حذف لأي بند.


متابعة v3.1 في PR24: ISSUE-058 CLOSED — الربط المجدد دفع12c95b5 بنجاح دون استخدام التوكن المنشور. ISSUE-060 FIXED-IN-REPO/NEEDS-LAB — اسم EICAR فريد، ربط selectors ثابت واختبارات mocks؛ سلوك execd/dedup لم يتحقق أصلياً. ISSUE-061 NEEDS-LAB — أداة فحص الصيغة وG2-0 موثقتان، لا نتيجة دقة أصلية. ISSUE-059/062 OPEN لمهام log_format والجدولة المتداخلة، لا إغلاق ضمن البنود الأربعة الحالية.

ISSUE-063 — OPEN منهجياً: v3.1 plan_math يستعمل Wilson–Hilferty تقريبياً ويسميه exact-style، وMWU power مشتق من normal two-sided/ARE تحت افتراضات توزيع؛ §5 بقي فيه floor20 وبند budget قديم بعد تعديل §9. صُححت تسميات helper وfloor في§5 إلى30، ووسم budget تاريخياً؛ mttd يبقى exactPoisson. الحسابات والتقرير لا يدعيان power مضمونة أو non-inferiority. حجم الجدول النهائي حسب UC/OS والجرد ما زال يحتاج مراجعة، دون تعديل خفي لنتائج أو نطاق.

## تدقيق السحابة 2026-09-11 — [AI]، PR #28

| ID | الخطورة | الدليل والمشكلة | الحالة ومعيار الإغلاق |
|---|---|---|---|
| ISSUE-064 | عالية لاعتماد المعمل | CLOUD_ENV_ACCESS §9: PID 1=tail؛ 19 zombie مع 5 خدمات Wazuh حية؛ Init=null، RestartPolicy=no، Healthcheck=null. العدادات تتقدم، لذلك التوقف الكلي المبلغ عنه ليس الحالة المثبتة الآن. غياب reaper يفسر تراكم zombie ولا يثبت سبب خروج الخدمات أصلاً | OPEN/NEEDS-LAB — حفظ الحالة ثم init مع إدارة خدمات وفحص صحة وتعافٍ فعلي؛ اختبار إعادة التشغيل والاستعادة ثم canary. لم يُنفذ إصلاح؛ قيود الجلسة تمنع الكتابة على /home/work |
| ISSUE-065 | عالية لفقد البيانات | `docker inspect kali1`: Mounts=[]؛ إعدادات الوكيل وهويته ليست محفوظة في volume ظاهر. إعادة الإنشاء العمياء من الصورة قد تفقد التعديلات وهوية agent 001 | OPEN/NEEDS-LAB — نسخة خاصة قابلة للاستعادة من الحالة قبل أي حذف، نموذج تخزين وصلاحيات مختبر، وعدم تشغيل هويتين متطابقتين. لا أسرار أو أرشيف حاوية في Git |
| ISSUE-066 | متوسطة للقياس والتوثيق | kali1 فعلياً Ubuntu 24.04.4 لا Kali؛ active وHTTP401/302 وNTP=yes وتقدم العدادات لا تثبت كل UC أو دقة الساعة أو الوصول للفهرس. alerts.json اليومي فارغ؛ AR/YARA غير موجودين في المسارات المحددة | OPEN/NEEDS-LAB — فصل الجرد السلبي عن canary/PILOT، إثبات المصدر والتنبيه والفهرسة والساعة بهوية فريدة بعد إصلاح064/065؛ ثم نشر المكونات الناقصة وفق بوابة الأمان. 145 اختباراً محلياً ناجحاً لا يغلق هذا البند |

ISSUE-061: أحدث تدقيق لم يستخرج تنبيهاً حياً جديداً ولم يقس دقة توليد timestamp. ظهور ثلاث خانات كسرية في المثال التاريخي يثبت التمثيل فقط؛ لا يبرر وحده إغلاق بوابة دقة الساعة/المصدر. يبقى القبول المعملي NEEDS-LAB كما في متابعة PR24، مع حفظ السجلات التاريخية أعلاه.
