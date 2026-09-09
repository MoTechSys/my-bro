# tests — الاختبارات وعقد القياس

> المالك ASTRA؛ 2026-09-09؛ الحالة اختبارات محلية وخطة، بلا نتائج معملية. المرجع TEST_PLAN.md (T-10).

- TEST_PLAN.md: عشر محاولات لكل سيناريو/OS/config بعد PILOT؛ baseline ساعة موثقة، وسجل مستقل عن alerts.json.
- SECURITY_REVIEW.md وtest_security.py: حدود الأمن واختبارات محلية، لا native acceptance.
- T-11 IN-PROGRESS: نواة scripts/measure/mttd.py الحالية موثقة أدناه؛ لا طرح timestamp من @timestamp ولا استبدال المفقود بصفر.
- ISSUE-019 لا يغلق بالخطة أو fixtures اصطناعية. النتائج الحقيقية فقط تغذي الفصل الخامس.

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
bash scripts/validate/validate_all.sh
```

## T-11 — عقد نواة القياس الحالية (PR #20)

الحالة: **IN-PROGRESS**؛ نواة كشف offline واختبارات محلية فقط. لا تستخدمها كتقرير T-11 نهائي. المرجع الأوسع TEST_PLAN لم يُختزل: AR وFP/hour وUC-01 وظهور اللوحة ومحللات أدلة المصدر ما زالت متطلبات متبقية.

### التشغيل

Python 3.9+؛ لا dependencies خارج المكتبة القياسية ولا شبكة ولا تعديل إعدادات/سجلات أصلية. تُمرّر ملفات rotation صراحةً، JSONL عادي لا gzip/JSON array/Indexer search envelope:

```bash
python3 -B scripts/measure/mttd.py --help
# ملفاتك المنقحة الفعلية؛ الناتج JSON إلى stdout، والأخطاء إلى stderr:
python3 -B scripts/measure/mttd.py \
  --journal attempts.jsonl \
  --alerts alerts-previous.jsonl alerts-current.jsonl \
  --manifest manifest.json
```

الخروج 0 = اكتمال حساب **النواة المحدودة** وليس نجاح كل التجارب أو اكتمال T-11. الخروج 2 = مدخلات غير صالحة؛ لا ينشر البرنامج تقريراً جزئياً إلى stdout. إذا حفظت stdout بملف، لا تعتمد وجود الملف وحده: shell قد ينشئ ملفاً فارغاً قبل فشل الأمر. لا تكتب فوق ملفات المصدر. راجع الناتج قبل نشره: يتضمن سجل المحاولات ومرجع الملف والمسار، وقد يحمل معلومات حساسة.

### manifest.json

كائن `{"version":1,"runs":[...]}`. كل run له:

| الحقول | العقد |
|---|---|
| run_id | نص فريد؛ مجموعة مستقلة لا تُجمع تلقائياً مع غيرها |
| agent_id, agent_name, manager_name, os | نصوص مطابقة للهوية الفعلية؛ الأصفار البادئة محفوظة |
| config_commit, config_sha256 | Git hash كامل 40 hex صغير، SHA-256 64 hex صغير لبيان الإعداد المنشور؛ ليست قيم fixture الاختبارات |
| timing_definition | تعريف دقيق موحد لمصدر الزمن والمعنى؛ تغييره ينشئ run جديداً |
| latency_kind | DETECTION أو INTEGRATION؛ وقت Suricata eve→manager عادة INTEGRATION، لا attack-to-detection |
| coverage_start, coverage_end | مجال UTC على مقياس ساعة المدير، يغطي كامل الرصد وNetcat lookback إن لزم |
| coverage_ref | مرجع مستقل لإثبات اكتمال السجلات/الرصد، ليس توقيت أول/آخر alert وحده |
| clock_verified | boolean حقيقي؛ false يعني لا أزمنة دقيقة موثوقة |
| clock_ref | مطلوب عند true؛ قياسات المزامنة قبل/بعد التجربة |
| clock_offset_ms | مطلوب عند true؛ **ساعة المصدر ناقص ساعة المدير**، موجب حين ساعة المصدر متقدمة |
| clock_uncertainty_ms | مطلوب عند true؛ حد غير سالب؛ >100 ms يترك الزمن TIMING_UNVERIFIED وفق هدف الجاهزية |

كل أوقات `t_source/t_before/t_after` تستخدم ساعة مصدر واحدة في run. عند اختلاف ساعة جهاز/مرحلة أنشئ run أو انتظر دعم timeline متعدد الساعات. مثال القيم وطريقة إنشاء fixtures القابلة للتشغيل في دالتي manifest/trial داخل test_measure.py؛ تلك **بيانات اختبار برمجية فقط** وليست قالباً لنسخ نتائجها إلى الرسالة.

### attempts.jsonl

كائن لكل سطر. حقول مشتركة: run_id، trial_id فريد داخل الجولة، uc = UC-01..08، variant، phase، status. phase = PILOT/MEASURED/BASELINE/SUPPRESSION_CONTROL.

- status المدخل = READY أو BLOCKED/INVALID/INTERFERED/AMBIGUOUS. لا تقبل DETECTED جاهزة كقرار للمشغّل.
- للاستبعاد يلزم reason. لا تُعدّل حالة حدث صحيح إلى BLOCKED بعد فشل الكشف لتحسين النسبة؛ راجع TEST_PLAN.
- READY للكشف يحتاج event_valid=true وsource_ref لإثبات الحدث الإيجابي مستقلًا عن alerts.
- expected_rule_ids قائمة نصوص، expected_levels قائمة أعداد صحيحة 0..16. اختَر التنبيه النهائي قبل التجربة، لا تطلب ظهور الأب والابن معاً.
- target_key كائن dotted-field→exact-value، مثال `{"syscheck.path":"/verified-root/trial-01.txt"}`. لا regex ولا nearest timestamp. للحقول غير المسار يلزم حقلان محددان على الأقل (مثلاً audit serial + PID، أو URL كامل بعلامة المحاولة + source IP). افحص أسماء الحقول الفعلية في PILOT؛ مثال ليس وعداً بأن decoder يوفرها. لا hash-only. لا يكفي عنوان ثابت أو وصف تهديد عام حتى لو اجتاز عدد الحقول.
- window_start وobserve_until وقتان **على مقياس المدير** مُحددان من رصد موثق؛ window_s موجب؛ window_ref يوضح اختيار النافذة قبل القياس. observe_until يغطي deadline على الأقل. UC-04: window_start نهاية المسح (مرساة deadline)، وmatch_start بداية المسح على مقياس المدير إلزامي؛ تُحسب التنبيهات أثناء المسح أيضاً ولا تُصنّف MISSED خطأً. في غيره match_start اختياري وافتراضه window_start؛ يجب ألا يتجاوز مرساة النافذة وأن يغطيه manifest.
- اختياري للتوقيت: t_source، أو t_before/t_after عند غيابه؛ source_precision_ms دقة غير سالبة عند الحساب. استخدم null للمفقود. ISO8601 مع Z أو offset، حتى 6 خانات كسرية؛ أكثر منها يُرفض بدل تقريب صامت.
- أي قيم هوية/إعداد مكررة داخل المحاولة يجب أن تطابق manifest. قواعد/مستويات/نافذة UC/variant في run واحدة لا تتغير بين المحاولات.

source_ref/clock_ref/coverage_ref/config_sha256 بيانات إقرار من المشغّل؛ **النواة لا تفتح هذه المراجع ولا تثبت محتواها أو إعداد المعمل**. hashes المدخلات في التقرير تثبت بايتات ما قُرئ فقط، لا صدق أصلها. لذلك إدخال بيانات المعمل واعتمادها يحتاجان مراجعة بشرية ومحللات/manifest أدلة لاحقة.

### alerts JSONL

كل سطر: id وmanager.name وagent.id وagent.name وrule.id نصوص، rule.level عدد صحيح، timestamp بمنطقة زمنية، والحقول التي يطلبها target_key. لا يُستخدم @timestamp لزمن الظهور. missing/malformed/duplicate JSON keys/non-finite constants/blank lines أخطاء صريحة؛ لا إسقاط صامت لتنبيه قد يكون مهماً. إن كانت سجلات المدير تتضمن صفوفاً لا تستوفي العقد فلا تحذفها بلا سجل؛ أضف adapter مدققاً في استكمال T-11.

التكرار المتطابق عبر rotation يُزال بمفتاح (manager.name,id)، مع حفظ كل مراجع السطر. نفس المعرف عند مديرين مختلفين ليس تكراراً. اختلاف محتوى نفس المفتاح خطأ مُوقِف. أول تنبيه نهائي مطابق داخل الرصد هو المختار، والتنبيه الذي يناسب محاولتين يجعل الربط AMBIGUOUS ولا يذهب للأقرب.

### المخرجات وحدود معناها

- scope = detection_core_only، وقائمة pending_features واضحة. كل محاولة محفوظة حتى المستبعدة؛ BASELINE وUC-01 تظهر NOT_EVALUATED لا نجاحاً وهمياً.
- DETECTED حتى deadline شاملاً؛ التنبيه المتأخر ضمن observe_until = MISSED + late_detected، ويبقى في المقام. ما بعد observe_until لا يدخل هذه التجربة.
- معدل الكشف لكل run/UC/variant = detected/(detected+missed) لمحاولات MEASURED المؤهلة فقط؛ أعداد المستبعدة وأسبابها ظاهرة. PILOT/SUPPRESSION_CONTROL خارج الملخص الأساسي.
- UC-08 MEASURED يتطلب تغطية 930 ثانية سابقة بلا 100051 على المدير؛ هذه بوابة محافظة على مستوى المدير وليست إثباتاً أصلياً لمدى كبت Wazuh. missing lookback = NOT_EVALUATED؛ وجود إطلاق قريب = INTERFERED. changing PID ليس إعادة ضبط.
- source_to_alert = alert - (source - offset). الأزمنة السالبة أو المصدر غير المؤرخ لا تصبح صفراً؛ TIMING_INVALID/UNVERIFIED لا تسقط المحاولة من معدل الكشف.
- مجال الفعل `[alert-after, alert-before]` قد يبدأ بسالب إذا ظهر التنبيه أثناء تنفيذ الفعل؛ INTERVAL_ONLY لا يدخل متوسط الزمن الدقيق.
- mean_source_to_alert_s مع n_timed/median/min/max؛ mttd_s فقط لنوع DETECTION. INTEGRATION ليس MTTD. عند غياب عينات زمنية القيمة null. أرقام JSON حسابية غير منسقة للنشر؛ قرّب العرض وفق precision/uncertainty ولا تعرض كسوراً توحي بدقة غير موجودة.
- الحدود: 2 MiB للسطر أو manifest، 64 MiB لكل مجموعة JSONL، 200000 سجل، و5 ملايين مقارنة journal×alerts. التجاوز خطأ صريح؛ قسّم **جولات كاملة** مع lookback/coverage ولا تقتطع المحاولات الفاشلة.

### المتبقي لإكمال T-11 — ليس اختيارياً

1. استخراج/تحقق أدلة المصدر والوقت والإعداد، بما فيها sanitization وhash manifest ومؤشرات اكتمال rotation؛ عينات JSON فعلية لكل UC.
2. timeline متعدد المراحل يميز trigger/AR completion/manager confirmation/visibility وUC-01 connection؛ مقام AR يشمل trigger بلا اكتمال، وليس الناجحين فقط.
3. baseline adjudication وFP/hour مع union لفترات التعرض المشترك وعدم جمع الساعة مرتين؛ FPR فقط عند توفر TN معرف.
4. اختبارات الشروط الجديدة ومراجعة مستقلة ثم PILOT معملية؛ تهيئة تصدير الرسوم/الجداول للفصل الخامس من أدلة فعلية فقط.

آخر تحقق: 34 اختبار قياس اصطناعي + 19 اختبار أمان = 53 محلياً؛ لا نتائج SOC فعلية.
