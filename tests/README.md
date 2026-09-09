# tests — الاختبارات وعقد القياس

> ASTRA؛ 2026-09-09؛ PR #24. **T-11 IN-PROGRESS** حتى المراجعة وPILOT معملية. عقد v2 وفق MASTER_PLAN v3.1 §5/§9؛ التعارضات ISSUE-050..057. لا نتائج SOC فعلية.

- TEST_PLAN.md: خمس PILOT، ثم30 لكل UC أو عدد أعلى وفق SD؛ baseline≥12h لكل OS/config؛ لا تجميع exposure مرتين.
- SECURITY_REVIEW.md وtest_security.py: حدود الأمن واختبارات محلية، لا native acceptance.
- T-11 IN-PROGRESS: نواة scripts/measure/mttd.py الحالية موثقة أدناه؛ لا طرح timestamp من @timestamp ولا استبدال المفقود بصفر.
- ISSUE-019 لا يغلق بالخطة أو fixtures اصطناعية. النتائج الحقيقية فقط تغذي الفصل الخامس.

```bash
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
bash scripts/validate/validate_all.sh
```

## v2 — العقد الحالي

145 اختباراً محلياً: 123 قياس (بما فيها36 للمشغّل) +22 أمان. التشغيل الاختباري mocks أو Python غير هجومي للنوم/argv، لا هجمات SOC. Python3.9+، stdlib فقط. استخدم CLI الموضح في الملحق لكن **manifest.version=2** و**schema_version=2** في كل محاولة. exit0 يعني اكتمال الحساب لا نجاح التجارب؛ exit2 خطأ إدخال بلا تقرير جزئي.

### manifest

كل run يحفظ حقول الهوية/الإعداد/التغطية الواردة في ملحق v1: run_id، agent_id/name، manager_name، os، config_commit، config_sha256، timing_definition، latency_kind، coverage_start/end/ref. تستبدل حقول الساعة القديمة بـ:

```json
{
  "session_id": "session-unique",
  "devices": {
    "attacker": {"ntp_offset_ms": 0, "uncertainty_ms": 1, "clock_ref": "REPLACE_WITH_REAL_MEASUREMENT"},
    "endpoint": {"ntp_offset_ms": 0, "uncertainty_ms": 1, "clock_ref": "REPLACE_WITH_REAL_MEASUREMENT"},
    "manager": {"ntp_offset_ms": 0, "uncertainty_ms": 1, "clock_ref": "REPLACE_WITH_REAL_MEASUREMENT"},
    "observer": {"ntp_offset_ms": 0, "uncertainty_ms": 1, "clock_ref": "REPLACE_WITH_REAL_MEASUREMENT"}
  },
  "clock_map": {
    "t0": "attacker", "t1": "endpoint", "t2": "manager", "t3": "observer",
    "t4": "endpoint", "t5": "observer", "t6": "manager", "t2_prime": "manager"
  }
}
```

**مقتطف بنيوي فقط، لا manifest كامل ولا قياسات ساعات فعلية.** لا تنسخ الأصفار. كل runs في session تسرد جميع أجهزتها. offset=device−UTC؛ المصحح=timestamp−offset مرة واحدة. أي |offset|>100 في manifest/أي محاولة يرفض جميع محاولات session آلياً، بما فيها السابقة؛ uncertainty>100 يرفض احتياطياً أيضاً (ISSUE-057). ±100 مقبول. الأجهزة والمراجع الناقصة خطأ إدخال.

`planned_n` اختياري بشرط≥30 لكل UC. baseline_rule_ids مطلوب للـbaseline. H4 يضاف إلى manifest:

```json
{"h4_comparisons":[{"hardened_run_id":"hardened", "official_run_id":"official",
 "uc":"UC-03", "variant":"create", "design_ref":"REPLACE_WITH_INDEPENDENT_GROUP_DESIGN"}]}
```

### المحاولة والخرج

- run_id/trial_id/uc/variant وsession_id؛ schema_version=2؛ phase إحدى المراحل الأربع. **exclusion_reason=null أو BLOCKED/INVALID/INTERFERED/AMBIGUOUS** وreason تفصيلي؛ لا status مدخلاً.
- t0..t6 **سبعة** حقول وt2_prime إضافي: epoch ms integer أو null، كلها موجودة. time_refs لغير null وmissing_reasons للمفقود. ntp_offset_ms لكل الأجهزة وpoll_interval_ms=1000. t5 يحتاج completion_kind=independent_observation.
- حافظ على event_valid/source_ref ومفاتيح التنبيه النهائي وwindow_start/match_start/window_s/observe_until/window_ref من عقد الربط السابق؛ UC-04 مرساة الموعد عند نهاية المسح. قواعد الربط exact، لا hash-only ولا nearest. لا تجعل غياب تنبيه الحساس دليلاً على عدم تنفيذ الفعل؛ استخدم إثبات فعل مستقل.
- stage_selectors كائن stage→{rule_ids,levels,target_key}. t2 إلزامي للكشف؛ UC-03: t2=FIM100200/100201 وt2_prime=87105؛ t6 غير null يحتاج selector خام. UC-07: t2 محفز FIM وfinal=108001. لا تغيير stage rules/levels/field names داخل run/UC/variant.
- BASELINE: baseline={start_ms,end_ms,activity_ref,adjudications:[{manager_name,alert_id,is_false_threat_alert,reason,ref}]}؛ true/false/null للحكم. مجالات [start,end) على مقياس المدير؛ union exposure لكل run بلا تكرار. غير المحسوم يمنع fp_upper_95 المنشور.
- scope=v3_measurement_candidate؛ metrics_s له الأسماء الثمانية في TEST_PLAN §4 وD_VT لـUC-03 فقط. المفقود null، والسالب INVALID_ORDER، والمستبعد EXCLUDED. ملخص n/median/q1/q3/iqr/p95/min/max/mean/sd لكل مقياس.
- كلا detection_rate_all_attempts وdetection_rate_valid مع Wilson95% ومقامين مسمّيين؛ مجموعات phase منفصلة. الزمن ملخص شرطي على DETECTED، لا متوسط كل المحاولات. لا legacy source_to_alert_s في خرج v2.
- Poisson upper95% exact fork≥0، MWU greater مع method/Δmedian/p وحكم CALCULATED_NOT_H4_PROOF، وتوصيات PILOT بعد5 عينات صالحة. الصيغ والافتراضات موثقة في TEST_PLAN §4، وplan_math مساعد لا تطبيق MWU.
- hashes للمدخلات والسكربت، وraw stage refs، وrejected_sessions؛ هذه لا تثبت صحة الإقرار بالمصدر/الساعة/اكتمال التغطية. لا تُعد عينات fixtures نتائج معملية.

## trial_runner.sh — واجهة الجمع المحمية

Linux orchestration (fcntl/process groups)، Python stdlib مع `-I -B`. يقرأ سجلات Windows **المصدّرة** لكنه ليس مشغّلاً أصلياً على Windows. حضّر spec ككائن `{"attempt": <attempt-v2-complete>, "source": <optional-adapter>}` وmanifest كاملاً. للمحاكاة البرمجية فقط، مولّد fixtures في manifest_v2/trial_v2 داخل test_measure.py؛ **لا تستخدم هوياتها أو أوقاتها كأدلة حقيقية**.

```bash
bash scripts/measure/trial_runner.sh --help
# قراءة ملفات سابقة فقط: لا يسمح بأمر إطلاق
bash scripts/measure/trial_runner.sh --replay \
  --spec trial-spec.json --manifest manifest.json --output attempts.jsonl \
  --alerts alerts-previous.jsonl alerts-current.jsonl \
  --source source.jsonl --observers observers.jsonl

# معمل معزول مصرح به فقط، بعد مراجعة الأمر وبدء المراقبين:
bash scripts/measure/trial_runner.sh --lab --device attacker \
  --spec trial-spec.json --manifest manifest.json --output attempts.jsonl \
  --alerts alerts-previous.jsonl alerts-current.jsonl \
  --source source.jsonl --observers observers.jsonl --timeout 60 --wait 300 \
  -- /absolute/path/to/reviewed-emulation-script --lab APPROVED_ARGUMENTS
```

الأمر الأخير **قالب لا أمر جاهز للتشغيل**. لا يضيف المشغّل --lab إلى سكربت الهجمة تلقائياً؛ مرره حسب واجهته. وجود --lab ليس بديلاً عن ترخيص الأهداف أو بوابة AR. لا shell/eval؛ secrets في argv ممنوعة لأنها تُحفظ. stdout/stderr للطفل إلى DEVNULL لمنع خرج غير محدود؛ جهّز سجل أدلة مستقل إذا احتجت مخرجاته. timeout/wait بين0 و3600 ثانية، وwait≥window_s. journal خارج FIM في مجلد خاص موثوق؛ ينشأ بصلاحية0600 إذا كان جديداً.

المشغّل يصفر المراحل المستوردة قبل الجمع، ويحافظ على t0 الموثق في replay؛ live يسجل t0 ويعمل fsync لملف pending قبل الإطلاق. يحسب نوافذ المدير من offset، وUC-04 يبدأ match_start عند إطلاق المسح وwindow_start عند نهايته. manifest يغطي كامل المدة المخططة. ينتظر الرصد كله ولو ظهر تنبيه مبكراً، ثم يجمع أدلة الملفات المحددة ويكتب سطر JSONL. --replay لا يخلط تلقائياً بين تشغيل اختبار سابق وتشغيل جديد.

### source adapters

مع --source يلزم source في spec والعكس. أدخل ملفات rotation صراحةً؛ الصادرات JSONL مسطحة لا gzip أو Indexer envelope. اختر correlation مثبتاً فريداً للمحاولة:

```json
{"format":"json", "timestamp_field":"timestamp", "timestamp_unit":"iso8601",
 "target_key":{"flow_id":123,"alert.signature_id":456}, "precision_ms":1}
```

هذا مثال EVE بنيوي، **ليس signature ID معتمداً**. generic JSON يدعم epoch_ms integer باختيار timestamp_unit=epoch_ms. لا تستبدل timestamp الحدث بـmtime. لـaudit: `{ "format":"audit", "serial":"42", "pid":"123", "precision_ms":1 }`؛ serial/PID لا يخمنان قبل الإطلاق، غالباً replay أو مراقب مستقل. لـApache: `{ "format":"apache", "client_ip":"VERIFIED_IP", "request_uri":"/?soc_trial=UNIQUE_ID", "precision_ms":1000 }`؛ يقرأ وقت Apache القياسي بمنطقته الزمنية وURI كاملاً لا substring.

### observers.jsonl

المشغّل **يستورد ولا ينشر أو يشغّل** مراقب inotify/iptables/Indexer. مثال بنيوي لسطر مصدر مؤرخ، بقيم تستبدل بدليل فعلي:

```json
{"run_id":"RUN", "trial_id":"TRIAL", "stage":"t4", "kind":"endpoint_start",
 "timestamp_ms":1788915604000, "device":"endpoint", "precision_ms":1,
 "evidence_ref":"REPLACE_WITH_ACTUAL_ENDPOINT_START_EVIDENCE"}
```

| stage | kind ومعناه |
|---|---|
| t1 | source_event من مراقب مصدر موثق، لا وقت alert |
| t3 | indexer_first_visible؛ poll_interval_ms=1000 وmanager_name/alert_id يطابقان **تنبيه t2 المختار** |
| t4 | endpoint_start؛ علامة بدء فعلية على الوكيل، لا تنبيه trigger لدى المدير |
| t5 | independent_observation؛ اكتمال الفعل من مراقب منفصل مع دليل السببية، لا script_success |
| event | action_confirmed لإثبات حدوث الهجمة/الفعل حتى إذا فشل الحساس في t1؛ لا يملأ t1 تلقائياً |

جميع الأسطر تحمل run/trial/device/timestamp_ms/precision_ms/evidence_ref. t1/t3/t4/t5 يطابق جهازها clock_map؛ تضارب أسطر المرحلة AMBIGUOUS. لا سجل Starting مضمون في AR الحالي: غير المتاح null مع سبب (ISSUE-055)، وt6 لا يستورد من observer بل من alerts.json المطابق.

exit0 = جمع صالح حسابياً وليس DETECTED أو نجاح AR؛ exit2 = رفض/فشل أو استبعاد موثق. الفشل/timeout لا يخفي محاولة: يمكن لحدث مثبت أن يبقى صالحاً ولو خرج الأمر برمز غير صفري. المصدر المفقود مع action_confirmed يبقى MISSED إن لم يظهر تنبيه، ودون أي ground truth يصبح INVALID.

القفل يمنع تزامن الكتابة لنفس journal، وترفض إعادة الهوية والروابط للخرج. pending موجود أو آخر سطر جزئي بعد انقطاع يستلزم مراجعة قبل الاستئناف؛ **لا تمسحه ولا تكرر الهجمة للتعويض**. حفظ الملفات الأصلية وlaunch intent ومراجعة الاستيراد جزء من التدقيق. لا ضمان آلي لاكتمال rotation أو كشف NTP غير المبلغ عنه؛ أعد تحليل الجلسة كاملة بعد قياسات نهايتها.

### UC-03: أسماء EICAR فريدة ومدمجة مع الربط

مرّر `--eicar-dir /home/kali/SOCfile` بدلاً من argv الهجمة، ومعه --lab صريح أو --replay للقراءة فقط. في spec استخدم القيمة النصية `__EICAR_PATH__` في final target `data.virustotal.source.file` وt2 selector `syscheck.path` وt2_prime selector `data.virustotal.source.file` وأي source/path أو t6 path متعلق به. غير UC-03 يرفض. لا تجمع --eicar-dir مع أمر مخصص.

```bash
bash scripts/measure/trial_runner.sh --lab --device attacker \
  --spec uc03-spec.json --manifest manifest.json --output attempts.jsonl \
  --alerts alerts-previous.jsonl alerts-current.jsonl \
  --observers observers.jsonl --eicar-dir /home/kali/SOCfile --wait 420
```

مثال واجهة وليس تفويض تشغيل؛ حضّر أدلة source/observers ونافذة مطابقة أولاً. إن استخدمت source adapter JSON فاستبدل path فيه بالـplaceholder نفسه ومرر --source. يحفظ المشغّل eicar_path وeicar_trial_key قبل الإطلاق: `eicar_<trial-prefix>_<identity-hash>.com`، مشتق بثبات من session/run/trial لتجنب إعادة المسار بين الجولات، وreplay يولد الاسم نفسه. المحتوى لا يتغير؛ الرفض الحصري/no-follow محفوظ. trial_id آمن ASCII حتى64 محرفاً؛ الجذر Linux المقيد نفسه. استخدام السكربت مباشرة يلزم UNIQUE_TRIAL_KEY جديداً عالمياً، لا إعادة استخدامه بعد AR/التنظيف. هذا لا يثبت سلوك keys الحقيقي؛ ISSUE-060 ما زال يحتاج PILOT.

### G2: فحص طابع المدير أولاً

```bash
python3 -B scripts/measure/mttd.py --inspect-alert-timestamps --alerts native-alerts.json
```

لا journal/manifest مع وضع الفحص؛ تقرير hash/أمثلة خام وعدد الخانات لكل manager. هذه أداة فحص **صيغة** لا إثبات accuracy/resolution أو NTP. `.000` لا يثبت ساعة ms ولا ساعة ثانية. اتبع G2-0 في TEST_PLAN: مراجعة native timestamp والإصدار، حفظ الدليل، وتقييد عرض t2/t2_prime/t6 والمقاييس المشتقة عند دقة ثانية أو دقة غير محسومة. لا PILOT أو نتائج أصلية في هذا التسليم (ISSUE-061).

## المتبقي قبل قبول T-11

اعتماد native collectors ودليل الساعة/المصدر/بدء AR/الاكتمال/رؤية API على المعمل؛ UC-01 اتصال؛ مراجعة تقنية وإحصائية مستقلة؛ PILOT n=5، ثم measured وbaseline وفق النتائج؛ مقام نجاح AR الشامل وتصدير النتائج للرسالة من أدلة حقيقية. لا تغيير لسكربتات الأمن ولا ادعاء قبول Windows/Wazuh/YARA بهذه الاختبارات.

## ملحق تاريخي — v1 فقط (PR #20)

الوصف أدناه خاص بـmanifest version=1، محفوظ لإعادة حساب الملفات التاريخية فقط. لا تحويل تلقائي إلى v2؛ اختلاف اصطلاح الساعة/المقامات/الحدود متعمد ومعلن. حالة v2 موضحة أعلاه، وليست قائمة فجوات PR #20 التاريخية.

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

### قائمة الفجوات التاريخية في PR #20 — ليست الحالة الحالية

1. استخراج/تحقق أدلة المصدر والوقت والإعداد، بما فيها sanitization وhash manifest ومؤشرات اكتمال rotation؛ عينات JSON فعلية لكل UC.
2. timeline متعدد المراحل يميز trigger/AR completion/manager confirmation/visibility وUC-01 connection؛ مقام AR يشمل trigger بلا اكتمال، وليس الناجحين فقط.
3. baseline adjudication وFP/hour مع union لفترات التعرض المشترك وعدم جمع الساعة مرتين؛ FPR فقط عند توفر TN معرف.
4. اختبارات الشروط الجديدة ومراجعة مستقلة ثم PILOT معملية؛ تهيئة تصدير الرسوم/الجداول للفصل الخامس من أدلة فعلية فقط.

تحقق PR #20 التاريخي: 34 قياس +19 أمان=53. العدد الحالي موضح في قسم v2؛ لا نتائج SOC فعلية.
