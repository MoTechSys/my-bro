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

## M1 — مراقب ظهور Indexer مستقل (2026-09-18)

التنفيذ `scripts/measure/visibility_observer.py`، الاختبارات `tests/test_visibility_observer.py`. قراءة HTTPS فقط، لا تشغيل هجمة أو AR أو تغيير الإعداد. يعيد استخدام حماية المخزن من `ai_agent/runner.py`؛ لا يستدعي نموذجاً. **هذا مراقب t3 لهوية t2 معروفة، وليس مكتشف t2 تلقائياً أو مراقب t4/t5.** يجب الحصول على manager.name وagent.id وid لتنبيه t2 المختار من دليل المدير الأصلي. قد يصل التنبيه للفهرس قبل بدء هذا المراقب؛ عندئذ يسجل preexisting دون زمن، ولا تُخفى هذه الحالات من نتائج القياس. يلزم مستقبلاً ربط اكتشاف t2 الجاري بالمراقب لتقليل التأخر، دون تزوير سلبية سابقة.

### عقد الإعداد والملفات

أنشئ spec/config خاصين0600 ومجلد عمل جديد0700 خارج FIM وGit في بيئة تشغيل مصرح بها؛ أسلافه مملوكةroot/UIDالحالي وغير قابلة لكتابة المجموعة/الآخرين، بلاsymlink أوhardlink. لا chmod شامل على Wazuh. المفاتيح أدناه **أمثلة بنيوية تستبدل من الدليل**، وليست قياسات/صلاحيات فعلية:

```json
{
  "schema_version": 1,
  "run_id": "RUN_FROM_MANIFEST",
  "trial_id": "TRIAL_FROM_JOURNAL",
  "device": "observer",
  "manager_name": "ACTUAL_MANAGER",
  "agent_id": "ACTUAL_AGENT_ID",
  "alert_id": "ACTUAL_SELECTED_T2_ID",
  "index": "wazuh-alerts-4.x-2026.09.18",
  "seconds": 30,
  "precision_ms": 1,
  "clock_ref": "REPLACE_WITH_ACTUAL_CLOCK_EVIDENCE"
}
```

`seconds` عدد ثوانٍ صحيح2..120؛ فحص أول عند0 وآخر عندseconds (حتى121 طلباً). ينتهي مبكراً عند أول إيجابية أو خطأ، وليس مراقب تعرض baseline. `precision_ms` دقة معلنة لساعة المراقب1..100 وليست دقة تثبتها الأداة؛ لا تنسخ1 بلا دليل. run/trial/device يجب أن تطابق سجل المحاولة وclock_map.t3؛ يتولى trial_runner تحقق الهوية والنافذة. index يومي صريح واحد، لا wildcard أوalias أوauto-discovery؛ **تحقق من اسم الفهرس والإصدار الحقيقي قبل الرصد، ولا تختَر index اعتماداً على ساعة العميل فقط**. عبور منتصف الليل/تغير فهرس/تعدد مجموعات خارج هذا العقد.

ملف config المنفصل، لا يُنسخ إلى مخزن الأدلة:

```json
{
  "schema_version": 1,
  "endpoint": "https://127.0.0.1:9200",
  "username": "PRIVATE_READ_ONLY_USER",
  "password": "PRIVATE_PASSWORD",
  "ca_pem": null
}
```

endpoint أصلHTTPS بعنوانIPv4 حرفي loopback أوRFC1918؛ لاDNS/روابط عامة/userinfo/query/fragment/path. المثال ليس وعداً بوجود Indexer محلي. استخدم حساباً مقيداً للبحث والقراءة في الفهرس المعتمد فقط، **لا admin**. ca_pem إماnull لجذورTLSالافتراضية أوPEMلشهادةCAالمعتمدة داخل configالخاص. يجب أن تطابقSANعنوانIP؛ لا verify=false أوتعطيلفحصالمضيف. لا بيانات اعتماد فيargv أوenv أوURL أوGit. لا proxy أوredirect، والطلبPOST إلى `_search` للقراءة فقط؛ راجع سياسة وصولIndex قبل اعتمادها.

### أوامر التشغيل والاستيراد

```bash
# Offline preview: no config/credentials or network needed.
python3 -I -B scripts/measure/visibility_observer.py preview \
  --spec /approved/private/visibility-spec.json

# Authorized read-only native observation; new empty store only.
python3 -I -B scripts/measure/visibility_observer.py observe --lab \
  --spec /approved/private/visibility-spec.json \
  --config /approved/private/indexer-readonly.json \
  --store /approved/private/visibility-store

# Save the emitted intent_sha256 independently, then export offline.
python3 -I -B scripts/measure/visibility_observer.py export \
  --store /approved/private/visibility-store \
  --intent-sha256 INDEPENDENTLY_RECORDED_INTENT_SHA256
```

احفظJSONLالمصدر إلى ملف جديد خاص (umask077 ومنعoverwrite)، ثم مرره إلى `trial_runner.sh --replay ... --observers FILE` مع دليل المصدر وتنبيهات المدير وبقية spec/manifest. مثال replay الكامل في §trial_runner أعلاه. لا تجمع JSONملخصobserve معobserverJSONL؛ exportفقط يعطي سطرstage=t3. لا تسجل stdoutفيملفداخلstore (مدخلغيرمتوقعيرفضexport). يقبل الاستيراد t3فقط إذاطابقت(manager_name,alert_id) تنبيهt2المختار، وبقيتنافذتهوجهازساعتهصحيحين. لا يراجع trial_runner ملفاتstoreبنفسه؛ **exportالمتحقق هو الحد الفاصل**، وإدخالJSONLمنمصدرآخر يحتاجتدقيقاًمستقلاً.

| الحالة | تصدير t3 | المعنى |
|---|---|---|
| observed | سطر واحد | صفر نتائج صحيح سابق ثم نتيجة واحدة مطابقة |
| preexisting | لا سطر | أول فحص إيجابي؛ أول الظهور سابق/مجهول، لا زمن مختلق |
| not_observed | لا سطر | اكتملت فحوص0..seconds دون نتيجة، لا دليل أن الهجمة MISSED |
| failed أوانقطاع/فساد | رفضexport | احتفظبالنيةوالسجلات؛ سجلt3مفقوداًوالسببفيالمحاولة |

observe exit0للرصدobserved، exit2لـpreexisting/not_observed/failedالمحفوظ. export/preview exit0لنجاحالعملية (قديكونexportفارغاً)، exit1للرفضبرسالةعامة، argparse2، والإلغاء130. لا تعيد المحاولة بنفسstore، ولا تحذفالفاشلةأوتستبدلهابناجحة. عندفشلحفظterminalقديبقىintentجزئياً؛ ممنوع استئناف تلقائي. نسق فقدان الدليل مع سجل المحاولة كي يبقى المقام كاملاً.

### ضمانات الرصد وحدوده

- الاستعلام ثابت: `size=2` و`track_total_hits=true`، وحقول `term` هي id/manager.name/agent.id. يطلب `_source` هذه الحقول فقط. يجب أن تكون total.relation=eq والنتائج صفرًا أو واحدة، وكل shards ناجحة؛ يفشل عند مهلة أو نتيجة ناقصة أو ملتبسة. لا يفسر HTTP403/404 أو JSON تالفاً كسلبية.
- الجدولة كل ثانية على monotonic، بسماح انحراف100ms؛ الفجوة ترفض الرصد. مهلة socket للخمول0.5s، ومؤقت POSIX كلي0.75s يغطي TLS والرؤوس والجسم. يلزم Linux وخيط التنفيذ الرئيسي وSIGALRM افتراضي غير محجوب بلا مؤقت موروث. لا ضمان hard-real-time ضد D-state/SIGKILL أو fsync عالق. لا ينشئ المراقب عمليات تابعة أو خدمة مستمرة.
- timestamp_ms هو وقت ساعة العميل عند اكتمال قراءة أول جواب إيجابي، **ليس @timestamp ولا وقت إدخال الخادم**. يحتفظ بقوس من بداية آخر طلب سلبي إلى نهاية الجواب الإيجابي؛ precision_ms يشمل عرض القوس ودقة الساعة المعلنة. اختلاف wall/monotonic بأكثر من100ms يرفض، لكنه لا يثبت NTP أو دقة المولد. لا تنشر دقة ms لمجرد تمثيلها عددياً.
- النتيجة رؤية هذا العميل لهذا الفهرس؛ replication/cache وفلترة الصلاحيات قد تؤثر. السلبية ليست غياباً مطلقاً من كل replica. يجب تثبيت ظروف التجربة، وعرض حالات preexisting بجانب العينة الموقوتة لأنها قد تسبب انحيازاً عند حذفها من المناقشة.
- يحفظ intent مع fsync قبل الشبكة، ثم رد كل poll (حتى64KiB) وmetadata وبصمته، ثم terminal. الحد الأقصى121 طلباً: نحو7.6MiB للردود دون metadata. ضع حصة كلية لكل التجارب؛ لا يدير السكربت retention بين المخازن.
- يعيد export التحقق من بايتات الردود، والتوقيت، وهوية الاستعلام، وبصمات الكود، وterminal وقائمة الملفات، دون config سري. احتفظ بإصدار الكود الأصلي لاستيراد أدلته؛ لا تعيد كتابة الأرشيف لتقبله نسخة أحدث. نفس UID قد يزوّر حزمة متسقة؛ البصمات ليست توقيعاً أو إثبات هوية خادم أو ساعة.
- لا يطبع الردود أو نصوص أخطاء HTTP أو الأسرار. المخزن خاص لأن الهوية والردود قد تكون حساسة رغم تصغير `_source`. لا ترفع الخام أو الإعدادات أو بيانات الاعتماد إلى Git أو مهام المراجعة.
- يعتمد الملف على ترتيب المستودع `scripts/measure/` و`ai_agent/`؛ ليس ملفاً منفرداً قابلاً للنسخ دون تبعياته. نشره لا يحتاج نسخ `.git` أو الأسرار. هذه الجلسة لم تنشره على مضيف آخر.

مصدر عقد المفاتيح: [Wazuh v4.14.1 template](https://github.com/wazuh/wazuh/blob/v4.14.1/extensions/elasticsearch/7.x/wazuh-template.json)، قرئ في2026-09-18، SHA256 `31a60d5812fb0b5cd7c2d58556b88f57f7fc2f2221dd7b6b32f2256b13ea2886`. الحقول id وmanager.name وagent.id من نوع keyword. هذا لا يتحقق من mapping المنشور. الاختبارات مصطنعة محلياً؛ لا قبول Indexer أو T-11 أو قياس SOC أصلي من نجاحها.

### إصلاح تنظيف عامل التجربة المرتبط — 2026-09-18

أثناء ربط M1 أُعيد إنتاج خطأ في `trial_runner.execute`: كانت `wait` تحصد القائد قبل `killpg`، ما يحرر PID مبكراً. أصبح يستخدم Linux `waitid(WNOWAIT)` ثم يرسل الإشارة للمجموعة قبل الحصد، وينتظر التنظيف حتى ثانيتين مع تأجيل SIGINT/SIGTERM خلاله. فشل التنظيف يرفع WORKER_CLEANUP_FAILED ويسجل مسار المحاولة INVALID؛ لا يدعي نجاح الاستجابة. يلزم SIGCHLD افتراضي وعدم وجود waiter آخر. تظل العمليات التي تغادر المجموعة، وD-state وSIGKILL للوالد، وإعادة حصاد الأحفاد مسؤولية إشراف خارجي. ثلاث regressions إضافية؛ لم نجبر إعادة استخدام PID أو D-state فعلياً.



### تحكيم مراجعة M1 المنفصلة — 2026-09-18

[المهمة d21f2fcc](https://www.genspark.ai/agents?id=d21f2fcc-8a16-5d27-8e73-37253fbd1cde) انتهت: تفتيش ساكن لأربعة ملفات مرفقة عندd850d4e، لا clone أو اختبارات لدى المراجع ولا قبول بشري. نُفذت الاختبارات والتعديلات التالية هنا. لا تُعامل أرقام الخطورة المقترحة كأحكام نهائية دون هذا التحكيم.

| البند | الحكم وما تغير |
|---|---|
| R1 بطء fsync يسبب فجوة | السلوك صحيح: شرط1s/100ms يشمل تكلفة الحفظ؛ الفجوة ليست قياساً صالحاً تحت هذا العقد. رُفض توسيع السماح تعويضاً لبطء التخزين. لا تُحذف الأدلة عند الرفض؛ يحتفظ بها وتبقى المحاولة في المقام. اختيار تخزين مناسب أو تغيير بروتوكول معلن قبل تجربة جديدة، لا قبول انتقائي بعد النتائج. |
| R2 حافة مؤقت الطلب | قُبل إصلاح تنظيف المؤقت: تعطيل أثر handler عند الانتهاء، حجبSIGALRM، disarm وتصريف pending ثم استعادة handler/mask. اختبار يرسلSIGALRM فعلياً عندdisarm تحقق من الاستعادة. رُفض توسيع REQUEST_OVERRUN: الحد المقاس الكلي يظل750ms ولو خرج النقل قبلها بقليل؛ هذا رفض محافظ موثق لا ادعاء أن كل نقل ينتهي عند نفس اللحظة. |
| R3 إشارة أثناءterminal | قُبل حجبSIGINT/SIGTERM خلال حفظterminal/fsync ثم استعادةmask. اختبار فعلي يرسلSIGTERM مرتين داخل الحفظ، ويتحقق من سجل كامل قبل تسليم الإلغاء. الانقطاع أثناء ملفاتpoll أوSIGKILL/انقطاع الطاقة ما زال قد يترك حزمة جزئية مرفوضة، لا تعهد crash-proof. |
| R4 export فارغ لحالتين | لا نغير JSONL الافتراضي لأن trial_runner يستورد صفوفمراقب لاenvelopes. أضيف `export --summary` لإظهار status/observer والبصمات؛ الافتراضي بلاصف عندpreexisting/not_observed. لا يُعتبرexit0 وحده قياسt3. |
| R5 سبب فشل عام | أضيف REQUEST_DEADLINE وقائمة ثابتة لأخطاء الجدولة/الساعة/هويةالجواب/اكتمالالبحث/الحجم. النصوص غير المعروفة تبقى OBSERVATION_FAILED بلا تسريبexception؛ فشل الرصد ليس حكم MISSED علىالهجمة. |
| R6 حسابالقراءةوCA | أضيف principal_sha256 لاسمحسابالقراءة وca_sha256 للشهادةالصريحة وtrust_mode. لا password أوhashلها. البصمات مربوطة بintentالمتوقع وتظهر فيsummary؛ بصمةاسم حساب قابلة للتخمين وليست إخفاءهوية قوياً. system_default لا يجمد حزمةجذورالنظام؛ سجّل إصدارها/سياسةRBAC ضمنmanifestالنشر. لا تحققهويةحسابأوخادممنالبصماتوحدها. |
| ملاحظةclock_refفيالمستهلك | عندما يوجدclock_refفيصفobserver، يجب أن يطابقdevice.clock_refفيmanifest. M1يرسلهدائماً؛ الصفوفالخارجيةالقديمةبدونالحقلتبقىعلىعقدهاالأقدم. اختباررفضالمخالفةواستيرادM1الصحيحناجحان. precisionيشملقوسالرصد، لذا لا نساويهبرقمNTPوحده. |

31 اختباراً للمراقب،127 للقياس،469 إجمالاً ناجحة محلياً. ربط--summary اختياري، لا تمررخرجهإلى--observers. أعلامacceptance تبقىfalse. تمييزالمحاولاتالفاشلةوحفظالمدخلاتلاتغنيانعنمعمل/مزامنة/تحكيمبشري؛ لا تجربةIndexerأصليةفيهذهالجولة.

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

## M2-A — مراقب أدلة المصدر وربطه بالقياس (2026-09-22)

**الحالة:** تنفيذ محلي مع 36 اختبار مصدر، لا قبول أصلي. الكود `scripts/measure/source_observer.py`، والربط في `trial_runner.py`. جميع المخازن والأمثلة هنا خاصة؛ لا ترفع spec أو snapshots الأصلية إلى Git. لا يشغّل المراقب هجمة، ولا يكتب محتوى الملف المستهدف أو ينشئه أو يحذفه. القراءة قد تحدث access time وفق نظام الملفات؛ ليست أداة حفظ جنائي تمنع كل تغيير metadata.

### عقد الإدخال والخصوصية

Linux، عملية CLI رئيسية واحدة، SIGALRM افتراضي وغير محجوب ولا timer قائم، مع ملكية حصرية لمعالجات الإشارات. الجهاز/الساعة معتمدان في manifest، ولا يكفي اسم `clock_ref` لإثبات صحة الساعة.

مثال هيكلي **يجب استبدال placeholders فيه قبل التشغيل**:

```json
{
  "schema_version": 1,
  "run_id": "APPROVED_RUN_ID",
  "trial_id": "UNIQUE_TRIAL_ID",
  "device": "endpoint",
  "clock_ref": "APPROVED_CLOCK_EVIDENCE",
  "directory": "/APPROVED/PRIVATE/TEST_DIRECTORY",
  "filename": "unique_test_file.dat",
  "expected_sha256": "<64 lowercase hex of approved test bytes>",
  "seconds": 30,
  "precision_ms": 1
}
```

- مجلد المصدر موجود وخاصة صلاحياته؛ leaf ملك UID الجاري بلا صلاحيات group/other، وأسلافه ملك root أو UID الجاري وبلا group/other write ولا symlinks. لا تغيّر صلاحيات مسارات Wazuh تلقائياً لتجاوز الرفض؛ عالجها ضمن تصميم المعمل.
- الملف عند ظهوره regular، single-link، ملك UID الجاري، بلا group/other permissions. حد المحتوى 65536 بايت، واسم آمن بطول 1..101، ومجلد absolute canonical. seconds integer2..120، precision_ms integer1..100؛ bool مرفوض.
- مدة poll كل 1s، jitter مقبول 100ms، سقف قراءة شامل 750ms بمؤقت POSIX. تغير wall/monotonic غير المتوافق أو التأخر أو محتوى خاطئ أو رابط/FIFO أو تبديل هوية الملف يفشل مغلقاً. لا retries لانتظار استقرار ملف بدأ بمحتوى غير متوقع.
- مخزن الأدلة موجود وفارغ وخاص 0700، منفصل عن شجرة المصدر في الاتجاهين؛ artifacts0600. لا تسمح aliases عبر bind mounts أو كاتب غير موثوق بنفس UID. تخزين الأدلة خارج monitored paths مسؤولية المشغّل أيضاً.
- `expected_sha256` لبايتات ملف الاختبار المخطط، وليس raw logs اعتباطية. يحتفظ المخزن بنسخة البايتات الفعلية؛ يلزم retention/ACL وحصة مساحة ومراجعة للخصوصية قبل القبول الحي.

### التحضير والتشغيل والتصدير

الأوامر التالية من جذر مستودع SOC. المتغيرات تشير إلى **مسارات خاصة معتمدة**؛ لا تُشغّل observe على معمل دون التفويض والبوابات. أعد المجلدات و spec الخاص مسبقاً وفق العقد، ولا تستخدم `.git` لحفظ أدلة التشغيل.

```bash
python3 -B scripts/measure/source_observer.py preview --spec "$SOURCE_SPEC"
python3 -B scripts/measure/source_observer.py observe --lab --spec "$SOURCE_SPEC" --store "$SOURCE_STORE"
python3 -B scripts/measure/source_observer.py export --store "$SOURCE_STORE" --intent-sha256 "$INTENT_SHA256" --summary
```

1. preview لا يقرأ المصدر؛ يعيد `source_spec_sha256` و`target_key`. بصمة spec لتمثيل JSON canonical (`r.json_bytes`) بعد التحقق، لا لمسافات الملف الأصلي. سجلهما في `attempt.source_binding` قبل الفعل، وثبت manifest وهوية trial ومساراً لا يعاد استخدامه بين التجارب.
2. ابدأ المراقب **قبل** فعل الاختبار في عملية مستقلة تحت إشراف المشغّل. intent يحفظ قبل قراءة المصدر؛ انتظر السلبية الأولى المنشورة قبل إطلاق الفعل المعتمد. لا يكفي أن تكون العملية قد بدأت، ولا تسجل سلبية تخمينية إن كان الملف قد ظهر.
3. احتفظ خارج المخزن ببصمة **بايتات intent.json الأصلية**؛ يمكنك الحصول عليها أثناء التشغيل بعد النشر أو من نتيجة observe. لا تعِد حساب قيمة ثقة جديدة من مخزن مشكوك فيه لتجاوز رفض importer.
4. observe يعيد 0 عند observed و 2 عند failed/preexisting/not_observed؛ الإلغاء CLI يعيد 130. أخطاء الإدخال/المخزن ترفض برمز 1. خروج 0 هنا يثبت عقد الرصد فقط، لا الكشف أو AR.
5. export العادي يعطي صف JSONL فقط عند observed؛ لا صف عند preexisting/not_observed. `--summary` يوضح الحالة؛ عند failed أو intent بلا terminal يعطي `artifacts_verified=false` و observer=null، وليس فحصاً جزئياً ناجحاً. terminal تالف يُرفض ولا يتحول تلقائياً إلى فشل موثوق.

المخزن: `intent.json` يحوي spec وبصمات الكود، ثم `poll-NNN.json` للتوقيت/الهوية والسلبية أو الإيجابية، و`poll-NNN.bin` عند وجود محتوى، ثم `terminal.json`. fsync للملف والدليل بعد كل نشر، وقفل nonblocking على inode الدليل. الفشل أو snapshot جزئي يبقي الأصل دون overwrite. التصدير لا يفتح المصدر أو الشبكة، لكنه يقرأ الكود الحالي لمقارنة البصمات؛ الأرشيف القديم يحتاج نسخته الأصلية من الكود.

### ربط محاولة القياس

إضافة إلى attempt ذي schema_version2 المعتمد، أضف:

```json
"source_binding": {
  "source_spec_sha256": "<canonical hash returned by preview>",
  "target_key": {"syscheck.path": "/APPROVED/PRIVATE/TEST_DIRECTORY/unique_test_file.dat"}
}
```

الربط الحالي مخصص لملف: يجب أن يطابق `stage_selectors.t2.target_key.syscheck.path`، وأي حقول path معروفة في target_key وبقية stage selectors. `device == clock_map.t1` و clock_ref مطابقان للـ manifest؛ run_id/trial_id يطابقان المحاولة. مع `--eicar-dir` يجب إعداد المسار المولد الفريد نفسه، لا نقل placeholder إلى binding.

```bash
python3 -B scripts/measure/trial_runner.py --replay \
  --spec "$TRIAL_SPEC" --manifest "$MANIFEST" --alerts "$ALERT_EXPORT" \
  --source-store "$SOURCE_STORE" --source-intent-sha256 "$INTENT_SHA256" \
  --output "$ATTEMPTS_JOURNAL"
```

- journal داخل parent خاص موثوق؛ لا يكون داخل مخزن المصدر أو alias لأي input. live يبقى `--lab` واختيار أمر مستقل معتمَد، ولا يبدأ المراقب ضمنياً.
- `--source-store` و`--source-intent-sha256` مطلوبان معاً؛ binding دون مخزن يرفض. importer يقرأ snapshots ويعيد حساب البايتات والهوية والتوقيت، ولا يثق بصف JSONL موسوم `soc-source-file-v1` وحده.
- صفوف legacy للمراقبين تبقى operator-supplied، ليست مصادقة مستقلة. clock_ref إن قُدم يتحقق حتى لمرحلة event. عند binding لا يسمح لصف legacy event آخر للمحاولة نفسها أن يستبدل الدليل. صفوف تجارب أخرى في ملفات rotation تُتجاهل بعد فحص JSON، ولا تسبب تعارضاً غير متعلق بالهوية.
- event الصحيح داخل نافذة القياس يجعل event_valid=true **دون ملء t1**. إذا غاب تنبيه الحساس يبقى MISSED في المقام، لا INVALID بسبب غياب الحساس وحده. غياب دليل المصدر أو فساده لا يصبح MISSED آلياً؛ يحتفظ runner بمحاولة مستبعدة/فاشلة وبسببها.
- أول poll إيجابي يعطي preexisting بلا event. التوقيت المصدّر هو نهاية الرصد الإيجابي مع القوس من بداية السلبية السابقة والدقة المحافظة، **ليس لحظة إنشاء الملف أو هوية الكاتب**. الربط يثبت ملف المحاولة المعلن لا أن AR تسبب بوجوده/اختفائه؛ لا ت 1/t4/t5 أو زمن مصدر مختلق.

### استعادة الانقطاع وحدود الديمومة

- source intent بلا terminal: summary فشل منقطع، ولا event أو إعادة رصد بنفس المخزن. لا تزيل الملفات ولا تصلح hashes. صفوف ناجحة يعاد بناؤها من snapshots؛ ملفات إضافية/ناقصة/متغيرة ترفض.
- trial journal: اسم journal و pending يزامنان في الدليل قبل الإطلاق، وبعد كتابة السطر ومحو pending. فشل sync قبل الإطلاق يمنع الأمر ويبقي النية. SIGINT/SIGTERM عند Popen يؤجلان حتى امتلاك الكائن ثم killpg قبل reap؛ cleanup محدود 2s. الإلغاء خارج المنطقة الداخلية يعطي 130 ويحفظ pending؛ داخلها يسجل failure وفق العقد الموجود.
- `.pending` سابق يمنع كل كتابة جديدة إلى journal نفسه عمداً حتى المراجعة. **لا تمسحه، ولا تعِد الهجمة، ولا تعتبر عدم وجود صف دليلاً على عدم الإطلاق.** راجع وجود عملية باقية عبر المشرف الموثوق، لا عبر PID قديم وحده؛ احفظ journal و pending ومدخلات manifest/spec الأصلية وبصماتها في موقع خاص خارج Git. تحقق من اكتمال آخر سطر ومن عدم وجود الهوية بالفعل في journal قبل بناء سجل فشل مشتق منفصل. لا تعيد كتابة الأصل أو دمج سطر جزئي؛ وثق أن pending لا يثبت هل نُفذ الأمر فعلياً ولا زمن خروجه. الاستعادة الآلية والتحقق من نسخها وربطها بالتقرير الكامل **LOCAL_PENDING**؛ هذه خطوات مراجعة يدوية وليست أداة استعادة منفذة.
- timeout يعني أن المشغّل **لم يلاحظ الخروج قبل deadline**، لا أنه قاس لحظة خروج العملية. قد تخرج العملية قرب الحد بين poll ين؛ لا نستبدل هذه الحالة برمز 0 لاحق ثم نزعم خروجاً ضمن المهلة. startup/cleanup/fsync وجدولة OS ليست hard-real-time.
- SIGKILL/power-loss/D-state ونسل يغادر process group، دقة الساعة، سلامة filesystem و ACL ومشرف init، وصدق المشغّل/كاتب بنفس UID خارج الضمان. اختبارات fault injection ليست اختبارات انقطاع طاقة.
- عدم تناظر مقصود حالياً: source export --summary يعرض فشل غير متحقق الأجزاء؛ M1 visibility export يرفض terminal ذي reason حتى مع summary. لا تتوقع واجهة تعافٍ متطابقة أو تعمم سلوك أحدهما على الآخر.

### تحكيم المراجعة المستقلة d1598bba

المهمة [d1598bba](https://www.genspark.ai/agents?id=d1598bba-abfd-5ef1-bb04-3f2c4ff797c1) منتهية فعلياً؛ نطاقها لقطة 2a50f77 ونص خمسة ملفات مع runner1–190. المراجع لم ينفذ اختبارات. النص الأصلي و JSON في `research/inbox/2026-09-22_m2_review_result.*`. الحكم التالي للمنفذ مدعوم بالفحوص، وليس شهادة من المراجع على الإصلاحات اللاحقة.

| البند | الحكم والأدلة |
|---|---|
| F1 إطلاق Popen | مقبول ومُعاد الإنتاج بطفل Python حقيقي؛ d632a2c أصلح نافذة الإلغاء، وأربع حالات SIGINT/SIGTERM تتحقق من kill/reap واستعادة المعالج. |
| F2 pending والإلغاء الخارجي | جزئي: pending يتعمد منع rerun وكانت قاعدة الاحتفاظ موثقة مسبقاً؛ لا يعالج بحذف تلقائي. أضيف خروج 130 ورسالة محدودة مع بقاء النية واختبار عدم overwrite. الاستعادة الآلية مازالت LOCAL_PENDING/ISSUE-097. |
| F3 خروج قرب deadline | نرفض تحويل timeout إلى نجاح استناداً إلى wait بعد انتهاء المهلة؛ لا يثبت زمن الخروج. الحد هو موعد ملاحظة الخروج، لا توقيت kernel. قيد دقة polling موثق أعلاه؛ لا نزعم معرفة ما حدث قبل deadline من رمز cleanup. |
| F4 تعارض صفوف تجارب أخرى | مقبول: الدالة القديمة 0c6b2d0 رفضت صفاً غير متعلق بـ SOURCE_STORE_REQUIRED، والحالية تقبل الدليل المرتبط وتتجاهل صفوف الهوية الأخرى. إصلاح 67ae769 واختبار rotation. |
| F5 غياب window_start بعد استبعاد الساعة | المثال المقدم غير قابل للوصول عبر CLI كما وصف: preflight في m.analyze_v2/validate_trial يطلب نافذة صالحة قبل الإطلاق. الاختبار الموجود يحفظ SESSION_CLOCK_LIMIT_EXCEEDED ويمنع الأمر. لا نعدل collect لفرضية تتجاهل preflight؛ فساد مدخلات آخر قد يسجل فشلاً صريحاً. |
| F6 fsync للدليل | مقبول في جوهره؛ وصف المراجع لـ pending بأنه write_once غير دقيق، إذ كان secure_open/write_all. أضيف sync_parent بعد نشر pending وقبل الأمر وبعد unlink، مع فحص parent خاص. اختبارات ترتيب ومزامنة واصف الدليل وفشل sync موجودة، دون ادعاء اختبار انقطاع طاقة. |
| F7 analyst socket timeout | قيد صحيح موثق أصلاً في UC-14؛ المسار المباشر لا يملك مهلة العامل تلقائياً. استخدم runner لجمع أدلة C4 المحدودة؛ لا ندعي منع التنقيط في المسار المباشر. |
| F8 اختلاف summary بين M1 و M2 | توضيح مقبول، موثق أعلاه. كلا المسارين يمنع إنتاج event/t3 من فشل، ولم تُغيّر واجهة M1. |

تدقيق ذاتي إضافي لا ننسبه للمراجع:959deea يغلق fd داخل الاستدعاء الموقّت. اختبار العودة من timed call فشل فعلياً على الدالة القديمة 3a5850d ونجح على الجديدة، مع تنظيف الواصف في الاختبار السلبي. يبقى محدوداً بنافذة العودة المختبرة، لا كل سباقات الإشارات في المكتبات.

**بوابة الإغلاق:**545 اختباراً محلياً على e8aef17، وتحقق CI للرأس النهائي في PR28. منها 36 للمصدر و 134 للقياس و 75 للـ runner. المراجعة الساكنة المستقلة محكّمة، لكنها ليست قبولاً حياً أو مراجعة إحصائية بشرية. M2-B/t4/t5 و M3/UC-01 ومقام AR و pending recovery و D1 مازالت أعمالاً محلية؛ لا تعاود بناء M2-A بدلاً عنها.

## استعادة pending إلى سجل متابعة خاص — 2026-09-23

**منفذ محلياً:** `scripts/measure/recovery.py` مع 46 اختباراً. هذه استعادة offline لا تشغّل أمراً، ولا تحذف pending أو تعدّل journal الأصلي. لا تحاول إثبات موت عملية من PID محفوظ. `--operator-stopped` تصريح من المشغّل بعد فحصه المستقل، وليس فحصاً آلياً؛ يبقى `process_cleanup_verified=false`.

### العقود

- يحتاج journal وملف `journal.pending` المجاور و manifest، مع SHA256 خارجي لكل ملف. الملفات regular أحادية الرابط، ملك UID الجاري، بلا group/other permissions؛ parent خاص 0700 وأسلاف موثوقة بلا symlinks. يرفض symlink و FIFO والروابط المتعددة والملفات العامة.
- تؤخذ نسخة من journal تحت قفل flock غير منتظر متوافق مع trial_runner، وتتحقق هوية الواصف والاسم قبل القراءة وبعدها. manifest و pending بلا قفل مستقل؛ شرط توقف الكاتب وصدق المشغّل وحدود same-UID صريحة.
- حد كل مدخل 2MiB، وحد كل JSONL20000 سطر، وخرج مشتق حتى 4MiB وفق حد storage الحالي. السطر الجزئي أو JSON التالف أوهوية متكررة يرفض كله؛ لا إسقاط لأسطر مجهولة أوضمّها إلى سطر جديد.
- منذ c954e95، pending يثبت بصمة manifest الكانونية؛ منذ a59f594 يثبت أيضاً مسار journal وطول وبصمة كامل البادئة الموجودة قبل المحاولة، تحت القفل. يتحقق importer من هذه العلاقة لا من hashes منفصلة فقط. يسمح بعد البادئة بصفر أوصف نهائي واحد مطابق للمحاولة؛ تقليص البادئة أوتغييرها أوإضافة صف غير متعلق يرفض.
- pending أقدم يفتقر إلى أحد الربطين يحتاج `--allow-legacy-unbound` صراحة، وتظهر قوة الربط كـ`operator_pinned_legacy`. العلم يخص نقص binding في **schema_version2/manifest.version2** فقط؛ لا يرقّي صيغة v1 ولا يثبت أن manifest استُعمل تاريخياً.
- إن لم تكن المحاولة في journal، يُلحق صف مشتق واحد بحالة INVALID وسبب INTERRUPTED_AFTER_PREPARED_INTENT، أويحفظ الاستبعاد المسبق وسببه. يحتفظ t0 الأصلي فقط؛ t1..t6 و exit_code و timed_out و execution_started لا تُختلق. النافذة الموروثة معلنة `predeclared_not_observed`.
- إن كان الصف النهائي منشوراً بالفعل، يتحقق من هوية المحاولة وإعداداتها و t0 و runner، ثم يحفظ journal **ببايتاته نفسها** دون استبدال الصف أوتكراره. ينطبق ذلك على COLLECTED و COLLECTION_FAILED و COLLECTION_INTERRUPTED و RECOVERED_INTERRUPTED وفق شروطها.
- السجل المشتق يحتفظ بجميع المحاولات السابقة؛ لا تجمعه مرة أخرى مع الأصل لأن ذلك يكرر المقام. أداة mttd هي التي تحلل هذا السجل الكامل مع تصديرات التنبيهات الأصلية. recovery لا يقرأ التنبيهات ولا ينشر تقرير دقة/كشف؛ استعمال analyze_v2 داخله للتحقق فقط.

### التشغيل

المسارات التالية يحددها المشغّل داخل موقع خاص معتمد. أوقف الكاتب وتحقق من بقاء الأبناء عبر المشرف المعتمد أولاً، واحفظ hashes خارج المخزن. لا تمرر ملفاً خاماً حساساً في Git.

```bash
python3 -B scripts/measure/recovery.py recover \
  --journal "$ORIGINAL_JOURNAL" --manifest "$MANIFEST" --store "$RECOVERY_STORE" \
  --journal-sha256 "$JOURNAL_HASH" --pending-sha256 "$PENDING_HASH" \
  --manifest-sha256 "$MANIFEST_HASH" --operator-stopped

python3 -B scripts/measure/recovery.py export \
  --store "$RECOVERY_STORE" --intent-sha256 "$RECOVERY_INTENT_HASH" --summary

python3 -B scripts/measure/recovery.py export \
  --store "$RECOVERY_STORE" --intent-sha256 "$RECOVERY_INTENT_HASH" \
  --output "$NEW_CONTINUATION_JOURNAL"
```

المخزن يجب أن يكون جديداً وفارغاً وخاصاً. `--output` ينشئ ملفاً0600 حصرياً ويزامن الملف والدليل؛ يرفض الأصل و manifest و pending ومخزن الاستعادة وأي destination له pending. **استخدم هذا الخيار بدلاً من shell redirection فوق ملف قائم.** تابع التجارب الجديدة فقط على سجل المتابعة، بهويات جديدة؛ اختبار CLI يثبت أن الهوية المستعادة لا تعاد وأن المقام يتزايد دون إسقاطها. الأصل و pending يبقيان للأرشفة الخاصة ولا يحذفان.

نجاح recover/export يعني بناء أثر مشتق متحقق، لا نجاح التجربة. exit0 للمكتمل،2 للمحاولة المسجلة كفشل،1 لرفض الإدخال/الاستيراد؛ argparse قد يعطي 2 للخيارات الناقصة، والإلغاء 130. أخطاء القراءة/التحقق تسجل RECOVERY_REJECTED؛ الأعطال الداخلية غير المتوقعة RECOVERY_INTERNAL_ERROR بلا نص استثناء حر.

### ديمومة المخزن واستيراده

`intent.json` ثم لقطات `journal.jsonl` و`pending.json` و`manifest.json`، ثم `attempts.jsonl` و`terminal.json`. intent يثبت pins والكود ومسارات المصدر وتصريح توقف المشغّل. كل نشر write_once مع fsync للملف والدليل. لا retry أو overwrite لمخزن جزئي؛ إذا غاب terminal أوكان failed يعرض summary فشلاً و`artifacts_verified=false` ولا ينتج سجل متابعة. terminal تالف أو artifact زائد أوبصمة مختلفة يرفض. export يعيد خطة الاستعادة من اللقطات ويقارن النتيجة والبايتات معاً دون فتح الأصل.

كل إصدار كود مثبت ببصماته؛ استيراد مخزن قديم يحتاج نسخته الأصلية من الكود. المسارات والـ argv الموجودة في آثار الاستعادة خاصة ولا ترفع إلى Git. حدود SIGKILL و D-state وصدق المشغّل و ACL و mount aliases وعدم أصالة hashes باقية. حدالحجم رفض صريح لا مبرر لحذف الأقدم من المقام.

تغيير سلوك الإلغاء في trial_runner: الإلغاء داخل التنفيذ/الجمع يسجل COLLECTION_INTERRUPTED وسبباً محدوداً، يحتفظ pending ويعيد 130. إن نجح نشر الصف قبل الانقطاع، recovery يتعرف عليه كـ already_recorded. الفشل العادي يبقى COLLECTION_FAILED وفق العقد السابق.

### تحكيم المراجعة المستقلة 66ea9527

المهمة [66ea9527](https://www.genspark.ai/agents?id=66ea9527-804b-5057-b138-2cfcf7756369) انتهت فعلياً؛ التقرير الأصلي والنص في `research/inbox/2026-09-23_recovery_review_result.*`. راجع المراجع النص المرسل عند 724433c، ولم يجلب الشجرة أوينفذ الاختبارات. الإضافات اللاحقة، ومنها `--output` و pipeline الرسالة، ليست مشمولة بأثر رجعي.

| البند | التحكيم |
|---|---|
| P1-1 الإلغاء الداخلي | تحسين مقبول: السلوك القديم لم يفقد المقام إذا نُشر صف الفشل، لكنه حذف pending وخلط الإلغاء بالخطأ العام.62636cc يميز الإلغاء ويحفظ pending ويعيد 130، مع اختبار مسار حقيقي واستعادة بلا تكرار. لا نستخدم عبارة «بعد التنفيذ» لأن الإلغاء قد يحدث أثناءه. |
| P1-2 ASCII و newline | مرفوض بدليل: analyst.encoded يستخدم ensure_ascii=True ولا يضيف LF؛ runner.json_bytes يضيف LF واحداً. اختبار مسار دليل عربي يثبت round-trip والاستيراد الصحيح. لا نغيّر encoding بناء على فرضية اعتماد غائب. |
| P1-3 pending↔journal | مقبول كتقوية فعلية: أضيف ربط مسار وبصمة وطول البادئة، لا startswith على time_ref وحده. اختبارات تغيير/فقد البادئة والمسار واللاحقة غير المتعلقة ترفض حتى مع pins جديدة. القديم لا يقبل إلا بوضع legacy صريح. |
| P2-1 حدود الحجم | الثوابت الحالية معلومة: مدخل 2MiB و storage4MiB؛ الخرج يتحقق قبل النشر. الحدود متعمدة ومعلنة؛ المخزن فوقها يرفض ولا يقص. ليست فجوة مثبتة من افتراض قيمة اعتماد لم يُقرأ. |
| P2-2 التشخيص | عولج بتمييز RECOVERY_INTERNAL_ERROR عن رفض الإدخال/IO، مع اختبار عدم تسريب payload الاستثناء. |
| P2-3 فحص pending حتى already_recorded | مقصود: لا يجوز لوجود صف منشور أن يسمح بتجاوز فساد النية التي نعلن التحقق منها. الفحص لا يستبدل الصف ولا ينشر مقاييس زائفة. |
| P2-4 تداخل المسارات | لا يُسمح للمدخل أن يكون داخل store. الاتجاه المعاكس يعني جعل ملف regular أباً للدليل، وهو غير صالح؛ يبقى parent مشترك مع أخوة ملفات مسموحاً. لا ادعاء عزل mount aliases. |
| P2-5 تغير الكود | سلوك مثبت ومعلن: استعمل الإصدار الأصلي للأرشيف ولا تعدّل hashes. تشخيص قائمة الملفات المتغيرة تحسين لاحق، لا نطبعه كبيانات غير محدودة. |
| P2-6 argparse | فرق واجهة موثق: نقص flags يعطي usage/2؛ أخطاء التنفيذ المحدودة JSON/1 أو 2. لا نساوي أخطاء syntax بمحاولة مسجلة. |
| P2-7 توقف الكاتب | شرط مشغّل لا ادعاء كشف آلي؛ قفل journal يمنع الكاتب المتعاون ولا يثبت موت ذرية العملية أوتوقف same-UID writer. |
| P2-8 الخصوصية | متفق عليه: الآثار والمسارات والـ argv خاصة، لا Git أونشر عام؛ ملفات 0600 وأدلة 0700. |
| P2-9 pending فارغ | فرضية IndexError مرفوضة: rows(single=True) يتحقق من عدد 1 قبل [0]. أضيف اختبار الفارغ والسطرين ويثبت INPUT_ROW_COUNT. |
| P2-10 legacy | موضح صراحة: نقص binding فقط ضمن v2؛ لا استعادة صيغة v1 أوترقية صامتة. |

اختبارات الاستعادة 46، والمصدر 37، وبناء الرسالة 13؛605 إجمالاً محلياً عند 68d4e1e. ليست اختبارات انقطاع طاقة أوقبول SOC. t4/t5 و UC-01 ومقام AR الشامل مازالت أعمالاً محلية مستقلة.


## AR — سياسة أدلة الاستجابة الاختيارية (2026-09-23)

أضيفت في `mttd.py` بوابة opt-in فقط لـUC-03 وUC-07. يظل manifest.version=2 والعقد القديم صالحًا بلا سياسة؛ غيابها ينتج `POLICY_NOT_DECLARED` ونسبًا null، لا فشلًا صفريًا ولا نجاحًا. **لم يُنفذ منتج t4 أوt5، ولم تُثبت سببية الاستجابة.** اختبارات `test_ar_denominator.py` اصطناعية، لا بيانات تجربة.

مقتطف يضاف إلى run واحد في manifest كامل؛ قيمه تعليمية وليست قياسات أو نافذة معتمدة:

```json
{
  "ar_policies": {
    "UC-03": {
      "window_s": 120,
      "precision_ms": {"t0": 1000, "trigger": 1000, "t4": 1000, "t5": 1000},
      "protocol_ref": "REPLACE_WITH_PREDECLARED_REVIEWED_PROTOCOL",
      "independent_trials": false
    }
  }
}
```

- يسمح بمفتاحيUC-03 وUC-07 فقط (أحدهما أوكلاهما)، ولكل سياسة هذه الحقول الأربعة بالضبط. `window_s` عدد صحيح1..3600، وكل precision عدد صحيح1..60000 ويمثل حد±محافظًا بالميلي ثانية؛ boolean ليس عددًا صالحًا. الاستقلال boolean ومرجع البروتوكول نص غير فارغ. `{}` لا يفعلAR لأيUC.
- ثبّت سياسة على مستوىrun قبل القياس؛ لا توجد سياسة override للمحاولة. لا تختر نافذة/دقة بعد رؤية النتائج. النصprotocol_ref لا يثبت التسجيل المسبق؛ احتفظ بنسخة مؤرخة معتمدة خارج مخرجات الحساب. هذه ليست دقة ±1ms ضمنية؛ precision يضاف إلى uncertainty الجهاز، ويطرح offset=device−UTC مرة واحدة.
- المحفزUC-03 هو `t2_prime` منVT87105، لاFIM؛ UC-07 هو`t2` منFIM. `stage_alert_refs` الخام مطلوبة؛ timestamp مصرح وحده لا يكفي. لا يملأt6 أوexit0 قيمةt5.
- التغطية يجب أن تستمر حتى نهاية نافذةAR كلها، حتى مع اكتمال مبكر. تنقص uncertainty المدير منobserve_until المصحح، وتضاف uncertainty/precision المحفز إلى بداية الموعد. هذا شرط بروتوكول محافظ وليس قولًا إن الاكتمال المبكر لم يحدث.
- ترتيبt0≤trigger≤t4≤t5 مطلوب؛ الانعكاس الاسمي INVALID_TIMELINE والتداخل ضمن حدود الخطأTIMING_UNCERTAIN. interval للاكتمال = (t5−trigger)±(خطأt5+خطأtrigger). high≤window يعنيCOMPLETED_WITHIN_WINDOW، low>window يعنيCOMPLETED_LATE، والتقاطعTIMING_UNCERTAIN.
- other states: EXCLUDED، NO_TRIGGER_OBSERVED، UNBOUND_RESPONSE_EVIDENCE، MISSING_LAUNCH_TIMESTAMP، OBSERVATION_INCOMPLETE، COMPLETION_WITHOUT_START، NO_START_OBSERVED، NO_COMPLETION_OBSERVED، OUTSIDE_OBSERVATION. هذه حالات **أدلة** وليست إثبات عدم حدوث فعل. BASELINE/non-AR →NOT_APPLICABLE؛ لا ملخصAR للـbaseline.

### المقامات والقراءة الصحيحة

لكل `(run_id, uc, variant, phase)` يبقى **جميع ما سُجل** في `denominator_all_recorded_attempts`، بما فيهBLOCKED/INVALID/INTERFERED/AMBIGUOUS والمفقود. البسط فقطCOMPLETED_WITHIN_WINDOW. المفقود من الخطة لا يُختلق من التنبيهات؛ راجعintent/pending/recovery واكتمال الجمع منفصلًا قبل النشر. لا تخلط PILOT وMEASURED أوالمتغيرات والأنظمة.

`denominator_observed_triggers` و`documented_completion_rate_triggered_only` مقام/نسبة ثانويان **للمحفزات التي اجتازت بوابات الاستبعاد**؛ لا يدعيان إحصاء كل محفز في الجهاز. الصف المستبعد لا يُعد محفزه مقبولًا، حتى لو تضمن refs تشخيصية قبل استبعاده. لا تستخدم هذه النسبة الشرطية بدل المقام الشامل.

حالة الكشف منفصلة: قد يبقىUC-07 MISSED لعدم وجود108001 بينما توجد أدلة supplied على اكتمال الفحص. لا تستنتج اكتشاف برمجية خبيثة من اكتمال الفحص. `completion_from_trigger_s` و`execution_s` وصفيان لصفوفCOMPLETED_WITHIN_WINDOW/LATE، **لا يشترطانDETECTED**؛ الملخصات القديمةmetrics_s تحتفظ بشرطDETECTED. المقاييس القديمةL_AR_trigger=t4−t2 لا تتغير؛ معيار مهلةUC-03 الجديد يبدأVT، فلا تخلط الاسمين.

Wilson محجوب افتراضيًا، ولا يظهر إلا مع`independent_trials=true`؛ يظل `independence_verified=false` ويحتاج الاستقلال والتجانس مراجعة تصميم. أعلام`causality_authenticated=false` و`acceptance_approved=false` ثابتة؛ لا حق للمستخدم بتغييرها بتحريرpolicy. `completion_kind=independent_observation` شرط schema لا تصديق للشاهد أوالسببية.

واجهة الحساب نفسها، على **نسخ خاصة مصرح بها**، لا على مخازن التشغيل الحية:

```bash
python3 -B scripts/measure/mttd.py --manifest PRIVATE_MANIFEST.json   --journal PRIVATE_ATTEMPTS.jsonl --alerts PRIVATE_ALERTS.jsonl
python3 -B -m unittest discover -s tests -p test_ar_denominator.py
```

لا تشغل المثال بأسماء وهمية كأنها بيانات. CLI يرفض journal فارغًا؛ الواجهة الداخلية analyze_v2([],[],manifest) لا تختلق صفوفًا. لا رفع لسجلات خام/هويات/مفاتيح إلىGit أوحزمة الكاتب. مراجعة46bbb5ff للقطة5bd2feb انتهت وحُكمت أدناه؛ لا تعاد. لا اعتماد بشري أوnative.


### تحكيم مراجعة AR المستقلة — 2026-09-23

[46bbb5ff](https://www.genspark.ai/agents?id=46bbb5ff-865c-58c0-b6bb-9cb17585df6e) مراجعة **آلية ساكنة** للنص المرسل عند5bd2feb. لم يتمكن المراجع من فتح checkout لديه، ولم يشغّل الاختبارات؛ تقريره يصرح بذلك. الأصل الكامل في `research/inbox/2026-09-23_ar_review_result.json`. أُعيد التحقق محليًا من الملاحظات؛ ليس هذا اعتمادًا بشريًا أو قبولًا أصليًا.

| البند | الحكم والإجراء | دليل الاختبار والحد |
|---|---|---|
| F1 اختلاف offset المحاولة عن run | السلوك قابل للإعادة، لكنه عقد v2 المقصود: تصحيح كل محاولة بقياسها الخاص، وفحص حدود المجموعتين. لم نفرض مساواة صامتة تمنع قياسات متجددة | اختبار99ms يثبت انقلاب حالة حد المهلة؛ أضيف clock_correction_source وclock_offsets_differ_from_run. تحتاج التصريحات أدلة ساعة؛ لا تضبط offset من النتيجة |
| F2 ملكية الدليل وفقد السبب | نرفض تخصيص الدليل المشترك لـB لمجرد خطأ وقتA؛ لا يثبت ذلك أن الحدث يخصB. فقد السبب السابق صحيح وقابل للإعادة | يحتفظ exclusion_details بخطأ timestamp وأخطاء stage المكتشفة ثم ambiguity؛ يبقى الصفان مستبعدين. حجب final المشترك خطأ الوقت في المثال الأول، فأعيد الإنتاج بمتغير final منفصل |
| F3 قبول VT بدل FIM فيUC-07 | صحيح؛ أعيد بـ87105 وكانت النتيجة COMPLETED_WITHIN_WINDOW | عند opt-in يقبل t2 من100300/100301/100303/100304 بمستوى7. اختبارات معرفات Windows ليست قبولًا للنظام الأصلي؛ بلا policy يبقى العقد السابق |
| F4 القول إن stamp يصحح NTP | فرضية غير صحيحة: يحول time zone فقط. النوافذ والتنبيهات كلاهما على مقياس المدير الخام، ثم يصحح coverage مرة واحدة | اختبار manager+90ms قرب observe_until يؤكد الاتساق. لا تغيير لتعريف النافذة؛ ISO/Z ليس دليل دقة ساعة |
| F5 المقام الشرطي لا يشمل المستبعد | صحيح أنه شرطي؛ المقام الشامل سليم، لكن الاسم يحتاج توضيحًا | أضيف observed_trigger_denominator_scope=non_excluded_trials_with_validated_raw_trigger؛ اختبار نجاح+محجوب يعطي .5 شاملًا و1 شرطيًا مع النطاق الصريح |
| F6 سياسة v1 مهملة | صحيح وقابل للإعادة: exit0 بلاAR | load_runs يرفضها؛ analyze_v2 يجرد نسخة legacy فقط بعد التحقق ويحفظ الأصل لحسابAR. CLI يعيد exit2 وstdout فارغًا؛ سياسة المحاولة مرفوضة أيضًا |
| F7 event_valid غير موثق | غير صحيح توثيقيًا: مدرج سابقًا في «المحاولة والخرج». تشخيص v1 كان مربكًا | أضيف تشخيص v2 مباشر واختبار غياب الحقل، دون تخفيف شرط الإثبات |
| F8 exact keys تكسر الجميع عند الإضافة | ليست مشكلة حالية؛ exact keys اختيار fail-closed، والإضافة المستقبلية ليست تغييرًا منشورًا | اختبار unknown fields؛ أي ترقية تحتاج عقد توافق واختبارات ترحيل، لا schema جديد بلا سبب |
| F9 invariant غير قابل للوصول | حارس دفاعي مقصود؛ كسره خطأ داخلي لا ينبغي إخفاؤه كتجربة عادية | أبقينا InputError وفشل التقرير بدل تقرير جزئي؛ اختبار صف داخلي غير متسق |

**ملاحظات الاختبارات:** مجموعة تنبيهات فارغة تختبر غياب المحفز، لا قيمة t2 المصرح بها وحدها. شريحة FIM دونVT تختبر فقد المرحلة الخارجية، وقيود UC-03 موجودة أصلًا في validate_v2. ترتيب t5 قبل108001 مسموح: التنبيه النهائي ليس بدءAR أو اكتماله. fixture الخاص بـUC-03 يجعلVT تنبيه الكشف ومحفزAR، وt6 مستقل ولا يملأt5؛ ليست هذه سلسلة حذف أصلية. اختبار completion_kind يثبت schema فقط، كما يصرح الدليل.

الإصلاح `fb4100a` ثم تصحيح fresh-checkout في `83ebff9`: **39 اختبارAR** (27+12)، و134 اختبار قياس سابق ناجحة. **680 اختبارًا كليًا في28.865s على dd87465** مع ALL CHECKS PASSED. لا يحتاج اختبارAR مجلد build موجودًا؛ ملفات CLI مؤقتة تحت جذر المستودع وتحذف تلقائيًا. CI الرأس النهائي منفصل في PR28.

**تنبيه توافق:** السياسة خاصة بـrun في manifestv2؛ لا override بالمحاولة. تصحيح الوقت يستخدم offsets المحاولة، بينما قيم run تبقى مرجع فحص جلسة وليست التصحيح المطبق. اختلافهما لا يصادق على المصدر: يجب مراجعة clock_ref/time_refs والنسخ المؤرخة قبل القياس. تظل السياسة والساعات إقرارات، لا نظام مصادقة أدلة.


## UC-01 — محلل دورات الاتصال offline (2026-09-23)

`python3 -B scripts/measure/connection_measure.py --help`

هذه أداة مستقلة عن `mttd.py` وعن مقام كشف الهجمات. تحلل **إقرارات أدلة** جُمعت مسبقًا، وتطابق تنبيهًا خامًا بملف تحقق فريد. لا تعيد تشغيل خدمة أو تسجيل وكيل، ولا تتصل بالمدير أو SSH أو API، ولا تنشئ ملف التحقق. مجمع الأدلة الأصلي وربط السجلات به ما زالا **عملًا برمجيًا محليًا متبقيًا**؛ الاختبارات الاصطناعية ليست قبولًا معمليًا.

### خطة مسبقة وعقد ثابت

مدخل `--plan` كائن JSON خاص. الحقول كاملة وصارمة، ولا تقبل مفاتيح إضافية:

| الحقل | العقد |
|---|---|
| schema_version / kind | العدد الصحيح1 / uc01_connection_plan |
| run_id / protocol_ref | نص غير فارغ ومرجع بروتوكول مثبت قبل التجربة؛ المرجع لا يثبت التسجيل المسبق بذاته |
| identity | manager_name، agent_id غير000، agent_name، os=linux/windows، config_sha256 بصمة64hex |
| clocks | أربعة أدوار: controller وendpoint وmanager وobserver؛ لكل دور offset_ms وuncertainty_ms وprecision_ms وref |
| window_s / poll_interval_ms |300 ثانية و5000ms وفق TEST_PLAN؛ ليست معاملات لتغيير النافذة بعد رؤية النتائج |
| coverage | start_ms/end_ms على ساعة المدير الخام وref؛ إقرار استمرارية أرشيف التنبيهات وليس إثباتًا آليًا لها |
| cycles |5 إلى100 دورة معلنة مسبقًا؛ لكل دورة cycle_id وtarget_path فريدان، وقائمتا rule_ids وlevels حسب الإعداد المعتمد |

قيم الساعة صحيحة بالميلي ثانية: offset=device−UTC، والمصحح=raw−offset مرة واحدة. uncertainty غير سالب وprecision موجب ويمثل حد±محافظًا؛ القيم حتى60000 للتحقق البنيوي، لكن |offset|>100 أوuncertainty>100 يمنع نجاح الدورات المسجلة. precision ليس دقة العرض أو عدد الخانات. لكل نقطة مجال `[raw−offset−error, raw−offset+error]` حيث error=precision+uncertainty. جميع الدورات تستخدم الساعات المثبتة في هذه الخطة؛ لا override من صف المحاولة. تغير الإعداد أو قياس الساعة يستلزم خطة/run جديدة.

المسار حرفي ومطلق وفق النظام، بلا `.` أو`..` أو أجزاء فارغة؛ مقارنة المسار في التنبيه exact. اختلاف حالة أحرف مسارات Windows في **الخطة** يمنع تكرار هدف واحد، لكن المطابقة الخام تظل حرفية؛ يجب تطبيع المصدر مسبقًا بطريقة مراجعة، ولا يعاد تفسير raw alert تلقائيًا. لا وصول إلى target_path من المحلل. لا تعد البصمة وحدها هوية محاولة؛ يجب اختيار ملف جديد لكل دورة قبل التنفيذ.

### السجل المطبع لكل دورة

`--records` ملف JSONL، صف واحد على الأكثر لكل cycle_id مخطط؛ غياب الصف مسموح ويصدر MISSING_RECORD. لا يجوز إسقاط دورة من الخطة لتجميل المعدل. مفاتيح كل صف:

- schema_version=1، run_id، cycle_id.
- exclusion_reason: null أوBLOCKED/INVALID/INTERFERED/AMBIGUOUS؛ reason=null عند عدم الاستبعاد، وإلا سبب نصي مطلوب.
- restart: null أو كائن يحوي request_ms وcommand_end_ms وold_instance وnew_instance وservice_started_ms وservice_running وref. request على ساعةcontroller؛ نهاية أمر إعادة التشغيل عليها أيضًا، وservice_started على ساعةendpoint. نهاية الأمر وبداية الخدمة والهويتان nullable، لكن النقص يمنع إثبات إعادة تشغيل جديدة. service_running قيمةboolean.
- canary: null أو `{created_ms, path, source_ref}`؛ الوقت من شاهد إنشاء علىendpoint، لاmtime ولاوقت عرضDashboard. source_ref مرجع شاهد مستقل محدد بالدورة، لا سجل نجاح الأمر وحده.
- polls: مصفوفة حتى128 عينة؛ كل عينة `{start_ms, end_ms, start_monotonic_ms, end_monotonic_ms, status, manager_name, agent_id, agent_name, ref}`. كل الأزمنة صحيحة؛ wall clock علىobserver، وmonotonic من عملية مراقب واحدة دون إعادة ضبط. الحالات فقط active/disconnected/pending/never_connected/error.

**هوية الخدمة ليستPID منفردًا.** يحتاج الجامع المقبل هوية incarnation مربوطة بـboot/session ووقت بداية أصلي ودليل هوية الوكيل/الإعداد؛ old_instance وnew_instance هنا نصان مصرح بهما، لا يثبت المحلل مصدرهما. command_end أوexit0 لا يثبتان service_started. إعادة استخدام new_instance أومرجعrestart أوsource_ref بين الدورات تجعل الدورات المرتبطة AMBIGUOUS_EVIDENCE حتى لو كانت إحداها مستبعدة.

المثال البنيوي الكامل الاصطناعي موجود في `tests/test_connection_measure.py` داخلplan()/record()/alert()، وهو **ليس بيانات معمل ولا قالبًا لقيم ساعات أصلية**. يشغّل الاختبار دورة واحدة مكتملة وأربع دورات مفقودة عمدًا لاختبار المقام. لا يُرفع raw log أوإقرار حساس إلىGit.

### التغطية والزمن والنتيجة

- يبدأ الرصد قبلrequest وينتهي بعد كامل نافذة300ث مع هامش حدود الساعة؛ الاكتمال المبكر لا يلغي شرط التغطية. عدم تغطية الطرفين فيpolls أوcoverage يعطي OBSERVATION_INCOMPLETE.
- دورة الاستطلاع5000±1000ms علىmonotonic، والطلب≤2000ms، ولا تداخل طلبات. سماح جدولة1000ms **ليس سماح خطأ ساعة**: اختلافwall/monotonic، داخل الطلب وبين الطلبات وبالنسبة لأول عينة، لا يتجاوز مجموع خطأي نقطتين علىobserver. تجاوز ذلك CLOCK_JUMP؛ فقد عينة أو تغيير ترتيبها POLL_GAP.
- تغير هوية الوكيل أوالمدير في أي عينة يرفض الدورة؛ عينةerror ليست disconnected ولا تصلح حدًا سالبًا، وتمنع نجاحها. تداخل نوافذ300ث لدورتين مع حدود الخطأ يجعل كلتيهما OVERLAPPING_CYCLE؛ الدورات لا تشغّل بالتوازي لهذا الوكيل.
- اتصالمرصود: أولactive بعد بدء الخدمة الأصلي، مع آخرpending/disconnected/never_connected بعد البدء، يولد transition_interval_s. بلا مشاهدة سلبية بعد البدء يبقى المجالnull وconnection_state=ACTIVE_WITHOUT_TRANSITION_BRACKET؛ لا نختلق وقت إعادة اتصال منcachedactive.
- التحقق الوظيفي مستقل: يحتاج إعادة تشغيل جديدة ودليلservice_running، وعينةactive، وشاهدإنشاءملف بعد بدء الخدمة ونهاية الأمر، ثم تنبيه خام جديد مطابق للهوية والمسار والقاعدة والمستوى. تنبيه سابق للإنشاء لا يُتجاوز لصالح تنبيه لاحق، بل PREEXISTING_CANARY_ALERT؛ تداخل مجال الوقت يعطيTIMING_UNCERTAIN.
- functional_confirmation_interval_s مجال أدلة مكونات التحقق، وليس زمن أول ظهور فيIndexer: أكبر الأوقات المصححة للـactive ونهايةالأمر وبدءالخدمة وتنبيهالمدير، ناقصrequest مع حدودالخطأ. high≤300 يعنيFUNCTIONAL_EVIDENCE_WITHIN_WINDOW؛ low>300 يعنيFUNCTIONAL_EVIDENCE_LATE؛ تقاطعالحد يعطيTIMING_UNCERTAIN. لا يسمى أي منهماMTTD.
- توجد أيضًا RESTART_UNPROVEN وNO_ACTIVE_OBSERVED وCANARY_NOT_SUPPLIED وCANARY_ALERT_NOT_OBSERVED وغيرها؛ غياب FIM لا يشخّص فشل التسجيل. connection_state منفصل عنstate الوظيفية. لا تحويلnullإلىصفر.

المقام **جميع الدورات المخططة**، لا المسجلة فقط ولاالناجحة. البسط FUNCTIONAL_EVIDENCE_WITHIN_WINDOW فقط؛ سجلcounts وrecorded_cycles والمفقود والاستبعاد. لاWilson افتراضيًا أوخيارلتفعيله هنا؛ خمس دورات لا تثبت استقلالًا أوفعالية عامة. `acceptance_approved=false` و`causality_authenticated=false` و`independence_verified=false` ثابتة. الناتج مطابقة بنيوية وزمنية لإقرارات وraw alert، وليس مصادقة شهود أوإثبات سببية أوأصالة.

### التشغيل والخصوصية

```bash
python3 -B scripts/measure/connection_measure.py \
  --plan PRIVATE_PLAN.json --records PRIVATE_CYCLES.jsonl --alerts PRIVATE_ALERTS.jsonl
python3 -B -m unittest discover -s tests -p test_connection_measure.py
```

CLI علىLinux يقرأ الملفات فقط: لاsymlink نهائي، ولاFIFO أوdirectory، مالكهاUIDالحالي وصلاحياتها0600 أوأضيق، regular أحاديةالرابط، حتى8MiB لكلملف و20000تنبيه. المجلداتالوسيطةموثوقة؛ لا ادعاء حماية منكاتبخبيثبنفسUID أوأننسخالملفاتالثلاثةsnapshotذري. استخدمصادراتثابتةخاصة. blankline أوduplicateJSONkey أوNaNأومدخلتالف يفشل كليًا بـexit2 وstdoutفارغ ورسالةعامةUC01_INPUT_REJECTED لاتسرب المحتوى. الملفاتالفارغةrecords/alerts مسموحة. نجاحالحسابexit0 لايعني نجاحالدورات؛ خزّنstdoutفيملفخاصبصلاحياتمقيدةإذااحتجتإلىالاحتفاظبه.

يحتويالناتجinput_sha256 لبايتاتالمدخلات وsource_sha256 للمحلل وmttd.py، ولاينسخالمدخلاتالخامإلىالتقرير. hashليس توقيعهوية. التطابقمعكودمخططلايعنياستخدامهفعليًا علىالوكيل.

### مصدر القرار وحدود الإنجاز

المرجع الداخلي TEST_PLAN §UC-01: خمس دورات،300ث،poll5ث،خدمة+active+حدثجديد؛ لا إعادةتثبيتأوتسجيلأوحذفkeys فيكلدورة. روجعت [وثيقة agent_control الرسمية](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-control.html) في2026-09-23: `-l` للاستعلام، و`-R` يعيدالتشغيل؛ لا يستخدمالمحلل أيًا منهما. صفحةcurrent لاتثبتإصدارالمعمل، وحالةactive المؤقتة لا تثبتعودةجديدة. وثيقةlifecycleالمؤرشفةسابقًاتذكرdefault15m للانقطاع؛ ليس بديلًالتعريفالقياس.

المنفذمحليًا: evaluator صارم ومقامخطةواختبارات50عندbe7a45c، ثم3اختباراتساعةوإصلاحdf1616b. الفحصالكامل730عندbe7a45c؛ العددبعدالإصلاحيتحققمنالجولةالكاملةالتالية. المراجعةالآلية6f1083f8 قيدالمتابعةعندوضعهذاالدليل؛ لااعتمادمسبق.

**المتبقي محليًا:** جامعأدلةقراءةفقط للخدمةوالحالةوتوقيتالمراقب، ربطهبهوياتالخطةوالجولةوببايتاتالمصادر، وربطcanaryأصليوملخصمراجعمصرحبالمخزن، معاختباراتالانقطاعوالتدويروالتلاعب. لا يلغيه وجودمحللالإقرارات. **المتبقيالأصلي:** جردوإعدادوساعاتمعتمدة، تجربتانظاميتانLinux/Windowsحسبالنطاق، تنفيذخمسدوراتتحتإشراف، ومراجعةالأدلة. t4/t5وISSUE-068 وتدقيقالفصولتبقىمساراتمستقلة.
