# UC-14 — نواة محلل التنبيهات الاستشاري

> الغرض: واجهة T-70 وحدود الثقة والقبول؛ المالك [AI]؛ التحديث 2026-09-18. تدقيق PR28 وقيوده في TAKEOVER_AUDIT §8.
> الحالة: نواة برمجية واختبارات اصطناعية، IN-PROGRESS وفق ADR-014؛ ليست محللاً منشوراً أو نتيجة C4.
> المصادر: `docs/DECISIONS.md` ADR-014، قواعد المستودع، توثيق Ollama الرسمي المرتبط أدناه.

## 1. ما نُفذ وما لم يُنفذ

| المستوى | الموجود في النواة | المتبقي |
|---|---|---|
| L1 شرح التنبيهات | اختيار L≥7، سياق مصغّر، واجهة نموذج اختيارية، مخطط توصيات مع مراجع | تشغيل نموذج فعلي وقياس جودة الشرح بالعربية/الإنجليزية |
| L2 الترابط | أزواج مرشحة لنفس manager/agent ضمن نافذة زمنية، وفحص مراجع النتائج | سرد مترابط مُقاس ومتعدد المصادر؛ الترابط الزمني ليس إثبات سببية أو سلسلة هجوم |
| L3 التوصيات | أنواع توصية محددة و`requires_human_review=true`؛ لا منفذ أوامر | سير عمل بشري مُصادق عليه وسجل قرارات؛ العلم البرمجي ليس نظام موافقات |
| RAG | استرجاع مطابق للقواعد وثلاث تقنيات MITRE v19.2 مثبتة؛ شروح مشروطة ببصمة القواعد؛ عقد جرد اختياري | جرد حقيقي معتمد ومراجعة مستقلة وقياس جودة التغطية؛ ليست قاعدة ATT&CK كاملة |
| C4 | `ai_agent/evaluate.py` للحساب و`ai_agent/runner.py` لحفظ المحاولات والتحقق من بايتات الأدلة والإسقاط، انظر §11 | مراجعة مختصة و30 تنبيهاً حقيقياً معلماً بشرياً وتجربة نموذج وتحكيم؛ لا نتائج أصلية بعد |

المصدر `ai_agent/analyst.py` مستقل عن مزود النموذج عبر callable: يستقبل سياقاً منقحاً ويعيد JSON نصياً. المحول الوحيد المطبق حالياً هو Ollama محلي. لا يوجد OpenAI أو أي API خارجي، ولا خدمة HTTP جديدة أو تكامل مباشر بالمدير، ولا تنزيل تلقائي لنموذج.

## 2. تشغيل دون نموذج — الوضع الافتراضي

من جذر المستودع، باستخدام **تصدير محدود وخاص** للتنبيهات، لا ملف أسرار أو stream غير محدود:

```bash
python3 -I -B ai_agent/analyst.py --alerts /approved/private/export.jsonl
```

المسار مثال يختاره المشغّل في بيئته المصرح بها؛ ليس مساراً أنشأته الجلسة. لا ترفع export حقيقياً إلى Git. الأداة تقرأ فقط وتكتب نتيجة JSON إلى stdout؛ لا تحفظ تقارير أو تعيد تعديل الملف المدخل. يعمل الفحص على Linux مع Python3.12/3.13 في CI؛ القراءة تستعمل O_NOFOLLOW/O_NONBLOCK، ولا يُدّعى توافق Windows أصلي.

حقول كل سطر غير فارغ:

```json
{"id":"example-event-1","timestamp":"2026-09-11T12:00:00+00:00","manager":{"name":"example-manager"},"agent":{"id":"001"},"rule":{"id":"100210","level":12},"data":{"srcip":"192.0.2.10"}}
```

هذا **مثال اصطناعي** وليس تنبيهاً مقاساً. `manager.name` و`agent.id` و`id` إلزامية لمنع دمج هويات من مديرين مختلفين. `rule.id` سلسلة رقمية؛ level عدد صحيح لا bool ضمن0..16. timestamp ذو timezone صريحة ويحوّل إلى UTC.

- حتى100 سجل و4MiB لكل من بايتات الملف UTF-8 والمدخل المركب بعد JSON ASCII serialization؛ الزيادة رفض وليست truncation صامتاً. الحدّان مستقلان: النص العربي قد يتوسع عند escaping ويرفض رغم أن الملف الخام أصغر؛ هذا حد ذاكرة محافظ، وليس ضمان قبول كل ملف خام دون4MiB.
- JSON صارم يرفض المفاتيح المكررة وNaN/Infinity والأعداد الفائضة والثوابت الصحيحة المفرطة.
- تكرار identity=(manager, agent, id) يُحسب مرة؛ اختلاف محتوى سجل يحمل الهوية نفسها رفض.
- المستوى دون7 مستبعد بعد التحقق البنيوي؛ أعداد الإدخال/المختار/المنخفض/المكرر تظهر في `counts`.
- `A1..An` تشير إلى السجلات المختارة. `source_record` هو رقم السجل **غير الفارغ** في التصدير، يبدأ1 ويحفظ ترتيب المصدر عبر الاستبعاد والتكرار؛ ليس رقم سطر مادي عند وجود أسطر فارغة. يحتفظ المشغّل بالتصدير الخاص لإعادة الربط.
- لا تنفذ الأداة حتى عملية inference دون `--infer`. الحالة الافتراضية `offline_context_only`، أو `no_eligible_alerts`؛ findings فارغة. لا تعني هذه النتيجة تحليلاً لغوياً من نموذج.

## 3. محول Ollama الاختياري

بعد تثبيت نموذج واختبار خدمته بواسطة المشغّل في سياق يسمح بذلك:

```bash
python3 -I -B ai_agent/analyst.py \
  --alerts /approved/private/export.jsonl \
  --infer --model INSTALLED_MODEL_NAME \
  --endpoint http://127.0.0.1:11434 --language ar
```

`INSTALLED_MODEL_NAME` placeholder وليس توصية باسم مخترع أو نموذج مثبت فعلاً. لم يُشغّل هذا الأمر على نموذج حقيقي في الجلسة.

- يُسمح فقط بـHTTP إلى literal `127.0.0.1` أو `[::1]` مع port صريح ومسار جذر؛ hostname وواجهات الشبكة العامة/الخاصة الأخرى وبيانات اعتماد URL وquery/fragment ممنوعة.
- proxies معطلة، وredirects مرفوضة. لا يكفي كون العنوان loopback لضمان موثوقية الخدمة: العملية المحلية ومالكها وإعداداتها جزء من حدود ثقة المشغّل.
- طلب `/api/chat` غير متدفق، `format` يحمل JSON schema، temperature0 وnum_predict2048. لا tools ولا API للحذف أو الحظر أو الموافقة.
- حد السياق128KiB؛ حد طلب المزود256KiB وحد رده128KiB. القيود تُرفض صراحة؛ لا يُقال إن كامل نافذة النموذج تتسع تلقائياً لهذه الأحجام.
- مهلة socket افتراضية30ث، وحد إعدادها60ث. هذه مهلة I/O وليست ضمان wall-clock كلي ضد خدمة ترسل ببطء؛ مهلة شاملة وعزل الموارد مطلوبان قبل تشغيل دائم.
- رد غير مكتمل أو tool_calls أو schema غير مطابق يُرفض. CLI يعطي خطأ عاماً دون طباعة محتوى السجل أو رد الخادم أو مسار حساس. إصلاحd13ff7f يضم HTTPException مثلBadStatusLine/IncompleteRead/LineTooLong إلى حد الأخطاء العام؛ لا traceback لنص الخادم أوstdout جزئي.
- `inference_seconds` قياس محلي لاستدعاء المزود والتحقق من رده؛ ليس MTTD ولا استجابة Wazuh، وليس إحصاء أداء معتمد من تجربة واحدة.

## 4. سياسة البيانات والخصوصية

السياسة هنا **تصغير بالحقول المسموحة**، وليست محاولة تنقيح كل نص حر بتعابير منتظمة:

| البيانات | ما يصل للسياق |
|---|---|
| اسم المدير ومعرف الوكيل | رموز batch-local؛ مفتاح الوكيل يجمع المدير والوكيل |
| srcip/dstip IPv4/IPv6 | رموز IP ثابتة داخل الدفعة فقط؛ لا عناوين أصلية |
| اسم الوكيل وagent.ip | غير مرسلين |
| full_log وrule.description ومسار الملف والمستخدم والروابط وحقول data الأخرى | محذوفة بالكامل |
| MITRE الذي يدعيه التنبيه | غير موثوق، لا يُعتمد |
| timestamp، rule.id، level، ترتيب سجل المصدر | باقية، ومقيدة بالتحقق البنيوي |
| قواعد المعرفة | rule ID وparents وannotations، وشروح مصغرة مشروطة ببصمة القواعد ومقتطفات MITRE مثبتة؛ match/path الأصليان مستبعدان |
| الجرد الاختياري | OS family/version وdeployment/role مع رمز الوكيل؛ الاسم ومعرف الوكيل الأصلي وsource_ref غير مرسلين |

لا تعاد خريطة فك الرموز، ولا تستخدم رموزاً ثابتة عبر دفعات. هذه **pseudonymization لا anonymization مضمونة**: التوقيت وندرة القواعد وأنماط العلاقات قد تكشف معلومات بالربط الخارجي. احتفاظ خدمة النموذج بالطلبات وسجلاتها يجب مراجعته قبل أي تشغيل حساس؛ لم يُختبر في هذه الجلسة.

استبعاد النص الحر يقلل خطر prompt injection لكنه يفقد تفاصيل مفيدة للشرح. لا نُخفي المقايضة: النواة ليست RAG غنياً أو حلاً شاملاً للخصوصية/الهلاوس. أضيفت أوصاف مثبتة وعقد جرد في §9؛ ما زال قياس التسريب وهجوم التعليمات والمراجعة المستقلة مطلوباً. البصمات وإصدار النظام قد تساعد في الربط الخارجي؛ تحديد الصيغة ليس ضمان إخفاء هوية.

## 5. عقد النتيجة وحدود الإسناد

كل finding يتضمن فقط المدخلات النموذجية التالية:

- `evidence_refs`: مراجع معروفة غير مكررة؛ كل تنبيه مختار مغطى **مرة واحدة** عبر النتائج، فلا إغفال أو نتائج متعارضة مكررة صامتة.
- `classification`: `suspicious` أو `likely_benign` أو `insufficient_evidence`؛ ليست حقيقة مكتشفة أو confirmed compromise.
- `assessment`: نص محدود بلا محارف تحكم؛ يعرض كنص غير موثوق، **لا HTML خام أو أوامر قابلة للتنفيذ**.
- `mitre_ids`: جزء من annotations قواعد التنبيهات المستشهد بها، ويتقاطع مع وثائق الحزمة المثبتة عند enrichment؛ القاعدة غير المعروفة لا تحصل على mapping مختلق. CLI يثري السياق افتراضياً؛ استخدام prepare مباشرة دون enrich يحتفظ بعقد metadata القديم. هذا يثبت مطابقة annotation/وثيقة فقط، لا صحة MITRE مستقلة.
- `recommendation`: `investigate` أو `request_isolation_review` أو `request_block_review` أو `request_quarantine_review` أو `none`.

الخادم البرمجي يضيف `knowledge_refs` و`requires_human_review=true` و`execution_authority=none`. الحقول الزائدة مثل command/approved/tool_calls تُرفض؛ لا يستطيع النموذج إلغاء شرط المراجعة. إذا جمع finding تنبيهات، يجب أن يطابق كل زوج منها رابطاً زمنياً مرشحاً لنفس الوكيل/المدير.

`semantic_grounding_verified=false` يبقى دائماً: وجود مرجع صحيح لا يثبت أن الجملة مستنتجة منه. يستطيع نموذج كتابة ادعاء خاطئ أو تعليمات داخل assessment؛ لا ينفذها البرنامج، وتحتاج مراجعة بشرية واختبارات C4. النسخ الدفاعية تمنع تعديل محول المزود للأدلة التي تستخدم للتحقق؛ لكنها **ليست sandbox** لشفرة Python مضافة بواسطة المشغّل.

## 6. الاختبارات المنفذة فعلاً

```bash
python3 -B -m unittest discover -s tests -p test_ai_analyst.py -v
bash scripts/validate/validate_all.sh
```

أحدث تشغيل2026-09-18:48 اختباراً اصطناعياً للمحلل +19 للمعرفة/الجرد +28 للتقييم؛ مجموع307 محلياً بعدa2ba875/d13ff7f. نقطة5744011 التاريخية كانت46/19/24 ومجموع301. أعداد258/277/300 نقاط تاريخية قبل التوسعة/التقوية. شغّل أيضاً `python3 -B -m unittest discover -s tests -p 'test_ai_*.py' -v`. تشمل التنقيح بالاستبعاد، قوالب التعليمات العدائية، source_record، الفلترة والتكرار المتعارض، العناوين، manager separation، حدود الزمن/الحجم، XML entities، JSON غير محدود، schema والمراجع وMITRE، عزل context، عدم تكرار finding، loopback/proxy/redirect والمهل والردود الجزئية/أخطاء المزود وCLI الافتراضي.

أعيد إنتاج خطأ مشاركة context في checkpoint7033616: محول يضيفT9999 إلى المعرفة ثم يعيده كان يغير دليل التحقق نفسه. صُحح بنسخ منفصلة، واختبار الانحدار يرفضه. جميع اتصالات المزود في الاختبارات mocked؛ ليست inference فعلية أو اختبار تغطية MITRE أو استغلالاً سحابياً. طُلبت مراجعة عبر consult_advisor لكن الأداة رفضت إتاحتها في نوع الجلسة؛ **المراجعة الحالية ذاتية لا مستقلة**. تحقق CI لأحدثSHA يسجل في PR28 ولا يفترض من تشغيل سابق.

## 7. بوابات الاستكمال — لا تُغلق T-70 قبلها

1. **معرفة مراجعة ومؤرخة:** MITRE ATT&CK مثبت الإصدار مع provenance وبصمات، أوصاف قواعد مصغّرة، جرد معمل موثوق مؤرخ؛ لا تعامل raw logs كتعليمات ولا الجرد القديم كحقيقة حية.
2. **تشغيل نموذجي أصلي:** اختيار نموذج مثبت، قياس حدود السياق والموارد وsocket/wall timeouts وانقطاع الخدمة؛ مراقبة SOC يجب أن تستمر عند فشل AI. لا تنزيل نموذج ضمن مسار معالجة التنبيه.
3. **C4:** 30 تنبيهاً على الأقل معلماً بشرياً مستقلاً عن نسخ MITRE tags الحالية. تثبيت نسخة المدخلات الخاصة والنموذج والمعرفة والسياسة؛ لا تمرير gold labels للنموذج. حفظ المحاولات الفاشلة والامتناع في المقام، وتحديد أثر الترابط بين التنبيهات على افتراض الاستقلال قبل Wilson.
4. **مقاييس:** صحة التصنيف وMITRE وفق rubric معلن، نسبة الادعاءات غير المسندة بتحكيم بشري، زمن التحليل، حالات الرفض والامتناع؛ لا تحويل regex/schema-valid إلى معدل هلاوس. أداة الحساب مطبقة في §10؛ البيانات البشرية والتجربة والنتائج الأصلية غير منفذة. صحة الأداة لا تعني صحة التصنيفات المدخلة.
5. **تكامل ومراجعة بشرية:** قناة قراءة بأقل صلاحية، حدود دفعات وتكرار عبر الدفعات، auth/سجل تدقيق/واجهة تعرض نصاً آمناً، ربط قرار المشغّل بالأدلة. لا منح هذا المكون سلطة AR في أي مرحلة.
6. **أدلة أكاديمية:** مخرجات منقحة من التجربة الأصلية للفصلين4/5؛ لا صور اصطناعية أو fixtures باعتبارها نتائج معمل.

## 8. مراجع الواجهة

راجعت في2026-09-11؛ روابط current قد تتغير، ولم تدّعَ مطابقة إصدار Ollama مثبت:

- [Ollama chat API](https://docs.ollama.com/api/chat).
- [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs): format/schema والتحقق بعد التوليد.
- [ADR-014](../DECISIONS.md#adr-014--ai-agent-داخل-النطاق-قرار-المستخدم-2026-09-09): النطاق الحاكم؛ النواة لا تلغي متطلباتRAG/C4.

## 9. المعرفة المثبتة والجرد الخاص — تنفيذ db1eab9

### 9.1 مصدر MITRE وحدود التغطية

`ai_agent/mitre_subset.json` من MITRE ATT&CK Enterprise **v19.2**، مستودع `mitre-attack/attack-stix-data`، commit `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`، ومسار `enterprise-attack/enterprise-attack.json`. تاريخ الجلب المسجل: `2026-09-11T12:58:53.290157+00:00`.

- [المصدر المثبت](https://github.com/mitre-attack/attack-stix-data/blob/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack.json).
- Git blob SHA1 المتحقق مقابل GitHub: `8b8a9c8cc9e553f96f963b91265f50ee0854636d`؛ حجم المصدر53835637 بايت. حُمّل في الذاكرة، ليس ملفاً مرفوعاً للمشروع.
- SHA256 للمصدر الكامل: `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`.
- SHA256 للحزمة المحلية: `50b6e920cceaf9a1548495f86b51621f4b324702fc026da279438fd7e4ae61e3`، مثبت في `knowledge.py`. الترخيص ونصه وبصمته محفوظة في الحزمة.
- التقنيات الثلاث فقط: T1059 (v2.7)، T1204.002 (v1.6)، T1571 (v1.3). هذه mappings القواعد الحالية، وليست تغطية ATT&CK عامة.
- الاسترجاع exact lookup بلا شبكة أو embeddings؛ يصل فقط ما طابق قواعد الدفعة. الوصف الأصلي محفوظ، والمقتطف يصل إلى1600 محرف مع `excerpt_truncated`. الروابط مراجع لا تُفتح آلياً.
- شروح القواعد13 مقيدة ببصمة `local_rules.xml`: `98154bbac8c95fddec70a5223253a46e1e8f716e40768662b420d3519d00443d`. أي تغيير، حتى whitespace، يعطل الشروح المنقحة ولا يعطل metadata؛ راجع قبل تحديث الثابت.
- **قيد دلالي:** rule108001 لا يثبت user execution لـT1204.002، وrule100051 لا يثبت protocol/port pairing لـT1571. بقيت القواعد كما هي وأضيف التحذير؛ لا تنسخ annotations إلى gold labels كحقيقة بشرية.

لتحديث الحزمة: اختر إصداراً رسمياً واضحاً، تحقق tag/commit وGit blob وحساب SHA256 للبايتات، احتفظ بالترخيص والنص الأصلي، راجع التغييرات الدلالية، حدّث الحزمة والثابت والاختبارات معاً ثم PR ومراجعة. **لا إعادة توليد من ذاكرة النموذج ولا تحديث تلقائي أثناء معالجة التنبيه.**

### 9.2 عقد inventory الاختياري

مثال بنيوي اصطناعي؛ التاريخ التالي ليس جرداً حياً وسيرفض إذا تجاوز24ساعة:

```json
{"schema_version":1,"as_of":"2026-09-11T13:00:00Z","assets":[{"manager":"example-manager","agent_id":"001","os_family":"linux","os_version":"unknown","deployment":"container","role":"endpoint","source_ref":"audit-example-1"}]}
```

لا حقول إضافية. `schema_version` عدد صحيح1؛ `as_of` ذو timezone، ليس مستقبلياً وعمره≤86400ث. الأصول1..100 وهوية `(manager,agent_id)` فريدة. القيم المسموحة:

- os_family: linux/windows/network/unknown.
- deployment: container/vm/physical/unknown.
- role: endpoint/server/network_device/unknown.
- os_version≤40 وsource_ref≤80؛ الحروف `[A-Za-z0-9._:-]` فقط. هذه قيود صيغة لا كشف آلي للأسرار؛ على المشغّل مراجعتها.

```bash
python3 -I -B ai_agent/analyst.py --alerts /approved/private/export.jsonl \
  --inventory /approved/private/inventory.json --inventory-sha256 APPROVED_SHA256
```

`APPROVED_SHA256` يجب استبداله ببصمة64hex صغيرة **معتمدة بعد مراجعة المصدر**، لا حساباً تلقائياً بديلاً عن الاعتماد. مطابقة الملف لا تثبت توقيعاً أو صحة الجرد. يربط البرنامج الهوية بالتصدير عبر source_record ثم لا يرسل manager/agent_id/source_ref؛ يرسل صفات الأصل ورمز AGENT فقط. الأصول غير المطابقة تظهر صراحة. غياب الجرد `not_supplied` لا يفترض Linux أو نسخة نظام. الحالة `operator_declared_snapshot` و`historical_event_state_verified=false` لا تثبت حال الأصل عند تنبيه تاريخي. لم يُجهّز جرد حقيقي لهذا العقد في هذه المرحلة.

## 10. أداة C4 offline — تنفيذ120efba وتقوية5744011

### 10.1 تشغيل وحد الثقة

```bash
python3 -I -B ai_agent/evaluate.py \
  --manifest /approved/private/c4_manifest.json \
  --attempts /approved/private/c4_attempts.json \
  --reviews /approved/private/c4_reviews.json
```

المسارات توضيحية وليست ملفات أنشئت في هذه الجلسة. الأداة تقرأ JSON فقط وتطبع تقريراً، لا تستدعي نموذجاً ولا تنفذ استجابة ولا تكتب ملفات. كل ملف≤4MiB، والمحتوى المركب serialized≤4MiB، والحالات≤1000. قارئ Linux no-follow والقيود العددية/المفاتيح الصارمة مشتركة مع analyst. exit0 يعني **صلاحية الحساب فقط** حتى لو جميع المحاولات مفقودة؛ exit1 رفض بعرض خطأ عام بلا محتوى خاص. فشل البنية يرفض الملف كاملاً ولا يسقط الصف بصمت.

هذا **عقد سجلات تقييم مطبّعة**، لا مستورداً آلياً لـanalyst JSON. SHA256 يربط تصريحات الملفات ببعضها، لكنه لا يتحقق من بايتات المصدر/النموذج/الرد غير المقدمة. لذلك دائماً `artifact_contents_verified=false` و`human_independence_verified=false` و`acceptance_approved=false`. CLI يضيف بصمات ملفات المدخلات الثلاثة المقروءة فعلاً. لا يسمى التقرير اعتماداً أصلياً بمجرد اجتياز checks.

### 10.2 مخطط الملفات — جميع الحقول المذكورة إلزامية، والزيادة رفض

**manifest** كائن بالمفاتيح:

| الحقل | العقد |
|---|---|
| schema_version | integer1، لا bool |
| evaluation_id | رمز غير حساس وفريد للتجربة |
| dataset_kind | synthetic أو real؛ تصريح لا إثبات |
| independent_human_labels | bool: هل gold من بشر مستقلين عن توليد النموذج؟ |
| independent_cases | bool: تصريح استقلال الحالات؛ يحتاج تبريراً خارج الأداة |
| provenance | كائن البصمات السبع أدناه |
| cases | قائمة1..1000 من صفوف الحالات أدناه؛ **المقام المخطط الكامل** |

`provenance` يحوي بالضبط: `code_sha256`, `model_sha256`, `prompt_sha256`, `knowledge_sha256`, `rules_sha256`, `configuration_sha256`, `rubric_sha256`. جميعها64hex صغيرة. قبل التجربة وثّق خارج الأداة أي بايتات حُسبت: code package manifest بأسماء وبصمات المصادر؛ model artifact/manifest مع digest لا tag متغير؛ SYSTEM وOUTPUT_SCHEMA والتغليف؛ الحزمة المثبتة؛ XML؛ خيارات اللغة/window/temperature/context/inventory ودقة الزمن؛ rubric التصنيف والتحكيم. ثبّت manifest قبل inference واحفظ دليلاً مؤرخاً؛ الأداة **لا توفر توقيعاً أو مخزناً غير قابل للتعديل أو إثبات وقت**.

كل case: `case_id`, `batch_id`, `alert_ref`, `cluster_id`, `input_sha256`, `labeler_ref`, `gold`.

- جميع رموز الهوية1..80 من `[A-Za-z0-9_.:-]` وبداية حرف/رقم؛ لا أسماء أشخاص أو مسارات خاصة. alert_ref منA1..A999 بنيوياً، ويجب أن يوجد فعلاً في السياق المدقق (analyst≤100).
- case_id فريد في التجربة، و(batch_id,alert_ref) فريد. كذلك(input_sha256,alert_ref) فريد حتى مع تغييرbatch_id؛ النسخ ترفض بـDUPLICATE_SOURCE_ALERT ولا تحذف صامتاً من المقام. A1 يمكن تكراره في exports مختلفة فقط. هذه مراجعة تصريحات لا كشف لكل نسخة أعيدت صياغتها أو لكل اعتماد خفي.
- input_sha256 بصمة **تصدير الدفعة الخاص**؛ كل حالات batch واحدة تحمل البصمة نفسها. احفظ الربط بين Aref وsource_record خارج Git. تبديل ترتيب التصدير يستلزم سياقاً وmanifest جديدين.
- cluster_id يجمع الحالات المترابطة لنفس الحادث/البيئة؛ لا تقسّم حادثاً إلى clusters مصطنعة للحصول على interval.
- gold كائن `classification` و`mitre_ids`. classification أحد suspicious/likely_benign/insufficient_evidence. MITRE قائمة فريدة≤20 بمعرفاتTdddd أوTdddd.ddd؛ الفحص هنا صيغة لا استعلام ATT&CK، ولا يقيد gold بحزمة التقنيات الثلاث كي لا يُخفي قصور الاسترجاع. القائمة الفارغة مسموحة.

**attempts** قائمة0..1000. لكل case محاولة معلنة واحدة فقط؛ إعادة المحاولة في تجربة مستقلة مع حفظ الأولى، لا انتقاء أفضل نتيجة. كل صف:

`case_id`, `input_sha256`, `provenance`, `status`, `prediction`, `output_sha256`, `latency_seconds`.

- input/provenance يجب أن يطابقا manifest حرفياً.
- status: completed أو failed (فشل تشغيل/timeout) أو rejected (رد مرفوض بالتحقق) أو abstained (امتناع دون finding صالح). غياب الصف ينتج missing؛ ليس status يسمح بإخفاء سجل.
- completed: prediction بنفس بنية gold، output_sha256 إلزامي، وزمن محدود0..86400ث ليس bool أو null.
- غير completed: prediction=null؛ output_sha256 إما بصمة أثر الرد/الفشل المحفوظ أوnull إن لم يوجد؛ الزمن إما قياس فعلي أوnull، لا صفر مختلق.
- finding صالح يصنف insufficient_evidence هو completed ويُحسب في `completed_insufficient_evidence`، لا حالة abstained التشغيلية. يمكن أن يطابق gold إن كان هذا الحكم البشري؛ أعلن rubric قبل التجربة لمنع تحيز المكافأة للامتناع.
- latency هنا مدة القياس وفق protocol، لا MTTD. المسار المباشر analyst يقيس inference_seconds للاستدعاء والتحقق. runner في §11 يقيس بدء العملية إلى انتهائها/قتلها وإعادة حصدها؛ يستثني تجهيز الأدلة والتحقق النهائي وكتابة الملفات. لا تخلط التعريفين في تجربة واحدة.

**reviews** قائمة0..1000؛ يسمح بـ`[]` مع إظهار نقص التحكيم، لا نسبة هلاوس صفرية. كل صف:

`case_id`, `output_sha256`, `reviewer_ref`, `independent`, `claims`, `unsupported_claims`.

المراجعة فريدة ولمحاولة completed فقط؛ بصمة الرد تطابق المحاولة. independent تصريح bool، وليس تحقق هوية بشري. العدّان integers0..1000000 وunsupported≤claims. claims=0 لا تدخل مقام الحالات ذات الادعاءات. لا تمرر gold أوreviews إلى النموذج.

### 10.3 من مخرجات analyst إلى عقد التقييم — فصل التحقق الآلي عن التحكيم البشري

1. ثبّت حالات **التنبيهات المؤهلة** مسبقاً مع خط أساس بشري مستقل وrubric: suspicious قرائن تستلزم تحقيقاً، likely_benign تفسير مشروع مسند، insufficient_evidence لا تكفي الأدلة للتمييز. لا تساوِ annotation أو مستوى الخطورة بحكم الحقيقة.
2. احفظ التصدير الخاص والسياق المنقح والرد الأصلي/الرفض وتوقيت المحاولة وإعداداتها وبصماتها. الربط إلى case عبر batch_id وAref وsource_record، لا اسم الوكيل وحده.
3. في التشغيل الأول فضّل **تنبيهاً واحداً لكل batch**. للمخرجات متعددة المراجع، نفس classification/MITRE ينطبق على كل evidence_ref وفق العقد الحالي؛ إسقاطه إلى الحالات يشترك في الرد والزمن وقد يظلم التصنيف على مستوى التنبيه. أعلن ذلك مسبقاً واحتفظ بـcluster مشترك؛ لا تسمه30 استدعاء مستقلاً.
4. evaluator منفرداً لا يقرأ الملف الأصلي. استخدم runner/export في §11 لإعادة بناء السياق والتحقق من بايتات الأدلة والإسقاط، مع مراجعة أصل البيانات خارج الأداة. لا تسجل offline_context_only كـcompleted؛ المستورد يرفضه. التحقق المحلي ليس توقيعاً أو إثبات تشغيل نموذج بعينه.
5. يقوم محكّم بشري، لا النموذج نفسه، بتقسيم assessment إلى ادعاءات قابلة للفحص ومراجعة كل ادعاء مقابل الأدلة المتاحة للنموذج؛ احفظ rubric والتعليل والخلافات الخاصة. توصية متحفظة أو سؤال ليسا تلقائياً ادعاء حقيقة. لا تستخدم schema-valid أو regex كحكم هلاوس.

### 10.4 المقاييس وحدودها

- `classification_all_planned` و`mitre_exact_all_planned`: عدد الإجابات الصحيحة/كل الحالات المخططة؛ الفاشلة/المرفوضة/الممتنعة/المفقودة **لا تختفي من المقام**، حتى لوgold MITRE فارغة. هذه معدلات نجاح تقديم الإجابة الصحيحة، لا دقة شرطية فقط.
- النظيران completed_only ومصفوفة الالتباس ومقاييسMITRE micro (TP/FP/FN وprecision/recall/F1) شرطية على الردود المكتملة ويجب عرضها مع completion rate. لا تُستخدم وحدها لإخفاء failures. مجموعتاMITRE فارغتان تعطيان exact match، بينما micro ذو مقام صفر=null لا1.
- الهلاوس هنا **نسبة ادعاءات غير مسندة بتحكيم بشري ضمن الردود المحكّمة فقط**؛ يعرض عدد غير المحكم وzero-claim. لا Wilson على مستوى الادعاءات لأنها مترابطة داخل النص. نسبة الحالات ذات ادعاءات غير مسندة لها مقام الحالات المحكّمة ذات claims>0؛ لا تمثل المفقود.
- الزمن: n/mean/median/p95 nearest-rank لكل status على حدة، مع untimed وmissing. n هو عدد الحالات ذات الزمن، لا عدد استدعاءات مستقلة؛ قد يتكرر زمن batch واحدة. لا يعوّض missing بصفر، ولا يعرض CI للأزمنة أو cluster-bootstrap غير مطبق.
- Wilson95 عند التصريح بالاستقلال وفردية cluster وbatch وinput_sha256 لكل حالة فقط؛ غير ذلك null وسببsuppressed. حقلintervals.source_count يبين عدد exports المعلنة المختلفة. حتى عند عرضه فهو مشروط بافتراض Bernoulli غير متحقق وقد تتأثر النتائج بالانتقاء/الترابط غير المعلن. لا interval عنقي بديل تلقائياً.
- gates مثل minimum_30_planned/completed وreal_data_declared وall_completed_reviewed مؤشرات وصفية، لا عتبات قبول جودة أو توقيع اكتمالT-70.

### 10.5 مثال اختبار قابل للإعادة — لا بيانات C4 أصلية

هذا يشغّل fixture من الاختبارات داخل الذاكرة بلا شبكة أو كتابة dataset. القيم والبصمات والمراجعين اصطناعية عمداً؛ **لا تنسخها إلى real manifest أو الرسالة كأدلة تجربة**:

```bash
python3 -I -B - <<'PY'
import runpy
f = runpy.run_path('tests/test_ai_evaluate.py')
m, attempts, reviews = f['fixture'](3)
r = f['e'].evaluate(m, attempts[:1], reviews[:1])
print(r['dataset_kind'], r['counts'])
print(r['classification_all_planned'])
print('acceptance_approved:', r['acceptance_approved'])
PY
```

المتوقع حسابياً: synthetic؛ completed=1 وmissing=2، المقام3 والنجاح1، acceptance=false. هذا اختبار اكتمال المقام لا أداء نموذج. أوامر اختبارات الملفين في §6 تشمل CLI مع temporary fixtures تحت `.git` وتنظيفها. **لا تؤرشف `.git` أو ترفعه**؛ يحتوي مواد SSH خاصة من الجلسة السابقة.


تدقيق2026-09-18: أُنجزت مراجعة آلية ثانية للقطة4f62a15 وأعيد التحقق من ملاحظاتها؛ ليست اعتماداً للإصلاحات اللاحقة أو المعمل. جدول التحكيم في TAKEOVER_AUDIT §8.3. صيغة قواعد CLI الحالية fragments بلا XML declaration؛ الملف الافتراضي يعمل. دعم full XML في077، وعقد سياق Python الناقص في078؛ ليس مسار CLI الحالي. أرقام commits أعلاه checkpoints قبل تجميع الجلسة؛ الرأس النهائي في PR28.

## 11. سجل أدلة AI والمهلة الكلية — تنفيذ محلي 2026-09-18

`ai_agent/runner.py` على Linux/Python stdlib: `prepare` و`export` بلا inference، و`run` يحتاج `--infer`. اختبارات runner اصطناعية؛ لم يُشغّل نموذج حي ولم تُجمع نتائج C4 أصلية. راجع PR28 لعدد اختبارات الرأس النهائي وCI؛ لا تعادل المراجعة الآلية تحكيماً بشرياً.

### 11.1 المدخلات والتثبيت المسبق

ملفات UTF-8 غير فارغة ومحدودة4MiB لكل artifact: تصديرalerts.jsonl، rules.xml، configuration.json، model.json، rubric.txt؛ inventory.json اختياري. manifest وفق §10 منفصل ويجب أن يغطي بالضبط كل Aref مؤهل في الدفعة، لا raw السجلات المستبعدة. يفضّل تنبيه واحد لكل batch في التجربة الأولى. لا تغيّر code/prompt/config/rubric أثناء تجربة مجمدة.

مثال **إعداد اصطناعي**، الاسم ليس نموذجاً مثبتاً:

```json
{"schema_version":1,"model":"INSTALLED_MODEL_NAME","endpoint":"http://127.0.0.1:11434","language":"ar","window_seconds":300,"deadline_seconds":30,"inventory_sha256":null}
```

اللغة ar/en؛ النافذة integer1..3600؛ المهلة رقم محدود أكبر من0 وحتى120ث؛ bool مرفوض. ملف model.json له المفاتيح فقط: schema_version=1، name مطابق للإعداد، sha256 بصمة weights التي يصرح بها المشغّل (64hex صغيرة). **حقل C4 model_sha256 هو بصمة بايتات ملف الوصف model.json، لا إثبات بصمة الأوزان المحملة في Ollama.** النموذج ورخصته وهويته التشغيلية تحتاج تحققاً مستقلاً. inventory_sha256 يجب أن يطابق بايتات الجرد المعتمد؛ الملف والبصمة مطلوبان معاً أو كلاهما غائب. حد freshness24h عند التحضير، لا عند قراءة أرشيف قديم.

تشغيل التحضير offline من جذر المستودع؛ `/approved/private` أمثلة لدى المشغّل لا مسارات أنشأتها الجلسة:

```bash
python3 -I -B ai_agent/runner.py prepare \
  --alerts /approved/private/alerts.jsonl \
  --rules wazuh/manager/rules/local_rules.xml \
  --configuration /approved/private/configuration.json \
  --model-record /approved/private/model.json \
  --rubric /approved/private/rubric.txt
```

أضف `--inventory /approved/private/inventory.json` عند وجوده. النتيجة input_sha256، provenance بسبع بصمات، وeligible_alerts(ref/source_record)، وinference_performed=false. استخدمها لتثبيت manifest الخاص قبل التشغيل مع gold بشري وcluster/labeler؛ لا تنقل gold إلى النموذج. `prepare` لا يحفظ السياق ولا يُشغّل أو يُنزّل نموذجاً. لا تحفظ datasets أو المراجعات أو مخزن الأدلة في Git.

### 11.2 تشغيل محاولة واحدة وأرشفتها

المشغّل ينشئ store فارغاً خاصاً0700 في مسار موثوق. الأسلاف root/current UID وبلا group/other write؛ لا `/tmp` ولا symlink. الملفات0600، عادية، رابط واحد؛ ACLs والنسخ الاحتياطية والاحتفاظ والحصة القرصية مسؤوليات تشغيلية. القفل flock على directory inode، وO_EXCL يمنع استبدال محاولة قديمة.

```bash
python3 -I -B ai_agent/runner.py run \
  --alerts /approved/private/alerts.jsonl \
  --rules wazuh/manager/rules/local_rules.xml \
  --configuration /approved/private/configuration.json \
  --model-record /approved/private/model.json \
  --rubric /approved/private/rubric.txt \
  --manifest /approved/private/manifest.json \
  --store /approved/private/evidence_store --batch-id BATCH_ID --infer
```

- قبل إطلاق العملية: فحص manifest/provenance/coverage، تجميد manifest.json حرفياً، إنشاء directory دفعة مشتق SHA256 من evaluation_id/batch_id، نسخ المدخلات والمعرفة المثبتة وcode.json/prompt.json/context.json، ثم intent.json. كل كتابة fsync للملف **وللدليل** قبل استدعاء المزود. code.json يحمل بصمات أربعة ملفات Python لا نسخها؛ احتفظ بإصدار الكود الأصلي.
- العملية `python -I -B` ببيئة دنيا، دون shell أو أسرار موروثة؛ argv يحوي مسارات config/context فقط، لا محتوياتها أو gold/manifest/rubric. ليست sandbox تمنع شفرة Python خبيثة بنفسUID؛ worker شفرة موثوقة.
- مهلة monotonic كلية تغطي العملية/الاتصال/القراءة، فلا يمددها dripping stdout. سقف captured output هو128KiB+1 لإثبات تجاوز الحد. stdout هنا **محتوى جواب النموذج UTF-8** بعد تحقق Ollama من envelope، وليس HTTP body الأصلي؛ فشل النقل قد يترك output.bin فارغاً ولا يحتفظ بنص خطأ خاص.
- output.bin ثم terminal.json بإصدار schema_version=2 يحوي intent hash، status/reason، returncode، latency_seconds، output hash، وvalidation_code. الأخير كود من قائمة ثابتة لأول خطأ تحقق أو INVALID_MODEL_RESPONSE للخطأ غير المعروف؛ null للمكتمل/فشل التشغيل. لا نص exception حر في metadata؛ export يعيد احتساب الكود ويرفض اختلافه. ملفات terminal v1 تُقرأ بإصدار الكود الأصلي فقط، لا تحويل الأرشيف الصامت. completed يعني فقط مخططاً ومراجع صحيحة؛ failed لأخطاء التشغيل/المهلة، rejected لجواب غير صالح. insufficient_evidence صالح يبقى completed حسب §10.
- الزمن من بدء worker إلى نهايته وتنظيفه، مشترك بين حالات batch؛ لا يشمل preflight/fsync/التحقق النهائي، ولا يثبت دقة الساعة. يوجد socket timeout30ث أيضاً؛ deadline ليس ضمان hard-real-time ولا يُلزم الخادم بوقف computation بعد قطع العميل.
- يستخدم Linux waitid مع WNOWAIT لملاحظة الخروج دون تحرير PID قبل إرسال killpg؛ يُحصد العامل بعد إرسال الإشارة لمجموعته، لا Ollama server. يجب أن يكون SIGCHLD افتراضياً ولا يوجد waiter آخر للعامل؛ Python embedding ليس sandbox ضد كود موازٍ يحصد أبناءه. SIGTERM/SIGINT أثناء العمل يؤديان إلى التنظيف؛ حتى الإشارة الأولى أثناء التنظيف تؤجل بقناع pthread_sigmask حتى إغلاق stdout واستعادة القناع. فشل kill/wait المحدود يسجل WORKER_CLEANUP_FAILED بلا prediction ولو كان الرد صالحاً؛ ليس إثباتاً أن العملية انتهت. إشارة ثانية لا تقطع التنظيف. لا يمكن للبرنامج ضمان التنظيف عند SIGKILL للوالد أو انقطاع الطاقة؛ يلزم إشراف عمليات خارجي قبل نشر دائم. نسل يغادر process group ليس sandboxed، وreaping الأحفاد مسؤولية init/subreaper.

### 11.3 الاستيراد والتعافي دون إعادة تشغيل

```bash
python3 -I -B ai_agent/runner.py export \
  --store /approved/private/evidence_store \
  --manifest-sha256 INDEPENDENTLY_RECORDED_MANIFEST_SHA256
```

بصمة manifest المتوقعة تؤخذ من السجل المعتمد خارج store، لا من ملف ربما عُدّل. `--attempts-only` يعيد array ملائماً لملف attempts في evaluate.py؛ بدونه يعيد envelope مع batches وحدود التحقق. export قراءة فقط ولا يتصل بالنموذج. يحتفظ evaluator بكل مقام manifest بما فيه دفعات لم تبدأ.

| الحالة المحفوظة | نتيجة الاستيراد |
|---|---|
| لا directory للدفعة | لا attempt؛ evaluator يحسبها missing |
| directory جزئي أو intent تالف/غائب | رفض التصدير، لا إخفاء المحاولة ولا إعادة تشغيل تلقائية |
| intent سليم بلا terminal | failed / INTERRUPTED_AFTER_INTENT؛ prediction/output_sha256/latency=null |
| output يتيم بلا terminal | يبقى failed؛ فحص النوع/الصلاحيات/الحجم فقط، unverified_artifacts=[output.bin] وstored_artifact_bytes_verified=false |
| terminal جزئي أو hash/schema/context/code غير مطابق أو ملف غير متوقع | رفض التصدير صراحة |
| terminal سليم | إعادة تحقق جواب النموذج وإسقاط classification/MITRE على كل evidence_ref مع نفس output hash والزمن |

التحقق يعيد بناء السياق من نسخ المدخلات عند prepared_at ويقارن كل بايت، ويشترط نفس بصمات الكود والمعرفة الحالية. استعمل إصدار الكود الأصلي لاستيراد تجربته؛ تعديله يستلزم تجربة جديدة، لا تحوير الأرشيف. توجد سلامة محلية لا توقيع تشفيري: نفسUID يستطيع تزوير سجل متسق أو حذف ملفات؛ missing/interrupt ليس إثباتاً لسبب الانقطاع. stored_artifact_bytes_verified يغطي المرفقات الموجودة المرتبطة بالـhash، **لا** أصالة المصدر أو الزمن أو استقلال البشر أو حقيقة تشغيل النموذج؛ الأعلام model_runtime_identity_verified/human_independence_verified/acceptance_approved تبقىfalse.

لا overwrite أو retry لنفس batch حتى لو فشل التحضير. الاحتفاظ بالأولى ثم تجربة جديدة صريحة بإقرار الحالات هو طريق إعادة المحاولة، لا انتقاء الأفضل. أكواد CLI:0 لنجاح prepare/export أوcompleted، 2 لمحاولة محفوظة failed/rejected، 1 لرفض preflight/مخزن/import برسالة عامة، 130 لإلغاء CLI. لا تضف طبقة تنفيذ AR لهذا المسار.

### 11.4 ما بقي قبل تجربة أصلية

مراجعة تقنية/إحصائية مختصة، اختيار نموذج ورخصة وموارد وهوية تشغيلية، اختبار transport فعلي وخصوصية/حقن تعليمات، جرد معتمد، rubric و30 labels بشرية مستقلة، ثم C4 مع المخرجات والفشل والتحكيم. SIGKILL/انقطاع الطاقة وحصة التخزين وinit/ACL والاحتفاظ مسؤوليات نشر تحتاج اختباراً أصلياً. المسار المباشر analyst.py لا يكتسب مهلة runner تلقائياً. لا إغلاق T-70 أو بوابات السحابة/Windows/PILOT من اختبارات هذا القسم.


## 12. تحكيم المراجعة الإضافية — 2026-09-18

[تقرير المراجع الآلي](https://www.genspark.ai/agents?id=6e1a4dd4-5fe5-55a0-ab98-7637fd35d393) للقطة09e91e2 (وصول خاص للمالك). انتهى التقرير؛ **مراجعة ساكنة للنص المرفق فقط**، لا clone ولا اختبار شُغّل عند المراجع. اختبارات وإعادة إنتاج هذا القسم أجريت هنا علىbe5160c ثم الإصلاحات74ddb8f/2e316e3 (checkpoints قبل تجميع الجولة). لا موافقة بشرية أو شهادة أمان. لا تُستعمل عبارة finished/succeeded للمهمة الآلية كدليل صحة كل ادعاء فيها.

| بند المراجع | التحكيم والدليل المحلي |
|---|---|
| K1 ملفات إضافية داخل batch | صحيح للقطة القديمة؛ أصلح بالفعل قبل التقرير فيbe5160c؛ اختبار UNEXPECTED_BATCH_ENTRY ناجح. |
| K2 output يتيم وعلم verified | صحيح للأثر اليتيم في09e91e2؛ عولج قبل التقرير بعلمfalse وقائمةunverified_artifacts وفحص الملف. لا تعهد مسبق بنتيجة لم تُولد بعد داخلintent؛ terminal يربطها لاحقاً. متجر بلا محاولات ليس ادعاء اكتمال: attempts=[] وmissing من manifest؛ العلم عن البايتات الموجودة فقط. |
| K3 إلغاء/جرد دون اختبارات | أصاب غياب اختبار signal فعلي في09e91e2؛ أصبح موجوداً فيbe5160c. ادعاء غياب اختباراتload_inventory عامة غير صحيح: tests/test_ai_knowledge.py يحوي freshness/hash/duplicates/unmatched؛ لم يرفق للمراجع. أضيف أيضاً تأجيل أول إشارة تقع أثناء cleanup. |
| N1 رفض الدفعة وغياب سبب الرفض | قبلنا التشخيص: validation_code مقيد داخلterminal v2 وإعادة تحقق عندexport، مع اختباراتprivacy/tamper. رفض الدفعة كاملة مقصود لمنع انتقاء الجزئيات، لا قبول كلfinding منفرداً أو حذف الحالات المتعثرة. الترابط الحالي لنفسmanager/agent لا ادعاء L2 متعدد الأجهزة. |
| N2 socket30 مقابل deadline حتى120 | حقيقتان منفصلتان، لا خرق سقف المهلة: socket timeout30 قد ينهي محاولة مبكراً، بينما سقف العملية يمنع التنقيط من تمديدها إلى ما لا نهاية. ادعاء أن كل محاولة تنتهي عند30 أو أن deadline يعد بانتظار120 غير صحيح. timeout نقل يُسجل حالياً WORKER_FAILED ولا يُميز عن بقية أخطاء النقل؛ هذا قيد تشخيص موثق، لا DEADLINE_EXCEEDED ملفق. لا تعديل العقد لزيادة timeout بلا حاجة. |
| N3 abstained غير صادر منrunner | صحيح ومقصود: evaluator العام يدعم سجلاتabstained، لكن runner يقبل insufficient_evidence صالحاً كـcompleted؛ prose/empty findings مرفوضة ولا يُخمّن قصد الامتناع. اختبار الإسقاط يؤكد counts؛ لا حذف حالة evaluator أو تغيير schema خفية. |
| N4 killpg بعدreap وفشلwait | أُعيد إنتاجهما: returncode مسجل قبلkillpg فيمسار النجاح؛ wait ثانٍ مصطنع يرفعTimeoutExpired وstdout لم يغلق. أصلح بـWNOWAIT ثمkillpg ثمwait، مع finally لإغلاقstdout، وتأجيلsignals وحالةcleanup_failed. اختبارات حقيقية لترتيب الخروج والنسل وخروجsignal؛ اختبارwait الفاشل حقن خطأ، لا جهاز D-state فعلي. لم نجبر PID reuse فعلياً. اقتراحpoll guard وحده رُفض لأنه يحصد القائد ويترك نسل المجموعة. |
| N5 سجل منخفض المستوى لكنه تالف | fail-closed مقصود للتصدير المحدود المجمد. لا skip صامت ولا تغيير المقام؛ صحح التصدير قبل تجميدmanifest. لا نطلب prefilter≥7 كي نخفي مدخلات غير سليمة. |
| refinement غيابintent | الرفض العام آمن ومقصود؛ لا ضرورة لإدخال اسم مسار خاص فيرسالة الخطأ. غيابterminal بعدintent مختلف فيالعقد ولا نساويهما. |
| الادعاء بأن rules.xml وmitre_subset.json غير متتبعين | رُفض: git ls-files يثبت الملفين متتبعين. لا حاجة للوصول إلى ملفات مختبر خاصة لإعادة اختباراتrunner. |

التحقق بعد الإصلاح: **59 runner و366 اختباراً إجمالاً محلياً ناجحاً** وALL CHECKS PASSED. 13 اختباراً إضافياً بعد353. آخرHEAD وCI الخاص به فيPR28، لا إعادة استخدام CI التاريخي. بقيت تجربةtransport/model فعلية وقياس الموارد والخصوصية والتحكيم البشري وC4، ونشر تحتinit/ACL/حصص/retention؛ لا تنفيذ حي أو نموذج في هذه الجولة.


## 13. التقرير الخاص المرتبط بالأدلة — report.py

`ai_agent/report.py` أداة قراءة offline: تستدعي export والتحقق من المخزن (§11.3)، ثم evaluator (§10)، لا نموذج أو شبكة أو تنفيذ AR. تشترط بصمة manifest المسجلة خارج المخزن، وملف تحكيم خاص ببصمة مستقلة **أو** تصريحاً صريحاً بغياب التحكيم. استخدم إصدار الكود الموافق للأدلة؛ reporter له بصمة منفصلة ولا يغير قائمة كود runner المجمدة.

من جذر المستودع، عيّن المسارات والبصمات من سجل التجربة المعتمد. الأمثلة لا تنشئ دليلاً أصلياً:

```bash
# Without reviews: absence remains visible, never zero hallucinations.
python3 -I -B ai_agent/report.py \
  --store /approved/private/evidence_store \
  --manifest-sha256 INDEPENDENTLY_RECORDED_MANIFEST_SHA256 \
  --no-reviews --format json

# With independent review-file byte binding:
python3 -I -B ai_agent/report.py \
  --store /approved/private/evidence_store \
  --manifest-sha256 INDEPENDENTLY_RECORDED_MANIFEST_SHA256 \
  --reviews /approved/private/reviews.json \
  --reviews-sha256 INDEPENDENTLY_RECORDED_REVIEWS_SHA256 \
  --format html
```

ملف reviews هو مصفوفة عقد §10: case_id/output_sha256/reviewer_ref/independent/claims/unsupported_claims. يجب أن يطابق الجواب المستورد وأن يكون ملفاً عادياً خاصاً أحادي الرابط في مسار موثوق، بلا symlink. لا تضع هوية بشرية حقيقية في أمثلة Git. قبول hash أو independent=true لا يثبت هوية المحكم أو استقلاله.

المخرج إلى stdout؛ احفظه فقط في مجلد خاص موجود وخارج FIM وGit. عند إعادة التوجيه استخدم `umask 077` و`set -C` لمنع استبدال ملف موجود، ثم افحص exit status قبل اعتماد الملف (قد يترك shell ملفاً فارغاً عند الرفض). لا تحفظ فوق ملفات store ولا ترسل JSON أو HTML إلى خادم عام تلقائياً. الملفات القديمة ذات صلاحيات عامة لا تصبح خاصة بمجرد umask.

- exit0: تقرير مكتمل حسابياً؛ ليس نجاح C4 أو اعتماد SOC. exit1: خطأ تحقق برسالة عامة وبدون تقرير جزئي؛ أخطاء argparse ترجع2.
- JSON يحتفظ بمخرجات evaluator، ويفصل `evidence_verification` عنها؛ علم `artifact_contents_verified=false` في evaluator لا يُحوّل خفية إلى true.
- HTML عربي RTL بلا JavaScript أو خطوط/صور/روابط/نماذج خارجية، وCSP يمنع المصادر الخارجية. تُهرب القيم الديناميكية. يعرض المقامات والفشل والرفض والمفقود، ونقص التحكيم، والأزمنة المجهولة، وشروط Wilson والمرفقات اليتيمة.
- لا يحتوي العرض على raw logs أو gold أو أسماء المحكمين أو نص تحليل النموذج؛ ليس واجهة L1 كاملة أو نظام موافقة. معرفات الحالات والتوقيت والبصمات قابلة للربط، لذا التقرير خاص حتى بعد التنقيح.
- `stored_artifact_bytes_verified` يصف المرفقات الموجودة المرتبطة بالبصمات، لا اكتمال العينة أو أصالة المصدر أو ساعة موثوقة أو تشغيل الأوزان المعلنة. تبقى أعلام القبول واستقلال البشر وهوية النموذج false.
- 16 اختبار تقرير اصطناعياً: فساد المخزن، مراجعات hash-bound، خصوصية الملفات، missing/unknown latency/orphan، escaping/CSP وCLI بلا نموذج. اجتاز التحقق الكلي 434 اختباراً بعد إصلاح Telegram في2026-09-18؛ نتائج كل HEAD فيPR28. لا استدلال أو C4 أصلي ضمن هذا التحقق.

## 14. متابعة عقد التشغيل واختبارات الاستلام — 2026-09-22 [AI]

أُعيد فحص النسخة8170031: runner/importer/report موجودة،469 اختباراً وCI ناجحان. هذه متابعة تنفيذ لا إعادة إنشاء. الإصلاحbd67699 والاختبارات9084325 يرفعان المجموع إلى **482، منها72runner**؛ CI push[35779096256](https://github.com/MoTechSys/my-bro/actions/runs/35779096256) على908432575d9eae6b4ab78cad5ea2deaba8437f4f ناجح3.12/3.13 وقرئت سجلات العدد. رأس الوثائق النهائي وCI الخاص به فيPR28، لا تُنسب نتيجة9084325 تلقائياً لأي تعديل لاحق.

### 14.1 التعديل الضروري وحدوده

ISSUE-092: الإلغاء داخلPopen أو قبل إسناد نتيجته كان يفلت من cleanup لأنproc لم يُسند بعد. اختبار جديد بحقن إشارات حقيقية عند هذين الحدين يفشل في4subcases علىالدالةالقديمة. `launch_cancellation_guard` يثبت معالجاً مؤقتاً يؤجل أولSIGINT/SIGTERM حتى امتلاك الكائن، ثم يعيد المعالج الأصلي ليجري killpg قبلreap وإغلاقstdout. لا يحجب الإشارات عبرfork/exec ولا يستخدمpreexec_fn؛ يستعيد القناع والمعالجات عندفشل الإطلاق أيضاً.

عقدembedding الآن صريح: التشغيل من **main thread** وملكية حصرية لمعالجات الإشارات وحصد الأبناء؛ non-main-thread يرفضقبلPopen. SIG_IGN يبقىمتجاهلاً، وSIG_DFL المستلمداخلنافذةالإطلاق يتحولإلىKeyboardInterrupt للتنظيف بدلاًمنإنهاءالأب فوراً. CLI يثبت أصلاًمعالجإلغاءويرجع130؛ الاستيراديحفظINTERRUPTED_AFTER_INTENT بزمن/ردnull ولايعيدالاستدعاء. هذا لا يمنعSIGKILL أوتعطلOS أوانتظاراتPopenغيرالقابلةللقطع؛ ليسحداًhard-real-time أوsandbox. لا يُقتلخادمOllama.

**لم تتغير schema** لـC4 أوintent أوterminal v2. code_sha256 يتغيرمعالكود؛ احتفظبنسخةالكودالأصليةلإعادةاستيرادالأرشيف، ولا تعِدكتابةالبصماتليقبلهابإصدارجديد. محاولةواحدةلكلbatch كماكانت؛ لاتغييرللمقامات أوالتحكيم.

### 14.2 تغطية الشروط الحالية

| الشرط | اختبار/دليل محلي | الحد الباقي |
|---|---|---|
| بصمة بايتات أصلية | CRLF/LF لهماJSONمتطابق وبصمتانمختلفتان؛التبديليرفضقبلالاستدعاء؛تلاعبartifactsيعادتحققه | سلامةبايتات لاأصالةمصدرأوتوقيع |
| case/batch/ref/source_record | بعدتصفيةlevelمنخفض وتكرارسجلمتطابق تصبحA1→record2 وA2→record4؛ترتيبcases/findingsلايغيرالإسقاط؛تزويرsource_record معإعادةhashيرفض | source_record ترقيمالسجلاتغيرالفارغةبعدread_alerts، لارقمسطرملفبمافيهالفراغات؛ تخصيصgoldالبشري مسؤوليةالمشغّل |
| عزل الدفعات | A1 فيدفعتينبمصدرينومخرجينمختلفين؛تبديلdirectoriesيرفضINTENT_BINDING_MISMATCH | reserializedexports واعتمادالمحتوىيحتاجانتدقيقاًبشرياً، لايدعيhashكشفكلتكرار |
| failure/retry/denominator | timeout محفوظقبلنجاحدفعةأخرى؛إعادةالأولىترفضدونworker؛1failed+1completed+1missing والمقام3 | لاانتقاءأفضلنتيجة؛إعادةتجربةصريحةلاتمحوالمحاولةالأصلية |
| interruption/recovery | إلغاءإطلاقفعليثمexportمتكررoffline؛حقنOSError بعدكلartifactمنشور | intentغائب/جزئيرفض،سليمبلاترمينالفشل،outputيتيمغيرمتوثق؛terminalسليممنشورقبلخطألاحقيبقىمرجعالحالة؛ليسفصلاًكهربائياًحقيقياً |
| رفض/امتناع | النثرالرافضمحفوظكـrejected والمقامكامل؛insufficient_evidenceصالحcompleted؛evaluatorيدعمabstainedللصيغةالمطبعة | runnerلايخمنabstainedمننصحر؛تغييرذلكيحتاجعقداًمصرحاًولايفعلهذهالجولة |
| privacy/authority | اختباراتسابقةتؤكدغيابgold/rubric/raw/الهوياتعنcontext/argv وبيئةالعامل؛metadataأكوادمقيدة؛لاسلطةتنفيذ | sameUIDموثوق؛النصالمولدخاصوقديحتاجتنقيحاًبشرياً؛schema/MITREليسا صحةاستنتاج |

```bash
# From the actual repository checkout; all fixtures are synthetic and temporary.
cd /home/user/webapp/my-bro
python3 -B -m unittest discover -s tests -p test_ai_runner.py
TMPDIR=/home/user/webapp/my-bro/.git PYTHONDONTWRITEBYTECODE=1 bash scripts/validate/validate_all.sh
git diff --check
```

### 14.3 الخطوة التالية القابلة للتنفيذ

اختبارtransport محلي اصطناعي مضبوط عبرCLI والعامل الحقيقي: تأخرheaders،bodyمنقط،قطعقبل/بعدheaders،حجمزائد،والتقاطrequestيثبتعدمإرسالgold/raw. لم يُشغّلHTTPserver أوOllamaأصلي بهذهالجولة؛ subprocessالاصطناعي لايساوياختبارخادمOllama. ثممراجعةمختصة واختيارنموذج/رخصة/موارد/هويةوجردمعتمد و30labelsبشرية وتحكيمC4. المراجعةالحاليةذاتية فقط، ومراجعات2026-09-18 السابقةمنتهيةلايعادطلبهاكأنهاعالقة. بواباتالسحابة068/الاستعادة/reboot/daemon/canary/Windows/PILOT مستقلة؛ لاكتابةخارجworkspace.

## 15. النقل HTTP الفعلي الاصطناعي — إصلاح8e0916a

`tests/test_ai_transport.py` يطلق خادم loopback اصطناعياً والعامل وCLI الحقيقيين؛17 اختباراً، لا Ollama weights ولا استنتاج أمني أصلي. يثبت request capture أن gold/rubric/raw logs لا تدخل سياق النموذج في fixtures المختبرة. الخادم يغلق بعد الاختبارات ولا يمثل واجهةSOC.

أُعيد إنتاج رد `Content-Length` أكبر من البايتات الفعلية لكن الجسم الموجود JSON تام: `HTTPResponse.read(limit)` لا يرفع دائماً `IncompleteRead`. أصبح المحول يتحقق من status200، framing ورقمContent-Length وحجمEnvelope وطولالجسم صراحة. يرفض TE+CL، وتكرارCL/TE، وencoding غيرidentity، وTransfer-Encoding غيرchunked؛ يدعمchunked الصحيح ويرفض الناقص. رفضCL المكرر حتى المتطابق **اختيارمحليأشدمنRFC** وليس ادعاء أنRFC يمنعكلالتكرارات.

يبقى التحقق منUTF-8/JSON الصارم وdone=true وassistant/message/content ورفضtool_calls. فشل النقل يصل إلىjournal كـfailed/WORKER_FAILED دون نص المزود، بينما schemaرفضٌ مستقل. dripping headers/body لا يمددdeadline العامل؛ اختبارات deadline0.6s تسمح بزمنجداريأقلمن4s للتشغيلوالتنظيف، لا وعدhard-real-time.

قيد لا نخفيه: EOF في close-delimited response بلاCL/TE لا يثبت أنجسماًذاJSONصالحلم يُقطع. المسارالمباشر `analyst --infer` يملكsocket timeoutفقط؛ استخدامه لا يمنحهعزلومهلةrunner تلقائياً. هويةالنموذجوالرخصةوالأوزانوالجردوالتحكيمالبشري ليستمستنتجةمننجاحHTTP/schema.

المصادرالمؤرخة والأرشيفات: `research/analyzed/2026-09-22_completion_research.md` وreceipts/أرشيفاتgzip فيinbox. RFC9112 §6.3/§8 وOllama chat وPythonHTTPResponse.read المحلي؛ ليس امتثالاً عاماً. مراجعةd1598bba للنصعند2a50f77شملتالمحول، بلااختباراتعندالمراجع، وتحكيمهافيtests/README §M2-A.

## 16. تحكيم مراجعة runner المستقلة ee00bee5

[المراجعة](https://www.genspark.ai/agents?id=ee00bee5-a873-5abe-9b12-4a9957489528) انتهت (finished/has_error=false). نطاقها `5e98757cadbcfc71860cefe8b139fafb74c4af26`، runner واختباراته؛ بعضdependenciesلم تُقرأ كاملةعندالمراجع. JSONالأصليوالنصالنهائيفي `research/inbox/2026-09-22_independent_review.*`. لا تشملإصلاحHTTPاللاحقأوsourceobserver تلقائياً، ولا تعدمراجعةبشرية.

| البند | حكم المنفذ والدليل |
|---|---|
| F1 تكرارA1داخلbatch | مرفوض: evaluate يتحققمن(case_id) ومن(batch_id,alert_ref) قبلworker/كتابةالأدلة. اختبارreview_f1 يثبتDUPLICATE_CASE_OR_BATCH_REFوعدمأيworker/artifact. لا إضافةفحصمكرربناءعلىdependencyلم يقرأهاالمراجع. |
| F2 تطبيعCRLF/BOM | مرفوض للـreader: analyst.read_file يفتحbinary ثمUTF-8 strict؛ test_review_f2 يحفظBOM/CRLF/CR بايتياً. لا نزعمأنparserيقبلJSONبـBOM. اختبارالبصمةالأصلييبقىموجوداً. |
| F3 final symlink والـpath race | فرضيةاتباعfinal symlink مرفوضة: O_NOFOLLOWموجودواختبارread_bytesيفشل. مخاطرparent replacement وكاتبsameUIDحدودمعلنة؛ ليسالاختبارشهادةأصالةولاsandbox. |
| F4 القفل طوالالعامل | تصميممقصود: LOCK_NBيرفضفوراًولاينتظر120ث؛ يحميعمليةexportمنإساءةتصنيفintentجاريةكمنقطعة. تحريرالقفل مبكراً يحتاجعقدconcurrencyوجرّبالأدلة، لا إصلاحسريع. |
| F5 testtempداخل.git | ملاحظةتنظيممقبولة: في60102d6 نُقلtemporaryrootلاختباراتrunnerإلىworkspace. اختباراتsourceالجديدةأيضاًخارجه. بقيةالحزم القديمةلمتنقلجميعها؛ لمتُقرأأوتؤرشفموادSSH. |
| F6 تشخيصعام | قيدobservabilityصحيحومقصودلحمايةالخصوصية؛ validation_codeالمقيدموجود. تمييزinternal faultsبأكوادمحدودةتحسينمحتمل، لا كشفexception/providertext. لمندعِتنفيذه. |
| F7 latency≤120 | اقتراحمرفوض: latencyيشملstartup/cleanupوقديتجاوزdeadline. فرض120سيرفضقياساًحقيقياً؛ hashليسإثباتصدقزمنالمشغّل. لا تقليممدةحقيقيةلتوافقالمهلة. |
| F8 أولإشارةفقط | عقدصريحومختبر: أولcancellationيعاد، SIG_IGNمحفوظ وSIG_DFLيتحولإلىKeyboardInterruptداخلنافذةالإطلاق. ليستقائمةانتظارلكلالإشارات. |
| F9 cleanupبعدdeadline | مقبولكقيدموثق؛ حدcleanup2sوفشلهلايخفى. لا hard-real-timeولااستنتاجهويةPIDأونسليغادرالمجموعة. |
| F10 WNOWAIT | لمتثبتفجوةجديدة؛ بقاءkillpgقبلreapمعملكيةحصريةللأبناءوSIGCHLDافتراضي، والاختباراتالموجودةلترتيبالتنظيفباقية. |

75 اختبارrunnerناجحة؛ثلاثةجديدةلـF1/F2/F3. مجموعالمشروع545علىe8aef17. تحكيمالكاتبليس«مراجعةمستقلةثانية»؛ المستقل هوالتقريرالمؤرشفوالفحصبعدهإعادةإنتاجذاتية. AIيبقىexecution_authority=none. لا inferenceحقيقيأو30labelsأونتائجC4أصليةفيهذهالجولة.
