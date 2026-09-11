# scripts/lab — تثبيت المكونات على Kali (kali1)
| سكربت | UC | الوظيفة |
|-------|----|---------|
| `install_auditd_kali.sh --lab` | 05 | auditd + قواعد execve من `wazuh/auditd/wazuh.rules` |
| `install_yara_kali.sh --lab SOURCE_SHA256 RULES_SHA256` | 07 | بناء YARA 4.5.5، إصلاح libyara، قواعد VALHALLA إلى `/var/ossec/etc/yara/rules/` |

شغّل كمستخدم المعمل غير root؛ sudo لخطوات التثبيت المعلنة فقط. البصمات مستقلة موثوقة؛ snapshot وrollback قبل أي تغيير. لم تختبر هذه المثبتات أصلياً هنا؛ راجع SECURITY_REVIEW §5–7.

## صحة الوكيل ودورة حياته — T-62، مرشح يحتاج قبول نشر

`agent_health.py` قراءة فقط؛ `agent_lifecycle.py` يغيّر حالة الخدمات ولا يعمل دون `--lab`. لا يستدعي أي منهما Docker أو SSH أو ينشئ حاوية، ولا يقرأ كلمات المرور أو يسجّلها. الكود مستقل عن حزم Python خارج المكتبة القياسية، Linux/Python 3.9+ مع zoneinfo متاحة؛ الاختبارات المحلية الحالية على Python 3.13. لا تعني هذه المتطلبات أن Windows مدعوم.

### فحص الصحة

داخل PID namespace الخاص بالوكيل:

```bash
python3 -I -B /opt/soc/agent_health.py --state-timezone UTC
python3 -I -B /opt/soc/agent_health.py --state-timezone UTC --progress
```

يمكن تمرير محتوى `agent_health.py` إلى `python3 -I -B -` عبر stdin للفحص دون تثبيت ملف، كما جرى في المعمل. المسار `/opt/soc` هنا مسار نشر مقترح، **لم يُنشأ على الخادم بهذه الجلسة**.

- يقرأ `/proc` وملفَي agentd/logcollector state دون `source`/eval أو تنفيذ أوامر من السجلات. يرفض FIFO/symlink النهائي والملف المتجاوز 1MiB.
- يشترط init معروفاً كـPID1، وخدمة حية واحدة لكل daemon مطلوب، ولا يحتسب zombie كخدمة حية. يتحقق من اسم العملية وargv0 ومن ثبات start_ticks؛ لا يعتمد على `ps | grep` أو ملف PID وحده. argv0/comm ليسا مصادقة ضد خصم يتحكم في عمليات الجهاز.
- حداثة ACK لا تتجاوز60ث ولا تقع مستقبلاً، واتصال connected، ومخزن رسائل فارغ. يشترط مصدر `process list` الموثق في إعداد المشروع، وstate حديثة ضمن120ث وبدون drops.
- هذه حدود تشغيل محافظة للمعمل، لا SLO عالمي لكل نشر Wazuh. مثال: تعطيل anti-flooding يجعل msg_buffer فارغاً بحسب التوثيق الرسمي؛ هذا النمط غير مقبول في ملف إعداد المعمل الحالي، ولا يُحوّل الفراغ إلى صفر بصمت.
- `--progress` يأخذ عينتين بفاصل65ث ليتجاوز دورة نشر logcollector الافتراضية60ث. يرفض ثبات/reset العدادات أو تبدل هوية الخدمة أو قفزة الساعة. التحقق من progress مستقل عن سلامة PID1.
- المخرجات JSON؛ exit0=اجتياز فحص الصحة المطلوب، exit1=رفض الصحة، exit2=خطأCLI، exit130=إلغاء. `canary_verified` و`deployment_approved` دائماً false. لا تنتج هذه الأداة MTTD أو شهادة end-to-end.
- يجب أن تطابق `--state-timezone` المنطقة التي استخدمتها عمليات الوكيل عند كتابة state؛ لا تستنتجها من timezone المضيف أو من صياغة JSON.

### إدارة دورة الحياة

**قبل النشر:** طبّق بوابات حفظ الحالة والهوية والاستعادة في `docs/lab/CLOUD_ENV_ACCESS.md §9.5`. الحاوية الحالية بلا mounts؛ لا تعِد إنشاءها عمياء. هذه الملفات ليست مثبتاً ولا ترحيل بيانات، ولا تعوّض إعداد ossec.conf أو التسجيل لدى المدير.

يثبّت المشغّل الملفين معاً في مسار root-owned محمي مثل `/opt/soc/` بعد مراجعة البصمات، ويستخدم إعدادات Docker التالية ضمن تعريف الحاوية الذي يحفظ الحالة بالفعل:

```yaml
# Settings only: NOT a complete compose file or a migration command.
init: true
entrypoint: ["/usr/bin/python3", "-I", "-B", "/opt/soc/agent_lifecycle.py", "--lab"]
restart: "on-failure:3"
stop_grace_period: 180s
healthcheck:
  test: ["CMD", "/usr/bin/python3", "-I", "-B", "/opt/soc/agent_health.py", "--state-timezone", "UTC"]
  interval: 30s
  timeout: 10s
  start_period: 240s
  retries: 3
```

هذا بديل entrypoint، لا إضافة فوق `/entrypoint.sh` القديم. يلزم agent مُعد مسبقاً وApache موجودان. لا `--pid=host` ولا Docker socket داخل الحاوية ولا صلاحيات privileged تلقائية.

- يرفض العمل خارج Linux/root أو إذا لم يكن ابناً مباشراً لـPID1/init معروف. يتحقق من حماية ملفات التثبيت وأسلافها، ويرفض خدمات Wazuh قائمة لتجنب تشغيل هويتين/مجموعتين معاً. حماية ACL وسلسلة توريد الحزم مسؤولية النشر، لا ضمان من اختبار path وحده.
- يبدأ Apache ثم `wazuh-control start` بأوامر argv ثابتة وبيئة محددة وTZ=UTC؛ كل بدء محدود45ث. لا يعدّل الإعدادات، ولا يحذف PID files، ولا يعيد تسجيل الوكيل.
- يراقب الصحة كل5ث؛ startup grace حتى120ث **بعد انتهاء أوامر البدء**، ثم ثلاث حالات رفض متتالية تؤدي للخروج غير الصفري. يتحقق من تقدم الجمع بفاصل65ث: فشلان متتاليان لنافذتين مكتملتين يؤديان للخروج افتراضياً، والنافذة الناجحة تصفّر عدادهما. لا يعاد احتساب نتيجة نافذة قديمة مع كل استقصاء؛ عداد الصحة منفصل عن عداد التقدم. هذا ليس وعداً بزمن كشف ثابت من لحظة بدء العطل.
- SIGTERM/SIGINT يطلبان الإغلاق؛ يوقف الخدمات بترتيب عكسي بمهلة30ث لكل منها. يتعامل مع بدء جزئي أو فشل/timeout في المراقبة والإيقاف، ولا يرجع نجاحاً عند فشل الإيقاف.
- `--init` يعالج reaping؛ المشرف يحوّل فشل الخدمة المستمر إلى خروج حاوية؛ restart policy تعالج الخروج. **Docker healthcheck وحده لا يعيد التشغيل**. `on-failure:3` ليس سياسة لإعادة الإقلاع عند restart للـDocker daemon؛ تتطلب إعادة إقلاع المضيف سياسة منفصلة يختارها المشغّل ويختبرها.

### الاختبارات وحدود القبول

```bash
python3 -B -m unittest discover -s tests -p test_agent_lifecycle.py -v
bash scripts/validate/validate_all.sh
```

67 اختباراً للصحة ودورة الحياة عند متابعة التسليم؛ مجموع212 محلياً. تغطي قراءة state، رفض الحقن والروابط/FIFO، zombie مع/بدون خدمات حية، duplicates، ACK قديم/مستقبلي، العدادات المتجمدة، إعادة التشغيل/الساعة، opt-in، بدءاً جزئياً، timeout، إيقافاً عكسياً وفشل التعافي. عمليات start/stop الحقيقية mocked؛ لا اختبار استعادة أو قتل خدمات Wazuh حي. لا مراجعة مستقلة مُدّعاة.

فاحص الصحة نفسه اختُبر قراءة فقط على kali1: `healthy=false` و`progress_verified=true` مع أسباب PID1/zombies. هذا يثبت مسار الرفض على البيئة المعيبة؛ **لا يثبت قبول المشرف أو التعافي على بيئة مُصلحة**.

### مراجع أولية راجعت في 2026-09-11

- [Docker: multi-process containers and init](https://docs.docker.com/engine/containers/multi-service_container/).
- [Docker: restart policies and their limits](https://docs.docker.com/engine/containers/start-containers-automatically/).
- [Wazuh agentd state](https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-agentd-state.html): تحديث افتراضي5ث؛ حالة الاتصال والعدّادات، وstate لا تظهر قبل أول اتصال.
- [Wazuh logcollector state](https://documentation.wazuh.com/current/user-manual/reference/statistics-files/wazuh-logcollector-state.html): تحديث افتراضي60ث؛ global/interval والعدّادات/targets. الروابط current متغيرة؛ مطابقة المخطط مع 4.14.1 تمت من قراءة الحاوية الفعلية، لا من افتراض تطابق كل إصدار.

### متابعة مراجعة تسليم السحابة — 2026-09-11

- أُعيد إنتاج عيب progress محلياً: عدادات متعافية بعد65ث، لكن النسخة السابقة تخرج عند75ث. أصلح عداد النوافذ المستقل ذلك؛ الاختبار يستمر حتى طلب الإيقاف عند400ث. تجمد مستمر يخرج عند130ث في المحاكاة. توجد اختبارات للعداد المستقل، تصفيره بعد نافذة سليمة، وفشل daemon دون انتظار نافذة ثانية. الأوقات هنا محاكاة لا قياس سحابي.
- الرقعة المسلّمة تضمنت `mock.patch.object` بلا استيراد `mock`؛ إعادة تشغيلها كما هي أعطت60/61 لا نجاحاً كاملاً. اختير إصلاح progress فقط مع توسيع الاختبارات؛ لم تعتمد الرقعة حرفياً، ولم يضف فحص وجود config المقترح.
- **عائق نشر صريح:** قياس12:01 UTC: `/var/ossec/etc/ossec.conf` هو root:104 بوضع0664؛ مجلده uid101:104 بوضع0770. يرفضهما شرط التثبيت المحمي الحالي. لا يثبت ذلك أن شرط الحماية زائد: config يمكن أن يحدد أوامر جمع/استجابة. اكتفاء الرقعة بملف عادي مع تتبع الروابط يزيل حدود ملكية وحماية، لذلك لم يعتمد. يلزم تصميم نشر يحمي الإعداد المحلي ومساره مع إبقاء مجلدات state/shared اللازمة قابلة للعمل، ثم اختبار توافق Wazuh وصلاحياته وACL فعلياً. لا chmod/chown شامل ولا تغيير خفي لعقد الثقة لتجاوز guard.
- SIGTERM أثناء أمر start محجوب يُسجَّل، لكن `subprocess.run` قد ينتظر المهلة45ث؛ timeout ما زال فشلاً مع cleanup عكسي بمهلة30ث لكل خدمة. الاختبار الجديد يثبت هذا بمضاعفات اختبار، وليس بقتل خدمات حية. `docker stop` اليدوي يوقف سياسة restart وفق Docker؛ إرسال SIGTERM مباشرة أو فشل cleanup سيناريو آخر يحتاج قياساً مستقلاً. لا يغلق أي منها بوابة إعادة إقلاع المضيف.
- النسخة الاحتياطية التي أنشأها وكيل السحابة موجودة، وفُحص gzip للأرشيفين ومطابقة هوية client.keys مع الوكيل الحالي دون كشف المحتوى. هذا ليس اختبار استعادة أو برهان اتساق كل state مع صورة التقطت في توقيت مختلف. الصورة الاحتياطية لا تُرفع إلى Git.
- هذه الجلسة لم تنشر أو توقف أي خدمة. مسار الكتابة المسموح هو `/home/user/webapp` فقط؛ صلاحيات SSH/sudo لا تغيره. يلزم سياق تنفيذ يسمح بتعديل الخادم قبل النشر والقبول الأصلي.
