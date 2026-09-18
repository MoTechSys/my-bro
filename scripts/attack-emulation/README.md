# Attack emulation — للعرض أمام اللجنة (معمل معزول فقط)
| سكربت | UC | التنبيه المتوقَّع |
|-------|----|-------------------|
| `eicar_test.sh --lab EXISTING_MONITORED_DIRECTORY UNIQUE_TRIAL_KEY` | 03 | 87105 → 100092 (L12) + حذف الملف |
| `nmap_scan.sh --lab PRIVATE_IPV4` (sudo) | 04 | 86601 NMAP SYN Scan |
| `netcat_tests.sh --lab` | 05 + 08 | 100210 (L12) ثم 100051 (L7) |
| `shellshock_test.sh --lab PRIVATE_IPV4` | 06 | 31168 (L15) |
| `malware_downloader.sh --lab COMMIT_40HEX SHA256_MANIFEST EXISTING_YARA_DIR` | 07 | 108001 إن طابقت القواعد؛ ليس مضموناً |

ترتيب مقترح للعرض (≈10 دقائق): 06 → 05 → 08 → 03 → 07 → 04. احتفظ بلقطات احتياطية في `docs/lab/evidence/`.

الواجهات كاملة في tests/SECURITY_REVIEW.md §6. EICAR ونص YARA اصطناعي فقط للديمو/القياس؛ لا تنزيل عينات حقيقية ضمن TEST_PLAN. PRIVATE_IPV4 ليس تفويضاً؛ يلزم معمل مصرح، snapshot وخطة استعادة. لا تنفذ العينات.

تحديث v3.1/ISSUE-060: EICAR الآن باسم `eicar_<UNIQUE_TRIAL_KEY>.com`، لا eicar.com ثابتاً. الاسم الفريد يغير file ضمن AR keys مع بقاء المحتوى؛ لا تعديل للحراس. للقياس استخدم trial_runner --eicar-dir وفق tests/README وربط الدليل قبل الإطلاق. الصور/المسارات التاريخية لم تتغير، ولا قبول execd أو PILOT من نجاح الاختبار المحلي.


## UC-09 / UC-11 — عملاء محدودون ومولّد إعداد SSH (2026-09-18)

`lab_scenarios.py` منفذ ومختبر محلياً، وليس نتائج معملية. الوضع الافتراضي **preview دون شبكة**؛ إضافة `--lab` تطلق الطلبات. لا تستخدمه على خادم الإدارة أو بيئة إنتاج. RFC1918 قيد وجهة، لا إثبات تفويض. الإخراج تقرير عميل فقط، ولا يحل محل سجل المحاولات والمراقبين في T-11.

### UC-09: توقيع SQLi غير مدمر على مسار HTTP ثابت

```bash
python3 -I -B scripts/attack-emulation/lab_scenarios.py sqli \
  --target 192.168.50.2 --port 80 --trial TRIAL0001
# بعد التحقق من المعمل والمسار الثابت: أضف --lab إلى الأمر نفسه.
```

العنوان مثال لا عنوان المعمل المثبت. طلب واحد إلى `/soc-probe-TRIAL0001?q=union%20select%20null,null`؛ لا اختيار SQL حر ولا استخراج بيانات. يشترط endpoint ثابتاً غير موصول بقاعدة بيانات/CGI. curl يتجاهلcurlrc والبروكسي، بلاredirects، بمهلة6ث. الكود0 من الأداة يعني إنتاج تقرير، حتى لو فشل العميل؛ افحص attempt/status/http_status. HTTP404 متوقع لمسار غير موجود ولا يعني فشل وصول السجل؛ HTTP200 ليس دليلاً على استغلال SQL.

المدخل الموجود `wazuh/agents/linux/ossec.conf.d/30-localfile-apache.xml` يراقبaccess.log. تحقق من LogFormat الحقيقي، واجتز native logtest على السطر الفعلي، ثم اربط marker بالـalert والفهرس. المصدر المثبتWazuh v4.14.1: **31103 SQL injection attempt (L7)**،31104 هجوم ويب عام وليس مرادفSQLi؛31106 قد يكون التنبيه النهائي حينstatus200. لا تفترض ID ثابتاً دون فحص السطر والإصدار.

### UC-11: طلبات SSH باسم مستخدم اختبار غير موجود، دون كلمات مرور

```bash
python3 -I -B scripts/attack-emulation/lab_scenarios.py ssh \
  --target 192.168.50.2 --port 22 --trial TRIAL0001 \
  --known-hosts /approved/private/known_hosts
```

ثبّت بصمة **هدف الاختبار** بقناة موثوقة أولاً؛ لا تستخدم StrictHostKeyChecking=no أو قبولاً تلقائياً. الأداة ترفض symlink وملفاً فارغاً/قابلاً للكتابة من الآخرين وتوسعاتمسار%/~. حماية أسلاف الملف مسؤولية المشغّل. `--lab` يطلق حتى12 اتصالاً باسم `socprobe_trial0001`؛ تأكد أنه غير موجود. لا password/key/agent forwarding أو أوامر بعيدة، ولا قراءةssh_config. لكل عميل≤6ث وسقفالجولة25ث؛ ما لم يطلق يبقىnot_launched_deadline في التقرير. SSH255 قد يعني host-key/network/auth failure؛ **ليس إثبات مصادقة فاشلة بحد ذاته**.

ينبغي وجود sshd ومصدره الحقيقي على endpoint مستقل؛ `60-localfile-sshd.xml` اختياري للأنظمة التي تكتب `/var/log/auth.log`. لا تضفه عند وجود مصدر مكرر، ولا تفترض أن حاويةkali1-init تولّد هذا الملف. الأنظمةjournal-only تحتاج مدخلjournald أصلياً معتمداً. لا تختبر فيauth.log غير مراقب ثم تستنتج توقفالجمع.

5710 هوinvalid user مفرد L5؛5712 و5763 correlation L10، frequency8/timeframe120/ignore60 فيالمصدرالمثبت. العدد12 حد للعميل، **لا ضمان لموعد firing**: يعتمد علىالسجلاتالمتولدة وعدادمحركWazuh والكبت. تحققnative منسجلssh ومنsame_source_ip؛ لا نسخfixtures كنتائج.

### إعداد firewall-drop مع استثناء الإدارة

```bash
python3 -I -B scripts/attack-emulation/lab_scenarios.py ssh-response \
  --management-ip 192.168.50.1 --probe-source 192.168.50.3 --enable-response
```

الأمر **يولد XML إلىstdout فقط**؛ لا يكتبossec.conf ولا يغيرfirewall. العناوين أمثلة، وprobe-source هو عنوان **جهاز إطلاق الاختبار كما يراهsshd**، لا عنوانالهدف. كررmanagement-ip لكل مسارإدارة/بوابة/NAT لازم؛ ترفضالأداة تطابقمصدرالاختبار معالاستثناء. القائمةتضاف إلىglobalالقائمة ولا تستبدل الاستثناءاتالقديمة. هذا القيد لا يقصر AR على عنوانprobe-source؛ الربطالأصلي يطال التنبيهاتالمطابقة، لذا يلزم معملمعزول ومراجعةالنطاق.

تأكد أن command باسمfirewall-drop موجود مرةواحدة معtimeout_allowed=yes وأن الـendpointLinux يملك backendFirewall مناسباً وصلاحياته. المولد يستخدمlocation=local وrules_id=5712,5763 وtimeout60 فقط؛ لاlevel/group لأنSelectorsفيAR تعملOR. لا تضفdisabled=yes علىmanager كتعطيللهذهالقاعدة؛ ذلكقديعطلARلكلالوكلاء. لا تمنححاويةالمعملNET_ADMINعشوائياً دونعزلومراجعة.

القبول: native config test قبلالتفعيل، مراقبةadd فيactive-responses.log وقاعدةfirewall نفسها، إثباتأنالإدارةمستثناة، ثمdeleteوإزالةالحظر بعدالمدة. الخطأ/انقطاعexecd قد يمنعunblock؛ جهّزمسارإدارةخارجمصدرالاختبار وإزالةمحددةللقاعدة، لاflushعام. للرجوع احذفربطARالمضاففقط بعدحفظالإعداد وفحصه؛ لا تحذفالأوامرالأصليةأوتغيرVT/YARA. لا تشغيل لهذهالسيناريوهاتفيجلسةالاختباراتالمحلية.

المصادر المقروءة2026-09-18:
- [Wazuh v4.14.1 sshd rules](https://github.com/wazuh/wazuh/blob/v4.14.1/ruleset/rules/0095-sshd_rules.xml)،SHA256: `4c360a2693ded4dc272ff91d83e411a674bb185b52b7b6b480f81afe71b3b430`.
- [Wazuh v4.14.1 web rules](https://github.com/wazuh/wazuh/blob/v4.14.1/ruleset/rules/0245-web_rules.xml)،SHA256: `1226e135a5298826a60910c501c7146ff0297ae61d6cc7d8e592f818dccfdca2`.
- [Active-response reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html)،معنىdisabled وOR وlocation/timeout. صفحاتcurrent قدتتغير؛ الاختبارالأصليلايستبدلبالبصماتأوالتوثيق.
