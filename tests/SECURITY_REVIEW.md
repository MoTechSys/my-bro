# T-15 — مراجعة الأمان وإصلاحات الاستجابة

> الغرض: جرد كامل للسكربتات وحدود الإصلاح؛ المالك [ASTRA]؛ التحديث 2026-09-09.
> الحالة: إصلاحات واختبارات محلية؛ **IN-PROGRESS حتى مراجعة Claude والتحقق الأصلي على Windows والمعمل**. لا اعتماد إنتاجي.
> المصادر: ISSUE-036، خطة TEST_PLAN، توثيق Wazuh 4.14 المرتبط أدناه، وملفات المستودع. لا نتائج معملية جديدة.

## 1. النطاق وملخص القرار

رُوجعت جميع الملفات التنفيذية تحت `wazuh/agents/*/active-response/` و`scripts/` في أساس العمل `8f4c0c6`، مع الملفات الجديدة التي تطلبتها الإصلاحات. لم تُحذف ميزة FIM/VT/YARA أو محاكاة حالة استخدام؛ أضيفت شروط تشغيل صريحة لمنع التنفيذ غير المقصود. الجداول أدناه تفرق بين التصحيح البرمجي والتحقق المطلوب.

**ISSUE-036:** لم يعد هناك حذف مستقل عن فحص `command=add`. غلاف Linux يمرر العمل إلى `soc_ar.py`، ولا يستخدم `rm` على بيانات التنبيه؛ الحذف هو `os.unlink` لاسم ملف داخل واصف المجلد الموافق عليه. يرفض delete/أمر غير معروف/JSON تالف/EOF/قرار غير continue. تتحقق قائمة مسارات، وملف عادي بلا روابط، وبصمة MD5 من `virustotal.source.md5` قبل الحذف. غياب البصمة **خطأ**، وليس سماحاً افتراضياً.

لم يُغلق ISSUE-036 نهائياً: توجد مخاطر سباق ملفات وضبط ACL واختبارات أصلية مذكورة في §4 و§7.

## 2. جرد الملفات والنتيجة

| الملف | الملاحظة الأصلية / التغيير | حدود التحقق |
|---|---|---|
| `linux/active-response/remove-threat.sh` | حذف خارج add ومسار من التنبيه؛ أصبح غلافاً ثابتاً للمحرك الآمن | اختبارات محلية للمحرك؛ توزيع الغلاف يحتاج اختبار Wazuh |
| `linux/active-response/soc_ar.py` (جديد) | مشي مكونات المسار بـO_NOFOLLOW، واصف أب مثبت، منع hardlinks/FIFO، بصمة وهوية الملف، مهلة 45 s للرد كله | سباق آخر لحظة داخل المجلد الموافق عليه يبقى، §4 |
| `linux/active-response/yara.sh` | انتظار بلا حد وتنفيذ مسار من extra_args؛ أصبح غلافاً ثابتاً | الأصل Linux فقط؛ فحص native YARA مطلوب |
| `windows/active-response/remove-threat.py` | انتظار stdin لا ينتهي وفحص ADS ناقص؛ أصبح مدخلاً للمحرك المشترك | يحتاج PyInstaller على Windows |
| `windows/active-response/soc_windows_ar.py` (جديد) | JSON بدون shell، قراءة محدودة بمهلة، allowlist صريحة، منع UNC/ADS/reparse في المكونات، بصمة، exit غير صفري للفشل | اختبارات lexer/EOF محلية فقط؛ native ACL/سباقات لم تُثبت |
| `windows/active-response/yara.bat` | حقن JSON في cmd/PowerShell وstdin.txt مشترك؛ يستدعي الآن soc-yara.exe بمسار ثابت دون لمس stdin | batch لم يُشغّل على Windows |
| `windows/active-response/yara.py` (جديد) | مدخل ماسح يعتمد قائمة argv وshell=False وtimeout | بناء native مطلوب |
| `windows/active-response/download_yara_rules.py` | شبكة عند import وكتابة فوق ملف قائم بلا تحقق؛ main guard وحد 20 MiB وبصمة متوقعة وكتابة حصرية | لم يُنزّل feed؛ حماية staging بالـACL مطلوبة |
| `scripts/attack-emulation/eicar_test.sh` | overwrite/روابط في الهدف؛ --lab، مجلد موجود تحت SOCfile، مشي no-follow وO_EXCL | لا تُنشأ المجلدات ضمن المحاكاة؛ no-flag مختبر |
| `scripts/attack-emulation/malware_downloader.sh` | mutable branch وتنزيل غير متحقق/كتابة فوق الهدف؛ commit مثبت وmanifest SHA-256 وموافقة نصية وحجم محدود وكتابة حصرية | **لم تُنزّل عينات حقيقية**؛ hashes يوفرها الفريق مستقلاً |
| `scripts/attack-emulation/nmap_scan.sh` | هدف قد يصبح خياراً وapt ضمن الاختبار؛ عنوان RFC1918 مفرد و--lab ومدة محدودة بلا تثبيت تلقائي | اختبرت العناوين المرفوضة فقط؛ الاستهداف الخاص ليس بديلاً عن تفويض المالك |
| `scripts/attack-emulation/shellshock_test.sh` | قراءة passwd في الحمولة وURL غير مقيد؛ علامة echo سليمة، IPv4 خاص، تعطيل proxy، حدود اتصال | يلزم هدف ثابت غير CGI؛ لم يُرسل طلب شبكي |
| `scripts/attack-emulation/netcat_tests.sh` | مستمع على كل الواجهات وعمل خلفي غير مُتابع؛ loopback فقط وطفل معلوم وتنظيف EXIT | اختلاف نسخ nc/الإغلاق المبكر يحتاج PILOT؛ ليس سكربت T-11 |
| `scripts/lab/install_auditd_kali.sh` | استبدال سياسة بلا backup وGID ثابت؛ --lab ونسخة احتياطية وحساب GID الحقيقي وinstall 0600 | التحميل/الاستعادة يحتاج المعمل؛ لم تُشغَّل apt/systemctl |
| `scripts/lab/install_yara_kali.sh` | بناء مصدر منزّل كـroot وfeed بلا بصمة وchmod recursive؛ تحقق hashes ومجلد خاص وبناء غير مميز وmake check ونسخة قواعد احتياطية | build/install غير مجرّب؛ manifest مستقل وتخطيط rollback مطلوبان |
| `scripts/validate/validate_all.sh` | أسماء /tmp قابلة للتنبؤ وتقسيم أسماء الملفات وpycache؛ لا ملفات مؤقتة مشتركة، Python AST في الذاكرة، globstar للسكربتات | شُغّل كاملاً بنجاح؛ لا يثبت دلالات Wazuh runtime |
| `scripts/validate/check_rule_ids.py` | روجع؛ فحص IDs/XML محلي وليس ماسح أسرار كاملاً أو validator Wazuh | لم يُغيَّر؛ placeholders تُحيد عمداً، يتطلب النشر استبدالها |

رُوجعت أيضاً إعدادات الربط: `30-active-response-remove-threat.xml` أصبح استجابة واحدة local؛ و`local_decoder.xml` يحفظ المسار الذي يحتوي مسافات؛ و`local_rules.xml` يطابق نتيجة AR النهائية بدلاً من تطابق عبارة النجاح أينما ظهرت. لا معرّفات Wazuh جديدة.

## 3. فصل Linux/Windows دون توجيه الاستجابة إلى جهاز خاطئ

وفق مرجع Wazuh، `location=defined-agent` و`agent_id` يحددان **وجهة التنفيذ**؛ ليسا شرطاً يرشح OS مصدر التنبيه. إرسال كل تنبيه 87105 إلى 001/002 بكلا الأمرين ليس إصلاحاً آمناً.

الحل المطبق: **عقد توزيع باسم واحد `remove-threat.exe` واستجابة واحدة `location=local`**. المدير يطلب الاسم مرة واحدة على الوكيل الذي أصدر التنبيه:

- على Linux: ملف `remove-threat.sh` نفسه يُثبّت باسم `remove-threat.exe`؛ امتداد الاسم لا يغيّر shebang الذي يشغله Linux. يوجد `soc_ar.py` بجواره.
- على Windows: الملف بهذا الاسم **exe أصلي** مبني من `remove-threat.py`، وليس ملف Linux.
- لا يوجد اكتشاف OS آلي من الامتداد، ولا fallback إلى تشغيل الملف الآخر، ولا حاجة إلى Rule IDs جديدة. فشل توزيع البرنامج المناسب يظهر كفشل تشغيل لا كتنفيذ بديل.
- اسم أمر المدير `remove-threat` بقي كما هو؛ يجب إزالة كتل AR القديمة المكررة، لا إضافة الكتلة الجديدة فوقها.

هذا تغيير تعاقد توزيع واضح؛ على Claude مراجعته قبل اعتماد النشر، وعلى الفريق إثبات تشغيل النوع المناسب في المعمل. لا يوسع مرشح VT تلقائياً إلى Windows: `20-virustotal-integration.xml` ما زال يرشح 100200/100201؛ اختبار Windows يحتاج تحقق إعداد تكامله كما في TEST_PLAN.

## 4. حدود الإصلاح والمخاطر الباقية — ليست مغلقة

1. **سباق الحذف:** Linux يثبت واصف الأب/الملف ويتحقق من inode/hash قبل unlink، لكن لا توجد عملية unlink-by-file-handle محمولة؛ يستطيع كاتب منافس تبديل الاسم في الفاصل الأخير داخل المجلد المسموح. Windows ما زال يعتمد حذفاً بالاسم بعد الفحص؛ يمكن أن يحدث سباق reparse/استبدال في مجلد يسيطر عليه خصم. لا ندّعي القضاء على TOCTOU. يتطلب الاستخدام خارج المعمل ACLs تمنع الكاتب المنافس أو تصميم حجر/حذف بمقابض Windows ومراجعة جديدة، لا موافقة AI تلقائية.
2. **Windows fail-closed:** `VT_ROOTS` و`YARA_ROOTS` فارغتان عمداً حتى يحدد الفريق مساراته الحقيقية قبل البناء. لا تُستنتج Downloads من حساب LocalSystem، ولا wildcard لكل Users. هذا إعداد مطلوب، وليس نجاح تشغيل أو حذفاً لمتطلب Windows.
3. **حدود الموارد:** الملفات أكبر من 100 MiB مرفوضة صراحة؛ Linux يحد انتظار الاستقرار إلى 10 s، والماسح إلى 10 s داخل YARA و25 s خارجياً، و100 مطابقة، والعملية الكلية إلى 45 s. Windows يستخدم مهلة stdin ومسح محددين، لكن حد موارد/hash أصلي مكافئ يحتاج اختباراً وتصميماً إضافياً. سجّل الملفات المستبعدة، لا تصفها سليمة.
4. **الثقة بالمكونات:** يجب حماية البرامج/القواعد/السجلات والأدلة من كتابة المستخدمين، بما فيها كل المجلدات الأب. فحص ملكية ملف YARA على Linux ليس بديلاً عن حماية سلسلة التوزيع. يتطلب native Windows اختبار ACLs وبرامج PyInstaller وتواقيع الإصدار.
5. **التنزيل:** البصمة يجب الحصول عليها مستقلاً؛ حسابها من نفس التنزيل ثم تقديمها ليس توثيق مصدر. لم تُخترع أي بصمات أو commits upstream. feed متغير، لذا قد يفشل توافقه مع manifest القديم؛ الفشل لا يُتجاوز.
6. **الرسائل:** معيار السماح يعتمد rule 87105 وحقول المصدر من مدير موثوق؛ ليس نظام مصادقة مستقلاً للتنبيه. لا تعرض stdout على أنه تقرير نجاح؛ stdout محجوز لبروتوكول execd.
7. **المثبتات:** backup سياسة/قواعد لا يساوي rollback كامل لحزم النظام أو `make install`؛ snapshot للـVM قبل التنفيذ لازم. أي فشل تحميل auditd يحتاج قرار الفريق واستعادة النسخة السابقة، لا متابعة صامتة.

## 5. نشر متحكم به وخطة الاستعادة

هذه **تعليمات مقترحة للمعمل، لم تُنفَّذ في هذه الجلسة**:

1. خذ snapshot وأرشفة خاصة للإعدادات/السكربتات المنشورة قبل النقل. لا تنشر API keys في Git. اختبر rollback من وحدة تحكم VM.
2. Linux: Python 3.9+ (المطلوب لـhashlib usedforsecurity)، coreutils، YARA 4.5.5، وقواعد دائمة موثقة. راجع `VT_ROOTS`/`YARA_ROOTS` في `soc_ar.py` مقابل FIM الفعلي. الأصول الافتراضية مأخوذة من إعداد المستودع لا من جهاز حي.
3. على Linux، من نسخة المستودع التي راجعتها، ثبّت الملفات التالية **معاً** في مجلدات التثبيت المحمية:

```bash
sudo install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/soc_ar.py /var/ossec/active-response/bin/soc_ar.py
sudo install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/remove-threat.sh /var/ossec/active-response/bin/remove-threat.exe
sudo install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/yara.sh /var/ossec/active-response/bin/yara.sh
```

4. Windows: املأ allowlists الفعلية في نسخة البناء، ثم ابنِ على Windows `pyinstaller --clean --onefile --name remove-threat remove-threat.py` و`pyinstaller --clean --onefile --name soc-yara yara.py` من مجلد `windows/active-response` بحيث تُضمّن وحدة `soc_windows_ar.py`. انسخ exe الاثنين و`yara.bat` إلى `active-response\bin` مع ACLs الإدارة/System فقط. لا حاجة لبايثون على endpoint إذا استُخدمت الحزم الصحيحة.
5. المدير: استبدل **كتلتي** AR القديمة بالكتلة الوحيدة الجديدة؛ طبّق تعديل decoder/result rules دون تغيير IDs. `wazuh-analysisd -t` ثم restart في نافذة صيانة. لا تنس استبدال `<USER_NAME>` وAPI placeholder محلياً.
6. PILOT أولاً: أمر delete لا يحذف، add خارج المسموح لا يحذف، بصمة خاطئة لا تحذف؛ ثم ملف EICAR مطابق داخل المسموح. تحقق من 100092/100093 ومصدر الحذف، ومن 108001 ومسار كامل وغياب تنفيذ أوامر من اسم ملف.
7. عند فشل أي بوابة، أوقف الاختبار والاستجابة ذات الصلة واستعد البرامج والإعدادات **كحزمة واحدة** من snapshot/backup، ثم تحقق من عودة الوكلاء. لا تستعد سكربتاً منفرداً وتترك أسماء التوزيع الجديدة.

## 6. واجهات سكربتات المعمل الجديدة

الأوامر القديمة في runbooks قد لا تحمل --lab؛ سيفشل تشغيلها بأمان حتى تُحدّث وفق الجدول. يحتاج Claude تحديث الأدلة المملوكة له؛ هذا التقرير هو مرجع واجهات T-15 الجديد.

| السكربت | الواجهة الجديدة |
|---|---|
| EICAR | `bash scripts/attack-emulation/eicar_test.sh --lab EXISTING_MONITORED_DIRECTORY` |
| nmap | `sudo bash scripts/attack-emulation/nmap_scan.sh --lab PRIVATE_IPV4` |
| Shellshock | `bash scripts/attack-emulation/shellshock_test.sh --lab PRIVATE_IPV4` |
| Netcat | `bash scripts/attack-emulation/netcat_tests.sh --lab` (loopback، لا shell بعيد) |
| عينات YARA | `bash scripts/attack-emulation/malware_downloader.sh --lab COMMIT_40HEX SHA256_MANIFEST EXISTING_YARA_DIR` ثم تأكيد نصي؛ أربع بصمات `hash filename` |
| auditd | `bash scripts/lab/install_auditd_kali.sh --lab` من مستخدم المعمل غير root |
| بناء YARA | `bash scripts/lab/install_yara_kali.sh --lab SOURCE_SHA256 RULES_SHA256` من مستخدم غير root |
| feed Windows | `python download_yara_rules.py --expected-sha256 VERIFIED_HASH --output NEW_STAGING_FILE`؛ ثم compile ومراجعة ونقل محمي |

## 7. الاختبارات ومعيار الإغلاق

شُغّل في 2026-09-09:

```bash
python3 -B -m unittest discover -s tests -p test_security.py -v
bash scripts/validate/validate_all.sh
```

النتيجة: **19 اختباراً محلياً ناجحاً**، و`ALL CHECKS PASSED`. تغطي add/delete/abort/EOF/JSON، مسارات خارج القائمة وtraversal، symlink في الأب والملف، hardlink/FIFO/ملف مفقود، بصمة/حجم، symlink للسجل، one-local-dispatch، guards Windows النصية، ورفض opt-in والعناوين غير المعتمدة وPython المضمّن والـdecoder.

لم يُشغَّل: Wazuh manager/execd، PyInstaller/Windows/ACL، YARA أصلي، nmap/HTTP على شبكة، apt/install، تنزيل feed أو malware. لا تختلط اختبارات الرفض الآمن مع اختبار الوظائف الإيجابية الأصلية.

**يبقى T-15 IN-PROGRESS**: مراجعة Claude، تثبيت عقد التوزيع والواجهات في runbooks، معالجة/قبول موثق لمخاطر §4، وبناء Windows وتجارب أصلية على المعمل. يمكن مراجعة وبناء T-11 محلياً أثناء انتظار هذه المتطلبات؛ لا تُشغّل قياسات الحذف على المعمل قبلها. ISSUE-036 حالته «إصلاح أولي في المستودع / يحتاج مراجعة ومعملاً»، لا CLOSED.

## 8. مراجع تقنية

- [Wazuh 4.14 — command/executable](https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/commands.html): اسم الملف المطلوب موجود محلياً في bin؛ أي اسم ملف مسموح.
- [Wazuh 4.14 — active-response/location](https://documentation.wazuh.com/4.14/user-manual/reference/ossec-conf/active-response.html): local مقابل defined-agent.
- [Wazuh 4.14 — custom AR](https://documentation.wazuh.com/4.14/user-manual/capabilities/active-response/custom-active-response-scripts.html): stdin وcheck_keys وadd/delete وبناء Windows.
- [YARA v4.5.5 cli/yara.c](https://github.com/VirusTotal/yara/blob/v4.5.5/cli/yara.c): جرى التحقق من `-a` timeout و`-l` max-rules من المصدر، لا من الذاكرة.
