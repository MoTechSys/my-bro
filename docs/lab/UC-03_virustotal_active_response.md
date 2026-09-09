# UC-03 — تكامل VirusTotal + الاستجابة النشطة (حذف الملف الخبيث)

**المصدر:** S2 ص11–26، لقطات `p13_0`, `p14_0`, `p15_0`, `p16_0`, `p17_0`, `p18_0`, `p18_1`.

## الهدف
عند إضافة/تعديل ملف في المجلد المراقب → المدير يستعلم VirusTotal بالـ hash → إن كان خبيثاً (rule 87105) → الوكيل يحذفه تلقائياً (AR) → تنبيه 100092.

## سلسلة الأحداث
`syscheck 550/554` → `100200/100201` (local) → `integratord → VirusTotal API` → `87105` → `AR remove-threat` (location local) → `657` → `100092` (نجاح) / `100093` (فشل).

## الوكيل (kali1)
1. Python 3.9+، snapshot وخطة استعادة، مجلدات تثبيت محمية؛ بوابات `tests/SECURITY_REVIEW.md §5`.
2. `<directories realtime="yes">/home/kali/SOCfile</directories>`
3. على Linux ثبّت الملفين معاً من جذر المستودع بعد مراجعة allowlists؛ الاسم `.exe` هنا سكربت Linux وليس ملف Windows:
   ```bash
   sudo install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/soc_ar.py /var/ossec/active-response/bin/soc_ar.py
   sudo install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/remove-threat.sh /var/ossec/active-response/bin/remove-threat.exe
   ```
   لا تنسخ ملف Windows التنفيذي إلى Linux. لا تستخدم defined-agent كمرشح OS؛ استجابة local واحدة على الوكيل المصدر.
4. `sudo systemctl restart wazuh-agent`

## المدير
1. قواعد 100200/100201 و100092/100093 (`wazuh/manager/rules/local_rules.xml`).
2. `wazuh/manager/ossec.conf.d/20-virustotal-integration.xml` (ضع مفتاحك — **لا تُرفعه للمستودع**).
3. `wazuh/manager/ossec.conf.d/30-active-response-remove-threat.xml`.
4. `sudo systemctl restart wazuh-manager`.

## Windows (win1)
غير جاهز للتشغيل: `VT_ROOTS` فارغة عمداً في `soc_windows_ar.py`. حدد الجذر الفعلي وطابق FIM ثم ابنِ على Windows `pyinstaller --clean --onefile --name remove-threat remove-threat.py` مع الوحدة المجاورة، واضبط ACL للإدارة/System. مرشح VT الحالي 100200/100201 خاص بمسار Linux؛ لا يعني توفر exe تفعيل Windows. لا تعطل Defender افتراضياً؛ الحجر السابق لـWazuh = INTERFERED موثق، لا نجاح AR. الاختبار الأصلي مطلوب.

## المحاكاة
```bash
: "${TRIAL_KEY:?Set a NEW globally unique ASCII trial key; never reuse after cleanup}"
bash scripts/attack-emulation/eicar_test.sh --lab /home/kali/SOCfile "$TRIAL_KEY"
```

## النتيجة الفعلية
`p18_1.png`: `/home/kali/SOCfile/eicar.com` → added ثم **deleted** (AR عمل). `p17_0.png`: ossec.conf على المدير بالتكامل + AR (المفتاح مطموس).

## الأخطاء المعروفة
- ISSUE-008 مسار `local_rules.xml` مكتوب خطأ في الدليل.
- ISSUE-030/036: حراسة add فقط وبصمة ومسار؛ الإصلاح مدموج #14 واختباره محلي، لا اعتماد معملي.
- R3: chmod/chown بريء أثناء hashing قد يغير ctime ويؤدي إلى `file changed while hashing` و100093؛ سجل السبب ولا تتجاوز الحارس.
- البصمة المفقودة/المختلفة والروابط والمسارات خارج القائمة تفشل مغلقة. سباق تبديل الاسم الأخير ما زال قيداً (ISSUE-039)، فلا اعتماد إنتاجي.
- VirusTotal free: 4 طلبات/دقيقة → لا تستخدم `<group>syscheck</group>` كمحفّز.

## استعلام اللوحة
Threat Hunting → `rule.id: is one of 553,100092,87105,100201`.

تحديث v3.1/ISSUE-060: EICAR الآن باسم `eicar_<UNIQUE_TRIAL_KEY>.com`، لا eicar.com ثابتاً. الاسم الفريد يغير file ضمن AR keys مع بقاء المحتوى؛ لا تعديل للحراس. للقياس استخدم trial_runner --eicar-dir وفق tests/README وربط الدليل قبل الإطلاق. الصور/المسارات التاريخية لم تتغير، ولا قبول execd أو PILOT من نجاح الاختبار المحلي.
