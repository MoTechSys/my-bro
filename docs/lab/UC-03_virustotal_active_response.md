# UC-03 — تكامل VirusTotal + الاستجابة النشطة (حذف الملف الخبيث)

**المصدر:** S2 ص11–26، لقطات `p13_0`, `p14_0`, `p15_0`, `p16_0`, `p17_0`, `p18_0`, `p18_1`.

## الهدف
عند إضافة/تعديل ملف في المجلد المراقب → المدير يستعلم VirusTotal بالـ hash → إن كان خبيثاً (rule 87105) → الوكيل يحذفه تلقائياً (AR) → تنبيه 100092.

## سلسلة الأحداث
`syscheck 550/554` → `100200/100201` (local) → `integratord → VirusTotal API` → `87105` → `AR remove-threat` (location local) → `657` → `100092` (نجاح) / `100093` (فشل).

## الوكيل (kali1)
1. `sudo apt -y install jq`
2. `<directories realtime="yes">/home/kali/SOCfile</directories>`
3. `wazuh/agents/linux/active-response/remove-threat.sh` → `/var/ossec/active-response/bin/` ; `chmod 750` ; `chown root:wazuh`
4. `sudo systemctl restart wazuh-agent`

## المدير
1. قواعد 100200/100201 و100092/100093 (`wazuh/manager/rules/local_rules.xml`).
2. `wazuh/manager/ossec.conf.d/20-virustotal-integration.xml` (ضع مفتاحك — **لا تُرفعه للمستودع**).
3. `wazuh/manager/ossec.conf.d/30-active-response-remove-threat.xml`.
4. `sudo systemctl restart wazuh-manager`.

## Windows (win1)
نفس المنطق مع `remove-threat.py` → `pyinstaller -F remove-threat.py` → `remove-threat.exe` في `active-response\bin\`. المجلد المراقب `C:\Users\<USER_NAME>\Downloads`. يجب إيقاف Defender realtime أثناء الاختبار (S2 ص25).

## المحاكاة
```bash
bash scripts/attack-emulation/eicar_test.sh /home/kali/SOCfile
```

## النتيجة الفعلية
`p18_1.png`: `/home/kali/SOCfile/eicar.com` → added ثم **deleted** (AR عمل). `p17_0.png`: ossec.conf على المدير بالتكامل + AR (المفتاح مطموس).

## الأخطاء المعروفة
- ISSUE-008 مسار `local_rules.xml` مكتوب خطأ في الدليل.
- ISSUE-030 `rm -f $FILENAME` غير مقتبس — أُصلح.
- VirusTotal free: 4 طلبات/دقيقة → لا تستخدم `<group>syscheck</group>` كمحفّز.

## استعلام اللوحة
Threat Hunting → `rule.id: is one of 553,100092,87105,100201`.
