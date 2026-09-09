# UC-07 — دمج YARA للكشف عن البرمجيات الخبيثة (FIM → Active Response)

**المصدر:** S2 ص39–55 (`p40_0`–`p49_1`, `p55_0`); S5 القسم الثالث (`img20`–`img29`).

## سلسلة الأحداث
FIM realtime → `100300/100301` (L7) → AR `yara_linux` → `yara.sh` → `active-responses.log` (`wazuh-yara: INFO - Scan result: <rule> <file>`) → decoder `yara_decoder` → `108000` → **`108001` (L12)**.

## الوكيل (kali1)
```bash
bash scripts/lab/install_yara_kali.sh --lab SOURCE_SHA256 RULES_SHA256     # YARA 4.5.5 من المصدر + قواعد VALHALLA إلى /var/ossec/etc/yara/rules (ISSUE-020)
sudo install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/soc_ar.py /var/ossec/active-response/bin/soc_ar.py
sudo install -o root -g wazuh -m 750 wazuh/agents/linux/active-response/yara.sh /var/ossec/active-response/bin/yara.sh
# ossec.conf: <directories realtime="yes">/tmp/yara/malware</directories>
sudo systemctl restart wazuh-agent
```
البصمتان SOURCE_SHA256 وRULES_SHA256 قيم معتمدة مستقلة وليستا نصين جاهزين؛ البناء كمستخدم غير root. helper مطلوب مع الغلاف. عند تفعيل UC-03 على Linux ثبّت remove-threat.sh باسم remove-threat.exe وفق UC-03؛ لا تنسخ exe الخاص بـWindows إلى Linux.

خطأ شائع (S2 ص41): `libyara.so.9: cannot open shared object file` → `echo "/usr/local/lib" >> /etc/ld.so.conf && ldconfig`.

## المدير
1. `wazuh/manager/decoders/local_decoder.xml` (yara_decoder, yara_decoder1).
2. `wazuh/manager/rules/local_rules.xml` — 100300/100301 **مرة واحدة فقط** (ISSUE-010) + 108000/108001.
3. `wazuh/manager/ossec.conf.d/40-active-response-yara.xml` (المسار الجديد للقواعد في extra_args).
4. `sudo systemctl restart wazuh-manager`.

## Windows (win1) — ⚠️ ISSUE-006 مكتوب ولم يُثبَت تنفيذه
حدد YARA_ROOTS في soc_windows_ar.py قبل البناء. من مجلد Windows AR ابنِ `pyinstaller --clean --onefile --name soc-yara yara.py` ثم وزع soc-yara.exe مع yara.bat، والماسح الثابت yara64.exe وقواعده المحمية. تنزيل القواعد: `python download_yara_rules.py --expected-sha256 VERIFIED_HASH --output NEW_STAGING_FILE` ثم compilation ومراجعة. لا حاجة valhallaAPI. لا تشغيل JSON عبر cmd أو PowerShell. البناء والـACL والاختبار الأصلي معلقة.

## المحاكاة
الأصل في القياس نص YARA اصطناعي غير تنفيذي حسب TEST_PLAN §6.7؛ لا تنزيل عينات حقيقية للقياس/الديمو. الأمر التالي مسار اختياري لتجربة عينات معزولة ومصرح بها، وليس شرطاً ولا أمراً جاهزاً قبل توفير commit وmanifest مستقلين؛ لا تنفذ العينات.
```bash
bash scripts/attack-emulation/malware_downloader.sh --lab COMMIT_40HEX SHA256_MANIFEST EXISTING_YARA_DIR     # عينات Mirai/Xbash/VPNFilter/WebShell — بيئة معزولة فقط
```

## النتيجة الفعلية
S5 `img24` (yara.sh)، `img27` (القواعد)، `img28` (decoder)، `img29` (AR config)؛ S2 `p49_1`: `rule.groups:yara` → "File ... is a positive match. Yara rule: ..." L12.

## الأخطاء المعروفة
- ISSUE-018 مسار `/tmp/home/kali/omar` في S5 img27 — يحتاج تحققاً.
- ISSUE-024 أوامر `yum` على Kali ليست "خطأ نظام".
- ISSUE-025 قواعد VALHALLA demo محدودة.

## استعلام اللوحة
Threat Hunting → `rule.groups:yara`.
