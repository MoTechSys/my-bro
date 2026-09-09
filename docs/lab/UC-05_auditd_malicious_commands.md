# UC-05 — مراقبة تنفيذ الأوامر الخبيثة (auditd + CDB list)

**المصدر:** S2 ص32–36 (`p35_0`, `p35_1`, `p36_0`, `p36_1`); S5 القسم الأول (`img01`–`img12`).

## الهدف
تسجيل كل أمر ينفّذه المستخدم (UID 1000) عبر auditd، وتصنيفه بقائمة CDB (yellow/orange/red)، ورفع تنبيه Level 12 عند تنفيذ أمر "red" (`nc`, `sudo`).

## سلسلة الأحداث
`auditd execve (key audit-wazuh-c)` → logcollector (`log_format audit`) → decoder auditd → `80792 Audit: Command` → CDB lookup `audit.command` → `100210` (L12).

## الوكيل (kali1)
```bash
bash scripts/lab/install_auditd_kali.sh --lab       # يثبّت auditd ويحمّل wazuh/auditd/wazuh.rules
```
القواعد (S2 ص32–33، S5 img02):
```
-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b32 -S execve -k audit-wazuh-c
-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b64 -S execve -k audit-wazuh-c
```
شرح صحيح للمعلمات (يصحّح ISSUE-023): `auid=1000` المستخدم الأول (omar/kali)؛ `egid!=994` استثناء مجموعة wazuh (تحقق GID على Kali — ISSUE-031)؛ `auid!=-1` استثناء العمليات بلا login UID (= 4294967295)؛ `-S execve` كل تنفيذ؛ `-k` مفتاح يربطه `audit-keys` بالتصنيف `command`.

ثم `wazuh/agents/linux/ossec.conf.d/20-localfile-audit.xml` + `sudo systemctl restart wazuh-agent`.

## المدير
1. `/var/ossec/etc/lists/suspicious-programs` ← `wazuh/manager/lists/suspicious-programs` (بدون تكرار — الأصل كرّر `nc` و`tcpdump`).
2. أضف `<list>etc/lists/suspicious-programs</list>` داخل `<ruleset>` (`p35_0.png`).
3. قاعدة 100210 (`wazuh/manager/rules/local_rules.xml`).
4. `sudo systemctl restart wazuh-manager`.

## المحاكاة
```bash
bash scripts/attack-emulation/netcat_tests.sh --lab    # nc -h → 100210 ; whoami → yellow (لا تنبيه مخصص)
```

## النتيجة الفعلية
- S5 `img10`/`img11`، S2 `p36_0`: `Audit: Highly Suspicious Command executed: /usr/bin/nc.traditional` — **rule 100210 level 12** على `kali1` (7 hits في p36_0).
- S5 `img12`: `grep` في `/var/log/audit/audit.log` يُظهر SYSCALL + EXECVE مع `key="audit-wazuh-c"`.

## الأخطاء المعروفة
- ISSUE-012 `apt install netcat` غير موجود في Kali 2025 → `netcat-traditional`.
- ISSUE-017 المستخدم `omar` (S5) vs `kali` (S2) — القاعدة تراقب UID 1000 فقط أياً كان اسمه.

## استعلام اللوحة
Threat Hunting → `data.audit.command:nc` أو `rule.id:100210`.
