# UC-08 — مراقبة العمليات المشبوهة (Netcat listener)

**المصدر:** S5 القسم الرابع (`img30`, `img31`).

## سلسلة الأحداث
`ps -e -o pid,uname,command` كل 30 ث (full_command) → `530` → `100050` (L0 grouping) → match `nc -l` → **`100051` (L7, ignore=900)**.

## الوكيل
`wazuh/agents/linux/ossec.conf.d/50-command-process-list.xml` → `sudo systemctl restart wazuh-agent`.

## المدير
قواعد 100050/100051 في `wazuh/manager/rules/local_rules.xml` → `sudo systemctl restart wazuh-manager`.

## المحاكاة
```bash
bash scripts/attack-emulation/netcat_tests.sh --lab     # مستمع loopback فقط؛ تحقق من بقائه 90 ثانية في PILOT
```

## النتيجة الفعلية
S5 `img30` (ossec.conf بالـ localfile full_command) و`img31` (القواعد 100050/100051).

## ملاحظات
- Level 0 للقاعدة الأب يمنع ضجيج قائمة العمليات كل 30 ثانية.
- `ignore="900"` = بعد إطلاق القاعدة 100051 مرة، **تُكبَت القاعدة نفسها** (لا العملية) لمدة 900 ثانية أياً كان PID أو المنفذ (تصحيح ISSUE-037 وفق Wazuh 4.14 Rules syntax). لذا في الاختبار يلزم فصل ≥ 930 ث بين المحاولات (انظر `tests/TEST_PLAN.md`).
- تكامل طبيعي مع UC-05: تنفيذ nc قد يطابق 100210 وفق AUID/CDB الفعليين؛ راجع audit serial والأمر (sudo أيضاً red). ظهور 100051 مشروط برصد العملية وعدم كبت القاعدة، وليس ضماناً.

## استعلام اللوحة
Threat Hunting → `rule.id:100051`.
