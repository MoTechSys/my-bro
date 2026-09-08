# UC-08 — مراقبة العمليات واكتشاف Netcat في وضع الاستماع

**المصدر:** S5 القسم الرابع (img30, img31). **الملفات:** `wazuh/agents/linux/ossec.conf.d/50-command-process-list.xml`, `local_rules.xml` (100050/100051).

## الهدف
جمع قائمة العمليات كل 30 ثانية وكشف `nc -l` (reverse shell / listener) → Level 7.

## Agent (kali1)
```xml
<localfile>
  <log_format>full_command</log_format>
  <alias>process list</alias>
  <command>ps -e -o pid,uname,command</command>
  <frequency>30</frequency>
</localfile>
```
`sudo systemctl restart wazuh-agent`

## Manager — `local_rules.xml`
```xml
<group name="ossec,">
  <rule id="100050" level="0">
    <if_sid>530</if_sid>
    <match>ossec: output: 'process list'</match>
    <description>List of running processes.</description>
    <group>process_monitor,</group>
  </rule>
  <rule id="100051" level="7" ignore="900">
    <if_sid>100050</if_sid>
    <match>nc -l</match>
    <description>netcat listening for incoming connections.</description>
    <group>process_monitor,</group>
  </rule>
</group>
```
- **Level 0** للقاعدة الأب يمنع الضجيج (كل 30 ث).
- `ignore="900"` = لا تكرار للتنبيه نفسه خلال 15 دقيقة.

## محاكاة
```bash
nc -l -p 4444 &        # (netcat-traditional) أو: nc -l 4444 (openbsd)
sleep 40
kill %1
```

## التحقق
Threat Hunting → `rule.id: 100051` → "netcat listening for incoming connections." Level 7.

## ملاحظات
- يعتمد الكشف على السلسلة الحرفية `nc -l`؛ `ncat -l` أو `nc -lvp` تُطابق أيضاً (`nc -l` جزء منها)، لكن `netcat -l` لا. يمكن التوسعة بـ `<regex>` لاحقاً.
- تكامل ممتاز مع UC-05: تنفيذ `nc` يولّد 100210 (L12) فوراً، وبقاؤه مستمعاً يولّد 100051 كل 15 دقيقة.
