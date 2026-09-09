# UC-02 — مراقبة سلامة الملفات (File Integrity Monitoring)

**المصدر:** S2 ص6–11، لقطات `p08_0`, `p08_1`, `p09_0`, `p09_1`, `p10_0`, `p18_1`.

## الهدف
كشف إنشاء/تعديل/حذف الملفات في مجلد محدد فورياً (realtime) على Linux وWindows.

## إعداد Linux (kali1) — `/var/ossec/etc/ossec.conf` داخل `<syscheck>`
```xml
<directories check_all="yes" report_changes="yes" realtime="yes">/home/kali/abdul</directories>
```
ملف الإعداد النظيف: `wazuh/agents/linux/ossec.conf.d/10-syscheck-dirs.xml`. ثم `sudo systemctl restart wazuh-agent`.

## إعداد Windows (win1) — `C:\Program Files (x86)\ossec-agent\ossec.conf`
```xml
<directories check_all="yes" report_changes="yes" realtime="yes">C:\Users\Lenovo\Desktop\abdul</directories>
```
ثم `Restart-Service -Name wazuh` (PowerShell admin).

## المحاكاة
```bash
echo test > /home/kali/abdul/ali2.txt ; sleep 5 ; echo more >> /home/kali/abdul/ali2.txt ; sleep 5 ; rm /home/kali/abdul/ali2.txt
```

## النتيجة الفعلية
`p09_1.png`: حدثان على `kali1` — `554 File added to the system` (/home/kali/abdul/ali2.txt) و`550 Integrity checksum changed` (/etc/resolv.conf). `p18_1.png`: 10 أحداث FIM على `/home/kali/SOCfile/` (added/modified/deleted).

## استعلام اللوحة
File Integrity Monitoring → Events → `rule.id: is one of 550,553,554`.

## ملاحظات
- `check_all="yes"` يشمل md5/sha1/sha256/size/owner/perm؛ `report_changes="yes"` يخزن diff للملفات النصية.
- لبيانات who-data (المستخدم/العملية) استخدم `whodata="yes"` بدل `realtime` (يحتاج auditd على Linux).
