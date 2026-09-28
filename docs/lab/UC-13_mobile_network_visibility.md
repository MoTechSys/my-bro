# UC-13 — رؤية الأجهزة والهواتف من الشبكة (M0)

**الحالة:** ✅ مُثبت حياً (محاكي RouterOS DHCP → UDP 514 → Wazuh 4.14.7).
**الصياغة الصادقة:** هذا **رؤية شبكية** (أي جهاز يأخذ عنواناً من DHCP) — **ليس** مراقبة داخل الهاتف (لا وكيل Wazuh رسمي للهواتف).

## القواعد (`local_rules_network.xml`)
| ID | L | المعنى |
|---|---|---|
| 100420 | 3 | DHCP lease: IP → MAC [hostname] (جرد) |
| 100422 | 8 | **جهاز غير معروف** (MAC ليس في `etc/lists/known-devices`) انضم للشبكة — T1200 |
| 100421 | 9 | جهاز غير معروف **بعنوان MAC عشوائي** (locally administered: الخانة الثانية 2/6/A/E) = نمط Android 10+/iOS 14+ → هاتف/تابلت على الأرجح |

## جرد الأجهزة المعروفة
`wazuh/manager/lists/known-devices` (CDB؛ المفاتيح بها `:` فتُقتبس):
```
"00:0C:29:AA:BB:01":kali1
```
أضف كل جهاز مُعتمَد → لا تصعيد له (100420 فقط).

## الدليل الحي
```
100421 9 Network visibility: UNKNOWN mobile-like device (randomized MAC 16:17:44:94:D6:49) Galaxy-A54 got 192.168.88.x
100420 3 Network visibility: DHCP lease 192.168.88.20 -> 00:0C:29:AA:BB:01 kali1.
100422 8 Network visibility: UNKNOWN device 3C:22:FB:10:20:30 Galaxy-S23 joined the network
```

## ما يُرى وما لا يُرى
| يُرى | لا يُرى |
|---|---|
| انضمام الجهاز، IP، MAC، hostname (إن أرسله) | التطبيقات، الملفات، العمليات داخل الهاتف |
| حركة الهاتف عبر الراوتر (firewall log / Suricata إن وُجد mirror) | حركة مشفرة (المحتوى) |
| هجمات يشنها الهاتف على الشبكة (100411، SSH 5712…) | ما يحدث على بيانات الجوال (4G/5G) خارج الشبكة |
