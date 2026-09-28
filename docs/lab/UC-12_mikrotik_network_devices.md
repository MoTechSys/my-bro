# UC-12 — أجهزة الشبكة (MikroTik RouterOS) عبر Syslog

**الحالة:** ✅ مُثبت حياً عبر UDP 514 على Wazuh 4.14.7، بمحاكي RouterOS (`mikrotik_syslog_sim.py`) لا راوتر فعلي.
**المساهمة C3:** Wazuh 4.14.7 الخام **لا يفك أي سطر RouterOS** (مُتحقَّق: 2501 أو لا شيء).

## الملفات
- `wazuh/manager/decoders/mikrotik_decoders.xml` — v6 + v7 (كل الأبناء باسم واحد `mikrotik-fields`: شرط Wazuh لتجربة كل regex)
- `wazuh/manager/rules/local_rules_network.xml` — 100400–100422
- `wazuh/manager/ossec.conf.d/70-remote-syslog-network-devices.xml` — `<remote>` syslog UDP 514 + `allowed-ips`

## القواعد
| ID | L | الحدث | MITRE |
|---|---|---|---|
| 100401 | 5 | login failure for user X from IP via winbox/ssh/web | T1110 |
| 100402 | 10 | 5 فشل من نفس IP خلال 120 ث (brute force على الإدارة) | T1110.001 |
| 100403 | 3 | دخول ناجح | — |
| 100404 | 12 | **دخول ناجح من نفس IP بعد brute force** = اختراق محتمل | T1078 |
| 100405 | 8 | تغيير إعداد (added/removed/changed/…) | T1562.004 |
| 100406 | 12 | تغيير أمني: user / filter rule / nat rule / ip service / firewall | T1562.004, T1136 |
| 100410 | 4 | سطر firewall log (input/forward) | — |
| 100411 | 10 | 15 منفذاً مختلفاً من نفس IP خلال 60 ث (port scan على الراوتر) | T1046 |

## إعداد الراوتر (RouterOS v6/v7)
```
/system logging action add name=wazuh target=remote remote=<MANAGER_IP> remote-port=514 bsd-syslog=yes
/system logging add topics=system   action=wazuh
/system logging add topics=dhcp     action=wazuh
/system logging add topics=firewall action=wazuh     # + log=yes على قواعد filter المطلوب رصدها
```
المدير: كتلة `70-...xml` مع `allowed-ips` = IP الراوتر فقط.

## المحاكاة
```bash
python3 scripts/attack-emulation/mikrotik_syslog_sim.py --lab <MANAGER_IP> all --source-ip <ROUTER_IP>
# سيناريوهات: bruteforce | config | scan | phone | known | all
```

## الدليل الحي (2026-09-28)
26 datagram → 100401×4، 100402، **100404 (L12)**، 100406×2، 100405، 100410×14، **100411**، 100421، 100420. datagram من مصدر غير مسموح (10.99.0.3) **أُسقط** (لا تنبيه). اختبارات: `tests/test_wazuh_engine.py::NetworkDevices` (9).

## حدود
محاكي لا جهاز؛ الرسائل بصيغة RouterOS الموثقة. تحقق حي على CHR/جهاز فعلي يبقى مستحسناً. switches غير MikroTik تحتاج decoders خاصة (العقد نفسه: syslog → decoder → 1004xx).
