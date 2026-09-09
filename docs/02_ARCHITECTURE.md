# 02 — معمارية المعمل وحقائقه (Lab Architecture & Facts)

> **قاعدة:** كل قيمة هنا لها مصدر. `📷` = مؤكَّد بلقطة شاشة، `📄` = من نص المصدر فقط، `⚠️` = غير مؤكَّد/متعارض.
> مسارات اللقطات نسبية إلى `docs/sources/screenshots/` (`wazuh_guide/pNN_M.png` = S2، `wazuh_report/imgNN.png` = S5).

---

## 1. طوبولوجيا المعمل الفعلية

```
                    VMware Workstation  —  192.168.100.0/24
 ┌────────────────────────────────────────────────────────────────────────────┐
 │  ┌───────────────────────────┐        ┌────────────────────────────────┐   │
 │  │  wazuh-server (OVA 4.14)  │        │  kali1 — Kali GNU/Linux 2025.4 │   │
 │  │  192.168.100.105  📷      │◄─1514──┤  192.168.100.108  📷           │   │
 │  │  • wazuh-manager          │◄─1515──┤  hostname: kaliabdualrahman 📷 │   │
 │  │  • wazuh-indexer          │        │  wazuh-agent 4.14.7 📷         │   │
 │  │  • wazuh-dashboard :443   │        │  + suricata 8.0.6 (eve.json) 📷│   │
 │  │  • filebeat (internal)    │        │  + auditd (execve rules) 📷    │   │
 │  │  cluster node: node01 📷  │        │  + apache2 2.4.68 (victim) 📷  │   │
 │  │  user: wazuh-user 📷      │        │  + yara 4.5.5 (AR) 📷          │   │
 │  └────────────┬──────────────┘        └────────────────────────────────┘   │
 │               │ 1514/1515                                                  │
 │  ┌────────────▼──────────────┐        ┌────────────────────────────────┐   │
 │  │  win1 — Windows 10 Edu    │        │  Attacker (curl / nmap)        │   │
 │  │  10.0.19045.2006  📷      │        │  = kali1 نفسها أو Kali ثانية ⚠️│   │
 │  │  192.168.100.106  📷      │        │  (Shellshock target ظهر على    │   │
 │  │  wazuh-agent 4.14.7 📷    │        │   192.168.0.186 ⚠️ ISSUE-004)  │   │
 │  │  FIM: Desktop\abdul 📄    │        └────────────────────────────────┘   │
 │  └───────────────────────────┘                                             │
 └────────────────────────────────────────────────────────────────────────────┘
        ▲  HTTPS 443 — Analyst browser → https://192.168.100.105 (admin)
```

- Wazuh 4.x **All-in-one (OVA)**: Manager + Indexer + Dashboard على VM واحدة. لا Elasticsearch/Kibana منفصلة (ISSUE-003).
- Suricata **على kali1 نفسها** تراقب `eth0`؛ HOME_NET = `192.168.100.0/24, 10.0.0.0/8, 172.16.0.0/12` 📷 `p29_0.png`.
- على الأرجح **جهازا Kali**: `kaliabdualrahman` (user `kali`) في S2، وجهاز بالمستخدم `omar` (UID 1000) في S5 ⚠️ ISSUE-017.

---

## 2. جدول الأصول (Asset Inventory)

| الأصل | Hostname | IP | OS | الدور | Agent ID | الحالة (وقت اللقطة) | المصدر |
|-------|----------|----|----|-------|:--------:|------|--------|
| Wazuh Server | `wazuh-server` | 192.168.100.105 | Wazuh OVA 4.14 ⚠️ (الرسالة تقول Ubuntu Server — ISSUE-015) | Manager+Indexer+Dashboard | — | up | 📷 p01_0, p01_1, img06 |
| Windows endpoint | `win1` | 192.168.100.106 | Windows 10 Education 10.0.19045.2006 | FIM, VT-AR, YARA-win | 001 | disconnected | 📷 p04_0 |
| Linux endpoint | `kali1` | 192.168.100.108 | Kali GNU/Linux 2025.4 | FIM, VT, YARA, auditd, Suricata, Apache victim | 002 | active | 📷 p04_0 |

---

## 3. الإصدارات المؤكَّدة

| المكوّن | الإصدار | المصدر |
|---------|---------|--------|
| Wazuh Agent (Win + Linux) | **4.14.7-1** | 📷 p04_0 (Version column), p05_3 (`wazuh-agent-4.14.7-1.msi`), p06_1 (`wazuh-agent_4.14.7-1_amd64.deb`) |
| Wazuh Manager | 4.14.x (يجب ≥ إصدار الوكيل) | استنتاج |
| Suricata | **8.0.6 RELEASE** (SYSTEM mode, af-packet) | 📷 p30_0 |
| ET Open rules | `suricata-8.0.6/emerging.rules.tar.gz` أو `suricata-update` | 📄 S2 ص27–28 |
| YARA | **4.5.5** (built from source) | 📷 img20, img21 |
| YARA rules | VALHALLA demo feed (1.23 MB) | 📷 img22 |
| Apache | **2.4.68-1** | 📷 img13 |
| Kali Linux | **2025.4** | 📷 p04_0 |
| Windows | **10 Education build 19045.2006** | 📷 p04_0 |
| Python + PyInstaller (Win AR) | 3.x | 📄 S2 ص19 |

---

## 4. تدفق البيانات المُنفَّذ فعلاً

```
[kali1 agent]                                    [wazuh-server: analysisd]
 syscheck realtime ────────────────────────────►  550/553/554 (FIM base)
   /home/kali/SOCfile                              ├─ 100200/100201 ─► integratord ─► VirusTotal API
   /home/kali/abdul, /tmp/yara/malware             │      └─ 87105 (VT positive, L12) ─► AR remove-threat (agent-local)
                                                   ├─ 100300/100301 ─► AR yara_linux ─► yara.sh ─► active-responses.log
                                                   │      └─ yara_decoder ─► 108000 ─► 108001 (L12)
 logcollector /var/log/audit/audit.log (audit) ──►  80792 ─► CDB suspicious-programs ─► 100210 (L12, red)
 logcollector /var/log/apache2/access.log ───────►  31168 Shellshock (L15) + MITRE T1068/T1190
 logcollector /var/log/suricata/eve.json (json) ─►  86600–86601 Suricata alerts (e.g. NMAP SYN scan)
 command  ps -e -o pid,uname,command (every 30s) ►  530 ─► 100050 (L0) ─► 100051 nc -l (L7, ignore 900)
                                                   ▼
                                               filebeat ─► wazuh-indexer (wazuh-alerts-4.x-*) ─► wazuh-dashboard :443
[win1 agent]
 syscheck Desktop\abdul / Downloads ─────────────► نفس المسار؛ AR: remove-threat.exe / yara.bat (100303/100304)
```

---

## 5. سجل معرّفات القواعد (Rule ID Registry)

| ID | Level | النوع | الوصف | المصدر | الحالة |
|----|:-----:|-------|-------|--------|--------|
| 530 | 0 | built-in | ossec: output (command monitoring) | core | — |
| 550 / 553 / 554 | 7/7/5 | built-in | FIM modified / deleted / added | core | — |
| 657 | 3 | built-in | Active response log | core | — |
| 80792 | 3 | built-in | Audit: Command executed | core | — |
| 86601 | 3 | built-in | Suricata alert | core | — |
| 87105 | 12 | built-in | VirusTotal positive match | core | — |
| 31168 | 15 | built-in | Shellshock attack detected | core | — |
| **100050** | 0 | local | List of running processes (`process_monitor`) | img31 | مستخدم |
| **100051** | 7 | local | netcat listening (`nc -l`), ignore=900 | img31 | مستخدم |
| **100092** | 12 | local | AR removed threat (VT) | S2 ص17, img10 | مستخدم |
| **100093** | 12 | local | AR error removing threat | S2 ص17, img10 | مستخدم |
| **100200** | 7 | local | File modified in /home/kali/SOCfile → VT | S2 ص15, p17_0 | مستخدم |
| **100201** | 7 | local | File added to /home/kali/SOCfile → VT | S2 ص15, p17_0 | مستخدم |
| **100210** | 12 | local | Audit: Highly Suspicious Command (CDB red) | S2 ص35, img10, p36_0 | مستخدم ✅ مُثبَت في اللوحة |
| **100300** | 7 | local | File modified in YARA dir → AR yara | S2 ص44, img27 | مستخدم ⚠️ مكرَّر في S2 (ISSUE-010) |
| **100301** | 7 | local | File added to YARA dir → AR yara | S2 ص44, img27 | مستخدم ⚠️ |
| **100303** | 7 | local | Win: Downloads modified → yara_windows | S2 ص53 | مكتوب، التنفيذ ⚠️ ISSUE-006 |
| **100304** | 7 | local | Win: Downloads added → yara_windows | S2 ص53 | مكتوب ⚠️ |
| **108000** | 0 | local | Yara grouping (decoded_as yara_decoder) | S2 ص44, img27 | مستخدم |
| **108001** | 12 | local | YARA positive match | S2 ص45, img27 | مستخدم |

محجوز: `100400–100499` (network devices/syslog)، `100500–100599` (AI/reporting).

---

## 6. المسارات المرجعية

### Linux agent (kali1)
| الغرض | المسار |
|-------|--------|
| إعدادات الوكيل | `/var/ossec/etc/ossec.conf` |
| AR scripts | `/var/ossec/active-response/bin/{remove-threat.sh,yara.sh}` (root:wazuh, 750) |
| AR log | `/var/ossec/logs/active-responses.log` |
| مجلدات FIM | `/home/kali/SOCfile`, `/home/kali/abdul`, `/tmp/yara/malware` |
| قواعد YARA | `/tmp/yara/rules/yara_rules.yar` ⚠️ في `/tmp` — تُمسح عند الإقلاع (ISSUE-020) |
| YARA binary | `/usr/local/bin/yara` |
| auditd | `/etc/audit/audit.rules`، وفي S5: `/etc/audit/rules.d/wazuh.rules` (img02) |
| Suricata | `/etc/suricata/suricata.yaml`, `/var/lib/suricata/rules/*.rules`, `/var/log/suricata/eve.json` |
| Apache | `/var/log/apache2/access.log` |

### Windows agent (win1)
| الغرض | المسار |
|-------|--------|
| إعدادات الوكيل | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| AR | `...\ossec-agent\active-response\bin\{remove-threat.exe,yara.bat}` |
| YARA | `...\active-response\bin\yara\yara64.exe`, `...\yara\rules\yara_rules.yar` |
| AR log | `...\ossec-agent\active-response\active-responses.log` |
| مجلدات FIM | `C:\Users\Lenovo\Desktop\abdul`, `C:\Users\<USER_NAME>\Downloads` |
| إعادة تشغيل | `Restart-Service -Name wazuh` |

### Wazuh server
| الغرض | المسار |
|-------|--------|
| إعدادات المدير | `/var/ossec/etc/ossec.conf` |
| قواعد مخصصة | `/var/ossec/etc/rules/local_rules.xml` |
| decoders مخصصة | `/var/ossec/etc/decoders/local_decoder.xml` |
| CDB lists | `/var/ossec/etc/lists/{audit-keys,suspicious-programs}` |
| إعادة تشغيل | `sudo systemctl restart wazuh-manager` |

---

## 7. المنافذ

| منفذ | بروتوكول | الاتجاه | الغرض |
|------|----------|---------|-------|
| 1514 | TCP | agent → manager | أحداث |
| 1515 | TCP | agent → manager | enrollment |
| 443 | TCP | analyst → dashboard | واجهة الويب |
| 9200 | TCP | manager → indexer | داخلي |
| 55000 | TCP | dashboard → manager | Wazuh API |
| 80 | TCP | attacker → kali1 | Apache victim |
| 514 | UDP/TCP | network devices → manager | **مستقبلي (P3)** syslog |

---

## 8. الطبقات الست للرسالة — النسخة المطابقة للواقع

| الطبقة (S4 §3.6.1) | المكوّن الفعلي |
|--------|----------------|
| 1. مصادر البيانات | win1, kali1, Apache logs, auditd, process list |
| 2. الجمع | Wazuh Agent 4.14.7 (syscheck, logcollector, command) + Suricata 8.0.6 |
| 3. المعالجة والربط | wazuh-analysisd: decoders → rules → CDB → MITRE ATT&CK → level |
| 4. القرار | level ≥ 3 → alert؛ قواعد مخصصة L7/L12/L15 |
| 5. الاستجابة والتخزين | Active Response + integratord (VirusTotal) → filebeat → Wazuh Indexer |
| 6. الإخراج | Wazuh Dashboard (Threat Hunting, FIM, MITRE ATT&CK) |

> أعمال مستقبلية فقط (غير منفَّذة): Zeek، Email/Telegram، TheHive، AI analyzer.
