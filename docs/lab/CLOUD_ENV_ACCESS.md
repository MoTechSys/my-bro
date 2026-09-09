# الوصول إلى بيئة التنفيذ السحابية (Cloud Lab) — للوكلاء

> **الغرض:** أي وكيل (CLAUDE / ASTRA / غيرهما) في **أي جلسة جديدة** يقرأ هذا الملف ويتصل ويكمل من حيث توقّف السابق — بدون إعادة اكتشاف.
> **المالك:** CLAUDE (أنشأها 2026-09-09). **يُحدَّث** كل مرة يتغيّر فيها شيء في البيئة (§7).
> **⚠️ لا أسرار هنا.** كلمات المرور في `~/soc/.secrets.env` **على السيرفر فقط** (mode 600). المفتاح الخاص للـSSH عند المستخدم/الوكيل الذي ولّده — لا يُرفع أبداً.

---

## 1. البيئة — ما هي

| البند | القيمة |
|---|---|
| المزوّد | Azure VM (مُدارة عبر Genspark Cloud Computer) |
| Hostname | `manus-mab1-f36ed7b3-5606-vm.azure.gensparkclaw.com` |
| IP عام | `20.196.217.36` |
| IP داخلي | `10.0.66.180/18` |
| OS | Ubuntu 24.04.4 LTS، kernel 6.17 azure |
| موارد | 4 vCPU · 15 GB RAM · 123 GB disk (88 متاح) |
| **حاجز صلب** | **لا nested virtualization** (`/dev/kvm` غير موجود) → **لا VMs**؛ Docker فقط |
| إنترنت | ✅ خارجي (packages.wazuh.com، virustotal.com) |
| المعمل المحلي (192.168.100.x) | ❌ **غير متاح** من السحابة — يحتاج WireGuard (§6) |
| Caddy | يشغل 80/443/8443 — **لا تلمسها**؛ لذلك Dashboard على **8444** |

## 2. كيف تتصل (SSH)

```bash
# 1. المفتاح: المستخدم يزوّدك بالمفتاح الخاص ~/.ssh/cloudlab (أو تولّد مفتاحاً جديداً وتطلب إضافته — §2.1)
chmod 600 ~/.ssh/cloudlab

# 2. تحقّق من بصمة المضيف قبل أول اتصال (ضد MITM):
ssh-keygen -lf <(ssh-keyscan -t ed25519 20.196.217.36 2>/dev/null)
#   يجب أن تطابق تماماً:
#   256 SHA256:ANroUBB9qIUa5XMt+782zNeJkfM2QafuBaRbL7ZJqJY (ED25519)
#   RSA: SHA256:q00Hg9ABoW4z0nQkE8CYIMXyqgwVlvqvmz/3P3HiLCk

# 3. اتصل:
ssh -i ~/.ssh/cloudlab work@20.196.217.36
#   user=work · port=22 · مفتاح فقط (PasswordAuthentication no) · sudo بلا كلمة مرور
```

### 2.1 وكيل جديد بمفتاح جديد
```bash
ssh-keygen -t ed25519 -C "<agent-name>-lab-agent" -f ~/.ssh/cloudlab -N ""
cat ~/.ssh/cloudlab.pub     # أرسل هذا فقط للمستخدم → يضيفه وكيل السحابة إلى /home/work/.ssh/authorized_keys
```
المفاتيح العامة المُصرَّح بها حالياً (3): مفتاح صاحب البيئة، مفتاح وكيل السحابة، ومفتاح CLAUDE:
`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBioG9VOW3xqrFA0/o4GHixP8OYB5x8Bhf+reA1Curjw claude-lab-agent`

## 2.3 الطريقة الأسرع: حزمة Bootstrap للنسخ واللصق (يحتفظ بها المستخدم)
المستخدم يملك ملفاً خاصاً `CLOUD_LAB_BOOTSTRAP_PRIVATE.txt` (**خارج Git** — فيه المفتاح الخاص base64 + بصمة المضيف + `~/.ssh/config` + أمر تحقق). يلصقه كاملاً في أي جلسة وكيل جديدة → الوكيل ينفّذ الكتلة → `ssh cloudlab` يعمل فوراً. **مُختبَر من HOME نظيف 2026-09-09 08:18Z.**
- إن ضاع الملف أو اشتُبه بتسرّب المفتاح: وكيل السحابة يحذف سطر `claude-lab-agent` من `/home/work/.ssh/authorized_keys`، ويُولَّد مفتاح جديد (§2.1) وتُعاد الحزمة.
- الحزمة **لا** تحوي كلمات مرور Wazuh؛ تلك تبقى في `~/soc/.secrets.env` على السيرفر.

### 2.2 مسار احتياطي: Genspark Mesh
السيرفر منضمّ إلى mesh حساب صاحب البيئة: `100.64.0.1` (اسم `manus-mab1-f36ed7b3-5606-vm`)، `gsk-mesh serve` يعمل. **يعمل فقط لوكيل على نفس حساب Genspark.** إن كنت كذلك: `gsk mesh join && gsk mesh ssh work@manus-mab1-f36ed7b3-5606-vm`.

## 3. ما هو منشور الآن (2026-09-09 08:05 UTC)

```
~/soc/
├── wazuh-docker/single-node/      # الرسمي v4.14.1، docker compose
│   ├── docker-compose.yml         # المنفذ 443→8444 مُعدَّل؛ كلمات المرور مُغيَّرة
│   └── config/wazuh_indexer/internal_users.yml   # hashes جديدة (بعد إصلاح YAML)
├── .secrets.env                   # INDEXER_ADMIN / DASHBOARD_KIBANASERVER / WAZUH_API  (600)
├── repo/                          # نسخة من wazuh/ + scripts/ من الريبو (tar من main)
├── agent/                         # Dockerfile + entrypoint لحاوية الوكيل
└── agent_config.sh                # يدفع إعدادات syscheck/localfile إلى kali1
```

| الحاوية | الصورة | الحالة | الوصول |
|---|---|---|---|
| `single-node-wazuh.manager-1` | wazuh/wazuh-manager:4.14.1 | ✅ 10/10 daemons | 1514/1515/514udp/55000 |
| `single-node-wazuh.indexer-1` | wazuh/wazuh-indexer:4.14.1 | ✅ cluster **green** | `https://localhost:9200` (admin) |
| `single-node-wazuh.dashboard-1` | wazuh/wazuh-dashboard:4.14.1 | ✅ HTTP 200 | `https://20.196.217.36:8444` (admin) |
| `kali1` | soc-agent:4.14.1 (Ubuntu 24.04 + agent + apache2 + auditd + nc + nmap) | ✅ **agent 001 active** | شبكة `single-node_default` |

**مُطبَّق على المدير:** `local_rules.xml` (مع `<USER_NAME>`→`Lenovo`)، `local_decoder.xml`، قوائم CDB (`suspicious-programs`, `malicious-ioc`)، `<list>` في `<ruleset>`، كتل AR `remove-threat` + `yara_linux/yara_windows`. `wazuh-analysisd -t` ✅.
**مُطبَّق على kali1:** syscheck realtime على `/home/kali/SOCfile`, `/home/kali/abdul`, `/tmp/yara/malware`؛ localfile apache (`log_format apache`)؛ full_command `ps` كل 30 ث. Real-time FIM **started** ✅.

**مُتحقَّق بـlogtest:** 31168 Shellshock ✅ · 100050 process grouping ✅.
**غير مُطبَّق بعد:** VirusTotal API key (placeholder)، سكربتات AR داخل kali1 (`soc_ar.py` وغلافه)، YARA binary، auditd rules (auditd في حاوية يحتاج `--privileged` أو host audit — ⚠️ قيد)، Suricata، Windows، MikroTik.

## 4. أوامر التحقق السريع (شغّلها أول ما تتصل)

```bash
cd ~/soc; source .secrets.env
docker ps --format "{{.Names}}\t{{.Status}}"
curl -s -k -u "admin:$INDEXER_ADMIN" https://localhost:9200/_cluster/health | jq -r .status      # green
TOKEN=$(curl -s -k -u "wazuh-wui:$WAZUH_API" -X POST https://localhost:55000/security/user/authenticate?raw=true)
curl -s -k -H "Authorization: Bearer $TOKEN" "https://localhost:55000/agents?select=id,name,status" | jq -c '.data.affected_items[]'
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status | grep -c "is running"   # 10
docker exec kali1 /var/ossec/bin/wazuh-control status | grep -c "is running"                          # 5
free -h | sed -n 2p   # ~3.8 GB used by stack
```

## 5. حقائق مُتحقَّقة مهمة للقياس

| الحقيقة | القيمة | الأثر |
|---|---|---|
| **دقّة `alert.timestamp`** (ISSUE-061) | **ميلي ثانية** — مثال `2026-09-09T07:56:41.333+0000` | ✅ t2 بدقة ms؛ لا تعديل على §5.4 |
| الذاكرة الفعلية للمكدّس | indexer 1.5 GB · manager 0.48 GB · dashboard 0.18 GB · kali1 ~0.1 GB = **~2.3 GB** | هامش كبير لحاويات إضافية (win ❌، mikrotik ❌ لأنها VMs) |
| Filebeat → Indexer | TLS 1.3 · `talk to server... OK` | التنبيهات تصل اللوحة |
| كلمة مرور admin الافتراضية | **401 مرفوضة** ✅ | البيئة ليست بالإعدادات الافتراضية |

## 6. حدود هذه البيئة وما يلزم للباقي

| UC | هنا (Docker) | يحتاج |
|---|---|---|
| 01,02,03,05*,06,07,08,09 | ✅ قابلة للتنفيذ | *auditd في حاوية: `--privileged` أو تشغيل auditd على المضيف وقراءة `/var/log/audit` — يُقرَّر في PILOT |
| 04 Suricata | ⚠️ جزئي | حاوية Suricata بـ`--net=host --cap-add=NET_ADMIN` ترى حركة الـVM كلها، لا شبكة معزولة |
| 10 Telegram | ✅ | توكن فقط |
| 11 SSH brute-force | ✅ | sshd داخل kali1 + hydra من حاوية ثانية؛ firewall-drop يحتاج `NET_ADMIN` (موجود) |
| 12 MikroTik، 13 M0 هاتف، Windows | ❌ | **WireGuard** بين السحابة (سيرفر، منفذ UDP 51820 مفتوح) وأجهزة أخيه (عملاء) — أو تشغيلها على المعمل المحلي |

## 7. سجل التغييرات على البيئة

| التاريخ (UTC) | من | ما تغيّر |
|---|---|---|
| 2026-09-09 ~07:30 | وكيل السحابة | Docker 29.1.3 مُركَّب؛ مفتاح CLAUDE مُضاف؛ mesh join+serve |
| 2026-09-09 07:53 | CLAUDE | clone wazuh-docker v4.14.1؛ certs؛ كلمات مرور عشوائية قوية؛ 443→8444؛ `compose up` |
| 2026-09-09 07:56 | CLAUDE | إصلاح `internal_users.yml` (regex كتب `\"`)؛ `securityadmin.sh` بمسار `config/certs/`؛ admin الجديد 200، الافتراضي 401 |
| 2026-09-09 07:58 | CLAUDE | نشر rules/decoders/lists/AR من الريبو؛ إصلاح تعليق XML مقطوع؛ `<USER_NAME>`→Lenovo |
| 2026-09-09 08:02 | CLAUDE | بناء `soc-agent:4.14.1`؛ تشغيل `kali1` → agent 001 active |
| 2026-09-09 08:04 | CLAUDE | `agent_config.sh`: syscheck realtime + apache + ps → FIM realtime started |

**⚠️ معلَّق:** إعادة تشغيل الـVM مطلوبة (kernel 1022 مُركَّب، 1020 شغّال) — **بعد** أخذ `docker compose down` أو التأكد أن `restart: always` مُفعَّل (هو مُفعَّل في compose الرسمي).

## 8. الخطوة التالية بالضبط (لمن يتصل بعدي)

1. `source ~/soc/.secrets.env` وشغّل §4.
2. **PILOT UC-02** (أبسط سلسلة): `docker exec kali1 sh -c 'echo x > /home/kali/SOCfile/p1'` → اقرأ `alerts.json` على المدير → سجّل t0/t2 بصيغة JSONL حسب `tests/README.md` (عقد v2 لأسترا).
3. ثبّت `soc_ar.py` + غلاف `remove-threat.exe` داخل kali1 وفق `wazuh/README.md`، ثم VT key (يزوّده المستخدم — **لا يُكتب في Git**).
4. PILOT UC-06 (curl Shellshock من حاوية ثانية إلى kali1:80) وUC-08 (nc -l داخل kali1).
5. قرار auditd (UC-05) وSuricata (UC-04) حسب §6.
6. حدّث §3 و§7 هنا بعد كل تغيير، وسجّل في `SESSIONS_LOG.md`.
