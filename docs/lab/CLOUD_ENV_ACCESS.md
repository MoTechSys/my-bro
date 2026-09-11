# الوصول إلى بيئة التنفيذ السحابية (Cloud Lab) — للوكلاء

> **آخر تحقق: 2026-09-11، تدقيق قراءة فقط [AI]. ابدأ من §9 قبل أي تجربة.** توجد 19 عملية zombie مع خمس خدمات Wazuh حية وتقدم عدادات الجمع؛ ليس توقفاً كلياً مثبتاً. PID 1 هو `tail`، ولا init أو healthcheck أو restart policy أو mounts. إصلاح دورة الحياة وcanary والاستعادة بوابات مفتوحة؛ نتائج 2026-09-09 أدناه تاريخية وليست اعتماداً للحالة الحالية.

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

## 8. تسلسل التجارب السابق — لا يبدأ قبل بوابات §9

الأوامر التالية محفوظة كسياق سابق، وليست أمراً بالتنفيذ فور الاتصال. طلب المستخدم الأحدث يقدّم إصلاح دورة حياة kali1 وإثبات الجمع والاستعادة على أي PILOT. لا تشغّل UC-03/07 قبل نشر AR/YARA الآمنين واجتياز بوابات SECURITY_REVIEW.

1. `source ~/soc/.secrets.env` وشغّل §4.
2. **PILOT UC-02** (أبسط سلسلة): `docker exec kali1 sh -c 'echo x > /home/kali/SOCfile/p1'` → اقرأ `alerts.json` على المدير → سجّل t0/t2 بصيغة JSONL حسب `tests/README.md` (عقد v2 لأسترا).
3. ثبّت `soc_ar.py` + غلاف `remove-threat.exe` داخل kali1 وفق `wazuh/README.md`، ثم VT key (يزوّده المستخدم — **لا يُكتب في Git**).
4. PILOT UC-06 (curl Shellshock من حاوية ثانية إلى kali1:80) وUC-08 (nc -l داخل kali1).
5. قرار auditd (UC-05) وSuricata (UC-04) حسب §6.
6. حدّث §3 و§7 هنا بعد كل تغيير، وسجّل في `SESSIONS_LOG.md`.

## 9. تدقيق حي 2026-09-11 — الحالة الحاكمة قبل الاستكمال

### 9.1 النطاق والاتصال

- الأساس البرمجي المفحوص: `e51dd7d66976014d298bd67258d30ad2923f4ddb`، مطابق لـmain عند بدء التدقيق؛ لا PR مفتوح حينها.
- SSH نجح عند `2026-09-11T09:46:41Z` بحساب `work`. فُحص سكربت bootstrap قبل استخدامه، ولم يُنفذ `curl | bash`.
- حُفظ المفتاح وknown_hosts وconfig في مجلد خاص تحت `.git/soclab-private/` داخل مساحة العمل، بصلاحيات 0700 للمجلد و0600 للملفات. ليست ملفات متتبعة ولا مخرجات عامة. لا تنسخ مجلد .git كحزمة مشاركة.
- الاتصال يستخدم `StrictHostKeyChecking=yes` و`IdentitiesOnly=yes` ولا يمرر SSH agent. بصمتا RSA/ED25519 تطابقان §2. لا يُنشر رابط bootstrap أو المفتاح أو كلمات المرور في Git/PR.
- **قيد الجلسة:** الكتابة مسموحة فقط تحت `/home/user/webapp`. لذلك لم تُعدّل ملفات الخادم `/home/work`، ولم يُكتب `~/lab/DECISIONS.md`، ولم تُعد حاوية أو خدمة. هذا عائق تنفيذ خاص بالجلسة، لا نقص تفويض من المستخدم ولا فشل SSH.

### 9.2 القياس المباشر مقابل البلاغ السابق

المستخدم أبلغ عن توقف كامل بسبب zombie. الفحص الحالي يثبت عيب reaping لكنه لا يثبت استمرار التوقف الكامل:

| الفحص | المخرج المرصود | الاستنتاج المسموح |
|---|---|---|
| `docker exec kali1 ps -eo pid,ppid,stat,etimes,comm` | PID 1=`tail`؛ 19 zombie؛ خدمات حية: execd=2118، agentd=2129، syscheckd=2143، logcollector=2179، modulesd=2195 | العمليات القديمة ميتة، لكن توجد بدائل حية؛ PIDs دليل لقطة لا ثوابت للنشر |
| Docker inspect للوكيل | Init=null؛ RestartPolicy.Name=no؛ Healthcheck=null؛ Mounts=[] | الحاوية غير معتمدة للتعافي التلقائي؛ إعادة الإنشاء قد تفقد حالتها الخاصة |
| `/entrypoint.sh` | يشغّل apache وwazuh-control ثم `exec tail -F /var/ossec/logs/ossec.log` | `tail` ليس مدير خدمات أو reaper؛ خروج خدمة لا يوقف PID 1 تلقائياً |
| الصورة الفعلية | soc-agent:4.14.1؛ `/etc/os-release`: Ubuntu 24.04.4 LTS | kali1 اسم وكيل؛ الحاوية ليست Kali Linux؛ لا تخلط نتائجها مع معمل Kali التاريخي |
| الحاويات | kali1 + manager/indexer/dashboard 4.14.1، الأربع Up 2 days | تشغيل الحاوية وحده لا يثبت سلامة التطبيق |
| `/var/ossec/logs/alerts/alerts.json` | 0 بايت، آخر تعديل `2026-09-11 00:00:01 UTC` عند لقطة 09:47 تقريباً | الملف اليومي الفارغ ليس دليلاً منفرداً على توقف الجمع؛ لا تنبيه اختبار جديد |

**عينتان سلبيتان، دون توليد حدث اختبار:**

| المؤشر | 09:47:44 UTC | 09:48:21 UTC | الفرق |
|---|---:|---:|---:|
| agentd msg_count | 13037 | 13038 | +1 |
| agentd msg_sent | 21989 | 21992 | +3 |
| logcollector global process-list events | 5966 | 5968 | +2 |
| remoted evt_count | 14139 | 14140 | +1 |
| analysisd events_processed | 18103 | 18112 | +9 |
| analysisd events_dropped | 0 | 0 | 0 |
| analysisd alerts_written | 285 | 285 | 0 |

`last_ack` تقدم من 09:47:29 إلى 09:48:09 UTC. فترتا logcollector المنشورتان تنتهيان 09:47:20 و09:48:20، وليستا التقاطاً ذرياً مع عدادات المدير. هذه أدلة على نشاط الجمع والنقل والتحليل، **لا ربط سببي لحدث فريد ولا نجاح لكل UC ولا قياس MTTD**. لا يُستنتج سبب خروج العمليات القديمة من وجود zombie وحده؛ غياب reaper يفسر بقاءها، لا سبب خروجها الأصلي.

### 9.3 حدود البيئة وما لم يُنشر

- الموارد المرصودة: RAM متاحة نحو 11 GiB، قرص متاح 67 GB. أربعة vCPU. هذه لقطة حالية لا ميزانية مضمونة لتشغيل نماذج.
- vmx/svm=0 ولا `/dev/kvm`. فشل ping إلى 192.168.100.105، ولا واجهة نفق ظهرت في labstate. هذا لا يثبت استحالة كل مسار شبكي؛ يطابق غياب الربط المحلي المبلغ عنه.
- labstate أعاد API=401 وIndexer=401 دون بيانات دخول وDashboard=302. هذه استجابات HTTP فقط؛ لا تحقق cluster green أو تسجيل دخول أو سلامة TLS لأن helper يستخدم `curl -k`.
- `timedatectl`: NTP=yes، NTPSynchronized=yes، Timezone=Asia/Aden. لا يثبت ذلك offset أو uncertainty أقل من 100ms؛ بوابة الساعات باقية. الأزمنة في هذا القسم UTC صراحةً.
- **غياب مثبت في kali1:** `soc_ar.py`، `remove-threat.exe`، `yara.sh` تحت active-response/bin؛ `/usr/local/bin/yara`؛ `/var/ossec/etc/yara/rules/yara_rules.yar`.
- لا فحص لمحتويات ملفات الأسرار، ولا تنزيل عينات أو تشغيل حذف أو هجمات. لا تعديل للقواعد أو المنافذ أو الشبكة أو Caddy أو الخدمات.

### 9.4 اختبارات المستودع المنفذة محلياً

على الأساس المذكور، داخل sandbox لا داخل الحاويات:

```bash
python3 -B -m unittest discover -s tests -v
# Ran 145 tests in 4.204s — OK
bash scripts/validate/validate_all.sh
# ALL CHECKS PASSED
```

Exit code=0 لكليهما. سجلا التشغيل الخاصان محفوظان تحت `.git/soclab-private/` في هذه الجلسة؛ لا ضمان لاستمرارهما خارج مساحة العمل. بصمتا SHA-256 لتعيين المخرج الأصلي، لا كبديل لمراجعته:

- unittest: `8474112020de42ece0d8be9b5ed48adfe0732cba26658711969cc63cc0bf8577`
- validator: `da4114f4f0e6312712d6ee26722719be8ad18e1ee2d34eedde2c964d56279718`
- العينتان السلبيتان: `6cc34ddc1eb4666700a92e84175665ce9f1e1213e996c9800c706ed7eb3291bb`

اختبارات اصطناعية وعمليات Python غير هجومية؛ ليست نتائج معملية. لا canary أو PILOT أو اختبارات Windows/YARA أصلية. لا إغلاق T-11/T-15/T-60.

### 9.5 خطة الإصلاح ومعيار القبول — غير منفذة

ينفذها مشغّل في جلسة تسمح بتعديل الخادم؛ **لا تبدأ بـdocker rm أو compose down -v**:

1. إعادة الجرد لحظة التنفيذ؛ حفظ وصف إنشاء الحاوية وشبكتها/capabilities وصورتها digest، ونسخة خاصة قابلة للاستعادة من حالتها وإعدادات الوكيل وهوية التسجيل وقواعد البيانات والملفات المراقبة. Mounts=[] يجعل النسخ قبل إعادة الإنشاء إلزامياً. لا نشر client.keys أو docker inspect الكامل أو أرشيف الحاوية في Git.
2. التحقق من مصدر إعدادات الحاوية الحالي ومقارنته بالصورة؛ لا تفترض أن إعادة التشغيل من الصورة تعيد التعديلات أو agent 001. اختبار الاستعادة دون تشغيل هويتين متطابقتين متزامنتين.
3. إدخال `init: true`/`--init` عند إعادة الإنشاء، مع إدارة عمر الخدمات فعلياً: supervisor أو تشغيل foreground موثّق وإيقاف منظم. **init يعالج reaping ولا يعيد تشغيل الخدمات الميتة وحده**؛ تحقق من خيارات البرامج قبل إعدادها.
4. إضافة healthcheck يفحص خدمة واحدة حية غير zombie لكل daemon مطلوب، وحداثة ACK وتقدم مصدر دوري خلال نافذته. إضافة restart policy مع سلوك واضح عند تعطل الخدمة؛ **Docker لا يعيد تشغيل الحاوية لمجرد unhealthy**. لا تكتف بفحص `docker ps` أو `wazuh-control status`.
5. تأمين استدامة الإعدادات والهوية وفق نموذج تخزين مختبر، والتحقق من صلاحياته؛ لا تركّب volume فارغاً فوق تثبيت Wazuh فتخفيه. تسجيل التغييرات والأوقات ونسخة الرجوع في `~/lab/DECISIONS.md` والمستودع.
6. بعد الإصلاح: اختبار إيقاف وتشغيل مضبوط واستعادة، مع عدم نمو zombies وعدم فقد الهوية. التحقق من استمرار الخدمات وتقدم العدادات، لا لقطة واحدة.
7. **ثم** canary غير مؤذٍ بهوية ومسار فريدين ومصدر مستقل وrule/agent/path مطابقين، مع التحقق من عدم تفعيل AR غير المعتمد. إثبات التنبيه الأصلي ووصوله للفهرس؛ لا اعتبار logtest بديلًا لمسار end-to-end.
8. فحص الساعات ودقة المصادر والمراقبين، ثم PILOT5 للحالات الجاهزة وفق TEST_PLAN. يبقى AR/YARA/Windows خارج القبول حتى نشرها وفحصها؛ لا إنتاج أرقام فصل5 من هذا التدقيق السلبي.

المشكلات المرتبطة: ISSUE-064 لدورة الحياة، ISSUE-065 لفقد الحالة عند إعادة الإنشاء، ISSUE-066 لحدود بيانات الصحة والقياس. تبقى OPEN/NEEDS-LAB حتى أدلة قبول مستقلة عن هذا الوصف.
