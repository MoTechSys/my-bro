# MASTER PLAN v3 — الخطة التفصيلية المدقَّقة رياضياً وبحثياً

> **المالك:** CLAUDE | **التاريخ:** 2026-09-09 | **الحالة:** v3 — تحلّ محل v2 كخطة حاكمة
> **ما الجديد في v3:** كل رقم في الخطة له اشتقاق رياضي أو مصدر أولي مقروء مباشرة (لا ملخصات). **غيّرت الرياضيات قرارات v2** (انظر §0). كل بند عليه علامة تدقيق: ✅ مُتحقَّق من مصدر أولي | 🧮 مُشتق رياضياً | ⚠️ افتراض يحتاج قياس.
> **المنهج:** (1) ما هو المشروع بالتفصيل، (2) ما نبنيه بالضبط، (3) كيف نقيسه بصرامة، (4) ما يُثبته كل رقم وما لا يُثبته.

---

## 0. ما غيّرته الرياضيات في v2 (اقرأ هذا أولاً)

| v2 قالت | التدقيق الرياضي كشف | v3 تقرر |
|---|---|---|
| "10 محاولات لكل UC" | 🧮 Wilson 95% CI عند 10/10 ناجحة = **[72.2%, 100%]** — أي لا نستطيع الادعاء بأكثر من "معدل الكشف ≥72%" | **n = 20 لكل UC×OS** (CI عند 20/20 = [83.9%, 100%])؛ **n = 30 لـUC-03 وUC-11** (الاستجابة الآلية — الأهم) → [88.6%, 100%] |
| "ساعة baseline واحدة" | 🧮 Poisson: 0 FP في ساعة → الحد الأعلى 95% = **3.0 FP/h** — رقم لا يُفيد | **≥ 6 ساعات baseline** لكل OS (0 FP → حد أعلى 0.5 FP/h)؛ تُجرى ليلاً بلا إشراف |
| "MTTD ≤ 60 ث هدف" | ⚠️ لا σ معروفة → لا يمكن تحديد n للمتوسط مسبقاً | **PILOT (n=5) يقيس σ أولاً** → ثم n = (1.96σ/E)² بهامش E = ±1 ث؛ إن σ≈2 ث → n=16، نعتمد 20 |
| "AR latency" مقياس واحد | ✅ Wazuh issue #13205: integratord يُسلسل ~**0.78 ث/تنبيه** → يُضاف لـUC-03 فقط | **AR latency يُفصَل إلى 3 مراحل** (§5.3)، ومرحلة VT تُبلَّغ منفصلة |
| "VirusTotal 4/دقيقة عائق" | 🧮 20 محاولة × 2 OS = 40 استعلام؛ بفاصل 90 ث = 60 دقيقة؛ السقف اليومي 500 غير مُقيِّد | ليس عائقاً — **جدولة UC-03 في جلسة منفصلة 90 دقيقة** |
| "نقيس الأداء/السعة" | ✅ Manzoor 2024: سقف Wazuh **2.7–2.8K EPS** لـFIM، **14K EPS** لـsyslog جدار ناري على i7/16GB؛ معملنا <50 EPS ثابت | **السعة ليست متغيراً في دراستنا** — نُصرّح بذلك ونستشهد بـManzoor بدل إعادة القياس |
| "C1: السكربت الرسمي غير آمن" | ✅ **قرأت السكربت الرسمي مباشرة** (Wazuh PoC guide 4.14): `rm -f $FILENAME` **خارج** شرط `if add`، **غير مقتبَس**، **بلا تحقق hash**، **بلا allowlist** | C1 مُثبَت من المصدر الأولي — نُدرج السكربت الرسمي حرفياً في ch4 كـ"قبل" |
| Wazuh baseline FP | ✅ Chamkar 2025 (Wazuh 4.3.10، 12 وكيلاً): FP rate القواعد الافتراضية **23%**، FN **4%**، دقة **76%** | مرجع مقارنة لـbaseline؛ **نتوقع FP أقل** لأن قواعدنا مخصَّصة (100050–108001) — فرضية قابلة للاختبار H3 |

---

## 1. ما هو المشروع — بالتفصيل الممل

### 1.1 المشكلة (من S4 P9–18، مُتحقَّقة أدبياً)
المؤسسات الصغيرة والمتوسطة (SMEs) لا تملك مركز عمليات أمنية لأن: (أ) الحلول التجارية (Splunk، QRadar) تكلّف عشرات آلاف الدولارات سنوياً؛ (ب) نقص الكوادر؛ (ج) تشتّت الأدوات (IDS منفصل عن FIM عن antivirus عن السجلات). **Manzoor et al. 2024 (PLOS ONE)** ✅ يُثبت الحاجة ويُثبت أن Wazuh هو الأعلى تقييماً بين الحلول المفتوحة (47/50) والأعلى أداءً (EPS) — لكن **لم يقيسوا زمن الكشف ولا زمن الاستجابة ولا الإنذارات الكاذبة** (مذكور صراحة في حدود دراستهم). **هذه فجوتنا.**

### 1.2 الحل (بجملة واحدة قابلة للدفاع)
منصة SOC مفتوحة المصدر بالكامل مبنية على Wazuh 4.14 + Suricata، تجمع 5 أنواع إشارات (ملفات، عمليات، سجلات نظام، سجلات تطبيقات، حركة شبكة) من 3 أنواع أجهزة (Windows، Linux، جهاز شبكة)، تكشف 12 سيناريو هجوم مربوطاً بـMITRE ATT&CK، **وتستجيب آلياً بسياسة أمنية مُحصَّنة** في 3 منها، مع **بروتوكول تقييم كمّي** بفواصل ثقة.

### 1.3 ما هو Wazuh وما ليس هو (حتى لا نُبالغ)
| Wazuh يُوفّر أصلاً ✅ | نحن نُضيف |
|---|---|
| Manager + Indexer + Dashboard | إعدادات مُصحَّحة ومُوثَّقة لـ12 UC بمعرّفات قواعد بلا تعارض |
| وكلاء Windows/Linux/macOS | تكامل Suricata + auditd + YARA + Apache على وكيل واحد |
| Active Response كآلية + سكربت PoC | **سكربت AR مُحصَّن** (C1) + سياسة متى يُسمح بالحذف |
| استقبال syslog + decoders لـCisco/pfSense (لا MikroTik) | **decoder + قواعد MikroTik** (C3) + عقد إدخال + اختبار رفض |
| 3000+ قاعدة | قواعد مخصَّصة 100050–108001 + 100400+ |
| لا أداة قياس | **`mttd.py` + بروتوكول تقييم** (C2) |
| لا وكيل هاتف ✅ (issue #32881 مفتوح منذ 2025-10) | **رؤية الهاتف من الشبكة M0** (DHCP/DNS/Suricata) |

### 1.4 حدود المشروع الصريحة (تُقال في ch1 وفي المناقشة)
- لا AI/LLM في التشغيل (S1 اقترحه، S4 نقله للمستقبل — قرار موثَّق).
- لا وكيل داخل الهاتف (لا يوجد رسمياً؛ M0 = ما يُرى من الشبكة فقط).
- لا Zeek/TheHive/Kibana (كانت في الورق القديم؛ حُذفت — ch1 §1.8).
- لا اختبار سعة/أداء (Manzoor 2024 غطّاه؛ معملنا أصغر بـ1–2 رتبة).
- الاستجابة الآلية **ليست** "لا تضرّ أبداً" — سباق تبديل الاسم الأخير موثَّق (ISSUE-039).

---

## 2. ما نبنيه بالضبط — 12 حالة استخدام + 3 مساهمات

### 2.1 جدول الحالات الكامل (كل سطر = ما يُنفَّذ + كيف يُثبَت)

| UC | الهجمة/الحدث | المصدر | المسار الكامل | القاعدة | المستوى | MITRE | AR؟ | n | حالة |
|---|---|---|---|---|---|---|---|---|---|
| 01 | نشر الوكلاء | agentd | keepalive → manager | 503/504 | 3 | — | — | 5 reboot | مُنفَّذ تاريخياً |
| 02 | FIM إضافة/تعديل/حذف | syscheck realtime | inotify → agent → manager | 550/553/554 → 100200/100201 | 7 | T1565.001 | — | 20×2 OS | مُنفَّذ |
| 03 | ملف خبيث → حذف آلي | syscheck → integratord → VT → execd | 100201 → VT API → 87105 → AR → 657 → 100092 | 87105/100092/100093 | 12 | T1204.002 | **✅ C1** | **30×2 OS** | مُنفَّذ؛ AR مُحصَّن محلياً |
| 04 | nmap SYN scan | Suricata eve.json | af-packet → ET Open → eve → logcollector | 86601 | 3 | T1046 | — | 20 | مُنفَّذ |
| 05 | أمر خبيث (nc/sudo) | auditd execve | audit.log → decoder → CDB → | 80792 → 100210 | 12 | T1059 | — | 20 | مُنفَّذ |
| 06 | Shellshock | Apache access.log | logcollector → decoder web | 31168 | 15 | T1190/T1068 | — | 20 | مُنفَّذ |
| 07 | YARA match | syscheck → AR yara.sh | 100300/100301 → AR → 108001 | 108001 | 12 | T1204.002 | ✅ (فحص فقط) | 20 | مُنفَّذ |
| 08 | Netcat listener | command `ps` كل 30 ث | 530 → 100050 → 100051 | 100051 | 7 | T1571 | — | 20 + suppression | مُنفَّذ |
| 09 | SQL Injection | Apache access.log | 31103/31104 (built-in) | 31103 | 7 | T1190 | — | 20 | **T-12 ☐** |
| 10 | Telegram L≥12 | integratord custom | أي L≥12 → custom-telegram.py | — | — | — | — | 20 (delivery rate) | **T-14 ☐** |
| 11 | SSH brute-force | sshd auth.log | 5710 ×8 في 120 ث → 5712 → AR firewall-drop | 5712 | 10 | T1110 | **✅ C1** | **30** | **T-13 ☐** |
| 12 | جهاز شبكة (MikroTik) | syslog UDP 514 → rsyslog → agent | decoder mikrotik → 100400+ | 100401 (login fail) | 5–10 | T1078 | — | 20 + 5 رفض | **T-31 ☐** |
| 13 | رؤية هاتف M0 | MikroTik DHCP lease + DNS + Suricata | 100420 (new DHCP client) + Suricata على IP الهاتف | 100420 | 3 | T1200 | — | 10 | **T-50 ☐** |

**تدقيق الأرقام:** معرّفات القواعد 100050–108001 مأخوذة من `wazuh/manager/rules/local_rules.xml` الحالي ✅؛ 31168/86601/5712/80792 built-in في Wazuh 4.14 ✅؛ 100400+ محجوزة لـUC-12/13 (لا تعارض — فُحص).

### 2.2 المساهمة C1 — Active Response مُحصَّن بسياسة (مُثبَت من المصدر الأولي ✅)

**السكربت الرسمي** (Wazuh PoC "Detecting and removing malware using VirusTotal integration", 4.14) — نصّه الحرفي:
```bash
read INPUT_JSON
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.data.virustotal.source.file)
COMMAND=$(echo $INPUT_JSON | jq -r .command)
if [ ${COMMAND} = "add" ]
then
 printf '{"version":1,...,"command":"check_keys", "parameters":{"keys":[]}}\n'
 read RESPONSE
 COMMAND2=$(echo $RESPONSE | jq -r .command)
 if [ ${COMMAND2} != "continue" ]; then ... exit 0; fi
fi
# Removing file
rm -f $FILENAME        # <-- خارج شرط add، غير مقتبَس، بلا تحقق
```

**العيوب المُوثَّقة (كل واحد قابل للإثبات بتجربة):**
| # | العيب | الإثبات التجريبي في ch4 | نسختنا `soc_ar.py` |
|---|---|---|---|
| V1 | `rm -f` يُنفَّذ عند `command=delete` أيضاً | أرسل JSON بـ`"command":"delete"` عبر stdin → الملف يُحذف | `delete` → `return 0` فوراً |
| V2 | `$FILENAME` غير مقتبَس → word splitting | ملف اسمه `a b` → يحذف `a` و`b` | `os.unlink(name, dir_fd=parent)` لا shell |
| V3 | لا تحقق من محتوى الملف | استبدل الملف بعد التنبيه وقبل AR → يُحذف البديل | MD5 من fd مقابل `source.md5` |
| V4 | لا allowlist للمسار | تنبيه مزيّف بـ`/etc/passwd` → يُحذف | `VT_ROOTS` فقط |
| V5 | يتبع symlink | `ln -s /etc/hosts /root/x` + تنبيه → يحذف الهدف | `O_NOFOLLOW` + `st_nlink==1` |
| V6 | `keys:[]` فارغة → لا dedup | تنبيهان لنفس الملف → تنفيذان | keys = [agent, file, md5] |

**ملاحظة إنصاف:** نسخة Windows الرسمية (`remove-threat.py`) **أفضل**: ترفض symlink/reparse/ADS وتتحقق `is_file()` — لكنها ما زالت بلا hash check ولا allowlist. نُوثّق الفرق.

**كيف يُقاس C1:** (أ) 6 تجارب V1–V6 على السكربت الرسمي مقابل نسختنا = جدول 6×2 "يحذف/يرفض" في ch4؛ (ب) AR completion latency لنسختنا (n=30) — الأمان لا يجوز أن يُبطئ >1 ث (فرضية H4).

### 2.3 المساهمة C2 — بروتوكول التقييم الكمّي (التفاصيل في §5)
ما لا يوجد في الأدبيات المقروءة: Manzoor 2024 قاس EPS فقط؛ Chamkar 2025 قاس inference latency لنموذج ML (45 ms) لا زمن الكشف الشامل؛ **لا أحد قاس AR completion**. بروتوكولنا يقيس 5 مقاييس بفواصل ثقة (§5).

### 2.4 المساهمة C3 — عقد إدخال مصدر شبكي (MikroTik) + M0
**المصدر الأولي ✅:** Wazuh blog "Monitoring network devices with Wazuh" (Jan 2024) يُوثّق: MikroTik **ليس** ضمن الأجهزة المدعومة out-of-the-box (القائمة: Cisco، Juniper، SonicWall، Checkpoint، pfSense، Huawei...)؛ يحتاج decoder مخصَّص؛ المسار الموصى به: MikroTik → rsyslog على وكيل → `<localfile>` → manager (لا مباشرة للمدير).

**العقد الذي نُوثّقه (قابل للتكرار لأي جهاز):**
1. **النقل:** UDP 514 → rsyslog (`$fromhost-ip startswith <IP>`) → `/var/log/mikrotik.log` → وكيل Wazuh بـ`out_format` يُضيف بادئة مميّزة.
2. **الهوية:** IP المصدر يُحفظ في `out_format` (لأن الوكيل يصير المصدر الظاهر — نقطة ضعف موثَّقة).
3. **الأمان:** `allowed-ips` إلزامي على المدير ✅ (docs: "mandatory") لكنه **ليس مصادقة** — UDP قابل للتزييف؛ نُثبته بتجربة: `logger -n <manager> --udp` من IP غير مسموح → مرفوض؛ من IP مسموح بمحتوى مزيّف → **مقبول** (حدّ معروف، يُذكر في ch5).
4. **الفكّ:** decoder بـ`prematch` على البادئة + PCRE2 لـ(user, action, ip, protocol).
5. **القواعد:** 100400 (base L0)، 100401 login failure L5، 100402 ×5 في 60 ث L10 (T1110)، 100403 config change L8، 100420 new DHCP lease L3.
6. **الاختبار:** 20 محاولة login فاشل + 5 محاولات من IP غير مسموح + 3 تعديلات إعداد.
7. **مقياس التوسّع:** ساعات العمل الفعلية + عدد الملفات المُعدَّلة (المتوقع: 3 ملفات — decoder، rules، ossec.conf الوكيل؛ **صفر** في نواة Wazuh).

**M0 (رؤية الهاتف):** هاتف اختبار يتصل بـWiFi MikroTik → DHCP lease → 100420 → Suricata يرى حركته (DNS، HTTP) → نُثبت: (أ) ظهور الهاتف كجهاز، (ب) تنبيه Suricata على حركة من IP الهاتف (مثلاً DNS إلى نطاق في قائمة ET)، (ج) **ما لا نراه**: محتوى TLS، تطبيقات، ملفات — يُكتب صراحة. MAC randomization (iOS 14+/Android 10+) يُكسر الهوية عبر الشبكات — يُوثَّق كحد.

---

## 3. الفرضيات القابلة للاختبار (H1–H6) — ما نُثبته أو ننفيه

| # | الفرضية | المقياس | معيار القبول | n | الإحصاء |
|---|---|---|---|---|---|
| H1 | كل UC يُكشف بمعدل ≥90% | Detection Rate | Wilson CI lower ≥ 0.80 | 20 | Wilson 95% |
| H2 | زمن الكشف (source→manager) لكل UC ≤ 10 ث في المتوسط | MTTD | median ≤ 10 ث و P95 ≤ 30 ث | 20 (بعد PILOT σ) | median + IQR + P95 |
| H3 | FP/hour للقواعد المخصَّصة < 1 | FP/h baseline | Poisson 95% upper < 1 → يحتاج ≥ 3 ساعات بـ0 FP، أو 6 ساعات بـ≤1 FP | ≥6 ساعات × 2 OS | Poisson exact |
| H4 | تحصين AR (C1) لا يُضيف > 1 ث | AR completion (نسختنا) − (الرسمية) | Δmedian ≤ 1 ث | 30 + 30 | Mann-Whitney U (لا نفترض توزيعاً طبيعياً) |
| H5 | السكربت الرسمي يفشل في V1–V6 ونسختنا تنجح | ثنائي | 6/6 vs 0/6 | 6×2 | جدول؛ لا اختبار إحصائي (حتمي) |
| H6 | إضافة مصدر شبكي لا يُغيّر النواة | عدد الملفات المُعدَّلة في نواة Wazuh | = 0 | 1 | `git diff --stat` |

**⚠️ ما لا نفترضه:** أن النتائج تُعمَّم خارج معملنا (2 وكلاء، <50 EPS). نقولها في ch5 §Threats to validity.

---

## 4. البيئة والأجهزة — بالتفصيل

| الجهاز | المواصفات | البرمجيات | الدور | التحقق قبل كل جلسة |
|---|---|---|---|---|
| wazuh-server | ≥4 GB RAM، 2 vCPU، 50 GB | Wazuh 4.14.x (Manager+Indexer+Dashboard)، chrony | المدير | `systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard`؛ `chronyc tracking` offset < 100 ms؛ مساحة القرص > 20% |
| kali1 | 2 GB، 2 vCPU | Kali 2025.x، wazuh-agent 4.14، Suricata 7 + ET Open، auditd، YARA 4.5، Apache 2.4، chrony | ضحية Linux + حساس | 5 خدمات active؛ `suricata --dump-config \| grep af-packet` يُظهر الواجهة الصحيحة؛ offset < 100 ms |
| win1 | 4 GB، 2 vCPU | Windows 10 Edu 19045، wazuh-agent 4.14، Python 3.x + PyInstaller (للبناء فقط)، w32tm | ضحية Windows | خدمة Wazuh running؛ `w32tm /query /status` offset < 100 ms؛ Defender realtime **OFF فقط أثناء UC-03** |
| mikrotik | CHR VM 256 MB **أو** جهاز فعلي RouterOS 7.x | logging action remote → kali1:514 | جهاز شبكة + DHCP للهاتف | `/system logging print` يُظهر remote؛ `/ip dhcp-server lease print` |
| phone | أي Android/iOS اختباري (**مملوك للفريق، بموافقة**) | لا شيء يُثبَّت | M0 | متصل بـWiFi MikroTik |
| attacker | kali1 نفسه أو VM ثانية | nmap، hydra، curl، sqlmap (اختياري) | مصدر الهجمات | — |

**⚠️ ذاكرة:** 4 + 2 + 4 + 0.25 = **10.25 GB** للـVMs + 2 GB للمضيف = **12.25 GB** → Cloud Computer 16 GB يكفي بهامش 3.75 GB. **لا يكفي** لإضافة VM مهاجم منفصلة بأكثر من 2 GB.

**شبكة:** 192.168.100.0/24 معزولة؛ المدير .105، kali1 .108، win1 .106، mikrotik .1 (gateway)، phone DHCP .150–.200. **الحساس Suricata على kali1 يرى فقط**: حركة kali1 نفسها + ما يُعاد توجيهه إليه. لرؤية حركة الهاتف نحتاج **إما** port mirror على MikroTik (`/tool sniffer` أو `/interface ethernet switch port mirror`) **أو** وضع kali1 كـgateway. **⚠️ قرار معماري يُحسم في PILOT** — بدونه M0 يعتمد على DHCP/DNS logs فقط.

---

## 5. بروتوكول القياس — التعريفات الرياضية الدقيقة

### 5.1 نموذج الزمن (Timeline Model)
لكل محاولة `i` من UC `u` على OS `o`، نُسجّل 6 طوابع زمنية بدقة ميلي ثانية، **كلها بـUTC من ساعات متزامنة بـchrony/w32tm (offset مُسجَّل)**:

```
t0  = لحظة إطلاق الهجمة (سكربت المهاجم يكتب t0 إلى سجل المحاولات قبل التنفيذ مباشرة)
t1  = طابع الحدث في سجل المصدر (auditd msg=audit(EPOCH)، eve.json "timestamp"، syscheck event time، access.log)
t2  = alert.timestamp في alerts.json على المدير (لحظة إنشاء التنبيه بـanalysisd)
t3  = لحظة ظهور التنبيه في استعلام Dashboard/Indexer (polling كل 1 ث بـAPI؛ دقة ±1 ث)
t4  = لحظة trigger الاستجابة (execd log "Starting" في active-responses.log على الوكيل)
t5  = لحظة اكتمال الفعل الفعلي (inotify على اختفاء الملف / iptables -L يُظهر DROP / تأكيد مستقل)
t6  = alert.timestamp لتنبيه التأكيد (100092 أو 657)
```

### 5.2 المقاييس المُشتقّة
| المقياس | الصيغة | ما يُثبته | ما لا يُثبته |
|---|---|---|---|
| **D_source** (زمن المصدر) | t1 − t0 | كم يتأخر المصدر (auditd/Suricata) في تسجيل الحدث | — |
| **MTTD** (زمن الكشف الخام) | t2 − t1 | أداء خط agent→manager→analysisd | لا يشمل تأخر المصدر ولا اللوحة |
| **MTTD_e2e** | t2 − t0 | ما يراه المحلل فعلاً كـ"من الهجمة للتنبيه" | — |
| **L_vis** (زمن الظهور) | t3 − t2 | Filebeat→Indexer→refresh | يعتمد على refresh_interval (افتراضي 1 ث) ودقة polling |
| **L_AR_trigger** | t4 − t2 | manager→execd→agent | — |
| **L_AR_complete** | t5 − t4 | زمن تنفيذ السكربت نفسه (**هنا يُقاس أثر C1**) | — |
| **L_AR_e2e** | t5 − t0 | من الهجمة لاكتمال الدفاع — **الرقم الذي يهمّ اللجنة** | — |
| **L_confirm** | t6 − t5 | تأخر تنبيه التأكيد | ⚠️ ليس زمن الاستجابة (خطأ شائع — T-11 صحّحه) |

**⚠️ UC-03 خاص:** بين t2 (100201) وt2' (87105) يوجد استعلام VirusTotal الخارجي: **D_VT = t2' − t2** يُبلَّغ منفصلاً لأنه يعتمد على الإنترنت وintegratord (~0.78 ث تسلسل ✅ issue #13205) ولا يمثّل أداء المنصة.

### 5.3 الإحصاء المُعتمَد
| السؤال | الطريقة | لماذا |
|---|---|---|
| ما هو زمن الكشف "النموذجي"؟ | **median** + **IQR** + **P95** + min/max | التوزيع غالباً غير طبيعي (ذيل أيمن بسبب polling/scan intervals)؛ المتوسط يُضلّل |
| هل نعرض المتوسط؟ | نعم، مع σ، **لكن ليس وحده** | للمقارنة مع أدبيات تعرض means |
| معدل الكشف بفاصل ثقة | **Wilson score 95%** (لا Wald — يفشل عند p=1) | n=20، k=20 → [0.839, 1.0] |
| هل تحصين AR أبطأ؟ (H4) | **Mann-Whitney U** أحادي الجانب، α=0.05 | لا افتراض توزيع؛ n=30+30 يكفي لكشف Δ≈0.5σ |
| FP/hour | **Poisson exact upper bound** = −ln(0.05)/T عند 0 حدث؛ أو chi² عند k>0 | معدل نادر؛ T بالساعات |
| هل n كافية؟ | PILOT n=5 → σ̂ → n = ⌈(1.96 σ̂ / E)²⌉ بـE=1 ث؛ **الحد الأدنى 20** | مُشتق 🧮 |
| استبعاد محاولة | فقط بأسباب مُسبقة: BLOCKED (بنية)، INVALID (خطأ مشغّل)، INTERFERED (تداخل)، AMBIGUOUS (لا يُحدَّد t) — **تُوثَّق كلها وتُعدّ في المقام للشفافية** | لا "cherry-picking" |

### 5.4 حدود الصلاحية (Threats to Validity) — تُكتب في ch5
1. **Internal:** ساعات غير متزامنة → نُسجّل offset ونرفض جلسة > 100 ms. Polling t3 بدقة ±1 ث → L_vis يُبلَّغ بدقة ±1 ث.
2. **Construct:** "كشف" = تنبيه بالقاعدة المتوقعة **تحديداً** (لا أي تنبيه). "استجابة مكتملة" = تأكيد مستقل (ls/iptables) لا سجل السكربت.
3. **External:** معمل 2 وكلاء <50 EPS؛ لا تعميم على مؤسسة 500 جهاز — نستشهد بـManzoor 2024 للسعة.
4. **Reliability:** كل محاولة لها JSONL خام + hash manifest؛ `mttd.py` يُعيد الحساب من الخام.

---

## 6. خطة التنفيذ — البوابات مع أرقام v3

| بوابة | المدة | العمل (مُحدَّث بالرياضيات) | دليل الخروج | المالك |
|---|---|---|---|---|
| **G0** اعتماد + بيئة | أسبوع 0 | D1–D7؛ Q5/Q6؛ Cloud Computer 16 GB أو mesh؛ **جرد حي** يُغلق ISSUE-045 | ADR-013؛ `02_ARCHITECTURE` بأدلة حيّة؛ `gsk mesh devices` أو VM شغّالة | بشري + CLAUDE |
| **G1** اتساق + أداة | أسبوع 1 | T-11 كامل (6 طوابع زمنية، Wilson، Poisson، Mann-Whitney في `mttd.py`)؛ ch3 ISSUE-047؛ **سكربت `trial_runner.sh`** يكتب t0 ويُطلق الهجمة ويجمع t1–t6 آلياً | 60+ اختبار محلي؛ ch3 v2 | ASTRA |
| **G2** نواة حيّة | أسبوع 1–2 | نشر كامل؛ AR Linux + Windows build؛ **PILOT n=5 لكل UC-01..08** → σ̂ لكل مقياس → تثبيت n النهائي | `tests/results/pilot/*.jsonl`؛ جدول σ̂؛ لقطة Agents=2 حيّة | ASTRA |
| **G3** UC-09/10/11 | أسبوع 2–3 | T-13 أولاً (AR firewall-drop مع استثناء IP الإدارة + timeout 300 ث + اختبار unblock)؛ T-12؛ T-14 | PILOT n=5 لكل منها | ASTRA |
| **G4** UC-12/13 | أسبوع 3–4 | MikroTik CHR + decoder + 5 قواعد + rsyslog؛ **قرار port mirror** لـM0؛ اختبار رفض allowed-ips؛ **قياس ساعات العمل** | PILOT؛ coverage matrix؛ H6 = 0 ملفات نواة | ASTRA |
| **G6** قياس | أسبوع 4–5 | MEASURED: **n=20** × UC-02,04,05,06,07,08,09,12 × OS؛ **n=30** × UC-03,11 × OS؛ **6 ساعات baseline** × 2 OS (ليلاً)؛ **V1–V6 على السكربت الرسمي** (H5)؛ **UC-03 في جلسة VT منفصلة** 90 دقيقة | كل JSONL؛ `mttd.py` → REPORT.md بـWilson/Poisson/MWU | ASTRA + بشري |
| **G7** رسالة | أسبوع 5–6 | ch4 (جدول V1–V6 "قبل/بعد"، جدول التوسّع)؛ ch5 (من JSONL فقط + Threats to validity)؛ front matter؛ DOCX؛ dry-run ×2 | PDF؛ §9 DEMO مُعبَّأ | ASTRA + CLAUDE مراجعة |
| **G8** تسليم | أسبوع 6 | tag؛ README نشر؛ صفر أسرار | — | ASTRA |

**🧮 ميزانية المحاولات الكلية:** (8 UC × 20 × ~1.5 OS) + (2 UC × 30 × 1.5) + (13: 10) = 240 + 90 + 10 = **~340 محاولة مُقاسة** + 40 PILOT + 12 ساعة baseline. بمتوسط 2 دقيقة/محاولة (بما فيه إعادة الضبط) = **~11 ساعة تنفيذ صافية** + 12 ساعة baseline ليلية → **3–4 أيام عمل** لـG6. واقعي.

---

## 7. الفجوات المتبقية بعد v3 (صريحة)

| # | الفجوة | الأثر | القرار |
|---|---|---|---|
| 1 | لا نعرف σ قبل PILOT | n قد يرتفع فوق 20 | ميزانية G6 تتحمّل حتى n=30 لكل UC (+50%) |
| 2 | port mirror على MikroTik CHR قد لا يعمل في VM | M0 يعتمد DHCP/DNS فقط | مقبول — يُوثَّق كحد؛ M0 يبقى صادقاً |
| 3 | Windows AR native غير مُثبَت | UC-03 Windows قد يفشل | R3: يُوثَّق؛ Linux يكفي لـC1 |
| 4 | Suricata على kali1 لا يرى حركة win1 | UC-04 على Windows غير قابل للقياس بدون mirror | UC-04 يُقاس على Linux فقط (n=20) — يُصرَّح |
| 5 | لا مرجع أدبي مقروء لـAR latency | C2 "أول قياس" ادعاء قوي | S-01 (وكيل المراجع) يبحث تحديداً؛ إن وُجد نُقارن، وإلا نقول "لم نجد في المراجعة" |

---

## 8. المصادر الأولية المقروءة مباشرة في v3 (لا ملخصات)

| المصدر | ما قُرئ | ما استُخرج |
|---|---|---|
| Manzoor et al., PLOS ONE 19(3) e0301183, 2024 | النص الكامل | i7-8550U/16GB؛ 4 SIEMs؛ EPS: Wazuh 14K pfSense، 10K Snort، 2.7K Win FIM، 2.8K Ubuntu FIM؛ 47/50؛ **لم يقيسوا** MTTD/AR/FP |
| Chamkar et al., JCP 5(2):34, 2025 | النص الكامل | Wazuh 4.3.10، 12 وكيلاً، 500 EPS؛ baseline قواعد: FP 23%، FN 4%، acc 76%، F1 0.72؛ ML: 45 ms inference (ingestion→output) |
| Wazuh PoC "Detect & remove malware with VirusTotal" 4.14 | النص الكامل + السكربتين | `rm -f $FILENAME` خارج `if add`؛ `keys:[]`؛ Windows PoC ترفض symlink/ADS؛ "This script is a PoC" |
| Wazuh docs: Active Response how-to 4.14 | كامل | location local/server/defined-agent/all؛ timeout؛ 750 root:wazuh |
| Wazuh docs: syslog collection 4.14 | كامل | `allowed-ips` **mandatory**؛ tcp/udp؛ توصية وكيل على rsyslog |
| Wazuh blog "Monitoring network devices" Jan 2024 | كامل | قائمة الأجهزة المدعومة (لا MikroTik)؛ decoders PCRE2 لـMikroTik؛ rules 110000–110004؛ مسار rsyslog→agent |
| Wazuh docs VirusTotal integration | مقتطف | 4 req/min، 500/day، "must not be used in commercial" |
| Wazuh issue #13205 (2022) | مقتطف | integratord ~0.78 s/alert تسلسلي |
| Wazuh issue #32881 (Oct 2025) | مقتطف | Feature request: Mobile agent — مفتوح → لا وكيل رسمي |
| NIST SP 800-61r3 (2025) | عنوان/ملخص | تعريفات دورة الاستجابة؛ يُقرأ كاملاً في S-01 |

---
*v3 — CLAUDE — 2026-09-09. كل رقم أعلاه إما 🧮 مُشتق (الكود في `scripts/measure/plan_math.py`) أو ✅ من مصدر أولي مذكور في §8 أو ⚠️ مُعلَّم كافتراض.*
