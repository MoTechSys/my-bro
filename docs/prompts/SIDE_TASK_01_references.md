# برومبت المهمة الجانبية S1 — مكتبة المراجع الأكاديمية الموسَّعة

> **للاستخدام:** انسخ كل ما تحت الخط الأفقي التالي وألصقه في جلسة جديدة لوكيل مستقل (Astra أو أي وكيل بحثي). لا يحتاج الوكيل إلى الوصول للمستودع كاملاً؛ يحتاج فقط لقراءة الملفات المذكورة في §2 إن توفّر الوصول، وإلا يعمل من الوصف.
> **المخرج المتوقع:** ملف واحد `docs/thesis/REFERENCES_LIBRARY.md` + PR منفصل. لا يلمس أي ملف آخر.

---

# مهمة: بناء مكتبة مراجع أكاديمية مُتحقَّقة لرسالة تخرّج في أمن المعلومات

## 1. من أنت وما دورك

أنت وكيل بحث أكاديمي مستقل. مهمتك **جانبية ومعزولة**: تبني مكتبة مراجع IEEE مُتحقَّقة لرسالة تخرّج جامعية دون أن تلمس أي كود أو وثيقة أخرى في المشروع. المنفّذ الرئيسي (ASTRA) والمخطّط (CLAUDE) يعملان بالتوازي على الكود والفصول؛ أنت تُغذّيهما بمراجع جاهزة للاستشهاد.

**قاعدة ذهبية:** مرجع واحد مُتحقَّق أفضل من عشرة مشكوك فيها. **كل DOI يجب أن يُحلّ فعلياً** (عبر `https://doi.org/<DOI>` أو Crossref API `https://api.crossref.org/works/<DOI>`) ويُطابق العنوان والمؤلفين والسنة. مرجع بلا تحقق = لا يُدرَج.

## 2. سياق المشروع (اقرأ هذا بعناية — هو كل ما تحتاجه)

**العنوان:** Design and Implementation of an Open-Source Security Operations Center Platform with Automated Threat Response using Wazuh and Suricata

**الجوهر:** مشروع تخرّج (4 طلاب) يبني طبقة تكامل فوق **Wazuh 4.14** (SIEM/XDR مفتوح المصدر) + **Suricata** (NIDS) لمراقبة Windows 10 وKali Linux وجهاز شبكة (MikroTik/Cisco عبر syslog)، مع **استجابة آلية (Active Response)** محكومة بسياسة أمنية، وتقييم مُقاس (MTTD، AR latency، FP/hour) على 12 حالة استخدام (FIM، VirusTotal+حذف آلي، Suricata، auditd+CDB، Shellshock، YARA، Netcat، SQLi، Telegram، SSH brute-force+firewall-drop، syslog شبكي).

**الإضافات العلمية الثلاث التي تحتاج دعماً أدبياً:**
- **C1:** Active Response مُحصَّن بسياسة (allowlist، تحقق hash، رفض symlink، حدود موارد) — مقابل السكربت الرسمي غير المحصَّن.
- **C2:** بروتوكول تقييم متعدد المراحل (source→manager، visibility latency، AR completion، FP/hour baseline).
- **C3:** عقد onboarding لمصدر شبكي (syslog + allowed-ips + decoder + rules) كإثبات قابلية توسّع، مع "رؤية الهواتف من الشبكة" (M0) بلا وكيل.

**المراجع الـ15 الموجودة حالياً (لا تُكرّرها — كمّلها):**
Vielberth 2020 (SOC systematic study)، NIST SP 800-61r2، González-Granadillo 2021 (SIEM)، Manzoor 2024 (open-source SIEM SMEs)، Amami 2024 (Wazuh CoDIT)، Wazuh docs 4.14، Winkler & Sharma 2025 (Wazuh MITRE)، Ismail 2025 (Wazuh RAG LLM)، Waleed 2022 (Snort/Suricata/Zeek)، Qutqut 2026 (Snort vs Suricata)، YARA docs، Mahdi 2024 (YARA)، Strom 2020 (ATT&CK)، CVE-2014-6271، Zhang 2021 (Shellshock Petri).

إن توفّر لك الوصول للمستودع `MoTechSys/my-bro`: اقرأ `docs/thesis/ch2_literature_review.md` (المراجع في آخره)، و`docs/MASTER_PLAN_v2.md §3 و§10`، و`docs/INTENT_STUDY_AND_BLUEPRINT.md §12`.

## 3. المطلوب بالضبط

ابنِ **30–40 مرجعاً جديداً** مُصنَّفاً في 8 محاور. لكل محور: العدد المستهدف، وما يجب أن يُثبته المرجع.

| # | المحور | العدد | ما نحتاج المرجع أن يدعمه | كلمات بحث مقترحة |
|---|---|---|---|---|
| A | **SOC/SIEM للمؤسسات الصغيرة والمتوسطة** | 4–5 | التكلفة، نقص الكوادر، جدوى المفتوح المصدر | "SME cybersecurity SIEM cost", "open-source SOC small business", "SOC-as-a-service SME" |
| B | **تقييم أداء SIEM ومنهجيات القياس** | 5–6 | تعريفات MTTD/MTTR/FP rate، منهجيات التجارب المُكرَّرة، NIST SP 800-61r3 (2025) | "SIEM evaluation methodology", "mean time to detect measurement", "detection latency benchmark", "false positive rate SIEM" |
| C | **الاستجابة الآلية وأمانها (SOAR / Active Response safety)** | 5–6 | مخاطر الاستجابة الآلية، سباقات الملفات (TOCTOU)، symlink attacks، مبدأ أقل امتياز في سكربتات الاستجابة، SOAR في المؤسسات | "automated incident response risks", "SOAR evaluation", "TOCTOU file race security", "symlink attack mitigation", "safe automated remediation" |
| D | **MITRE ATT&CK في الكشف والتقييم** | 3–4 | ربط القواعد بالتقنيات، تغطية الكشف، Atomic Red Team/adversary emulation | Al-Sada 2024 ACM CSUR (10.1145/3687300)، "adversary emulation detection validation", "ATT&CK coverage measurement" |
| E | **مراقبة أجهزة الشبكة عبر syslog وأمان syslog** | 4–5 | RFC 5424/5425/6587، ضعف UDP syslog، التزييف، allowed-ips ليست مصادقة، MikroTik/Cisco logging | "syslog security spoofing", "RFC 5424", "network device log collection SIEM", "syslog TLS" |
| F | **رؤية الأجهزة المحمولة من الشبكة (بدون وكيل)** | 3–4 | حدود MAC randomization، DHCP/DNS fingerprinting، TLS يحدّ الرؤية، MDM vs network visibility | "mobile device network visibility", "MAC address randomization impact", "agentless mobile monitoring", "DNS-based device fingerprinting" |
| G | **FIM / تكامل VirusTotal / YARA / auditd** | 3–4 | فعالية FIM، حدود hash-based detection، auditd overhead | "file integrity monitoring evaluation", "hash-based malware detection limitations", "Linux audit framework performance" |
| H | **IDS/NIDS: Suricata وقواعد ET Open** | 2–3 | أداء Suricata، جودة قواعد Emerging Threats، حدود الرؤية (SPAN/TAP) | "Suricata performance evaluation", "Emerging Threats ruleset quality", "network sensor placement visibility" |

**أولوية المصادر:** IEEE Xplore > ACM DL > Elsevier (Computers & Security, Computer Networks) > Springer > MDPI (Sensors, JCP, Electronics) > PLOS ONE > arXiv (فقط إذا مُحكَّم لاحقاً أو ≥50 استشهاداً) > NIST/RFC/وثائق رسمية. **السنوات:** 2019–2026 مفضَّلة؛ الكلاسيكيات (RFC، NIST) بلا قيد.

## 4. بروتوكول التحقق الإلزامي (لكل مرجع)

```
1. ابحث → احصل على DOI أو URL رسمي.
2. حلّ الـDOI: GET https://api.crossref.org/works/<DOI>
   → تحقق: title، author[0].family، issued.date-parts[0][0]، container-title.
3. إذا لم يُحلّ أو اختلف العنوان → ارفض المرجع واكتب سبب الرفض في §رفوضات.
4. اقرأ الملخص (abstract) على الأقل؛ اكتب جملة واحدة: "ما يُثبته هذا المرجع لمشروعنا".
5. صنّفه في المحور المناسب وأعطه رقماً يبدأ من [16].
```

**ممنوع منعاً باتاً:** اختراع DOI، الاستشهاد بمقال لم تقرأ ملخصه، مقالات من مجلات مفترسة (تحقق من Beall's list / DOAJ)، مدونات شركات كمراجع أكاديمية (يجوز كـ"مصدر رمادي" في قسم منفصل وبعدد محدود ≤5).

## 5. شكل المخرج — ملف واحد

**المسار:** `docs/thesis/REFERENCES_LIBRARY.md`

```markdown
# مكتبة المراجع الموسَّعة — REFERENCES LIBRARY v1
> المالك: [اسم الوكيل] | التاريخ | الحالة: مُتحقَّق عبر Crossref في <تاريخ>
> يُكمّل المراجع [1]–[15] في ch2. الترقيم يبدأ من [16]. للاستشهاد: انسخ السطر كما هو.

## 0. ملخص
| المحور | العدد | مُتحقَّق | مرفوض |
|---|---|---|---|
| A ... | | | |
**الإجمالي:** N مرجعاً مُتحقَّقاً.

## A. SOC/SIEM للمؤسسات الصغيرة والمتوسطة
[16] A. Author, B. Author, "Title," *Journal*, vol. X, no. Y, pp. Z–W, 2024, doi: 10.xxxx/yyyy.
  - **يدعم:** C2 / ch1 §1.2 مشكلة الدراسة
  - **الجملة:** يُثبت أن 68% من SMEs لا تملك SOC بسبب التكلفة (عيّنة n=...).
  - **تحقق:** Crossref ✅ 2026-09-xx

[17] ...

## B. ...

## X. مصادر رمادية (≤5، للسياق التقني فقط)
[G1] Wazuh Inc., "Monitoring network devices with Wazuh," blog, Jan. 2024. [Online]. Available: ... (accessed ...)

## Y. مرفوضات (للشفافية)
| المرجع المُقترَح | سبب الرفض |
|---|---|
| "Title..." | DOI لا يُحلّ / مجلة مفترسة / العنوان لا يطابق |

## Z. خريطة الاستخدام المقترحة
| الفصل/القسم | المراجع المقترحة |
|---|---|
| ch1 §1.2 مشكلة الدراسة | [16], [17] |
| ch2 §2.x | ... |
| ch4 C1 (AR safety) | ... |
| ch5 مقارنة النتائج | [4], [xx] |
```

## 6. معايير القبول (يُفحص عليها عملك)

- [ ] 30–40 مرجعاً جديداً، كلها بصيغة IEEE موحَّدة مثل [1]–[15].
- [ ] **100%** منها له DOI/URL رسمي مُحلّ فعلياً وموثَّق بتاريخ التحقق.
- [ ] كل مرجع له "يدعم" + "الجملة" (ما يُثبته).
- [ ] المحاور A–H كلها مُغطّاة بالحد الأدنى.
- [ ] قسم المرفوضات موجود (حتى لو فارغاً — يُثبت أنك فحصت).
- [ ] خريطة الاستخدام تربط كل مرجع بفصل/قسم.
- [ ] **صفر** تعديل على أي ملف آخر في المستودع.
- [ ] PR واحد بعنوان `[SIDE-S1] docs(thesis): references library v1 (N verified refs)`.

## 7. إن لم يتوفر لك وصول للمستودع

أخرج الملف كنص كامل في ردّك النهائي بنفس البنية أعلاه؛ سيُلصقه المستخدم في المسار. لا تختصر.

## 8. قواعد العمل

- اشتغل **بخطوات صغيرة**: محور واحد → تحقق → احفظ (commit إن أمكن) → المحور التالي. إن انقطعت الجلسة لا يضيع شيء.
- إن وجدت مرجعاً يناقض افتراضاً في المشروع (مثلاً: دراسة تُثبت أن Active Response يزيد المخاطر) — **أدرجه وعلّم عليه ⚠️** في "الجملة"؛ هذا أهم من المراجع المؤيِّدة.
- لا تكتب فقرات أدبية؛ فقط الجداول والقوائم بالشكل المحدَّد.
- اللغة: المراجع بالإنجليزية (IEEE)، الشروح بالعربية.
- عند الانتهاء: تقرير من 5 أسطر — العدد، التوزيع، أقوى 3 مراجع، أي ⚠️، رابط PR.

**ابدأ بالمحور B (منهجيات القياس) ثم C (أمان الاستجابة الآلية) — هما الأكثر إلحاحاً للفصلين 4 و5.**
