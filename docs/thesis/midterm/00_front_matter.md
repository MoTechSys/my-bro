<!-- ملف: 00_front_matter.md — الصفحات التمهيدية لتسليم منتصف الفصل (الفصول 1–3)
     تعليمات لوكيل المستندات: كل قسم يبدأ بصفحة جديدة. الترقيم بالحروف الأبجدية (أ، ب، ج…) للصفحات التمهيدية،
     وبالأرقام من الفصل الأول. الحقول بين [ ] يملؤها الفريق. -->

# صفحة الغلاف

**[شعار الجامعة]**

**[اسم الجامعة]**
**[اسم الكلية]**
**قسم [اسم القسم]**

---

## تصميم وتنفيذ منصة مركز عمليات أمنية مفتوحة المصدر مع استجابة آلية للتهديدات باستخدام Wazuh وSuricata

### Design and Implementation of an Open-Source Security Operations Center Platform with Automated Threat Response using Wazuh and Suricata

---

مشروع مُقدَّم استكمالاً لمتطلبات الحصول على درجة البكالوريوس في [التخصص]

**إعداد الطلاب:**

| الاسم | الرقم الجامعي |
|---|---|
| [الطالب 1] | [ ] |
| [الطالب 2] | [ ] |
| [الطالب 3] | [ ] |
| [الطالب 4] | [ ] |

**إشراف:** [اسم المشرف ولقبه العلمي]

**تسليم منتصف الفصل — الفصول الأول والثاني والثالث**

[الفصل الدراسي] — [العام الجامعي] — 2026م

---

# الإهداء

إلى من علّمونا أن العلم أمانة، وأن الأمانة حماية…
إلى آبائنا وأمهاتنا، وإلى أساتذتنا، وإلى كل من يسهر ليبقى غيره آمناً.

---

# شكر وتقدير

نتقدم بخالص الشكر والتقدير إلى [اسم المشرف] على توجيهه ومتابعته، وإلى أعضاء هيئة التدريس في قسم [ ]، وإلى كل من أسهم في إنجاز هذا العمل. كما نشكر مجتمعات البرمجيات مفتوحة المصدر (Wazuh وSuricata وYARA وMITRE ATT&CK) التي أتاحت أدوات ومعارف جعلت هذا المشروع ممكناً.

---

# الملخص

تواجه المؤسسات الصغيرة والمتوسطة تهديدات سيبرانية متزايدة، في حين تعجز غالباً عن تحمّل تكلفة حلول مراكز العمليات الأمنية (SOC) التجارية أو توفير كوادر لتحليل آلاف التنبيهات يدوياً. يقدّم هذا المشروع تصميماً وتنفيذاً لمنصة مركز عمليات أمنية مفتوحة المصدر مبنية على نظام Wazuh 4.14 لإدارة معلومات وأحداث الأمن (SIEM) ونظام Suricata لكشف التسلل الشبكي، تجمع في خط أنابيب واحد إشاراتِ نقاط النهاية (Windows وLinux) وأجهزةِ الشبكة (راوتر MikroTik عبر Syslog) وحركةِ الشبكة، وتمرّ بست مراحل: الاستشعار، والجمع، والكشف، والقرار، والاستجابة، والعرض.

ويتجاوز المشروع التثبيت الافتراضي لـ Wazuh بثلاث إضافات قابلة للقياس: (1) استجابة آلية مُحصَّنة بسياسة لحذف الملفات الخبيثة تتحقق من البصمة والمسار ونوع الملف قبل أي حذف، بعد إثبات ستة عيوب في السكربت المرجعي؛ (2) بروتوكول تقييم كمّي بسبعة طوابع زمنية وثمانية مقاييس وفواصل ثقة إحصائية؛ (3) عقد إدخال لمصادر شبكية غير مدعومة أصلاً، مع رؤية الأجهزة والهواتف من الشبكة دون وكيل عليها. ويُضاف إلى ذلك محلل أمني بالذكاء الاصطناعي يشرح التنبيهات ويربطها في حوادث ويقترح إجراءات من قائمة مسموحة لا تُنفَّذ إلا بموافقة بشرية.

اتُّبع منهج علم التصميم (Design Science Research) بدورات تكرارية، وصُمّمت أربع عشرة حالة استخدام مرتبطة بإطار MITRE ATT&CK، وخمسة عشر متطلباً وظيفياً وثمانية غير وظيفية، ومخططات تدفق بيانات على ثلاثة مستويات، ونموذج بيانات منطقي، وخمس وعشرون قاعدة كشف مخصصة. وتعرض هذه الفصول الثلاثة الأولى المقدمة والإطار النظري والمنهجية والتصميم؛ بينما يعرض الفصلان الرابع والخامس التنفيذ والنتائج المقاسة.

**الكلمات المفتاحية:** مركز عمليات الأمن، SIEM، Wazuh، Suricata، الاستجابة الآلية، MITRE ATT&CK، أجهزة الشبكة، الذكاء الاصطناعي.

---

# Abstract

Small and medium-sized enterprises (SMEs) face growing cyber threats while rarely being able to afford commercial Security Operations Center (SOC) solutions or analysts to triage thousands of alerts manually. This project designs and implements an open-source SOC platform built on the Wazuh 4.14 SIEM and the Suricata network IDS. The platform unifies endpoint signals (Windows and Linux), network-device logs (MikroTik via Syslog) and network traffic in a single pipeline of six stages: sense, collect, detect, decide, respond and present.

Beyond a default Wazuh deployment, the project contributes three measurable additions: (1) a policy-hardened active response that removes malicious files only after verifying hash, path and file type, motivated by six demonstrated defects in the reference script; (2) a quantitative evaluation protocol with seven timestamps, eight metrics and statistical confidence intervals; and (3) an input contract for network sources that Wazuh does not decode natively, including network-level visibility of devices and phones without an on-device agent. A grounded AI security analyst explains alerts, correlates them into incidents and proposes allow-listed actions that execute only after human approval.

Following Design Science Research with iterative cycles, fourteen use cases mapped to MITRE ATT&CK, fifteen functional and eight non-functional requirements, three-level data-flow diagrams, a logical data model and twenty-five custom detection rules were designed. These first three chapters present the introduction, background, methodology and design; Chapters 4 and 5 present the implementation and measured results.

**Keywords:** Security Operations Center, SIEM, Wazuh, Suricata, Active Response, MITRE ATT&CK, network devices, artificial intelligence.

---

# فهرس المحتويات

<!-- يُولَّد تلقائياً في Word: References → Table of Contents (مستويات 1–3). -->

[يُدرج جدول المحتويات التلقائي هنا]

# قائمة الأشكال

<!-- Word: References → Insert Table of Figures (التسمية: شكل) -->

| رقم | عنوان الشكل | الفصل |
|---|---|---|
| (1.1) | الحلقة الأساسية لمركز العمليات الأمنية | 1 |
| (2.1) | معمارية Wazuh 4.x | 2 |
| (2.2) | موقع المشروع بين الدراسات السابقة | 2 |
| (3.1) | مراحل منهجية علم التصميم التكرارية | 3 |
| (3.2) | النموذج المرجعي ذو المراحل الست | 3 |
| (3.3) | مخطط السياق (DFD المستوى 0) | 3 |
| (3.4) | مخطط تدفق البيانات — المستوى 1 | 3 |
| (3.5) | مخطط تدفق البيانات — المستوى 2 (مطابقة القواعد) | 3 |
| (3.6) | مخطط حالات الاستخدام | 3 |
| (3.7) | تسلسل الاستجابة الآلية — VirusTotal (UC-03) | 3 |
| (3.8) | تسلسل حظر هجوم القوة الغاشمة (UC-11) | 3 |
| (3.9) | تسلسل المحلل بالذكاء الاصطناعي بموافقة بشرية (UC-14) | 3 |
| (3.10) | مخطط الكيانات والعلاقات لمخازن البيانات | 3 |
| (3.11) | طوبولوجيا المعمل الافتراضي | 3 |
| (3.12) | خط الزمن لقياس المحاولة الواحدة (t0–t6) | 3 |

# قائمة الجداول

| رقم | عنوان الجدول |
|---|---|
| (1.1) | الأدوات والتقنيات المستخدمة |
| (2.1) | الوحدات الوظيفية في Wazuh ذات الصلة |
| (2.2) | مقارنة Suricata وZeek |
| (2.3) | مقارنة الحلول البديلة |
| (2.4) | ملخص الدراسات السابقة |
| (3.1) | مراحل المنهجية ومدخلاتها ومخرجاتها |
| (3.2) | أصحاب المصلحة واحتياجاتهم |
| (3.3) | المتطلبات الوظيفية |
| (3.4) | المتطلبات غير الوظيفية |
| (3.5) | المساهمات الثلاث فوق Wazuh وطريقة إثباتها |
| (3.6) | المكونات المنطقية والفيزيائية |
| (3.7) | طبقات النظام ومكوناتها |
| (3.8) | رموز مخططات تدفق البيانات |
| (3.9) | مصفوفة حالات الاستخدام على المراحل الست |
| (3.10) | سجل معرّفات القواعد المخصصة (25 قاعدة) |
| (3.11) | مخازن البيانات الفعلية |
| (3.12) | قاموس بيانات سجل المحاولات (attempts.jsonl) |
| (3.13) | التهديدات الموجهة إلى المنصة وضوابطها |
| (3.14) | جدول الأصول |
| (3.15) | المنافذ والبروتوكولات |
| (3.16) | المقاييس المشتقة |
| (3.17) | الفرضيات ومعايير القبول |
| (3.18) | ضوابط التجربة وتهديدات الصلاحية |
| (3.19) | التوسعات المنفَّذة والمستقبلية |
| (3.20) | مصفوفة تتبع المتطلبات |

# قائمة المختصرات

| المختصر | المعنى |
|---|---|
| AR | Active Response — الاستجابة النشطة/الآلية |
| API | Application Programming Interface — واجهة برمجة التطبيقات |
| CDB | Constant Database — قوائم مفاتيح/قيم في Wazuh |
| CVE | Common Vulnerabilities and Exposures |
| DFD | Data Flow Diagram — مخطط تدفق البيانات |
| DHCP | Dynamic Host Configuration Protocol |
| DSR | Design Science Research — بحث علم التصميم |
| EPS | Events Per Second — أحداث في الثانية |
| ERD | Entity-Relationship Diagram — مخطط الكيانات والعلاقات |
| FIM | File Integrity Monitoring — مراقبة سلامة الملفات |
| FP | False Positive — إنذار كاذب |
| FR / NFR | Functional / Non-Functional Requirement |
| HIDS / NIDS | Host / Network Intrusion Detection System |
| IDS / IPS | Intrusion Detection / Prevention System |
| JSONL | JSON Lines — سطر JSON لكل سجل |
| LLM | Large Language Model — نموذج لغوي كبير |
| MAC | Media Access Control address |
| MITRE ATT&CK | Adversarial Tactics, Techniques & Common Knowledge |
| MTTD | Mean/Median Time To Detect — زمن الكشف |
| NIST | National Institute of Standards and Technology |
| RAG | Retrieval-Augmented Generation — التوليد المعزّز بالاسترجاع |
| SIEM | Security Information and Event Management |
| SME | Small and Medium-sized Enterprise |
| SOC | Security Operations Center — مركز عمليات الأمن |
| UC | Use Case — حالة استخدام |
| VT | VirusTotal |
