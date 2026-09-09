# 📋 TASKBOARD — لوحة المهام المشتركة (Claude + Astra)

> ⚠️ **2026-09-09 — تسليم كامل:** CLAUDE أنهى كل مهامه وسلّم المشروع بالكامل إلى **ASTRA** (اقرأ `docs/HANDOFF_CLAUDE_TO_ASTRA.md`). كل مهمة "CLAUDE" أدناه أصبحت مملوكة لـ ASTRA.

> **الحالات:** 🟢 FREE (متاح للحجز) | 🔒 [AGENT] yyyy-mm-dd (محجوز) | ◐ IN-PROGRESS (مع "المتبقي") | ✅ DONE (مع commit) | ⛔ BLOCKED (مع السبب)
> **قاعدة:** احجز قبل أن تلمس. حدّث قبل أن تُغلق الجلسة. سطر واحد لكل مهمة. التفاصيل في `03_ROADMAP.md`.

| ID | المهمة | المالك الافتراضي | الحالة | ملفات المخرجات | ملاحظات |
|----|--------|:---:|--------|----------------|---------|
| T-01 | تأسيس المستودع (P0 كامل) | CLAUDE | ✅ DONE `859aa03` | كل المستودع | — |
| T-02 | وثيقة النية الموحَّدة | CLAUDE | ✅ DONE `0102eae` | `docs/05_*` | المرجع الأعلى |
| T-03 | بروتوكول التعاون + TASKBOARD + SESSIONS_LOG | CLAUDE | ✅ DONE | `COLLABORATION_PROTOCOL.md`, `docs/TASKBOARD.md`, `docs/SESSIONS_LOG.md` | — |
| T-10 | **خطة الاختبار المُقاس** (P2.1): بروتوكول لكل UC-01..08 — الخطوات، المتوقَّع، كيفية قياس MTTD/AR-latency/FP | ASTRA | ✅ DONE [ASTRA] 2026-09-09 — PR #6 | `tests/TEST_PLAN.md` | مكتملة توثيقياً مع مراجعة ثابتة، بلا نتائج معملية. المتبقي بالضبط: حجز T-11 لعقد سجل المحاولات + المصدر + alerts.json، مراجعة سلامة AR ضمن T-15، ثم PILOT5 ثم30 لكل UC أو أكثر حسب SD وbaseline≥12h وفق v3/PR #24 (ISSUE-051). ISSUE-019 وT-23 يبقيان معلقين على النتائج الفعلية |
| T-11 | أداة قياس بسجل محاولات مستقل + تنبيهات + أدلة مصدر وmanifest للوقت والإعداد | ASTRA | IN-PROGRESS [ASTRA] 2026-09-09 — متابعة v3 §5 بتوجيه المستخدم؛ حجز metrics/runner/tests | `scripts/measure/mttd.py`, اختبارات وعقد الإدخال | PR #24: عقد v2 و8 مقاييس+D_VT وNTP session وإحصاء stdlib وrunner محمي وTEST_PLAN/README؛ 145 اختباراً محلياً وvalidate_all ناجحة. v3.1 floor30/baseline12h/EICAR فريد/G2-0 دقة timestamp؛ ISSUE-050..063؛ التالي أولاً G2-0 على alerts.json الأصلي ثم native observers/UC-01/مقام نجاح AR الشامل ومراجعة تقنية/إحصائية وPILOT معملية؛ IN-PROGRESS لا اكتمال |
| T-12 | **UC-09 SQL Injection** — runbook + إعداد + سكربت محاكاة | ASTRA | 🟢 FREE | `docs/lab/UC-09_sql_injection.md`, `scripts/attack-emulation/sqli_test.sh` | قواعد 31103/31104 (built-in) ؛ يُغلق ISSUE-007 |
| T-13 | **UC-11 SSH brute-force + firewall-drop AR** — runbook + إعداد | ASTRA | 🟢 FREE | `docs/lab/UC-11_ssh_bruteforce_ar.md`, `wazuh/manager/ossec.conf.d/50-ar-firewall-drop.xml` | قواعد 5710/5712/5763 built-in ؛ AR `firewall-drop` مدمج |
| T-14 | **UC-10 Telegram notification** عند level ≥ 12 | ASTRA | 🟢 FREE | `docs/lab/UC-10_telegram.md`, `wazuh/manager/integrations/custom-telegram.py`, `…/60-integration-telegram.xml` | لا توكن حقيقي في الريبو ؛ يُغلق ISSUE-016 |
| T-15 | مراجعة أمنية لكل سكربتات `wazuh/agents/**/active-response` و`scripts/**` (quoting, injection, perms) — **أولوية عالية** بعد ISSUE-036 | ASTRA | ◐ IN-PROGRESS [ASTRA] 2026-09-09 — PR #14 | `tests/SECURITY_REVIEW.md` + fixes + `tests/test_security.py` | نُفذت إصلاحات AR ومراجعة scripts كاملة و19 اختباراً محلياً. المتبقي بالضبط: مراجعة Claude مكتملة #17 وR1/R3 وواجهات runbooks مصححة؛ المتبقي ضبط ACL/allowlists وبناء Windows واختبار Wazuh/YARA الأصلي؛ مخاطر السباق في التقرير غير مغلقة. لا نشر قبل البوابات |
| T-20 | **الفصل 2** — الإطار النظري والدراسات السابقة (SOC/SIEM/IDS/FIM/AR/MITRE + مقارنة Wazuh/Splunk/ELK/OSSEC + ≥10 مراجع IEEE) | CLAUDE | ✅ DONE (v1 مسودة كاملة، 3,100 كلمة، 15 مرجعاً مُتحقَّقاً) | `docs/thesis/ch2_literature_review.md` | تحتاج مراجعة الفريق + مرجع محلي إن وُجد |
| T-21 | **الفصل 3** — إكمال §3.1–3.5 + إعادة صياغة §3.6 وفق النموذج الستّي (بلا Zeek/Kibana) + مخططات DFD L1/L2 (Mermaid) | CLAUDE | ✅ DONE (v1: 11 قسماً، 6 مخططات Mermaid، 6 جداول) | `docs/thesis/ch3_methodology.md` | يعتمد `docs/05`؛ الأشكال تُصدَّر PNG في T-25 |
| T-22 | **الفصل 4** — التنفيذ: كل UC على الخط الستّي، من S5 + runbooks + لقطات | ASTRA | 🟢 FREE | `docs/thesis/ch4_implementation.md` | يعتمد UC-01..08 |
| T-23 | **الفصل 5** — النتائج (جدول T-11) + الخاتمة + Future Work (AI, TheHive, Zeek, network devices, phones) | ASTRA | ⛔ BLOCKED (يعتمد T-11 نتائج فعلية) | `docs/thesis/ch5_results_conclusion.md` | — |
| T-24 | توحيد الفصل 1 مع الواقع (ISSUE-001/002/003/015): تعديل جدول 1.1 | CLAUDE | ✅ DONE (v2: نص S4 حرفياً + 9 تصحيحات موثَّقة في §1.8) | `docs/thesis/ch1_introduction.md` | تصحيح #1 (OVA) قابل للنقض بجواب Q1 |
| T-25 | تجميع DOCX نهائي بقالب الجامعة (بعد Q6) | ASTRA | ⛔ BLOCKED (Q6 القالب) | `docs/thesis/build/` | — |
| T-30 | Demo Script للجنة (10–15 دقيقة، 4 هجمات حية، خطة بديلة) | CLAUDE | ✅ DONE [CLAUDE] 2026-09-09 (v1: §0–§9، 4 هجمات مرجَّعة بمعرّفات القواعد، خطة B، Q&A، checklist) | `docs/DEMO_SCRIPT.md` | **توثيقي؛ يحتاج dry-run بشري ×2 + أرقام Δt من T-11 (ASTRA يعبّئ §6)** |
| T-31 | UC-12 أجهزة الشبكة عبر Syslog — **تصميم + تنفيذ** decoders/قواعد 100400+ | ASTRA (كان CLAUDE→ASTRA) | 🟢 FREE | `extension/UC-12_network_syslog_design.md`, `wazuh/manager/rules/local_rules_network.xml` | تنفيذه يعتمد Q5 |
| T-32 | الملخص التنفيذي + المقدمة العامة + الخاتمة الأدبية للرسالة | ASTRA (كان CLAUDE) | 🟢 FREE | `docs/thesis/front_matter.md` | بعد ch4/ch5 |
| T-33 | مراجعة لغوية/منطقية للفصلَين 4 و5 | ASTRA (كان CLAUDE) — أو الفريق البشري | ⛔ BLOCKED (T-22/T-23) | تعليقات في ISSUES | — |
| T-40 | نقل CI: `.github/workflows-pending/validate.yml` → `.github/workflows/` (يحتاج صلاحية workflows — المستخدم يدوياً) | USER | ⛔ BLOCKED (توكن) | — | — |
| T-16 | تدقيق الاستلام وتوحيد التخطيط والتوثيق وواجهات runbooks/demo | ASTRA | IN-PROGRESS [ASTRA] 2026-09-09 — حجز بتوجيه المستخدم | docs/، README، البروتوكول، tests/README | PR #19 مدموج: الخطة والواجهات وR1/R3؛ T-17 قرأ نص الأصول وch3؛ المتبقي الفصول 1–2 والمراجع وبقية الصور وتصحيحات FR/NFR والافتراضات وفق TAKEOVER_AUDIT |
| T-17 | دراسة نية صاحب المشروع من الأصول والصوتيات وبحث رسمي للنماذج ومخطط مقترح | ASTRA | IN-REVIEW [ASTRA] 2026-09-09 — دراسة ومخططات في PR #22 | docs/INTENT_STUDY_AND_BLUEPRINT.md، allocation، سجل تغطية | نص الأصول والصوت ومصادر رسمية ومصفوفة 13FR/8NFR؛ المتبقي تأكيد صاحب المشروع D1–D7 ومراجعة مستقلة؛ لا تغيير نطاق أو قبول معملي من دمج الدراسة |
