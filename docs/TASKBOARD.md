# 📋 TASKBOARD — لوحة المهام المشتركة (Claude + Astra)

> **الحالات:** 🟢 FREE (متاح للحجز) | 🔒 [AGENT] yyyy-mm-dd (محجوز) | ◐ IN-PROGRESS (مع "المتبقي") | ✅ DONE (مع commit) | ⛔ BLOCKED (مع السبب)
> **قاعدة:** احجز قبل أن تلمس. حدّث قبل أن تُغلق الجلسة. سطر واحد لكل مهمة. التفاصيل في `03_ROADMAP.md`.

| ID | المهمة | المالك الافتراضي | الحالة | ملفات المخرجات | ملاحظات |
|----|--------|:---:|--------|----------------|---------|
| T-01 | تأسيس المستودع (P0 كامل) | CLAUDE | ✅ DONE `859aa03` | كل المستودع | — |
| T-02 | وثيقة النية الموحَّدة | CLAUDE | ✅ DONE `0102eae` | `docs/05_*` | المرجع الأعلى |
| T-03 | بروتوكول التعاون + TASKBOARD + SESSIONS_LOG | CLAUDE | ✅ DONE | `COLLABORATION_PROTOCOL.md`, `docs/TASKBOARD.md`, `docs/SESSIONS_LOG.md` | — |
| T-10 | **خطة الاختبار المُقاس** (P2.1): بروتوكول لكل UC-01..08 — الخطوات، المتوقَّع، كيفية قياس MTTD/AR-latency/FP | ASTRA | 🔒 [ASTRA] 2026-09-09 | `tests/TEST_PLAN.md` | **لا** يُغلق ISSUE-019 وحده — الإغلاق يحتاج نتائج فعلية (T-11 + تنفيذ معملي). تصحيح من Astra |
| T-11 | سكربت قياس زمن الكشف آلياً (يقرأ `alerts.json` ويحسب Δt بين الحدث والتنبيه) | ASTRA | 🟢 FREE | `scripts/measure/mttd.py` | يعتمد T-10 |
| T-12 | **UC-09 SQL Injection** — runbook + إعداد + سكربت محاكاة | ASTRA | 🟢 FREE | `docs/lab/UC-09_sql_injection.md`, `scripts/attack-emulation/sqli_test.sh` | قواعد 31103/31104 (built-in) ؛ يُغلق ISSUE-007 |
| T-13 | **UC-11 SSH brute-force + firewall-drop AR** — runbook + إعداد | ASTRA | 🟢 FREE | `docs/lab/UC-11_ssh_bruteforce_ar.md`, `wazuh/manager/ossec.conf.d/50-ar-firewall-drop.xml` | قواعد 5710/5712/5763 built-in ؛ AR `firewall-drop` مدمج |
| T-14 | **UC-10 Telegram notification** عند level ≥ 12 | ASTRA | 🟢 FREE | `docs/lab/UC-10_telegram.md`, `wazuh/manager/integrations/custom-telegram.py`, `…/60-integration-telegram.xml` | لا توكن حقيقي في الريبو ؛ يُغلق ISSUE-016 |
| T-15 | مراجعة أمنية لكل سكربتات `wazuh/agents/**/active-response` و`scripts/**` (quoting, injection, perms) | ASTRA | 🟢 FREE | تقرير في `tests/SECURITY_REVIEW.md` + fixes | — |
| T-20 | **الفصل 2** — الإطار النظري والدراسات السابقة (SOC/SIEM/IDS/FIM/AR/MITRE + مقارنة Wazuh/Splunk/ELK/OSSEC + ≥10 مراجع IEEE) | CLAUDE | 🟢 FREE | `docs/thesis/ch2_literature_review.md` | — |
| T-21 | **الفصل 3** — إكمال §3.1–3.5 + إعادة صياغة §3.6 وفق النموذج الستّي (بلا Zeek/Kibana) + مخططات DFD L1/L2 (Mermaid) | CLAUDE | 🟢 FREE | `docs/thesis/ch3_methodology.md` | يعتمد `docs/05` |
| T-22 | **الفصل 4** — التنفيذ: كل UC على الخط الستّي، من S5 + runbooks + لقطات | ASTRA | 🟢 FREE | `docs/thesis/ch4_implementation.md` | يعتمد UC-01..08 |
| T-23 | **الفصل 5** — النتائج (جدول T-11) + الخاتمة + Future Work (AI, TheHive, Zeek, network devices, phones) | ASTRA | ⛔ BLOCKED (يعتمد T-11 نتائج فعلية) | `docs/thesis/ch5_results_conclusion.md` | — |
| T-24 | توحيد الفصل 1 مع الواقع (ISSUE-001/002/003/015): تعديل جدول 1.1 | CLAUDE | 🟢 FREE | `docs/thesis/ch1_introduction.md` (نسخة مُصحَّحة من S4) | — |
| T-25 | تجميع DOCX نهائي بقالب الجامعة (بعد Q6) | ASTRA | ⛔ BLOCKED (Q6 القالب) | `docs/thesis/build/` | — |
| T-30 | Demo Script للجنة (10–15 دقيقة، 4 هجمات حية، خطة بديلة) | CLAUDE | 🟢 FREE | `docs/DEMO_SCRIPT.md` | — |
| T-31 | تصميم UC-12 أجهزة الشبكة عبر Syslog (decoder + قواعد 100400+ + MikroTik CHR/pfSense VM) | CLAUDE | 🟢 FREE | `extension/UC-12_network_syslog_design.md`, `wazuh/manager/rules/local_rules_network.xml` | تنفيذه يعتمد Q5 |
| T-40 | نقل CI: `.github/workflows-pending/validate.yml` → `.github/workflows/` (يحتاج صلاحية workflows — المستخدم يدوياً) | USER | ⛔ BLOCKED (توكن) | — | — |
