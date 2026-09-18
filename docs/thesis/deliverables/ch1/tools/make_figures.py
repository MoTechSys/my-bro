#!/usr/bin/env python3
"""
Generate all Chapter-1 vector figures (SVG) + PNG previews.

Every value drawn here is sourced from docs/02_ARCHITECTURE.md (lab facts),
docs/05_PROJECT_INTENT_UNIFIED_VISION.md (scope), docs/DECISIONS.md (ADR-014).
Re-run:  python3 make_figures.py   (needs rsvg-convert for PNG previews)
"""
from __future__ import annotations
import os, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "figures")
os.makedirs(OUT, exist_ok=True)

AR = "Noto Naskh Arabic, Noto Sans Arabic, Arial"
EN = "DejaVu Sans, Arial, Helvetica"
MONO = "DejaVu Sans Mono, Consolas, monospace"

# Palette (print-safe, colour-blind friendly)
C = dict(
    bg="#ffffff", ink="#1f2937", muted="#6b7280", line="#374151",
    server="#1d4ed8", server_l="#dbeafe",
    linux="#047857", linux_l="#d1fae5",
    win="#7c3aed", win_l="#ede9fe",
    attack="#b91c1c", attack_l="#fee2e2",
    net="#b45309", net_l="#fef3c7",
    future="#9ca3af", future_l="#f3f4f6",
    ai="#0e7490", ai_l="#cffafe",
    ok="#15803d", warn="#b45309",
)


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def text(x, y, s, size=14, fill=C["ink"], anchor="middle", font=AR, weight="normal", extra=""):
    return (f'<text x="{x}" y="{y}" font-family="{font}" font-size="{size}" fill="{fill}" '
            f'text-anchor="{anchor}" font-weight="{weight}" {extra}>{esc(s)}</text>')


def rect(x, y, w, h, fill, stroke, rx=10, sw=2, dash=""):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>'


def arrow(x1, y1, x2, y2, color=C["line"], sw=2, dash="", marker="arr"):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}" marker-end="url(#{marker})"{d}/>'


def defs():
    return f'''<defs>
  <marker id="arr" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="userSpaceOnUse">
    <path d="M0,0 L10,5 L0,10 z" fill="{C['line']}"/></marker>
  <marker id="arr_red" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="userSpaceOnUse">
    <path d="M0,0 L10,5 L0,10 z" fill="{C['attack']}"/></marker>
  <marker id="arr_blue" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="userSpaceOnUse">
    <path d="M0,0 L10,5 L0,10 z" fill="{C['server']}"/></marker>
  <marker id="arr_grey" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto" markerUnits="userSpaceOnUse">
    <path d="M0,0 L10,5 L0,10 z" fill="{C['future']}"/></marker>
</defs>'''


def svg(w, h, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
            f'font-family="{AR}">\n<title>{esc(title)}</title>\n{defs()}\n'
            f'<rect width="{w}" height="{h}" fill="{C["bg"]}"/>\n{body}\n</svg>\n')


def save(name, content):
    p = os.path.join(OUT, name + ".svg")
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    if shutil.which("rsvg-convert"):
        subprocess.run(["rsvg-convert", "-w", "2400", p, "-o", os.path.join(OUT, name + ".png")], check=True)
    print("wrote", name)


# ----------------------------------------------------------------------------
# Figure 1.1 — Lab topology (facts: 02_ARCHITECTURE §1, §2, §7)
# ----------------------------------------------------------------------------
def fig_1_1_topology():
    W, H = 1300, 760
    b = []
    b.append(text(W/2, 40, "الشكل (1.1): طوبولوجيا بيئة المعمل الافتراضية — VMware Workstation، الشبكة 192.168.100.0/24", 20, weight="bold"))
    # outer VMware box
    b.append(rect(40, 70, 1220, 620, "#fafafa", C["muted"], rx=16, sw=2, dash="8 6"))
    b.append(text(1240, 95, "VMware Workstation — Host-only / NAT 192.168.100.0/24", 14, C["muted"], "end", EN))

    # Server
    sx, sy, sw_, sh = 70, 130, 420, 250
    b.append(rect(sx, sy, sw_, sh, C["server_l"], C["server"], rx=14, sw=3))
    b.append(text(sx+sw_/2, sy+32, "wazuh-server — خادم SOC المركزي", 18, C["server"], weight="bold"))
    b.append(text(sx+sw_/2, sy+58, "Wazuh OVA 4.14 (All-in-one) — 192.168.100.105", 14, C["ink"], font=EN))
    comps = ["Wazuh Manager (analysisd, integratord, AR orchestration)",
             "Wazuh Indexer (OpenSearch-based) — wazuh-alerts-4.x-*",
             "Wazuh Dashboard :443 — Threat Hunting / FIM / MITRE ATT&CK",
             "Filebeat (internal) — alerts → indexer",
             "cluster node: node01   user: wazuh-user"]
    for i, c in enumerate(comps):
        b.append(text(sx+20, sy+95+i*28, "•  " + c, 13, C["ink"], "start", EN))

    # Kali
    kx, ky, kw, kh = 790, 130, 440, 250
    b.append(rect(kx, ky, kw, kh, C["linux_l"], C["linux"], rx=14, sw=3))
    b.append(text(kx+kw/2, ky+32, "kali1 — نقطة نهاية Linux + خادم ويب ضحية", 18, C["linux"], weight="bold"))
    b.append(text(kx+kw/2, ky+58, "Kali GNU/Linux 2025.4 — 192.168.100.108 — Agent ID 002 (active)", 13, C["ink"], font=EN))
    comps = ["wazuh-agent 4.14.7 (syscheck realtime, logcollector, command)",
             "Suricata 8.0.6 (af-packet, eth0) → eve.json",
             "auditd (execve rules) → /var/log/audit/audit.log",
             "Apache 2.4.68 (victim) → access.log",
             "YARA 4.5.5 + Active Response (remove-threat.sh, yara.sh)"]
    for i, c in enumerate(comps):
        b.append(text(kx+20, ky+95+i*28, "•  " + c, 13, C["ink"], "start", EN))

    # Windows
    wx, wy, ww, wh = 70, 450, 420, 200
    b.append(rect(wx, wy, ww, wh, C["win_l"], C["win"], rx=14, sw=3))
    b.append(text(wx+ww/2, wy+32, "win1 — نقطة نهاية Windows", 18, C["win"], weight="bold"))
    b.append(text(wx+ww/2, wy+58, "Windows 10 Education 10.0.19045.2006", 13, C["ink"], font=EN))
    b.append(text(wx+ww/2, wy+78, "192.168.100.106 — Agent ID 001", 13, C["ink"], font=EN))
    comps = ["wazuh-agent 4.14.7 (FIM: Desktop\\abdul, Downloads)",
             "Active Response: remove-threat.exe (VirusTotal), yara.bat",
             "Windows Event Log channels (Security, System)"]
    for i, c in enumerate(comps):
        b.append(text(wx+20, wy+112+i*28, "•  " + c, 13, C["ink"], "start", EN))

    # Attacker
    ax, ay, aw, ah = 790, 450, 440, 200
    b.append(rect(ax, ay, aw, ah, C["attack_l"], C["attack"], rx=14, sw=3))
    b.append(text(ax+aw/2, ay+32, "المهاجم — محاكاة الهجمات (داخل المعمل فقط)", 18, C["attack"], weight="bold"))
    b.append(text(ax+aw/2, ay+58, "kali1 نفسها أو جهاز Kali ثانٍ (curl / nmap / nc / EICAR)", 13, C["ink"], font=EN))
    comps = ["nmap SYN scan → Suricata 86601", "curl User-Agent «() { :; };» → Shellshock 31168 (L15)",
             "nc -l → process monitor 100051 (L7)", "EICAR / red-list command → VT 87105 / audit 100210 (L12)"]
    for i, c in enumerate(comps):
        b.append(text(ax+20, ay+92+i*24, "•  " + c, 12, C["ink"], "start", EN))

    # Arrows agents -> server (kali -> server, along the bottom edge of the boxes to avoid text)
    b.append(arrow(kx, ky+kh-20, sx+sw_+4, sy+sh-20, C["server"], 3, marker="arr_blue"))
    b.append(text((kx+sx+sw_)/2, sy+sh-30, "TCP 1514 events / 1515 enrollment (TLS)", 12, C["server"], font=EN))
    b.append(arrow(wx+ww/2, wy, wx+ww/2, sy+sh+4, C["server"], 3, marker="arr_blue"))
    b.append(text(wx+ww/2+80, sy+sh+40, "TCP 1514 / 1515", 12, C["server"], font=EN))
    # attacker -> kali (HTTP 80) and scan
    b.append(arrow(ax+aw/2, ay, ax+aw/2, ky+kh+4, C["attack"], 3, marker="arr_red"))
    b.append(text(ax+aw/2+75, ky+kh+40, "TCP 80 / scans", 12, C["attack"], font=EN))
    # analyst (centre column)
    b.append(rect(540, 540, 220, 80, "#f9fafb", C["muted"], rx=12))
    b.append(text(650, 570, "محلل الأمن", 15, C["ink"], weight="bold"))
    b.append(text(650, 595, "HTTPS 443 → Dashboard", 12, C["muted"], font=EN))
    b.append(f'<path d="M 600 540 C 600 460, 500 440, {sx+sw_-40} {sy+sh+2}" fill="none" stroke="{C["muted"]}" stroke-width="2" stroke-dasharray="6 4" marker-end="url(#arr_grey)"/>')
    # legend future
    b.append(rect(540, 130, 220, 60, C["future_l"], C["future"], rx=12, dash="6 4"))
    b.append(text(650, 155, "أجهزة الشبكة / الهواتف", 13, C["muted"]))
    b.append(text(650, 176, "Syslog 514 — توسعة مستقبلية", 11, C["muted"]))
    b.append(arrow(560, 190, sx+sw_-40, sy-2, C["future"], 2, dash="6 4", marker="arr_grey"))
    b.append(text(W/2, 725, "المصدر: docs/02_ARCHITECTURE.md §1–§2، §7 — كل قيمة مؤكدة بلقطة شاشة (p01_0, p04_0, p30_0, img13, img20)", 12, C["muted"]))
    save("fig_1_1_lab_topology", svg(W, H, "\n".join(b), "Lab topology"))


# ----------------------------------------------------------------------------
# Figure 1.2 — Six-stage pipeline (docs/05 §3)
# ----------------------------------------------------------------------------
def fig_1_2_pipeline():
    W, H = 1300, 520
    b = []
    b.append(text(W/2, 40, "الشكل (1.2): النموذج المرجعي الست المراحل لخط أنابيب المنصة — كشف → قرار → استجابة → عرض", 20, weight="bold"))
    stages = [
        ("SENSE", "الاستشعار", ["Endpoints (Win/Linux)", "Network traffic", "Web/audit logs", "[Infra: syslog]*"], C["linux"], C["linux_l"]),
        ("COLLECT", "الجمع", ["Wazuh Agent 4.14.7", "FIM / logcollector / command", "Suricata eve.json", "[Syslog 514]*"], C["server"], C["server_l"]),
        ("DETECT", "الكشف", ["decoders → rules", "CDB lists", "MITRE ATT&CK tags", "100050–108001"], C["net"], C["net_l"]),
        ("DECIDE", "القرار", ["rule level (3/7/12/15)", "thresholds / frequency", "VirusTotal verdict", "policy (soc_ar.py)"], C["win"], C["win_l"]),
        ("RESPOND", "الاستجابة", ["Active Response", "remove-threat (VT)", "yara.sh scan", "[firewall-drop]*"], C["attack"], C["attack_l"]),
        ("PRESENT", "العرض", ["Wazuh Dashboard", "MITRE / Threat Hunting", "alerts.json (JSONL)", "[Telegram]* / AI advisor†"], C["ai"], C["ai_l"]),
    ]
    n = len(stages); bw = 180; gap = 30; x0 = (W - (n*bw + (n-1)*gap)) / 2; y0 = 90; bh = 250
    for i, (en, ar, items, col, coll) in enumerate(stages):
        x = x0 + i*(bw+gap)
        b.append(rect(x, y0, bw, bh, coll, col, rx=14, sw=3))
        b.append(text(x+bw/2, y0+32, en, 18, col, font=EN, weight="bold"))
        b.append(text(x+bw/2, y0+58, ar, 16, C["ink"], weight="bold"))
        for j, it in enumerate(items):
            b.append(text(x+bw/2, y0+100+j*34, it, 12, C["ink"], font=EN))
        if i < n-1:
            b.append(arrow(x+bw+2, y0+bh/2, x+bw+gap-2, y0+bh/2, C["line"], 3))
    # feedback arrow respond -> present -> analyst
    b.append(f'<path d="M {x0+4*(bw+gap)+bw/2} {y0+bh+6} C {x0+4*(bw+gap)+bw/2} {y0+bh+60}, {x0+bw/2} {y0+bh+60}, {x0+bw/2} {y0+bh+6}" fill="none" stroke="{C["muted"]}" stroke-width="2" stroke-dasharray="6 4" marker-end="url(#arr_grey)"/>')
    b.append(text(W/2, y0+bh+58, "حلقة مغلقة: نتيجة الاستجابة تعود كحدث جديد (قاعدة 657 → 100092/100093) وتُقاس زمنياً", 13, C["muted"]))
    b.append(text(W/2, 430, "* بين معقوفتين = توسعة مخطَّطة (UC-10/11/12) — لم تُعتمد معملياً حتى تاريخ هذا الفصل.   † AI advisor: مساعد تحليل استشاري بلا سلطة تنفيذ (ADR-014).", 12, C["muted"]))
    b.append(text(W/2, 460, "المصدر: docs/05_PROJECT_INTENT_UNIFIED_VISION.md §3 — النموذج الذهني الواحد الذي يُقرأ عليه كل حالة استخدام", 12, C["muted"]))
    save("fig_1_2_six_stage_pipeline", svg(W, H, "\n".join(b), "Six-stage pipeline"))


# ----------------------------------------------------------------------------
# Figure 1.3 — Scope boundary (In / Extension / Out)
# ----------------------------------------------------------------------------
def fig_1_3_scope():
    W, H = 1300, 640
    b = []
    b.append(text(W/2, 40, "الشكل (1.3): حدود المشروع — النطاق الأساسي، التوسعة المخطَّطة، وخارج النطاق", 20, weight="bold"))
    # Three side-by-side columns (clearer than nested rings for print)
    cols = [
        ("النطاق الأساسي — MUST", "مُنفَّذ أو ملزم للتسليم", C["server"], C["server_l"],
         ["Wazuh 4.14 Manager / Indexer / Dashboard", "وكلاء Windows 10 + Kali Linux", "FIM لحظي · VirusTotal + حذف آلي",
          "Suricata NIDS · auditd + CDB", "Shellshock · YARA + فحص آلي · Netcat", "تنبيهات مرتبطة بـ MITRE ATT&CK",
          "تقييم كمّي مُقاس (DR · MTTD · AR · FP)", "مساعد AI استشاري مُقيَّد (ADR-014)"]),
        ("التوسعة المخطَّطة — SHOULD / COULD", "كود جاهز أو مُصمَّم؛ القبول الحي متبقٍّ", C["net"], C["net_l"],
         ["UC-09 كشف SQL Injection", "UC-11 SSH brute-force → firewall-drop", "UC-10 إشعار Telegram عند L≥12",
          "UC-12 جهاز شبكة عبر Syslog (100400+)", "M0 رؤية الهاتف من الشبكة (بلا وكيل)", "YARA على Windows (إثبات)",
          "مصفوفة تغطية المصادر", "WireGuard سحابة ↔ معمل محلي"]),
        ("خارج النطاق — WON'T", "يُذكر كأعمال مستقبلية أو مقارنة نظرية", C["muted"], C["future_l"],
         ["Zeek (تكرار وظيفي لـ Suricata)", "TheHive (إدارة الحالات)", "Kibana / Elasticsearch منفصلان",
          "وكيل داخل الهاتف (لا دعم رسمي)", "إدارة مراكز بيانات فعلية", "الاستجابة القانونية / الجنائية",
          "اختبار اختراق خارج المعمل", "«أداة أقوى من Wazuh» → «طبقة تكامل فوق Wazuh»"]),
    ]
    cw = 390; gap = 25; x0 = (W - (3*cw + 2*gap)) / 2; y0 = 80
    for i, (h, sub, col, coll, items) in enumerate(cols):
        x = x0 + i*(cw+gap)
        b.append(rect(x, y0, cw, 480, coll, col, rx=14, sw=3, dash=("8 6" if i == 2 else "")))
        b.append(rect(x, y0, cw, 70, col, col, rx=14))
        b.append(text(x+cw/2, y0+30, h, 16, "#fff", weight="bold"))
        b.append(text(x+cw/2, y0+55, sub, 12, "#fff"))
        for j, it in enumerate(items):
            b.append(f'<circle cx="{x+cw-22}" cy="{y0+105+j*48-5}" r="4" fill="{col}"/>')
            b.append(text(x+cw-36, y0+105+j*48, it, 13, C["ink"], "end"))
    # arrows showing possible promotion
    b.append(arrow(x0+cw+gap+cw/2-40, y0+490, x0+cw/2+40, y0+490, C["net"], 2, dash="6 4"))
    b.append(text(x0+cw+gap/2, y0+515, "يُرقَّى إلى MUST بعد القبول الحي (بوابة G4)", 11, C["muted"]))
    b.append(text(W/2, 625, "المصدر: docs/05 §5 مصفوفة MoSCoW + ADR-014 (docs/DECISIONS.md) — AI انتقل من WON'T إلى MUST كمساعد تحليل لا كمحرك كشف", 12, C["muted"]))
    save("fig_1_3_scope_boundary", svg(W, H, "\n".join(b), "Scope boundary"))


# ----------------------------------------------------------------------------
# Figure 1.4 — Technology stack layers (02_ARCHITECTURE §8)
# ----------------------------------------------------------------------------
def fig_1_4_stack():
    W, H = 1200, 620
    b = []
    b.append(text(W/2, 40, "الشكل (1.4): الطبقات الست للمنصة والمكوّنات الفعلية المُثبَتة في كل طبقة", 20, weight="bold"))
    layers = [
        ("6", "الإخراج والعرض", "Wazuh Dashboard 4.14 (Threat Hunting · FIM · MITRE ATT&CK) — AI advisor (استشاري)", C["ai"], C["ai_l"]),
        ("5", "الاستجابة والتخزين", "Active Response (remove-threat / yara / soc_ar.py) · integratord→VirusTotal · Filebeat→Wazuh Indexer", C["attack"], C["attack_l"]),
        ("4", "القرار", "rule level ≥3 → alert · قواعد مخصصة L7 / L12 / L15 · CDB red-list · ignore=900", C["win"], C["win_l"]),
        ("3", "المعالجة والربط", "wazuh-analysisd: decoders → rules (built-in + local_rules.xml) → MITRE tags", C["net"], C["net_l"]),
        ("2", "الجمع", "Wazuh Agent 4.14.7 (syscheck · logcollector · command) · Suricata 8.0.6 eve.json", C["server"], C["server_l"]),
        ("1", "مصادر البيانات", "win1 (Windows 10) · kali1 (Kali 2025.4) · Apache 2.4.68 access.log · auditd · process list · network traffic", C["linux"], C["linux_l"]),
    ]
    y = 80; lh = 78
    for num, ar, comp, col, coll in layers:
        b.append(rect(120, y, 960, lh-10, coll, col, rx=12, sw=2.5))
        b.append(f'<circle cx="160" cy="{y+(lh-10)/2}" r="20" fill="{col}"/>')
        b.append(text(160, y+(lh-10)/2+7, num, 18, "#fff", font=EN, weight="bold"))
        b.append(text(1060, y+28, ar, 17, col, "end", weight="bold"))
        b.append(text(1060, y+54, comp, 12.5, C["ink"], "end", EN))
        y += lh
    b.append(arrow(80, 540, 80, 90, C["muted"], 2, dash="6 4", marker="arr_grey"))
    b.append(text(60, 320, "تدفق البيانات", 12, C["muted"], extra='transform="rotate(-90 60 320)"'))
    b.append(text(W/2, 600, "المصدر: docs/02_ARCHITECTURE.md §8 (النسخة المطابقة للواقع للطبقات الست من S4 §3.6.1) — Zeek/Kibana/Elasticsearch غير موجودة في أي طبقة", 12, C["muted"]))
    save("fig_1_4_platform_layers", svg(W, H, "\n".join(b), "Platform layers"))


# ----------------------------------------------------------------------------
# Figure 1.5 — Use-case coverage map (8 implemented + planned)
# ----------------------------------------------------------------------------
def fig_1_5_usecases():
    W, H = 1300, 660
    b = []
    b.append(text(W/2, 40, "الشكل (1.5): خريطة حالات الاستخدام على مراحل الخط الستّي — المنفَّذ (مُثبَت بلقطات) والمخطَّط", 20, weight="bold"))
    cols = ["UC", "الوصف", "SENSE", "COLLECT", "DETECT (rule)", "DECIDE (level)", "RESPOND", "الحالة"]
    cw = [70, 260, 120, 150, 170, 130, 190, 150]
    x0 = (W - sum(cw)) / 2; y = 80; rh = 34
    # header
    x = x0
    for c, w in zip(cols, cw):
        b.append(rect(x, y, w, rh, "#e5e7eb", C["muted"], rx=4, sw=1))
        b.append(text(x+w/2, y+23, c, 13, C["ink"], weight="bold"))
        x += w
    rows = [
        ("01", "نشر الوكلاء Win/Linux", "—", "agent 4.14.7", "—", "—", "—", "✅ مُثبَت"),
        ("02", "FIM لحظي", "ملف", "syscheck", "550/553/554", "L5–7", "—", "✅ مُثبَت"),
        ("03", "VirusTotal + حذف آلي", "ملف", "syscheck", "100200/1→87105", "L12", "حذف الملف (AR)", "✅ مُثبَت"),
        ("04", "Suricata NIDS", "ترافيك", "eve.json", "86601", "L3+", "—", "✅ مُثبَت"),
        ("05", "auditd + CDB أوامر خبيثة", "أمر مُنفَّذ", "audit.log", "80792+CDB→100210", "L12", "—", "✅ مُثبَت"),
        ("06", "Shellshock عبر Apache", "HTTP", "access.log", "31168", "L15", "—", "✅ مُثبَت"),
        ("07", "YARA + فحص آلي", "ملف", "syscheck", "100300/1→108001", "L12", "فحص YARA (AR)", "✅ مُثبَت"),
        ("08", "مراقبة العمليات — Netcat", "عملية", "ps كل 30 ث", "100050→100051", "L7", "—", "✅ مُثبَت"),
        ("09", "SQL Injection", "HTTP", "access.log", "31103/31106", "L6+", "—", "◐ كود جاهز"),
        ("10", "إشعار Telegram", "—", "—", "L≥12", "—", "إشعار", "◐ كود جاهز"),
        ("11", "SSH brute-force", "auth", "auth.log", "5763", "L10", "firewall-drop (AR)", "◐ كود جاهز"),
        ("14", "مساعد AI استشاري", "alerts.json", "—", "RAG/MITRE", "—", "اقتراح فقط", "◐ كود جاهز"),
    ]
    for r in rows:
        y += rh
        x = x0
        done = r[-1].startswith("✅")
        fill = "#f0fdf4" if done else "#fffbeb"
        for c, w in zip(r, cw):
            b.append(rect(x, y, w, rh, fill, "#d1d5db", rx=0, sw=1))
            col = C["ok"] if (c.startswith("✅")) else (C["warn"] if c.startswith("◐") else C["ink"])
            fnt = EN if any(ch.isdigit() for ch in c) and not any('\u0600' <= ch <= '\u06FF' for ch in c) else AR
            b.append(text(x+w/2, y+23, c, 12, col, font=fnt))
            x += w
    b.append(text(W/2, y+rh+40, "✅ مُثبَت = نُفِّذ في معمل 2026-08 وموثَّق بلقطات شاشة (docs/sources/screenshots)", 12, C["muted"]))
    b.append(text(W/2, y+rh+64, "◐ كود جاهز = مُنفَّذ برمجياً باختبارات آلية، والقبول المعملي الحي متبقٍّ", 12, C["muted"]))
    b.append(text(W/2, y+rh+88, "عمود RESPOND فارغ في 5 من 8 حالات مُثبَتة → محور التعميق الأول للمشروع (docs/05 §6)", 12, C["muted"]))
    save("fig_1_5_usecase_coverage", svg(W, H, "\n".join(b), "Use-case coverage"))


# ----------------------------------------------------------------------------
# Figure 1.6 — Problem → Objectives → Contribution chain
# ----------------------------------------------------------------------------
def fig_1_6_problem_chain():
    W, H = 1300, 560
    b = []
    b.append(text(W/2, 40, "الشكل (1.6): سلسلة المنطق البحثي — من مشكلة الدراسة إلى الإضافة العلمية القابلة للقياس", 20, weight="bold"))
    colx = [60, 480, 900]; cw = 360; y0 = 80
    heads = [("مشكلة الدراسة", C["attack"], C["attack_l"]), ("الأهداف", C["server"], C["server_l"]), ("الإضافة العلمية (Contribution)", C["ok"], "#dcfce7")]
    for (h, col, coll), x in zip(heads, colx):
        b.append(rect(x, y0, cw, 44, col, col, rx=10))
        b.append(text(x+cw/2, y0+30, h, 17, "#fff", weight="bold"))
    problems = ["حلول أمنية منفصلة بلا منصة مركزية", "ارتفاع تكلفة SOC التجاري", "نقص الكوادر — التحليل اليدوي غير عملي", "تأخر الاستجابة → فقدان بيانات/تعطل", "«نجاح 100%» بلا قياس في الأدلة المعملية"]
    objectives = ["منصة مركزية مفتوحة المصدر (Wazuh+Suricata)", "تكلفة ترخيص صفرية — معمل افتراضي", "استجابة آلية للتهديدات L≥12 بلا تدخل", "تنبيهات مرتبطة بـ MITRE ATT&CK", "تقييم كمّي: DR · MTTD · AR latency · FP/h"]
    contribs = ["C1 تكامل معماري: 7 آليات كشف بسجل قواعد موحَّد", "C1 AR مُحصَّن بسياسة (soc_ar.py) يعالج 6 عيوب في PoC الرسمي", "C2 بروتوكول تقييم كمّي بطوابع t0–t6 وفواصل ثقة", "C3 عقد إدخال مصدر شبكي بلا تغيير المعمارية", "C4 مساعد AI استشاري مُقاس (ADR-014)"]
    for i in range(5):
        yy = y0 + 70 + i*72
        for lst, (h, col, coll), x in zip([problems, objectives, contribs], heads, colx):
            b.append(rect(x, yy, cw, 56, coll, col, rx=10, sw=1.5))
            b.append(text(x+cw/2, yy+34, lst[i], 13, C["ink"]))
        b.append(arrow(colx[0]+cw+4, yy+28, colx[1]-4, yy+28, C["line"], 2))
        b.append(arrow(colx[1]+cw+4, yy+28, colx[2]-4, yy+28, C["line"], 2))
    b.append(text(W/2, 540, "المصدر: ch1 §1.3–§1.4 (نص S4) · docs/05 §4 · MASTER_PLAN_v3 §3 (C1–C3) · ADR-014 (C4)", 12, C["muted"]))
    save("fig_1_6_problem_objectives_contribution", svg(W, H, "\n".join(b), "Problem chain"))


# ----------------------------------------------------------------------------
# Figure 1.7 — Project timeline / gates
# ----------------------------------------------------------------------------
def fig_1_7_timeline():
    W, H = 1300, 420
    b = []
    b.append(text(W/2, 40, "الشكل (1.7): مراحل المشروع وبوابات الإنجاز — المُنجَز والجاري والمتبقي", 20, weight="bold"))
    phases = [
        ("P0", "التأسيس", "مستودع · تحليل 7 مصادر · وثيقة النية · بروتوكول تعاون", "done"),
        ("P1", "المعمل والإعدادات", "8 حالات استخدام · إعدادات مُصحَّحة · AR مُحصَّن · 307 اختبار", "done"),
        ("P2", "القياس", "بروتوكول t0–t6 · أداة mttd.py · PILOT n=5 → n=30 · baseline 12h", "progress"),
        ("P3", "التوسعة", "UC-09/10/11 · UC-12 Syslog · مساعد AI (T-70) · Windows AR", "progress"),
        ("P4", "الرسالة", "ch1–3 مسودات ✓ · ch4 التنفيذ · ch5 النتائج · DOCX", "progress"),
        ("P5", "الدفاع", "Demo 15 دقيقة · dry-run ×2 · Q&A اللجنة", "todo"),
    ]
    n = len(phases); bw = 195; gap = 14; x0 = (W - (n*bw + (n-1)*gap))/2; y = 100
    colmap = {"done": (C["ok"], "#dcfce7", "✅ مُنجَز"), "progress": (C["warn"], C["net_l"], "◐ جارٍ"), "todo": (C["muted"], C["future_l"], "☐ متبقٍّ")}
    for i, (p, ar, desc, st) in enumerate(phases):
        col, coll, lab = colmap[st]
        x = x0 + i*(bw+gap)
        b.append(rect(x, y, bw, 200, coll, col, rx=12, sw=2.5))
        b.append(text(x+bw/2, y+30, p, 18, col, font=EN, weight="bold"))
        b.append(text(x+bw/2, y+56, ar, 15, C["ink"], weight="bold"))
        # wrap desc by ' · '
        parts = desc.split(" · ")
        for j, part in enumerate(parts):
            b.append(text(x+bw/2, y+90+j*24, part, 12, C["ink"]))
        b.append(text(x+bw/2, y+185, lab, 13, col, weight="bold"))
        if i < n-1:
            b.append(arrow(x+bw+1, y+100, x+bw+gap-1, y+100, C["line"], 2))
    b.append(text(W/2, 350, "بوابات G0–G8 (MASTER_PLAN_v3 §6): لا تُعلَن مرحلة «مُنجَزة» بلا دليل حي (Zero-Skip). تاريخ اللقطة: 2026-09-18", 12, C["muted"]))
    b.append(text(W/2, 380, "المصدر: docs/03_ROADMAP.md · docs/TASKBOARD.md · docs/00_PROJECT_STATE.md", 12, C["muted"]))
    save("fig_1_7_phases_gates", svg(W, H, "\n".join(b), "Phases and gates"))


if __name__ == "__main__":
    fig_1_1_topology()
    fig_1_2_pipeline()
    fig_1_3_scope()
    fig_1_4_stack()
    fig_1_5_usecases()
    fig_1_6_problem_chain()
    fig_1_7_timeline()
    print("done →", os.path.abspath(OUT))
