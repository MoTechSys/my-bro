#!/usr/bin/env python3
"""Validate Wazuh custom rules/decoders in wazuh/manager.

Checks:
  1. Every *.xml in rules/ and decoders/ is well-formed once wrapped in a root
     (Wazuh files are XML fragments with multiple top-level <group>/<decoder>).
  2. Rule IDs are unique across all rule files.
  3. Custom rule IDs are in the 100000-120000 range (Wazuh convention).
  4. Every <if_sid> refers to a known built-in or a custom rule defined here.
  5. Rule IDs are inside the namespaces registered in docs/02_ARCHITECTURE.md.
  6. No real-looking API keys (VirusTotal 64-hex) are committed.
Exit code 0 = OK, 1 = failure.
"""
import re
import sys
import pathlib
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[2]
RULES_DIR = ROOT / "wazuh" / "manager" / "rules"
DEC_DIR = ROOT / "wazuh" / "manager" / "decoders"
CONF_DIRS = [ROOT / "wazuh"]

# Built-in Wazuh rule IDs that our custom rules chain from (documented in 02_ARCHITECTURE.md §5)
KNOWN_BUILTIN = {530, 550, 553, 554, 657, 80792, 86601, 87105, 31168}

# Registered namespaces (start, end, purpose)
NAMESPACES = [
    (100050, 100051, "process monitoring"),
    (100092, 100093, "VirusTotal AR results"),
    (100200, 100201, "FIM SOCfile -> VT"),
    (100210, 100210, "audit red-list"),
    (100300, 100304, "FIM YARA dirs (Linux/Windows)"),
    (108000, 108001, "YARA results"),
    (100400, 100499, "RESERVED network devices/syslog"),
    (100500, 100599, "RESERVED AI/reporting"),
]

errors, warnings = [], []


def parse_fragment(path: pathlib.Path):
    text = path.read_text(encoding="utf-8")
    # Wazuh rule descriptions may contain raw '<USER_NAME>' placeholders inside <description>; escape for parsing only
    safe = re.sub(r"<USER_NAME>", "USER_NAME_PLACEHOLDER", text)
    try:
        return ET.fromstring(f"<root>{safe}</root>")
    except ET.ParseError as e:
        errors.append(f"{path.relative_to(ROOT)}: XML parse error: {e}")
        return None


def in_namespace(rid: int):
    return any(lo <= rid <= hi for lo, hi, _ in NAMESPACES)


def main():
    seen = {}
    if_sids = []
    for f in sorted(RULES_DIR.glob("*.xml")):
        root = parse_fragment(f)
        if root is None:
            continue
        for rule in root.iter("rule"):
            rid = int(rule.get("id"))
            lvl = rule.get("level")
            if lvl is None:
                errors.append(f"{f.name}: rule {rid} missing level")
            if rid in seen:
                errors.append(f"{f.name}: DUPLICATE rule id {rid} (also in {seen[rid]}) — Wazuh will refuse to start")
            seen[rid] = f.name
            if not (100000 <= rid <= 120000):
                errors.append(f"{f.name}: rule {rid} outside custom range 100000-120000")
            if not in_namespace(rid):
                warnings.append(f"{f.name}: rule {rid} not in a registered namespace (update 02_ARCHITECTURE.md §5)")
            if rule.find("description") is None:
                errors.append(f"{f.name}: rule {rid} has no <description>")
            for s in rule.findall("if_sid"):
                for part in s.text.split(","):
                    if_sids.append((rid, int(part.strip()), f.name))

    for rid, ref, fname in if_sids:
        if ref not in KNOWN_BUILTIN and ref not in seen:
            errors.append(f"{fname}: rule {rid} <if_sid>{ref}</if_sid> refers to unknown rule (add to KNOWN_BUILTIN if built-in)")

    for f in sorted(DEC_DIR.glob("*.xml")):
        root = parse_fragment(f)
        if root is None:
            continue
        names = [d.get("name") for d in root.iter("decoder")]
        for d in root.iter("decoder"):
            p = d.find("parent")
            if p is not None and p.text not in names:
                errors.append(f"{f.name}: decoder {d.get('name')} parent '{p.text}' not defined")

    # Secrets scan: 64-hex VirusTotal-like key not equal to placeholder/demo
    hexkey = re.compile(r"\b[0-9a-f]{64}\b")
    for d in CONF_DIRS:
        for f in d.rglob("*"):
            if f.is_file() and f.suffix in {".xml", ".sh", ".py", ".bat", ".md", ".conf", ""}:
                try:
                    txt = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                for m in hexkey.findall(txt):
                    if set(m) != {"1"}:  # VALHALLA demo key is all 1s
                        errors.append(f"{f.relative_to(ROOT)}: possible real API key committed: {m[:8]}…")

    print(f"Rules found: {sorted(seen)}")
    for w in warnings:
        print("WARN ", w)
    for e in errors:
        print("ERROR", e)
    if errors:
        print(f"\nFAILED with {len(errors)} error(s)")
        return 1
    print("\nOK: rule IDs unique, XML well-formed, if_sid chain valid, no secrets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
