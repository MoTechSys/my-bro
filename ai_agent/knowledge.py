"""Knowledge base for the SOC AI analyst (RAG, no external vector DB).

Sources (all local, versioned in this repo):
  * our Wazuh rules  (wazuh/manager/rules/*.xml)   -> id, level, description, MITRE, groups
  * MITRE ATT&CK techniques used by the project      -> ai_agent/data/mitre_techniques.json
  * lab runbooks     (docs/lab/UC-*.md)              -> response procedures
Retrieval = BM25 over tokenised chunks (pure stdlib, deterministic, explainable in
the thesis). Built-in Wazuh rule IDs the project relies on are described in
ai_agent/data/builtin_rules.json so the analyst never invents their meaning.
"""
import json
import math
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).resolve().parent / 'data'
TOKEN = re.compile(r'[a-z0-9_.]+')


def tokenize(text):
    return [t for t in TOKEN.findall(str(text).lower()) if len(t) > 1]


def _strip_comments(text):
    return re.sub(r'<!--.*?-->', '', text, flags=re.S)


def load_project_rules(rules_dir=ROOT / 'wazuh/manager/rules'):
    rules = {}
    for f in sorted(Path(rules_dir).glob('*.xml')):
        root = ET.fromstring('<root>' + _strip_comments(f.read_text(encoding='utf-8')) + '</root>')
        for rule in root.iter('rule'):
            rid = rule.get('id')
            rules[rid] = {
                'id': rid, 'level': int(rule.get('level', 0)), 'source': f.name,
                'description': (rule.findtext('description') or '').strip(),
                'mitre': [m.text for m in rule.findall('mitre/id')],
                'groups': [g for g in (rule.findtext('group') or '').split(',') if g],
            }
    return rules


def load_json(name):
    return json.loads((DATA / name).read_text(encoding='utf-8'))


def _runbook_chunks(lab_dir=ROOT / 'docs/lab'):
    for f in sorted(Path(lab_dir).glob('UC-*.md')):
        text = f.read_text(encoding='utf-8')
        for i, part in enumerate(re.split(r'\n(?=## )', text)):
            if part.strip():
                yield {'id': f'{f.stem}#{i}', 'kind': 'runbook', 'title': f.stem,
                       'text': part.strip()[:1500]}


class KnowledgeBase:
    k1, b = 1.5, 0.75

    def __init__(self):
        self.rules = load_project_rules()
        self.builtin = load_json('builtin_rules.json')
        self.mitre = load_json('mitre_techniques.json')
        self.docs = []
        for r in self.rules.values():
            self.docs.append({'id': f"rule:{r['id']}", 'kind': 'rule', 'title': f"Rule {r['id']}",
                              'text': f"rule {r['id']} level {r['level']} {r['description']} "
                                      f"mitre {' '.join(r['mitre'])} groups {' '.join(r['groups'])}"})
        for rid, r in self.builtin.items():
            self.docs.append({'id': f'rule:{rid}', 'kind': 'rule', 'title': f'Built-in rule {rid}',
                              'text': f"rule {rid} {r['meaning']} use case {r.get('uc', '')}"})
        for tid, t in self.mitre.items():
            self.docs.append({'id': f'mitre:{tid}', 'kind': 'mitre', 'title': f"{tid} {t['name']}",
                              'text': f"{tid} {t['name']} tactic {t['tactic']} {t['summary']} "
                                      f"mitigation {t['mitigation']}"})
        self.docs.extend(_runbook_chunks())
        self._index()

    def _index(self):
        self.tf = [Counter(tokenize(d['title'] + ' ' + d['text'])) for d in self.docs]
        self.len = [sum(c.values()) for c in self.tf]
        self.avg = sum(self.len) / max(len(self.len), 1)
        df = Counter()
        for c in self.tf:
            df.update(c.keys())
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - v + 0.5) / (v + 0.5)) for t, v in df.items()}

    def search(self, query, k=5, kinds=None):
        q = tokenize(query)
        scores = []
        for i, c in enumerate(self.tf):
            if kinds and self.docs[i]['kind'] not in kinds:
                continue
            s = 0.0
            for t in q:
                if t in c:
                    f = c[t]
                    s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.len[i] / self.avg))
            if s > 0:
                scores.append((s, i))
        scores.sort(reverse=True)
        return [dict(self.docs[i], score=round(s, 3)) for s, i in scores[:k]]

    def rule_info(self, rid):
        rid = str(rid)
        if rid in self.rules:
            return self.rules[rid]
        if rid in self.builtin:
            return dict(self.builtin[rid], id=rid)
        return None

    def technique(self, tid):
        return self.mitre.get(tid)
