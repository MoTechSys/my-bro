"""SOC AI analyst (T-70 / ADR-014) - owner [CLAUDE], 2026-09-28.

Levels
  L1 explain    one alert -> plain-language explanation, MITRE, severity rationale, evidence.
  L2 correlate  a stream of alerts -> incidents (attack chains) grouped by entity + time,
                ordered by ATT&CK tactic, with a narrative.
  L3 suggest    incident -> proposed response actions from a FIXED allowlist. Nothing runs
                until a human approves (responder.py). The model can never add actions.

Design choices that matter for the thesis / defence
  * Model-agnostic: any OpenAI-compatible endpoint (cloud gateway, Ollama `/v1`, vLLM) via
    OPENAI_BASE_URL / OPENAI_API_KEY / SOC_AI_MODEL. With no endpoint the analyst still works
    in deterministic mode (rules + MITRE KB), so the demo never depends on the internet.
  * Grounded (RAG): the prompt contains only retrieved facts (our rules, Wazuh built-in rule
    meanings, MITRE v19 extracts, runbooks). The model must cite the evidence IDs it used;
    uncited or unknown rule/technique IDs are detected and rejected (hallucination guard).
  * Privacy: alerts are redacted (secrets, tokens, hashes shortened) before leaving the host.
  * Bounded: timeout, max tokens, strict JSON schema validation, deterministic fallback.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import defaultdict

try:
    from .knowledge import KnowledgeBase
except ImportError:  # executed as a script
    from knowledge import KnowledgeBase

TACTIC_ORDER = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence',
                'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery',
                'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact']

# L3 allowlist: the ONLY actions that can ever be proposed/executed. Each maps to an
# existing, reviewed Wazuh active response (no shell, no free-form commands).
ACTIONS = {
    'block_ip':        {'command': 'firewall-drop', 'needs': 'srcip', 'timeout': 600,
                        'desc': 'Temporarily block the source IP on the agent firewall (auto-unblock).'},
    'quarantine_file': {'command': 'remove-threat', 'needs': 'file',
                        'desc': 'Delete the file only if hash + allowlisted path still match (soc_ar.py guards).'},
    'disable_account': {'command': 'disable-account', 'needs': 'user', 'timeout': 900,
                        'desc': 'Temporarily lock the local account used in the attack.'},
    'notify':          {'command': None, 'needs': None,
                        'desc': 'Escalate to the on-call analyst (Telegram UC-10); no system change.'},
    'monitor':         {'command': None, 'needs': None,
                        'desc': 'No action; keep watching (used for low-confidence or benign events).'},
}

REDACT = [
    (re.compile(r'(?i)\b(pass(word)?|pwd|secret|token|api[_-]?key)\b(\s*[=:]\s*)\S+'), r'\1\3[REDACTED]'),
    (re.compile(r'(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}'), 'Bearer [REDACTED]'),
    (re.compile(r'\b\d{5,15}:[A-Za-z0-9_-]{30,64}\b'), '[REDACTED_TOKEN]'),
]
ID_RE = re.compile(r'\b(T\d{4}(?:\.\d{3})?)\b')


def redact(value):
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        for pattern, repl in REDACT:
            value = pattern.sub(repl, value)
        return value[:2000]
    return value


def g(d, path, default=None):
    for k in path.split('.'):
        if not isinstance(d, dict) or k not in d:
            return default
        d = d[k]
    return d


# Rule groups that are posture/inventory noise for incident correlation (still explainable in L1).
NOISE_GROUPS = {'sca', 'rootcheck', 'dpkg', 'ossec', 'pam', 'sudo', 'syslog_audit'}
NOISE_RULES = {'510', '533', '502', '5402', '5501', '5502', '19004', '19007', '19008', '19009'}
AR_RESULT_RULES = {'651', '652', '100092', '100093'}   # always kept: they prove the response
LINK_KEYS = ('srcip', 'file', 'mac')      # user names are per-attempt in brute force: not a link key


def entities(alert):
    """Observable entities used for correlation and for L3 action parameters.

    Active-response result alerts (651/652/657/100092/100093) carry the ORIGINAL alert under
    data.parameters.alert; their entities are taken from there so the response joins its incident.
    """
    e = {}
    inner = g(alert, 'data.parameters.alert') if isinstance(g(alert, 'data.parameters.alert'), dict) else {}
    sources = [alert, inner] if inner else [alert]
    for key, paths in {
        'srcip': ('data.srcip', 'data.src_ip'),
        'file': ('syscheck.path', 'data.virustotal.source.file', 'data.yara_scanned_file'),
        'user': ('data.dstuser', 'data.srcuser'),
        'url': ('data.url',),
        'mac': ('data.dhcp.mac',),
        'exe': ('data.audit.exe',),
    }.items():
        for src in sources:
            v = next((g(src, p) for p in paths if g(src, p) not in (None, '', '-')), None)
            if v is not None:
                e[key] = str(v)
                break
    e['agent'] = str(g(alert, 'agent.name', 'unknown'))
    return e


def is_noise(alert):
    rid = str(g(alert, 'rule.id'))
    groups = set(g(alert, 'rule.groups', []) or [])
    return rid in NOISE_RULES or (groups & {'sca', 'rootcheck', 'dpkg'} and rid not in ('100092', '100093'))


def parse_ts(ts):
    try:
        return time.mktime(time.strptime(ts[:19], '%Y-%m-%dT%H:%M:%S'))
    except (TypeError, ValueError):
        return 0.0


class LLM:
    """Minimal OpenAI-compatible chat client (stdlib)."""

    def __init__(self, base_url=None, api_key=None, model=None, timeout=90, opener=None):
        self.base_url = (base_url or os.environ.get('OPENAI_BASE_URL', '')).rstrip('/')
        self.api_key = api_key or os.environ.get('OPENAI_API_KEY', '')
        self.model = model or os.environ.get('SOC_AI_MODEL', 'gpt-5-mini')
        self.timeout = timeout
        self.opener = opener or urllib.request.urlopen

    @property
    def enabled(self):
        return bool(self.base_url) and os.environ.get('SOC_AI_OFFLINE') != '1'

    def chat(self, system, user):
        body = json.dumps({'model': self.model, 'messages': [
            {'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
            'response_format': {'type': 'json_object'}}).encode()
        headers = {'Content-Type': 'application/json'}
        if self.api_key:
            headers['Authorization'] = 'Bearer ' + self.api_key
        req = urllib.request.Request(self.base_url + '/chat/completions', data=body, headers=headers)
        with self.opener(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode('utf-8'))
        text = data['choices'][0]['message']['content']
        m = re.search(r'\{.*\}', text, re.S)
        return json.loads(m.group(0) if m else text)


SYSTEM = ('You are a senior SOC analyst for a Wazuh-based SOC graduation project. Use ONLY the '
          'evidence provided in CONTEXT. Cite evidence ids (e.g. "rule:5712", "mitre:T1110") in '
          '"citations". Never invent rule ids, MITRE ids, hosts or IPs. If evidence is insufficient '
          'say so and lower confidence. Answer strictly as a JSON object. Write text fields in {lang}.')


class Analyst:
    def __init__(self, kb=None, llm=None, lang='Arabic'):
        self.kb = kb or KnowledgeBase()
        self.llm = llm if llm is not None else LLM()
        self.lang = lang
        self.stats = defaultdict(int)

    # ------------------------------------------------------------------ helpers
    def _mitre(self, alert):
        ids = list(g(alert, 'rule.mitre.id', []) or [])
        info = self.kb.rule_info(g(alert, 'rule.id'))
        if info:
            ids += [m for m in info.get('mitre', []) if m not in ids]
        return ids

    def _context(self, query, alert_ids=(), mitre=()):
        docs, seen = [], set()
        for rid in alert_ids:
            info = self.kb.rule_info(rid)
            if info and f'rule:{rid}' not in seen:
                seen.add(f'rule:{rid}')
                docs.append({'id': f'rule:{rid}', 'text': json.dumps(info, ensure_ascii=False)})
        for t in mitre:
            info = self.kb.technique(t)
            if info and f'mitre:{t}' not in seen:
                seen.add(f'mitre:{t}')
                docs.append({'id': f'mitre:{t}', 'text': json.dumps(info, ensure_ascii=False)})
        for d in self.kb.search(query, k=4):
            if d['id'] not in seen:
                seen.add(d['id'])
                docs.append({'id': d['id'], 'text': d['text'][:900]})
        return docs

    def _grounded(self, result, context, allowed_mitre):
        """Hallucination guard: every cited id must be in context; every MITRE id mentioned must be known."""
        ctx_ids = {d['id'] for d in context}
        cites = [c for c in result.get('citations', []) if isinstance(c, str)]
        bad_cites = [c for c in cites if c not in ctx_ids]
        text = json.dumps({k: v for k, v in result.items() if k != 'citations'}, ensure_ascii=False)
        mentioned = set(ID_RE.findall(text))
        bad_mitre = sorted(t for t in mentioned if t not in allowed_mitre and not self.kb.technique(t))
        return (not bad_cites and not bad_mitre and bool(cites)), bad_cites, bad_mitre

    def _ask(self, kind, payload, context, allowed_mitre, schema_keys, fallback):
        self.stats[f'{kind}_requests'] += 1
        if not self.llm.enabled:
            self.stats[f'{kind}_offline'] += 1
            return dict(fallback, mode='deterministic')
        user = json.dumps({'task': kind, 'CONTEXT': context, 'INPUT': redact(payload),
                           'required_keys': schema_keys}, ensure_ascii=False)
        try:
            t0 = time.time()
            out = self.llm.chat(SYSTEM.format(lang=self.lang), user)
            latency = round(time.time() - t0, 2)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, KeyError) as e:
            self.stats[f'{kind}_llm_error'] += 1
            return dict(fallback, mode='deterministic', llm_error=type(e).__name__)
        missing = [k for k in schema_keys if k not in out]
        ok, bad_cites, bad_mitre = self._grounded(out, context, allowed_mitre)
        if missing or not ok:
            self.stats[f'{kind}_rejected'] += 1
            return dict(fallback, mode='deterministic', llm_rejected={
                'missing': missing, 'bad_citations': bad_cites, 'unknown_mitre': bad_mitre})
        out.update(mode='llm', model=self.llm.model, latency_s=latency)
        return out

    # ------------------------------------------------------------------ L1
    def explain(self, alert):
        rid = str(g(alert, 'rule.id'))
        level = int(g(alert, 'rule.level', 0) or 0)
        mitre = self._mitre(alert)
        ent = entities(alert)
        info = self.kb.rule_info(rid) or {}
        techniques = [f"{t} {self.kb.technique(t)['name']}" for t in mitre if self.kb.technique(t)]
        sev = 'critical' if level >= 12 else 'high' if level >= 10 else 'medium' if level >= 7 else 'low'
        fallback = {
            'summary': f"{g(alert, 'rule.description', '')} (rule {rid}, level {level}) on {ent['agent']}.",
            'severity': sev,
            'why': f"Wazuh rule {rid} ({info.get('source', 'built-in')}) matched; level {level} → {sev}.",
            'mitre': techniques,
            'evidence': ent,
            'next_steps': self._default_steps(rid, ent),
            'citations': [f'rule:{rid}'] + [f'mitre:{t}' for t in mitre if self.kb.technique(t)],
        }
        context = self._context(f"{g(alert, 'rule.description', '')} {' '.join(mitre)}", [rid], mitre)
        return self._ask('explain', {'alert': alert}, context, set(mitre),
                         ['summary', 'severity', 'why', 'mitre', 'next_steps', 'citations'], fallback)

    def _default_steps(self, rid, ent):
        steps = []
        if 'srcip' in ent:
            steps.append(f"Check other activity from {ent['srcip']} in the last hour.")
        if 'file' in ent:
            steps.append(f"Confirm hash/VirusTotal verdict for {ent['file']} and whether AR removed it (100092/100093).")
        if 'user' in ent:
            steps.append(f"Verify whether account {ent['user']} activity is legitimate.")
        return steps or ['Review the full log and related alerts on the same agent.']

    # ------------------------------------------------------------------ L2
    def correlate(self, alerts, window_s=900, min_level=5):
        """Group alerts that share an entity (srcip/file/user/mac) on the same agent within window_s."""
        items = []
        for a in alerts:
            is_ar = str(g(a, 'rule.id')) in AR_RESULT_RULES
            if (int(g(a, 'rule.level', 0) or 0) < min_level and not is_ar) or is_noise(a):
                continue
            items.append((parse_ts(g(a, 'timestamp', '')), a))
        items.sort(key=lambda x: x[0])
        incidents = []
        for ts, a in items:
            ent = entities(a)
            keys = {f'{k}={v}' for k, v in ent.items() if k in LINK_KEYS}
            target = None
            for inc in incidents:
                if ts - inc['last'] <= window_s and (keys & inc['keys'] or
                                                     (not keys and inc['agent'] == ent['agent'])):
                    target = inc
                    break
            if target is None:
                target = {'keys': set(), 'alerts': [], 'first': ts, 'last': ts, 'agent': ent['agent']}
                incidents.append(target)
            target['alerts'].append(a)
            target['keys'] |= keys
            target['last'] = max(target['last'], ts)
        out = []
        for i, inc in enumerate(incidents, 1):
            out.append(self._describe_incident(i, inc))
        return out

    def _describe_incident(self, n, inc):
        alerts = inc['alerts']
        rules = []
        tactics, mitre = set(), []
        for a in alerts:
            rid = str(g(a, 'rule.id'))
            if rid not in rules:
                rules.append(rid)
            for t in self._mitre(a):
                if t not in mitre:
                    mitre.append(t)
                info = self.kb.technique(t)
                if info:
                    tactics |= {x.strip() for x in info['tactic'].split(',') if x.strip()}
        chain = [t for t in TACTIC_ORDER if t in tactics]
        max_level = max(int(g(a, 'rule.level', 0) or 0) for a in alerts)
        responded = any(str(g(a, 'rule.id')) in ('100092', '651') for a in alerts)
        failed = any(str(g(a, 'rule.id')) == '100093' for a in alerts)
        users = sorted({entities(a).get('user') for a in alerts if entities(a).get('user')})
        score = min(100, max_level * 5 + 10 * len(chain) + (5 if len(alerts) > 3 else 0) - (15 if responded else 0))
        # Stable id: same first alert + entities -> same id whatever the query window/order.
        import hashlib
        seed = f"{inc['agent']}|{sorted(inc['keys'])}|{g(alerts[0], 'id', '')}|{g(alerts[0], 'timestamp', '')}"
        base = {
            'incident': 'INC-' + hashlib.sha1(seed.encode()).hexdigest()[:8],
            'seq': n, 'agent': inc['agent'], 'entities': sorted(inc['keys']),
            'first_seen': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(inc['first'])),
            'last_seen': time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(inc['last'])),
            'alert_count': len(alerts), 'rules': rules, 'mitre': mitre, 'kill_chain': chain,
            'max_level': max_level, 'auto_response_seen': responded, 'auto_response_failed': failed, 'users': users[:10], 'risk_score': max(score, 0),
        }
        base['narrative'] = (f"{len(alerts)} alert(s) on {inc['agent']} sharing {', '.join(sorted(inc['keys'])) or 'agent'}: "
                             f"rules {', '.join(rules)}; tactics {' → '.join(chain) or 'n/a'}; "
                             f"{'automatic response already executed' if responded else 'no automatic response yet'}.")
        base['_alerts'] = alerts          # member alerts (dropped before printing)
        base['citations'] = [f'rule:{r}' for r in rules if self.kb.rule_info(r)] + \
                            [f'mitre:{t}' for t in mitre if self.kb.technique(t)]
        return base

    def narrate(self, incident):
        """Optional LLM narrative for an L2 incident (grounded, falls back to template)."""
        context = self._context(' '.join(incident['rules'] + incident['mitre']), incident['rules'], incident['mitre'])
        fb = {'narrative': incident['narrative'], 'hypothesis': 'n/a', 'citations': incident['citations']}
        return self._ask('narrate', {'incident': {k: v for k, v in incident.items()
                                                  if k != 'citations' and not k.startswith('_')}},
                         context, set(incident['mitre']), ['narrative', 'hypothesis', 'citations'], fb)

    # ------------------------------------------------------------------ L3
    def suggest(self, incident, alerts=None):
        """Return proposals from ACTIONS only; each carries concrete, validated parameters.

        Parameters come ONLY from the incident's own correlation keys and member alerts
        (bug fixed 2026-09-28: taking entities from the whole alert file proposed blocking an
        unrelated older IP).
        """
        ent = {}
        for key in incident.get('entities', []):          # correlation keys win
            k, _, v = key.partition('=')
            ent.setdefault(k, v)
        members = incident.get('_alerts') if alerts is None else alerts
        for a in members or ():
            for k, v in entities(a).items():
                if k in ('srcip', 'file', 'mac') and k in ent and ent[k] != v:
                    continue
                ent.setdefault(k, v)
        succ = [entities(a).get('user') for a in (members or ())
                if str(g(a, 'rule.id')) in ('100404', '100403') and entities(a).get('user')]
        if succ:
            ent['user'] = succ[-1]                         # the account that actually logged in
        elif incident.get('users') and 'user' not in ent:
            ent['user'] = incident['users'][0]
        rules = set(incident.get('rules', []))
        props = []
        if rules & {'5712', '5763', '100402', '100404', '100411', '31103', '31106', '31168'} and 'srcip' in ent:
            if not incident.get('auto_response_seen'):
                props.append(self._proposal('block_ip', {'srcip': ent['srcip']}, 'Repeated attack from one source IP.'))
        if rules & {'87105', '108001'} and 'file' in ent and not incident.get('auto_response_seen'):
            props.append(self._proposal('quarantine_file', {'file': ent['file']}, 'Malware verdict on a monitored file.'))
        if '100404' in rules and 'user' in ent:
            props.append(self._proposal('disable_account', {'user': ent['user']},
                                        'Successful login right after brute force (possible compromise).'))
        if incident.get('max_level', 0) >= 10:
            props.append(self._proposal('notify', {}, 'High-severity incident needs analyst review.'))
        if not props:
            props.append(self._proposal('monitor', {}, 'Low risk or already handled by automatic response.'))
        result = {'incident': incident.get('incident'), 'proposals': props,
                  'requires_human_approval': any(p['action'] not in ('notify', 'monitor') for p in props),
                  'mode': 'deterministic'}
        if self.llm.enabled:
            context = self._context(' '.join(incident.get('rules', [])), incident.get('rules', []), incident.get('mitre', []))
            fb = {'ranking': [p['action'] for p in props], 'rationale': 'rule-based', 'citations': incident.get('citations', [])}
            public = {k: v for k, v in incident.items() if not k.startswith('_')}
            llm = self._ask('suggest', {'incident': public, 'candidate_actions': props,
                                        'instruction': 'Rank ONLY the candidate actions; you may drop some, never add.'},
                            context, set(incident.get('mitre', [])), ['ranking', 'rationale', 'citations'], fb)
            ranking = [a for a in llm.get('ranking', []) if a in {p['action'] for p in props}]
            if ranking:
                order = {a: i for i, a in enumerate(ranking)}
                result['proposals'] = sorted([p for p in props if p['action'] in order], key=lambda p: order[p['action']])
            result.update(mode=llm.get('mode'), rationale=llm.get('rationale'))
        return result

    @staticmethod
    def _proposal(action, params, reason):
        spec = ACTIONS[action]
        return {'action': action, 'wazuh_command': spec['command'], 'params': params,
                'timeout': spec.get('timeout'), 'reason': reason, 'description': spec['desc']}
