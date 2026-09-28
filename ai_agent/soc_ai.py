#!/usr/bin/env python3
"""SOC AI analyst CLI (T-70).

  soc_ai.py explain   [--alerts FILE] [--rule ID | --last N] [--min-level L]
  soc_ai.py correlate [--alerts FILE] [--since MIN] [--min-level L] [--narrate]
  soc_ai.py suggest   [--alerts FILE] [--since MIN] INCIDENT_ID
  soc_ai.py respond   [--alerts FILE] [--since MIN] INCIDENT_ID ACTION --agent 000 --approver NAME [--approve HASH] [--dry-run]
  soc_ai.py report    [--alerts FILE] [--since MIN] [--out FILE.md]     (daily incident report)

Environment: OPENAI_BASE_URL, OPENAI_API_KEY, SOC_AI_MODEL (default gpt-5-mini; any
OpenAI-compatible server, e.g. Ollama http://127.0.0.1:11434/v1 + SOC_AI_MODEL=llama3.1),
SOC_AI_OFFLINE=1 forces deterministic mode, SOC_AI_LANG (Arabic|English),
WAZUH_API_* for `respond`. Default alerts file: /var/ossec/logs/alerts/alerts.json.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyst import Analyst, g, parse_ts  # noqa: E402
import responder  # noqa: E402

DEFAULT_ALERTS = '/var/ossec/logs/alerts/alerts.json'


def load_alerts(path, since_min=None, min_level=0):
    out, cutoff = [], (time.time() - since_min * 60) if since_min else None
    with open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            try:
                a = json.loads(line)
            except ValueError:
                continue
            if int(g(a, 'rule.level', 0) or 0) < min_level:
                continue
            if cutoff and parse_ts(g(a, 'timestamp', '')) < cutoff:
                continue
            out.append(a)
    return out


def pr(obj):
    if isinstance(obj, dict):
        obj = {k: v for k, v in obj.items() if not k.startswith('_')}
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def find_incident(analyst, alerts, inc_id, min_level):
    incs = analyst.correlate(alerts, min_level=min_level)
    for inc in incs:
        if inc['incident'] == inc_id:
            return inc, inc['_alerts']
    raise SystemExit(f'{inc_id} not found; run "correlate" first ({len(incs)} incidents)')


def report(analyst, alerts, min_level):
    incs = sorted(analyst.correlate(alerts, min_level=min_level), key=lambda i: -i['risk_score'])
    lines = ['# SOC incident report', '', f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} — "
             f"{len(alerts)} alerts ≥ L{min_level}, {len(incs)} incidents, mode: "
             f"{'LLM ' + analyst.llm.model if analyst.llm.enabled else 'deterministic'}", '',
             '| Incident | Risk | Agent | Alerts | Kill chain | Rules | Auto-response |',
             '|---|---:|---|---:|---|---|---|']
    for i in incs:
        lines.append(f"| {i['incident']} | {i['risk_score']} | {i['agent']} | {i['alert_count']} | "
                     f"{' → '.join(i['kill_chain']) or '-'} | {', '.join(i['rules'][:8])} | "
                     f"{'yes' if i['auto_response_seen'] else 'no'} |")
    lines.append('')
    for i in incs[:10]:
        n = analyst.narrate(i) if analyst.llm.enabled else {'narrative': i['narrative'], 'mode': 'deterministic'}
        s = analyst.suggest(i)
        lines += [f"## {i['incident']} (risk {i['risk_score']})", '', n.get('narrative', ''), '',
                  f"*Hypothesis:* {n.get('hypothesis', 'n/a')}", '', '**Proposed actions (need approval):**']
        for p in s['proposals']:
            lines.append(f"- `{p['action']}` {json.dumps(p['params'], ensure_ascii=False)} — {p['reason']} "
                         f"(hash `{responder.proposal_hash(p)}`)")
        lines.append('')
    return '\n'.join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cmd', choices=['explain', 'correlate', 'suggest', 'respond', 'report'])
    ap.add_argument('args', nargs='*')
    ap.add_argument('--alerts', default=os.environ.get('SOC_ALERTS', DEFAULT_ALERTS))
    ap.add_argument('--since', type=float, help='minutes')
    ap.add_argument('--min-level', type=int, default=5)
    ap.add_argument('--rule')
    ap.add_argument('--last', type=int, default=1)
    ap.add_argument('--narrate', action='store_true')
    ap.add_argument('--agent')
    ap.add_argument('--approver')
    ap.add_argument('--approve')
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--out')
    a = ap.parse_args(argv)
    analyst = Analyst(lang=os.environ.get('SOC_AI_LANG', 'Arabic'))
    alerts = load_alerts(a.alerts, a.since, 0)

    if a.cmd == 'explain':
        pool = [x for x in alerts if int(g(x, 'rule.level', 0) or 0) >= a.min_level]
        if a.rule:
            pool = [x for x in pool if str(g(x, 'rule.id')) == a.rule]
        for alert in pool[-a.last:]:
            pr(analyst.explain(alert))
    elif a.cmd == 'correlate':
        for inc in analyst.correlate(alerts, min_level=a.min_level):
            if a.narrate:
                inc['llm'] = analyst.narrate(inc)
            pr(inc)
    elif a.cmd == 'suggest':
        inc, members = find_incident(analyst, alerts, a.args[0], a.min_level)
        res = analyst.suggest(inc, members)
        for p in res['proposals']:
            p['approval_hash'] = responder.proposal_hash(p)
        pr(res)
    elif a.cmd == 'respond':
        if len(a.args) != 2 or not a.agent or not a.approver:
            ap.error('respond INCIDENT ACTION --agent ID --approver NAME [--approve HASH]')
        inc, members = find_incident(analyst, alerts, a.args[0], a.min_level)
        props = [p for p in analyst.suggest(inc, members)['proposals'] if p['action'] == a.args[1]]
        if not props:
            raise SystemExit(f'action {a.args[1]} was not proposed for {a.args[0]}')
        p = props[0]
        h = responder.proposal_hash(p)
        print(json.dumps(p, ensure_ascii=False, indent=2))
        approved = a.approve
        if not approved:
            if not sys.stdin.isatty():
                raise SystemExit(f'non-interactive: re-run with --approve {h}')
            if input(f'Type the hash {h} to approve: ').strip() != h:
                raise SystemExit('not approved')
            approved = h
        pr(responder.execute(p, a.agent, a.approver, approved, dry_run=a.dry_run))
    elif a.cmd == 'report':
        text = report(analyst, alerts, a.min_level)
        if a.out:
            Path(a.out).write_text(text, encoding='utf-8')
            print(f'written {a.out}')
        else:
            print(text)
    if analyst.stats:
        print(json.dumps({'stats': dict(analyst.stats)}), file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
