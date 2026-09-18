#!/usr/bin/env python3
"""M1 read-only Indexer visibility observer. Linux single-thread CLI; no AR.

A known selected t2 identity is required. First-poll positives are left-censored,
not t3 measurements. Prior negative + exact positive give an observation bracket,
not server insertion time. See tests/README.md before approved native use.
"""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('_visibility_storage', ROOT/'ai_agent/runner.py')
r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r)
MAX_RESPONSE = 65536
POLL_NS = 1_000_000_000
JITTER_NS = 100_000_000
REQUEST_SECONDS = .75
FAILURE_CODES = frozenset({'SCHEDULING_GAP', 'POLL_GAP', 'CLOCK_JUMP', 'REQUEST_OVERRUN',
    'INCOMPLETE_SEARCH', 'SHARDS_REQUIRED', 'SHARD_COUNTS', 'INCOMPLETE_SHARDS',
    'HITS_REQUIRED', 'AMBIGUOUS_TOTAL', 'HIT_COUNT_MISMATCH', 'WRONG_INDEX',
    'WRONG_IDENTITY', 'HTTP_STATUS', 'RESPONSE_LIMIT', 'ARTIFACT_TOO_LARGE'})
SPEC_KEYS = {'schema_version', 'run_id', 'trial_id', 'device', 'manager_name',
             'agent_id', 'alert_id', 'index', 'seconds', 'precision_ms', 'clock_ref'}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def private_json(path):
    path = Path(path).absolute()
    fd = r.directory(path.parent)
    try:
        return r.a.strict_json(r.read_at(fd, path.name, MAX_RESPONSE))
    finally:
        os.close(fd)


def check_spec(s):
    require(isinstance(s, dict) and set(s) == SPEC_KEYS, 'SPEC_KEYS')
    require(type(s['schema_version']) is int and s['schema_version'] == 1, 'SPEC_VERSION')
    for key in ('run_id', 'trial_id', 'device', 'manager_name', 'agent_id', 'alert_id', 'clock_ref'):
        value = s[key]
        require(isinstance(value, str) and 1 <= len(value) <= 256 and
                all(ord(c) >= 32 for c in value), 'SPEC_TEXT')
    require(isinstance(s['index'], str) and
            re.fullmatch(r'wazuh-alerts-4\.x-\d{4}\.\d{2}\.\d{2}', s['index']), 'EXPLICIT_DAILY_INDEX')
    require(type(s['seconds']) is int and 2 <= s['seconds'] <= 120, 'OBSERVATION_LIMIT')
    require(type(s['precision_ms']) is int and 1 <= s['precision_ms'] <= 100, 'CLOCK_PRECISION')
    return s


def check_config(c):
    require(isinstance(c, dict) and set(c) == {'schema_version', 'endpoint', 'username', 'password', 'ca_pem'}, 'CONFIG_KEYS')
    require(type(c['schema_version']) is int and c['schema_version'] == 1, 'CONFIG_VERSION')
    url = urllib.parse.urlsplit(c['endpoint'])
    require(url.scheme == 'https' and url.path in ('', '/') and not url.query and
            not url.fragment and url.username is None and url.password is None, 'HTTPS_ORIGIN_ONLY')
    ip = ipaddress.ip_address(url.hostname)
    require(ip.version == 4 and (ip.is_loopback or any(ip in ipaddress.ip_network(net)
            for net in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))), 'LAB_LITERAL_IP_REQUIRED')
    require(url.port is None or 1 <= url.port <= 65535, 'PORT')
    for key in ('username', 'password'):
        require(isinstance(c[key], str) and 1 <= len(c[key]) <= 1024 and
                all(ord(v) >= 32 for v in c[key]), 'CREDENTIAL_FIELD')
    require(':' not in c['username'], 'USERNAME_COLON')
    require(c['ca_pem'] is None or (isinstance(c['ca_pem'], str) and
            len(c['ca_pem']) <= 32768 and 'BEGIN CERTIFICATE' in c['ca_pem']), 'CA_PEM')
    return c


def query(s):
    return {'size': 2, 'track_total_hits': True, '_source': ['id', 'manager.name', 'agent.id'],
            'query': {'bool': {'filter': [
                {'term': {'manager.name': s['manager_name']}},
                {'term': {'agent.id': s['agent_id']}}, {'term': {'id': s['alert_id']}}]}}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class RequestDeadline(BaseException):
    pass


def alarm_contract():
    require(threading.current_thread() is threading.main_thread() and
            signal.getsignal(signal.SIGALRM) == signal.SIG_DFL and
            signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0) and
            signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, set()), 'EXCLUSIVE_ALARM_REQUIRED')


def deadline_call(function):
    """Total POSIX timer, not a socket idle timeout; not hard real time in D-state."""
    alarm_contract()
    active = True
    def expired(*_):
        if active:
            raise RequestDeadline()
    signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, REQUEST_SECONDS)
        return function()
    finally:
        active = False
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if signal.SIGALRM in signal.sigpending():
                signal.sigwait({signal.SIGALRM})
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def fetch(c, s):
    def request():
        context = ssl.create_default_context(cadata=c['ca_pem'])
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                             urllib.request.HTTPSHandler(context=context))
        authorization = base64.b64encode((c['username'] + ':' + c['password']).encode()).decode('ascii')
        req = urllib.request.Request(c['endpoint'].rstrip('/') + '/' + s['index'] + '/_search',
            data=r.json_bytes(query(s)), method='POST',
            headers={'Content-Type': 'application/json', 'Authorization': 'Basic ' + authorization})
        with opener.open(req, timeout=.5) as response:
            require(response.status == 200, 'HTTP_STATUS')
            raw = response.read(MAX_RESPONSE + 1)
        require(len(raw) <= MAX_RESPONSE, 'RESPONSE_LIMIT')
        return raw
    return deadline_call(request)


def match(raw, s):
    value = r.a.strict_json(raw)
    require(isinstance(value, dict) and value.get('timed_out') is False and
            value.get('terminated_early', False) is False and '_clusters' not in value, 'INCOMPLETE_SEARCH')
    shards = value.get('_shards')
    require(isinstance(shards, dict), 'SHARDS_REQUIRED')
    for key in ('total', 'successful', 'failed'):
        require(type(shards.get(key)) is int, 'SHARD_COUNTS')
    require(shards['total'] > 0 and shards['successful'] == shards['total'] and shards['failed'] == 0,
            'INCOMPLETE_SHARDS')
    hits = value.get('hits')
    require(isinstance(hits, dict), 'HITS_REQUIRED')
    total = hits.get('total')
    require(isinstance(total, dict) and total.get('relation') == 'eq' and
            type(total.get('value')) is int and total['value'] in (0, 1), 'AMBIGUOUS_TOTAL')
    rows = hits.get('hits')
    require(isinstance(rows, list) and len(rows) == total['value'], 'HIT_COUNT_MISMATCH')
    if not rows:
        return False
    hit = rows[0]
    require(isinstance(hit, dict) and hit.get('_index') == s['index'], 'WRONG_INDEX')
    source = hit.get('_source')
    require(isinstance(source, dict) and source.get('id') == s['alert_id'] and
            isinstance(source.get('manager'), dict) and source['manager'].get('name') == s['manager_name'] and
            isinstance(source.get('agent'), dict) and source['agent'].get('id') == s['agent_id'], 'WRONG_IDENTITY')
    return True


def source_hashes():
    paths = [Path(__file__), *(ROOT/'ai_agent'/n for n in r.SOURCE_NAMES)]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def classify(s, polls):
    """Recomputable observation state; reject clock jumps/gaps instead of hiding them."""
    last = None
    for i, poll in enumerate(polls):
        require(set(poll) == {'start_ms', 'end_ms', 'start_ns', 'end_ns', 'response_sha256', 'found'}, 'POLL_KEYS')
        for key in ('start_ms', 'end_ms', 'start_ns', 'end_ns'):
            require(type(poll[key]) is int and poll[key] >= 0, 'POLL_TIME')
        require(type(poll['found']) is bool, 'POLL_FOUND')
        r.e.sha256(poll['response_sha256'])
        elapsed = poll['end_ns'] - poll['start_ns']
        require(0 <= elapsed <= int(REQUEST_SECONDS * 1e9), 'REQUEST_OVERRUN')
        require(poll['end_ms'] >= poll['start_ms'] and
                abs((poll['end_ms'] - poll['start_ms']) * 1e6 - elapsed) <= JITTER_NS, 'CLOCK_JUMP')
        if last:
            gap = poll['start_ns'] - last['start_ns']
            require(abs(gap - POLL_NS) <= JITTER_NS and poll['start_ns'] >= last['end_ns'], 'POLL_GAP')
            require(abs((poll['start_ms'] - last['start_ms']) * 1e6 - gap) <= JITTER_NS, 'CLOCK_JUMP')
        if poll['found']:
            require(i == len(polls) - 1, 'POLLS_AFTER_POSITIVE')
            if last is None:
                return 'preexisting', None
            row = {'run_id': s['run_id'], 'trial_id': s['trial_id'], 'device': s['device'],
                   'stage': 't3', 'kind': 'indexer_first_visible', 'timestamp_ms': poll['end_ms'],
                   'manager_name': s['manager_name'], 'alert_id': s['alert_id'], 'poll_interval_ms': 1000,
                   'precision_ms': max(s['precision_ms'], poll['end_ms'] - last['start_ms'] + s['precision_ms']),
                   'evidence_ref': 'sha256:' + poll['response_sha256'],
                   'last_negative_request_start_ms': last['start_ms'],
                   'first_positive_response_end_ms': poll['end_ms'], 'clock_ref': s['clock_ref']}
            return 'observed', row
        last = poll
    return 'not_observed', None


def observe(s, c, store):
    check_spec(s); check_config(c); alarm_contract()
    with r.store_lock(store) as fd:
        require(not os.listdir(fd), 'NEW_EMPTY_STORE_REQUIRED')
        intent = {'schema_version': 1, 'spec': s, 'query': query(s), 'source_sha256': source_hashes(),
                  'endpoint': c['endpoint'], 'acceptance_approved': False,
                  'principal_sha256': r.digest(c['username'].encode('utf-8')),
                  'ca_sha256': r.digest(c['ca_pem'].encode('utf-8')) if c['ca_pem'] else None,
                  'trust_mode': 'explicit_ca' if c['ca_pem'] else 'system_default'}
        intent_raw = r.json_bytes(intent)
        r.write_once(fd, 'intent.json', intent_raw)
        polls = []
        terminal = {'status': 'failed', 'reason': 'INTERRUPTED', 'observer': None,
                    'intent_sha256': r.digest(intent_raw), 'poll_count': 0}
        start = time.monotonic_ns()
        try:
            for i in range(s['seconds'] + 1):
                due = start + i * POLL_NS
                time.sleep(max(0, (due - time.monotonic_ns()) / 1e9))
                ns = time.monotonic_ns()
                require(0 <= ns - due <= JITTER_NS, 'SCHEDULING_GAP')
                before = time.time_ns() // 1_000_000
                raw = fetch(c, s)
                after = time.time_ns() // 1_000_000
                end = time.monotonic_ns()
                r.write_once(fd, f'poll-{i:03d}.json', raw)
                poll = {'start_ms': before, 'end_ms': after, 'start_ns': ns, 'end_ns': end,
                        'response_sha256': r.digest(raw), 'found': match(raw, s)}
                r.write_once(fd, f'poll-{i:03d}.meta.json', r.json_bytes(poll))
                polls.append(poll)
                status, row = classify(s, polls)
                terminal.update(status=status, reason=None, observer=row, poll_count=len(polls))
                if row is not None or status == 'preexisting':
                    break
        except (Exception, RequestDeadline) as exc:
            code = 'REQUEST_DEADLINE' if isinstance(exc, RequestDeadline) else 'OBSERVATION_FAILED'
            if isinstance(exc, ValueError) and len(exc.args) == 1 and isinstance(exc.args[0], str):
                if exc.args[0] in FAILURE_CODES:
                    code = exc.args[0]
            terminal.update(status='failed', reason=code, observer=None, poll_count=len(polls))
        except KeyboardInterrupt:
            terminal.update(status='failed', reason='INTERRUPTED', observer=None, poll_count=len(polls))
            raise
        finally:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                r.write_once(fd, 'terminal.json', r.json_bytes(terminal))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        return {'status': terminal['status'], 'intent_sha256': terminal['intent_sha256'],
                'acceptance_approved': False}


def export(store, expected, *, summary=False):
    r.e.sha256(expected)
    with r.store_lock(store) as fd:
        raw = r.read_at(fd, 'intent.json')
        require(r.digest(raw) == expected, 'INTENT_HASH_MISMATCH')
        intent = r.a.strict_json(raw)
        require(isinstance(intent, dict) and set(intent) == {'schema_version', 'spec', 'query',
                'source_sha256', 'endpoint', 'acceptance_approved', 'principal_sha256', 'ca_sha256',
                'trust_mode'} and type(intent['schema_version']) is int and intent['schema_version'] == 1
                and intent['acceptance_approved'] is False, 'INTENT_SCHEMA')
        r.e.sha256(intent['principal_sha256'])
        if intent['ca_sha256'] is not None:
            r.e.sha256(intent['ca_sha256'])
        require(intent['trust_mode'] == ('explicit_ca' if intent['ca_sha256'] else 'system_default'), 'TRUST_MODE')
        s = check_spec(intent['spec'])
        require(intent['source_sha256'] == source_hashes() and intent['query'] == query(s), 'SOURCE_OR_QUERY_CHANGED')
        terminal = r.a.strict_json(r.read_at(fd, 'terminal.json'))
        require(set(terminal) == {'status', 'reason', 'observer', 'intent_sha256', 'poll_count'} and
                terminal['intent_sha256'] == expected and terminal['reason'] is None, 'INCOMPLETE_OBSERVATION')
        n = terminal['poll_count']
        require(type(n) is int and 1 <= n <= s['seconds'] + 1, 'POLL_COUNT')
        allowed = {'intent.json', 'terminal.json'}
        polls = []
        for i in range(n):
            name = f'poll-{i:03d}'
            allowed.update({name + '.json', name + '.meta.json'})
            raw = r.read_at(fd, name + '.json', MAX_RESPONSE)
            poll = r.a.strict_json(r.read_at(fd, name + '.meta.json'))
            require(poll['response_sha256'] == r.digest(raw) and poll['found'] is match(raw, s), 'POLL_TAMPERED')
            polls.append(poll)
        require(set(os.listdir(fd)) == allowed, 'UNEXPECTED_STORE_ENTRY')
        status, row = classify(s, polls)
        require(terminal['status'] == status and terminal['observer'] == row, 'TERMINAL_MISMATCH')
        require(status != 'not_observed' or n == s['seconds'] + 1, 'TRUNCATED_OBSERVATION')
        if summary:
            return {'status': status, 'observer': row, 'intent_sha256': expected,
                    'principal_sha256': intent['principal_sha256'], 'ca_sha256': intent['ca_sha256'],
                    'trust_mode': intent['trust_mode'], 'acceptance_approved': False}
        return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    preview = commands.add_parser('preview'); preview.add_argument('--spec', required=True)
    run = commands.add_parser('observe')
    run.add_argument('--spec', required=True); run.add_argument('--config', required=True)
    run.add_argument('--store', required=True); run.add_argument('--lab', action='store_true', required=True)
    out = commands.add_parser('export'); out.add_argument('--store', required=True)
    out.add_argument('--intent-sha256', required=True)
    out.add_argument('--summary', action='store_true', help='JSON status envelope, not observer JSONL')
    args = parser.parse_args(argv)
    try:
        if args.action == 'preview':
            result = {'query': query(check_spec(private_json(args.spec))), 'network_used': False}
        elif args.action == 'observe':
            result = observe(private_json(args.spec), private_json(args.config), args.store)
        else:
            result = export(args.store, args.intent_sha256, summary=args.summary)
            if result is None:
                return 0  # no t3; inspect retained terminal for not_observed/preexisting
        print(r.json_bytes(result).decode('ascii'), end='')
        return 2 if args.action == 'observe' and result['status'] != 'observed' else 0
    except (Exception, RequestDeadline):
        print('{"status":"rejected","acceptance_approved":false}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
