#!/usr/bin/env python3
"""UC-01 offline declared-evidence evaluator; never restarts or enrolls an agent.

Separate from attack detection/MTTD. Native collection and authenticity are not
implemented here. See tests/README: planned cycles, private exports, clock bounds.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

_spec = importlib.util.spec_from_file_location('_connection_metrics', Path(__file__).with_name('mttd.py'))
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)
require = m.require
MAX_BYTES = 8 * 1024 * 1024
MAX_ALERTS = 20000
WINDOW_MS = 300000
POLL_MS = 5000
JITTER_MS = 1000
REQUEST_MS = 2000
STATES = {'active', 'disconnected', 'pending', 'never_connected', 'error'}
EXCLUDED = {'BLOCKED', 'INVALID', 'INTERFERED', 'AMBIGUOUS'}
CLOCKS = {'controller', 'endpoint', 'manager', 'observer'}
# File-creation canaries from the existing UC-02 contract, not arbitrary alerts.
CANARY_RULES = {'linux': {'554': 5, '100201': 7, '100301': 7},
                'windows': {'554': 5, '100304': 7}}


def keys(value, expected, code):
    require(isinstance(value, dict) and set(value) == set(expected.split()), code)


def text(value, code):
    require(isinstance(value, str) and 1 <= len(value) <= 1024 and bool(value.strip()) and
            not any(ord(c) < 32 or ord(c) == 127 for c in value), code)


def integer(value, low, high, code):
    require(type(value) is int and low <= value <= high, code)


def timestamp(value):
    integer(value, 0, 253402300799999, 'TIMESTAMP')


def check_plan(p):
    keys(p, 'schema_version kind run_id protocol_ref identity clocks cycles window_s poll_interval_ms coverage', 'PLAN_KEYS')
    require(type(p['schema_version']) is int and p['schema_version'] == 1 and
            p['kind'] == 'uc01_connection_plan', 'PLAN_VERSION')
    text(p['run_id'], 'RUN_ID'); text(p['protocol_ref'], 'PROTOCOL_REF')
    keys(p['identity'], 'manager_name agent_id agent_name os config_sha256', 'IDENTITY_KEYS')
    for value in p['identity'].values():
        text(value, 'IDENTITY_TEXT')
    require(re.fullmatch(r'[0-9]{3,8}', p['identity']['agent_id']) and
            int(p['identity']['agent_id']) != 0, 'ENDPOINT_AGENT_REQUIRED')
    require(p['identity']['os'] in {'linux', 'windows'}, 'OS')
    require(re.fullmatch(r'[0-9a-f]{64}', p['identity']['config_sha256']), 'CONFIG_HASH')
    keys(p['clocks'], 'controller endpoint manager observer', 'CLOCK_ROLES')
    for c in p['clocks'].values():
        keys(c, 'offset_ms uncertainty_ms precision_ms ref', 'CLOCK_KEYS')
        integer(c['offset_ms'], -60000, 60000, 'CLOCK_OFFSET')
        integer(c['uncertainty_ms'], 0, 60000, 'CLOCK_UNCERTAINTY')
        integer(c['precision_ms'], 1, 60000, 'CLOCK_PRECISION')
        text(c['ref'], 'CLOCK_REF')
    require(type(p['window_s']) is int and p['window_s'] == 300 and
            type(p['poll_interval_ms']) is int and p['poll_interval_ms'] == POLL_MS, 'FIXED_PROTOCOL')
    keys(p['coverage'], 'start_ms end_ms ref', 'COVERAGE_KEYS')
    timestamp(p['coverage']['start_ms']); timestamp(p['coverage']['end_ms'])
    require(p['coverage']['end_ms'] > p['coverage']['start_ms'], 'COVERAGE_ORDER')
    text(p['coverage']['ref'], 'COVERAGE_REF')
    require(isinstance(p['cycles'], list) and 5 <= len(p['cycles']) <= 100, 'PLANNED_CYCLES_5_TO_100')
    ids, paths = set(), set()
    for c in p['cycles']:
        keys(c, 'cycle_id target_path rule_ids levels', 'CYCLE_KEYS')
        text(c['cycle_id'], 'CYCLE_ID'); text(c['target_path'], 'TARGET_PATH')
        path = c['target_path']
        require((path.startswith('/') if p['identity']['os'] == 'linux' else
                 bool(re.match(r'^[A-Za-z]:\\', path))) and not path.endswith(('/', '\\')) and
                not any(x in {'.', '..', ''} for x in re.split(r'[/\\]', path)[1:]), 'CANONICAL_TARGET_PATH')
        path_key = path if p['identity']['os'] == 'linux' else path.casefold()
        require(c['cycle_id'] not in ids and path_key not in paths, 'DUPLICATE_PLANNED_CYCLE_OR_PATH')
        ids.add(c['cycle_id']); paths.add(path_key)
        require(isinstance(c['rule_ids'], list) and c['rule_ids'] and len(c['rule_ids']) <= 16 and
                all(isinstance(x, str) and x.isdecimal() for x in c['rule_ids']) and
                len(set(c['rule_ids'])) == len(c['rule_ids']), 'RULE_IDS')
        require(isinstance(c['levels'], list) and c['levels'] and len(c['levels']) <= 16 and
                all(type(x) is int and 0 <= x <= 16 for x in c['levels']) and
                len(set(c['levels'])) == len(c['levels']), 'LEVELS')
        supported = CANARY_RULES[p['identity']['os']]
        require(set(c['rule_ids']) <= set(supported) and
                set(c['levels']) == {supported[x] for x in c['rule_ids']}, 'CANARY_CREATION_RULES')
    return p


def check_record(r, p):
    keys(r, 'schema_version run_id cycle_id exclusion_reason reason restart canary polls', 'RECORD_KEYS')
    require(type(r['schema_version']) is int and r['schema_version'] == 1, 'RECORD_VERSION')
    require(r['run_id'] == p['run_id'] and r['cycle_id'] in {c['cycle_id'] for c in p['cycles']}, 'UNPLANNED_CYCLE')
    require(r['exclusion_reason'] is None or
            isinstance(r['exclusion_reason'], str) and r['exclusion_reason'] in EXCLUDED, 'EXCLUSION')
    if r['exclusion_reason']:
        text(r['reason'], 'EXCLUSION_REASON')
    else:
        require(r['reason'] is None, 'UNEXCLUDED_REASON')
    if r['restart'] is not None:
        s = r['restart']
        keys(s, 'request_ms command_end_ms old_instance new_instance service_started_ms service_running ref', 'RESTART_KEYS')
        timestamp(s['request_ms'])
        for k in ('command_end_ms', 'service_started_ms'):
            if s[k] is not None:
                timestamp(s[k])
        for k in ('old_instance', 'new_instance'):
            if s[k] is not None:
                text(s[k], 'INSTANCE_ID')
        require(type(s['service_running']) is bool, 'SERVICE_RUNNING')
        text(s['ref'], 'RESTART_REF')
    if r['canary'] is not None:
        keys(r['canary'], 'created_ms path source_ref', 'CANARY_KEYS')
        timestamp(r['canary']['created_ms']); text(r['canary']['path'], 'CANARY_PATH')
        text(r['canary']['source_ref'], 'CANARY_SOURCE_REF')
    require(isinstance(r['polls'], list) and len(r['polls']) <= 128, 'POLL_LIMIT')
    for q in r['polls']:
        keys(q, 'start_ms end_ms start_monotonic_ms end_monotonic_ms status manager_name agent_id agent_name ref', 'POLL_KEYS')
        for k in ('start_ms', 'end_ms', 'start_monotonic_ms', 'end_monotonic_ms'):
            timestamp(q[k])
        require(isinstance(q['status'], str) and q['status'] in STATES, 'POLL_STATUS')
        for k in ('manager_name', 'agent_id', 'agent_name', 'ref'):
            text(q[k], 'POLL_TEXT')


def point(p, role, raw):
    c = p['clocks'][role]
    value = raw - c['offset_ms']
    error = c['precision_ms'] + c['uncertainty_ms']
    return value - error, value + error


def classify(p, c, r, alerts):
    out = {'cycle_id': c['cycle_id'], 'state': 'MISSING_RECORD', 'connection_state': 'NOT_OBSERVED',
           'transition_interval_s': None, 'functional_confirmation_interval_s': None,
           'alert_refs': [], 'exclusion_reason': None,
           'causality_authenticated': False, 'acceptance_approved': False}
    def finish(state):
        out['state'] = state
        return out
    if r is None:
        return out
    if r['exclusion_reason']:
        out['exclusion_reason'] = r['exclusion_reason']
        return finish('EXCLUDED')
    if any(abs(x['offset_ms']) > 100 or x['uncertainty_ms'] > 100 for x in p['clocks'].values()):
        return finish('SESSION_CLOCK_LIMIT_EXCEEDED')
    s, polls = r['restart'], r['polls']
    if s is None:
        return finish('MISSING_RESTART_EVIDENCE')
    t0 = point(p, 'controller', s['request_ms'])
    if s['command_end_ms'] is None or s['service_started_ms'] is None:
        return finish('RESTART_UNPROVEN')
    end = point(p, 'controller', s['command_end_ms'])
    start = point(p, 'endpoint', s['service_started_ms'])
    if end[1] < t0[0] or start[1] < t0[0]:
        return finish('INVALID_TIMELINE')
    if min(start[0], end[0]) < t0[1]:
        return finish('TIMING_UNCERTAIN')
    if not s['service_running'] or not s['old_instance'] or not s['new_instance'] or s['old_instance'] == s['new_instance']:
        return finish('RESTART_UNPROVEN')
    if not polls:
        return finish('OBSERVATION_INCOMPLETE')
    previous = None
    clock = p['clocks']['observer']
    # Scheduling jitter is not permission to exceed the declared wall-clock error.
    wall_tolerance = 2 * (clock['precision_ms'] + clock['uncertainty_ms'])
    for q in polls:
        if any(q[k] != p['identity'][k] for k in ('manager_name', 'agent_id', 'agent_name')):
            return finish('IDENTITY_CHANGED')
        dt = q['end_monotonic_ms'] - q['start_monotonic_ms']
        if not 0 <= dt <= REQUEST_MS or q['end_ms'] < q['start_ms']:
            return finish('POLL_TIMING_INVALID')
        if abs(q['end_ms'] - q['start_ms'] - dt) > wall_tolerance:
            return finish('CLOCK_JUMP')
        if previous:
            gap = q['start_monotonic_ms'] - previous['start_monotonic_ms']
            if not POLL_MS - JITTER_MS <= gap <= POLL_MS + JITTER_MS or q['start_monotonic_ms'] < previous['end_monotonic_ms']:
                return finish('POLL_GAP')
            if abs(q['start_ms'] - previous['start_ms'] - gap) > wall_tolerance:
                return finish('CLOCK_JUMP')
        # Compare to the first sample too; small per-poll drift must not accumulate.
        if abs(q['start_ms'] - polls[0]['start_ms'] -
               (q['start_monotonic_ms'] - polls[0]['start_monotonic_ms'])) > wall_tolerance:
            return finish('CLOCK_JUMP')
        previous = q
    coverage = p['coverage']
    if (point(p, 'observer', polls[0]['end_ms'])[1] > t0[0] or
        point(p, 'observer', polls[-1]['end_ms'])[0] < t0[1] + WINDOW_MS or
        point(p, 'manager', coverage['start_ms'])[1] > t0[0] or
        point(p, 'manager', coverage['end_ms'])[0] < t0[1] + WINDOW_MS):
        return finish('OBSERVATION_INCOMPLETE')
    if any(q['status'] == 'error' for q in polls):
        return finish('POLL_ERROR')
    active = None
    negative = None
    for q in polls:
        if point(p, 'observer', q['start_ms'])[0] < start[1]:
            continue
        if q['status'] == 'active':
            active = q
            if negative is not None:
                lower = point(p, 'observer', negative['start_ms'])[0]
                upper = point(p, 'observer', q['end_ms'])[1]
                out['transition_interval_s'] = [(lower - t0[1]) / 1000, (upper - t0[0]) / 1000]
                out['connection_state'] = 'TRANSITION_OBSERVED'
            else:
                out['connection_state'] = 'ACTIVE_WITHOUT_TRANSITION_BRACKET'
            break
        negative = q
    if active is None:
        return finish('NO_ACTIVE_OBSERVED')
    canary = r['canary']
    if canary is None:
        return finish('CANARY_NOT_SUPPLIED')
    if canary['path'] != c['target_path']:
        return finish('CANARY_TARGET_MISMATCH')
    created = point(p, 'endpoint', canary['created_ms'])
    if created[1] < max(start[0], end[0]):
        return finish('INVALID_TIMELINE')
    if created[0] < max(start[1], end[1]):
        return finish('TIMING_UNCERTAIN')
    matches = [a for a in alerts if
               all(a['raw'][obj][key] == p['identity'][label] for obj, key, label in
                   [('manager', 'name', 'manager_name'), ('agent', 'id', 'agent_id'), ('agent', 'name', 'agent_name')]) and
               a['raw']['rule']['id'] in c['rule_ids'] and
               a['raw']['rule']['level'] == CANARY_RULES[p['identity']['os']][a['raw']['rule']['id']] and
               m.field(a['raw'], 'syscheck.path') == c['target_path'] and
               coverage['start_ms'] <= m.to_ms(a['raw']['timestamp']) <= coverage['end_ms']]
    if not matches:
        return finish('CANARY_ALERT_NOT_OBSERVED')
    first = matches[0]
    out['alert_refs'] = list(first['refs'])
    alert_at = point(p, 'manager', m.to_ms(first['raw']['timestamp']))
    # A reused path/event before creation is not skipped to cherry-pick a later match.
    if alert_at[1] < created[0]:
        return finish('PREEXISTING_CANARY_ALERT')
    if alert_at[0] < created[1]:
        return finish('TIMING_UNCERTAIN')
    # Do not combine an early/stale active state with a later canary after
    # disconnection. Require a positive sample wholly after the raw event.
    corroboration = next((q for q in polls if q['status'] == 'active' and
                          point(p, 'observer', q['start_ms'])[0] >= alert_at[1]), None)
    if corroboration is None:
        return finish('ACTIVE_NOT_CORROBORATED_AFTER_CANARY')
    active_at = point(p, 'observer', corroboration['end_ms'])
    lower = max(alert_at[0], active_at[0], end[0], start[0]) - t0[1]
    upper = max(alert_at[1], active_at[1], end[1], start[1]) - t0[0]
    out['functional_confirmation_interval_s'] = [lower / 1000, upper / 1000]
    if upper <= WINDOW_MS:
        return finish('FUNCTIONAL_EVIDENCE_WITHIN_WINDOW')
    if lower > WINDOW_MS:
        return finish('FUNCTIONAL_EVIDENCE_LATE')
    return finish('TIMING_UNCERTAIN')


def evaluate(plan, records, alert_rows):
    check_plan(plan)
    require(isinstance(records, list) and len(records) <= len(plan['cycles']), 'RECORD_LIMIT')
    require(isinstance(alert_rows, list) and len(alert_rows) <= MAX_ALERTS, 'ALERT_LIMIT')
    by_id, refs, spans = {}, defaultdict(set), []
    for r in records:
        check_record(r, plan)
        cid = r['cycle_id']
        require(cid not in by_id, 'DUPLICATE_RECORD')
        by_id[cid] = r
        if r['restart']:
            s = r['restart']
            if s['new_instance']:
                refs[('instance', s['new_instance'])].add(cid)
            refs[('restart', s['ref'])].add(cid)
            low, high = point(plan, 'controller', s['request_ms'])
            spans.append((low, high + WINDOW_MS, cid))
        if r['canary']:
            refs[('canary', r['canary']['source_ref'])].add(cid)
    ambiguous = set().union(*(ids for ids in refs.values() if len(ids) > 1))
    overlap = set()
    for i, (a, b, cid) in enumerate(spans):
        for x, y, other in spans[i+1:]:
            if max(a, x) < min(b, y):
                overlap.update((cid, other))
    alerts, duplicates = m.normalize_alerts(alert_rows)
    rows = [classify(plan, c, by_id.get(c['cycle_id']), alerts) for c in plan['cycles']]
    for row in rows:
        cid = row['cycle_id']
        row['integrity_conflicts'] = (['REUSED_EVIDENCE'] if cid in ambiguous else []) + (['OVERLAPPING_CYCLE'] if cid in overlap else [])
        if row['integrity_conflicts']:
            row['state_before_integrity_check'] = row['state']
            row['state'] = 'AMBIGUOUS_EVIDENCE' if cid in ambiguous else 'OVERLAPPING_CYCLE'
            row['transition_interval_s'] = row['functional_confirmation_interval_s'] = None
    count = sum(r['state'] == 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW' for r in rows)
    return {'schema_version': 1, 'scope': 'UC01_DECLARED_EVIDENCE_ONLY', 'run_id': plan['run_id'],
            'cycles': rows, 'counts': dict(Counter(r['state'] for r in rows)),
            'denominator_planned_cycles': len(rows), 'recorded_cycles': len(records),
            'documented_functional_count': count, 'documented_functional_rate': count / len(rows),
            'duplicate_alert_lines': duplicates, 'wilson_95': None, 'independence_verified': False,
            'causality_authenticated': False, 'acceptance_approved': False,
            'notice': 'Not MTTD or an attack detection rate. Missing planned cycles stay in denominator. '
                      'Service, canary, clock and coverage evidence are declarations; raw alert matching is not authenticity. '
                      'Native collectors, binding and acceptance remain required. No independence confidence interval.'}


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and
                before.st_nlink == 1 and not before.st_mode & 0o077, 'PRIVATE_REGULAR_SINGLE_LINK_REQUIRED')
        require(before.st_size <= MAX_BYTES, 'INPUT_SIZE')
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink', 'st_uid')
        require(len(raw) <= MAX_BYTES and all(getattr(before, k) == getattr(after, k) for k in fields), 'INPUT_CHANGED_OR_LARGE')
    return raw


def parse_lines(raw, limit):
    """Bound line count BEFORE JSON parsing; literal LF, not Unicode separators."""
    if not raw:
        return []
    lines = raw.decode('utf-8').split('\n', limit + 1)
    if lines[-1] == '':
        lines.pop()
    require(len(lines) <= limit, 'INPUT_LINE_LIMIT')
    return [m.strict_json(line) for line in lines]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--records', required=True, help='JSONL normalized cycle records; empty allowed')
    parser.add_argument('--alerts', required=True, help='JSONL raw alerts; empty allowed')
    args = parser.parse_args(argv)
    try:
        raw = {k: read_private(getattr(args, k)) for k in ('plan', 'records', 'alerts')}
        plan = m.strict_json(raw['plan'].decode('utf-8'))
        records = parse_lines(raw['records'], 100)
        alerts = [(line, f'alerts:{i}') for i, line in enumerate(parse_lines(raw['alerts'], MAX_ALERTS), 1)]
        result = evaluate(plan, records, alerts)
        result['input_sha256'] = {k: hashlib.sha256(v).hexdigest() for k, v in raw.items()}
        result['source_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in (Path(__file__), Path(m.__file__))}
        print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError):
        # Do not leak raw records, identifiers or parser excerpts to stderr.
        print('UC01_INPUT_REJECTED', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
