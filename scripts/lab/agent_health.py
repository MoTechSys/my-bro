#!/usr/bin/env python3
"""Read-only Linux Wazuh health gate; AI, 2026-09-11, ISSUE-064..066.

No SSH, Docker mutation, shell evaluation, secrets, or report-file writes.
Run inside the agent's PID namespace. Health is NOT end-to-end acceptance.
State timestamps require the explicitly declared timezone of the agent processes.
"""
import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re
import sys
import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

DAEMONS = ('wazuh-execd', 'wazuh-agentd', 'wazuh-syscheckd',
           'wazuh-logcollector', 'wazuh-modulesd')
INIT_NAMES = {'docker-init', 'tini', 'dumb-init'}
MAX_BYTES = 1024 * 1024
MAX_PROCESSES = 32768
ACK_MAX_AGE = 60
COLLECTOR_MAX_AGE = 120


class HealthError(ValueError):
    pass


def bounded_text(path):
    with Path(path).open('r', encoding='utf-8') as stream:
        value = stream.read(MAX_BYTES + 1)
    if len(value) > MAX_BYTES:
        raise HealthError('INPUT_TOO_LARGE')
    return value


def integer(value, label):
    if type(value) is not int or value < 0:
        raise HealthError('INVALID_' + label)
    return value


def parse_stat(text):
    match = re.fullmatch(r'(\d+) \((.*)\) (.+)\s*', text.strip())
    if not match:
        raise HealthError('INVALID_PROC_STAT')
    fields = match[3].split()
    if len(fields) < 20 or len(fields[0]) != 1:
        raise HealthError('SHORT_PROC_STAT')
    return {'pid': int(match[1]), 'name': match[2], 'state': fields[0],
            'start_ticks': integer(int(fields[19]), 'START_TICKS')}


def parse_agent_state(text):
    """Parse assignments without sourcing/evaluating shell content."""
    result = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r"([a-z_]+)='([^'\r\n]*)'", line.strip())
        if not match or match[1] in result:
            raise HealthError('INVALID_AGENT_STATE')
        result[match[1]] = match[2]
    for key in ('msg_count', 'msg_sent', 'msg_buffer'):
        if not re.fullmatch(r'\d+', result.get(key, '')):
            raise HealthError('INVALID_' + key.upper())
        result[key] = int(result[key])
    if result.get('status') not in {'connected', 'pending', 'disconnected'}:
        raise HealthError('INVALID_CONNECTION_STATUS')
    return {key: result.get(key) for key in
            ('status', 'last_ack', 'msg_count', 'msg_sent', 'msg_buffer')}


def epoch(value, zone):
    if not isinstance(value, str):
        raise HealthError('MISSING_TIMESTAMP')
    return datetime.strptime(value, '%Y-%m-%d %H:%M:%S').replace(tzinfo=zone).timestamp()


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise HealthError('DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def constant(_):
        raise HealthError('NONFINITE_JSON')
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def collect(proc=Path('/proc'), state=Path('/var/ossec/var/run'), zone='UTC'):
    """Bounded snapshot. Only allowlisted state fields enter the report."""
    snapshot = {'at': time.time(), 'monotonic': time.monotonic(), 'timezone': zone,
                'processes': [], 'zombies': 0, 'pid1': None, 'errors': []}
    try:
        tz = ZoneInfo(zone)
        entries = [p for p in proc.iterdir() if p.name.isdecimal()]
        if len(entries) > MAX_PROCESSES:
            raise HealthError('PROCESS_LIMIT')
        for path in entries:
            try:
                record = parse_stat(bounded_text(path / 'stat'))
                if record['pid'] != int(path.name):
                    raise HealthError('PID_IDENTITY_MISMATCH')
                if record['pid'] == 1:
                    snapshot['pid1'] = record['name']
                if record['state'] == 'Z':
                    snapshot['zombies'] += 1
                names = [n for n in DAEMONS if n[:15] == record['name']]
                if not names:
                    continue
                record['name'] = names[0]
                if record['state'] != 'Z':
                    argv0 = bounded_text(path / 'cmdline').split('\x00')[0]
                    record['identity_ok'] = argv0 == '/var/ossec/bin/' + names[0]
                    again = parse_stat(bounded_text(path / 'stat'))
                    if (again['start_ticks'], again['state']) != (record['start_ticks'], record['state']):
                        raise HealthError('PROCESS_CHANGED_DURING_READ')
                else:
                    record['identity_ok'] = False
                snapshot['processes'].append(record)
            except FileNotFoundError:
                continue  # A required disappearing daemon is caught by its missing count.
        agent = parse_agent_state(bounded_text(state / 'wazuh-agentd.state'))
        agent['ack_epoch'] = epoch(agent.pop('last_ack'), tz)
        snapshot['agent'] = agent
        raw = strict_json(bounded_text(state / 'wazuh-logcollector.state'))
        global_state = raw['global']
        files = global_state['files']
        if not isinstance(files, list):
            raise HealthError('INVALID_COLLECTOR_FILES')
        matches = [f for f in files if isinstance(f, dict) and f.get('location') == 'process list']
        if len(matches) != 1:
            raise HealthError('PROCESS_LIST_SOURCE_REQUIRED_ONCE')
        source = matches[0]
        targets = source['targets']
        if not isinstance(targets, list):
            raise HealthError('INVALID_COLLECTOR_TARGETS')
        agent_targets = [t for t in targets if isinstance(t, dict) and t.get('name') == 'agent']
        if len(agent_targets) != 1:
            raise HealthError('AGENT_TARGET_REQUIRED_ONCE')
        snapshot['collector'] = {
            'start_epoch': epoch(global_state['start'], tz),
            'end_epoch': epoch(global_state['end'], tz),
            'events': integer(source['events'], 'EVENTS'),
            'drops': integer(agent_targets[0]['drops'], 'DROPS')}
    except (OSError, ValueError, KeyError, TypeError, ZoneInfoNotFoundError, RecursionError):
        snapshot['errors'].append('SNAPSHOT_INCOMPLETE_OR_INVALID')
    return snapshot


def assess(snapshot):
    reasons = list(snapshot['errors'])
    if snapshot['pid1'] not in INIT_NAMES:
        reasons.append('PID1_NOT_RECOGNIZED_INIT')
    if snapshot['zombies']:
        reasons.append('ZOMBIES_PRESENT')
    for name in DAEMONS:
        live = [p for p in snapshot['processes'] if p['name'] == name and p['state'] != 'Z']
        if len(live) != 1:
            reasons.append('LIVE_PROCESS_COUNT:' + name)
        elif live[0]['state'] not in {'R', 'S'} or not live[0]['identity_ok']:
            reasons.append('PROCESS_NOT_HEALTHY:' + name)
    agent = snapshot.get('agent')
    if agent:
        age = snapshot['at'] - agent['ack_epoch']
        if agent['status'] != 'connected':
            reasons.append('AGENT_NOT_CONNECTED')
        if not 0 <= age <= ACK_MAX_AGE:
            reasons.append('ACK_STALE_OR_FUTURE')
        if agent['msg_buffer']:
            reasons.append('AGENT_BUFFER_NOT_EMPTY')
    else:
        reasons.append('AGENT_STATE_MISSING')
    collector = snapshot.get('collector')
    if collector:
        if not collector['start_epoch'] <= collector['end_epoch'] <= snapshot['at']:
            reasons.append('COLLECTOR_TIME_ORDER')
        if not 0 <= snapshot['at'] - collector['end_epoch'] <= COLLECTOR_MAX_AGE:
            reasons.append('COLLECTOR_STATE_STALE_OR_FUTURE')
        if collector['drops']:
            reasons.append('COLLECTOR_DROPS_PRESENT')
    else:
        reasons.append('COLLECTOR_STATE_MISSING')
    return reasons


def assess_progress(first, second):
    reasons = []
    elapsed = second['monotonic'] - first['monotonic']
    if not 60 <= elapsed <= 180:
        reasons.append('PROGRESS_WINDOW_OUTSIDE_60_180_SECONDS')
    if abs((second['at'] - first['at']) - elapsed) > 1:
        reasons.append('WALL_CLOCK_JUMP')
    if first['timezone'] != second['timezone']:
        reasons.append('TIMEZONE_CHANGED')
    def identities(s):
        return sorted((p['name'], p['pid'], p['start_ticks']) for p in s['processes'] if p['state'] != 'Z')
    if identities(first) != identities(second):
        reasons.append('DAEMON_RESTARTED_DURING_WINDOW')
    try:
        a, b = first['collector'], second['collector']
        if a['start_epoch'] != b['start_epoch'] or b['end_epoch'] <= a['end_epoch']:
            reasons.append('COLLECTOR_RESET_OR_NOT_UPDATED')
        if b['events'] <= a['events']:
            reasons.append('PROCESS_LIST_NOT_ADVANCING')
        for key in ('msg_count', 'msg_sent'):
            if second['agent'][key] <= first['agent'][key]:
                reasons.append('AGENT_COUNTER_NOT_ADVANCING:' + key)
        if second['agent']['ack_epoch'] <= first['agent']['ack_epoch']:
            reasons.append('ACK_NOT_ADVANCING')
    except KeyError:
        reasons.append('PROGRESS_INPUT_MISSING')
    return reasons


def report(samples):
    reasons = [f'sample{i + 1}:' + r for i, s in enumerate(samples) for r in assess(s)]
    progress = assess_progress(*samples) if len(samples) == 2 else None
    reasons.extend(progress or [])
    return {'schema_version': 1, 'scope': 'agent_operational_health_only',
            'healthy': not reasons, 'reasons': reasons,
            'progress_verified': progress == [], 'samples': samples,
            'canary_verified': False, 'deployment_approved': False,
            'notice': 'Local process/state evidence is not authenticated telemetry or end-to-end detection. '
                      'Requires configured process-list source; no MTTD or clock-accuracy claim.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-timezone', required=True, help='timezone used by agent state files, e.g. UTC')
    parser.add_argument('--progress', action='store_true', help='take a second read-only sample after 65 seconds')
    args = parser.parse_args(argv)
    try:
        ZoneInfo(args.state_timezone)
    except (ValueError, ZoneInfoNotFoundError):
        parser.error('unknown state timezone')
    samples = [collect(zone=args.state_timezone)]
    if args.progress:
        time.sleep(65)
        samples.append(collect(zone=args.state_timezone))
    result = report(samples)
    print(json.dumps(result, ensure_ascii=True, allow_nan=False, indent=2))
    return 0 if result['healthy'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
