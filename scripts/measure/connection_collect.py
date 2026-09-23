#!/usr/bin/env python3
"""Read-only UC-01 native capture and byte-verified offline binding (Linux).

Fixed agent_control/systemctl queries or Linux procfs reads. Never restarts services or writes
canaries. systemd/hostname adapter constraints and remaining attestations are
explicit in tests/README. Private stores are immutable by convention, not signed.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c = load('_collect_connection', Path(__file__).with_name('connection_measure.py'))
s = load('_collect_source', Path(__file__).with_name('source_observer.py'))
p = load('_collect_process', Path(__file__).with_name('connection_process.py'))
r = s.r
require = c.require
LIMIT = 65536
COUNT = 64  # first poll then every 5 seconds through 315 seconds
KINDS = {'manager', 'service', 'linuxproc'}
PROPERTIES = ('ActiveState', 'SubState', 'InvocationID', 'MainPID', 'ExecMainStartTimestamp')
STATUS = {'Active': 'active', 'Disconnected': 'disconnected',
          'Pending': 'pending', 'Never connected': 'never_connected'}


def source_hashes():
    paths = {Path(__file__), Path(c.__file__), Path(c.m.__file__), Path(s.__file__), Path(s.v.__file__), Path(p.__file__)}
    paths.update(ROOT/'ai_agent'/name for name in r.SOURCE_NAMES)
    return {str(p.relative_to(ROOT)): r.digest(p.read_bytes()) for p in sorted(paths)}


def native_plan(raw):
    plan = c.check_plan(c.m.strict_json(raw.decode('utf-8')))
    # This adapter timestamps polls on the manager itself. Clock-source estimates
    # must agree; producer precision may differ between raw alerts and queries.
    manager, observer = plan['clocks']['manager'], plan['clocks']['observer']
    require(all(manager[k] == observer[k] for k in ('offset_ms', 'uncertainty_ms', 'ref')),
            'SHARED_MANAGER_OBSERVER_CLOCK')
    return plan


def trusted_binary(path):
    original = Path(path)
    resolved = original.resolve(strict=True)
    for item in {original, *original.parents, resolved, *resolved.parents}:
        st = item.stat()
        require(st.st_uid == 0 and not st.st_mode & 0o022, 'UNPROTECTED_COMMAND')
    require(resolved.is_file() and os.access(resolved, os.X_OK), 'EXECUTABLE_REQUIRED')


def command(kind, plan):
    if kind == 'manager':
        return ['/var/ossec/bin/agent_control', '-i', plan['identity']['agent_id'], '-j']
    require(kind == 'service', 'CAPTURE_KIND')
    return ['/usr/bin/systemctl', 'show', 'wazuh-agent.service', '--no-pager',
            '--property=' + ','.join(PROPERTIES)]


def native_sample(kind, plan):
    expected_host = plan['identity']['manager_name' if kind == 'manager' else 'agent_name']
    host = socket.gethostname()
    require(host == expected_host, 'HOSTNAME_BINDING')
    if kind == 'linuxproc':
        require(plan['identity']['os'] == 'linux', 'LINUX_PROC_ONLY')
        raw, boot = p.collect(trusted_binary)
        return raw, host, boot
    argv = command(kind, plan)
    trusted_binary(argv[0])
    boot = None
    if kind == 'service':
        with open('/proc/sys/kernel/random/boot_id', 'rb') as stream:
            boot = stream.read(128).decode('ascii').strip()
        require(re.fullmatch(r'[0-9a-f-]{36}', boot), 'BOOT_ID')
    result = r.bounded_process(argv, 1.5)
    require(result['reason'] == 'OK' and result['returncode'] == 0 and
            len(result['output']) <= LIMIT, 'NATIVE_QUERY_FAILED')
    return result['output'], host, boot


def normalize(kind, raw, host, boot, plan):
    require(isinstance(raw, bytes) and len(raw) <= LIMIT, 'RAW_LIMIT')
    expected_host = plan['identity']['manager_name' if kind == 'manager' else 'agent_name']
    require(host == expected_host, 'HOSTNAME_BINDING')
    if kind == 'manager':
        obj = c.m.strict_json(raw.decode('utf-8'))
        c.keys(obj, 'error data', 'AGENT_CONTROL_KEYS')
        require(type(obj['error']) is int and obj['error'] == 0 and isinstance(obj['data'], dict), 'AGENT_CONTROL_ERROR')
        data = obj['data']
        require(data.get('id') == plan['identity']['agent_id'] and
                data.get('name') == plan['identity']['agent_name'], 'AGENT_IDENTITY')
        require(isinstance(data.get('status'), str) and data['status'] in STATUS, 'AGENT_STATUS')
        require(boot is None, 'MANAGER_BOOT_FIELD')
        return {'status': STATUS[data['status']], 'manager_name': host,
                'agent_id': data['id'], 'agent_name': data['name']}
    if kind == 'linuxproc':
        require(plan['identity']['os'] == 'linux', 'LINUX_PROC_ONLY')
        return p.normalize(c.m.strict_json(raw.decode('utf-8')), boot)
    require(kind == 'service' and plan['identity']['os'] == 'linux', 'LINUX_SYSTEMD_ONLY')
    require(isinstance(boot, str) and re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot), 'BOOT_ID')
    fields = {}
    for line in raw.decode('utf-8').splitlines():
        key, sep, value = line.partition('=')
        require(sep and key in PROPERTIES and key not in fields, 'SYSTEMD_PROPERTIES')
        fields[key] = value
    require(set(fields) == set(PROPERTIES), 'SYSTEMD_PROPERTIES')
    require(re.fullmatch(r'[0-9]{1,10}', fields['MainPID']), 'SYSTEMD_PID')
    invocation = fields['InvocationID']
    require(invocation == '' or re.fullmatch(r'[0-9a-f]{32}', invocation), 'INVOCATION_ID')
    started = None
    if fields['ExecMainStartTimestamp'] not in ('', 'n/a'):
        # systemctl textual native timestamp is second-resolution. Never invent ms precision.
        value = fields['ExecMainStartTimestamp']
        require(re.fullmatch(r'[A-Z][a-z]{2} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC', value), 'SYSTEMD_TIMESTAMP_FORMAT')
        dt = datetime.strptime(value, '%a %Y-%m-%d %H:%M:%S UTC').replace(tzinfo=timezone.utc)
        require(dt.strftime('%a %Y-%m-%d %H:%M:%S UTC') == value, 'SYSTEMD_TIMESTAMP_CANONICAL')
        started = int(dt.timestamp()) * 1000
    running = fields['ActiveState'] == 'active' and fields['SubState'] == 'running' and int(fields['MainPID']) > 0
    return {'instance': boot + ':' + invocation if invocation else None,
            'started_ms': started, 'running': running, 'precision_ms': 1000}


def check_times(entries, kind, plan):
    role = 'observer' if kind == 'manager' else 'endpoint'
    clock = plan['clocks'][role]
    tolerance = 2 * (clock['precision_ms'] + clock['uncertainty_ms'])
    for i, q in enumerate(entries):
        for key in ('start_ms', 'end_ms', 'start_monotonic_ms', 'end_monotonic_ms'):
            c.timestamp(q[key])
        elapsed = q['end_monotonic_ms'] - q['start_monotonic_ms']
        require(0 <= elapsed <= c.REQUEST_MS and q['end_ms'] >= q['start_ms'], 'QUERY_OVERRUN')
        require(abs(q['end_ms'] - q['start_ms'] - elapsed) <= tolerance, 'CLOCK_JUMP')
        if i:
            prev = entries[i-1]
            gap = q['start_monotonic_ms'] - prev['start_monotonic_ms']
            require(c.POLL_MS-c.JITTER_MS <= gap <= c.POLL_MS+c.JITTER_MS and
                    q['start_monotonic_ms'] >= prev['end_monotonic_ms'], 'POLL_GAP')
            require(abs(q['start_ms'] - entries[0]['start_ms'] -
                        (q['start_monotonic_ms'] - entries[0]['start_monotonic_ms'])) <= tolerance, 'CLOCK_JUMP')


def check_snapshot(value, query, kind, plan):
    if kind in {'service', 'linuxproc'} and value['started_ms'] is not None:
        # Native wall timestamp must not assert a start after this observation.
        require(c.point(plan, 'endpoint', value['started_ms'])[0] <=
                c.point(plan, 'endpoint', query['end_ms'])[1], 'SERVICE_START_AFTER_SNAPSHOT')


def capture(plan_raw, cycle_id, kind, store):
    plan = native_plan(plan_raw)
    require(kind in KINDS and cycle_id in {x['cycle_id'] for x in plan['cycles']}, 'CAPTURE_IDENTITY')
    require(kind == 'manager' or plan['identity']['os'] == 'linux', 'LINUX_ENDPOINT_ONLY')
    with r.store_lock(store) as fd:
        require(not os.listdir(fd), 'EMPTY_STORE_REQUIRED')
        intent = {'schema_version': 1, 'kind': kind, 'cycle_id': cycle_id, 'capture_id': uuid.uuid4().hex,
                  'plan_sha256': r.digest(plan_raw), 'source_sha256': source_hashes(), 'acceptance_approved': False}
        raw = r.json_bytes(intent)
        r.write_once(fd, 'plan.json', plan_raw)
        r.write_once(fd, 'intent.json', raw)
        terminal = {'intent_sha256': r.digest(raw), 'status': 'failed', 'count': 0, 'reason': 'INTERRUPTED'}
        entries = []
        try:
            origin = time.monotonic()
            for i in range(COUNT if kind == 'manager' else 1):
                delay = origin + i*5 - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                q = {'start_ms': time.time_ns()//1000000, 'start_monotonic_ms': time.monotonic_ns()//1000000}
                payload, host, boot = native_sample(kind, plan)
                q.update(end_ms=time.time_ns()//1000000, end_monotonic_ms=time.monotonic_ns()//1000000,
                         raw_sha256=r.digest(payload), hostname=host, boot_id=boot)
                value = normalize(kind, payload, host, boot, plan)
                check_snapshot(value, q, kind, plan)
                check_times(entries + [q], kind, plan)
                r.write_once(fd, f'sample-{i:03d}.bin', payload)
                r.write_once(fd, f'sample-{i:03d}.json', r.json_bytes(q))
                entries.append(q)
                terminal['count'] = len(entries)
            terminal.update(status='complete', reason=None)
        except Exception:
            terminal.update(status='failed', reason='CAPTURE_FAILED')
        finally:
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                r.write_once(fd, 'terminal.json', r.json_bytes(terminal))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        return dict(terminal, acceptance_approved=False)


def export(store, expected, plan_raw, cycle_id, kind):
    """Replay all raw bytes, not stored derived statuses. No partial success export."""
    r.e.sha256(expected)
    plan = native_plan(plan_raw)
    require(kind in KINDS and cycle_id in {x['cycle_id'] for x in plan['cycles']}, 'CAPTURE_IDENTITY')
    with r.store_lock(store) as fd:
        raw = r.read_at(fd, 'intent.json')
        require(r.digest(raw) == expected, 'INTENT_HASH')
        intent = c.m.strict_json(raw.decode())
        require(isinstance(intent, dict) and isinstance(intent.get('capture_id'), str) and
                re.fullmatch(r'[0-9a-f]{32}', intent['capture_id']), 'CAPTURE_NONCE')
        require(type(intent.get('schema_version')) is int and intent.get('acceptance_approved') is False, 'INTENT_TYPES')
        require(intent == {'schema_version': 1, 'kind': kind, 'cycle_id': cycle_id, 'capture_id': intent['capture_id'],
                           'plan_sha256': r.digest(plan_raw), 'source_sha256': source_hashes(),
                           'acceptance_approved': False}, 'INTENT_BINDING')
        require(r.read_at(fd, 'plan.json') == plan_raw, 'PLAN_BYTES')
        terminal = c.m.strict_json(r.read_at(fd, 'terminal.json').decode())
        require(isinstance(terminal, dict) and type(terminal.get('count')) is int, 'TERMINAL_TYPES')
        require(terminal == {'intent_sha256': expected, 'status': 'complete',
                             'count': COUNT if kind == 'manager' else 1, 'reason': None}, 'INCOMPLETE_CAPTURE')
        allowed = {'plan.json', 'intent.json', 'terminal.json'}
        entries, normalized = [], []
        for i in range(terminal['count']):
            name = f'sample-{i:03d}'
            allowed.update({name+'.bin', name+'.json'})
            q = c.m.strict_json(r.read_at(fd, name+'.json').decode())
            c.keys(q, 'start_ms end_ms start_monotonic_ms end_monotonic_ms raw_sha256 hostname boot_id', 'SAMPLE_KEYS')
            data = r.read_at(fd, name+'.bin', LIMIT)
            require(r.digest(data) == q['raw_sha256'], 'SAMPLE_BYTES')
            value = normalize(kind, data, q['hostname'], q['boot_id'], plan)
            check_snapshot(value, q, kind, plan)
            if kind == 'manager':
                value.update({key: q[key] for key in ('start_ms', 'end_ms', 'start_monotonic_ms', 'end_monotonic_ms')})
                value['ref'] = expected + ':' + name
            else:
                value.update(captured_start_ms=q['start_ms'], captured_end_ms=q['end_ms'], ref=expected)
            entries.append(q); normalized.append(value)
        check_times(entries, kind, plan)
        require(set(os.listdir(fd)) == allowed, 'UNEXPECTED_STORE_ENTRY')
        return {'kind': kind, 'cycle_id': cycle_id, 'samples': normalized, 'intent_sha256': expected,
                'stored_bytes_verified': True, 'acceptance_approved': False, 'authenticity_verified': False}


def bind(plan_raw, request_raw, manager, before, after, source):
    """Bind verified local stores; controller request times remain explicit attestations.

    Each store descriptor is {path, sha256}. Source evidence brackets creation,
    not a native creation timestamp; require the plan to cover its full error.
    """
    plan = native_plan(plan_raw)
    request = c.m.strict_json(request_raw.decode())
    c.keys(request, 'schema_version run_id cycle_id request_ms command_end_ms controller_ref', 'REQUEST_KEYS')
    require(type(request['schema_version']) is int and request['schema_version'] == 1 and
            request['run_id'] == plan['run_id'], 'REQUEST_BINDING')
    c.timestamp(request['request_ms']); c.timestamp(request['command_end_ms'])
    c.text(request['controller_ref'], 'CONTROLLER_REF')
    cid = request['cycle_id']
    require(cid in {x['cycle_id'] for x in plan['cycles']}, 'UNPLANNED_CYCLE')
    for label, desc in [('manager', manager), ('before', before), ('after', after), ('source', source)]:
        optional = ' kind' if label in {'before', 'after'} and isinstance(desc, dict) and 'kind' in desc else ''
        c.keys(desc, 'path sha256'+optional, 'STORE_DESCRIPTOR')
        c.text(desc['path'], 'STORE_PATH'); r.e.sha256(desc['sha256'])
    backend = before.get('kind', 'service')
    require(isinstance(backend, str) and backend in {'service', 'linuxproc'} and
            after.get('kind', 'service') == backend, 'SERVICE_BACKEND_BINDING')
    require(len({x['sha256'] for x in (manager, before, after, source)}) == 4, 'DISTINCT_STORES_REQUIRED')
    polls = export(manager['path'], manager['sha256'], plan_raw, cid, 'manager')['samples']
    old = export(before['path'], before['sha256'], plan_raw, cid, backend)['samples'][0]
    new = export(after['path'], after['sha256'], plan_raw, cid, backend)['samples'][0]
    require(old['running'] and new['running'] and old['instance'] and new['instance'] and
            old['instance'] != new['instance'] and new['started_ms'] is not None, 'RESTART_NOT_OBSERVED')
    require(plan['clocks']['endpoint']['precision_ms'] >= max(old['precision_ms'], new['precision_ms']), 'SERVICE_PRECISION')
    require(c.point(plan, 'endpoint', old['captured_end_ms'])[1] < c.point(plan, 'controller', request['request_ms'])[0] and
            c.point(plan, 'endpoint', new['captured_start_ms'])[0] > c.point(plan, 'controller', request['command_end_ms'])[1], 'SNAPSHOT_ORDER')
    if backend == 'linuxproc':
        require(old['namespaces'] == new['namespaces'], 'PROC_NAMESPACE_CHAIN')
        require(not set(old['daemon_instances'].values()) & set(new['daemon_instances'].values()),
                'PARTIAL_DAEMON_RESTART')
        require(c.point(plan, 'endpoint', new['earliest_started_ms'])[0] >
                c.point(plan, 'controller', request['request_ms'])[1], 'DAEMONS_NOT_AFTER_REQUEST')
    event = s.export(source['path'], source['sha256'])
    require(isinstance(event, dict), 'SOURCE_EVENT_REQUIRED')
    cycle = next(x for x in plan['cycles'] if x['cycle_id'] == cid)
    require(event['run_id'] == plan['run_id'] and event['trial_id'] == cid and
            event['device'] == 'endpoint' and event['clock_ref'] == plan['clocks']['endpoint']['ref'] and
            event['target_key'] == {'syscheck.path': cycle['target_path']}, 'SOURCE_BINDING')
    require(plan['clocks']['endpoint']['precision_ms'] >= event['precision_ms'], 'SOURCE_PRECISION')
    # Reject source observations that began before service restart completed.
    require(c.point(plan, 'endpoint', event['last_negative_start_ms'])[0] >
            c.point(plan, 'controller', request['command_end_ms'])[1], 'SOURCE_AFTER_RESTART_REQUIRED')
    row = {'schema_version': 1, 'run_id': plan['run_id'], 'cycle_id': cid, 'exclusion_reason': None, 'reason': None,
           'restart': {'request_ms': request['request_ms'], 'command_end_ms': request['command_end_ms'],
                       'old_instance': old['instance'], 'new_instance': new['instance'],
                       'service_started_ms': new['started_ms'], 'service_running': new['running'],
                       'ref': r.digest(request_raw) + ':' + before['sha256'] + ':' + after['sha256']},
           'canary': {'created_ms': event['timestamp_ms'], 'path': cycle['target_path'], 'source_ref': source['sha256']},
           'polls': polls}
    c.check_record(row, plan)
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    cap = sub.add_parser('capture'); cap.add_argument('--lab', action='store_true')
    out = sub.add_parser('export'); out.add_argument('--sha256', required=True)
    for command_parser in (cap, out):
        command_parser.add_argument('--plan', required=True); command_parser.add_argument('--cycle', required=True)
        command_parser.add_argument('--kind', choices=sorted(KINDS), required=True); command_parser.add_argument('--store', required=True)
    join = sub.add_parser('bind'); join.add_argument('--plan', required=True); join.add_argument('--request', required=True)
    join.add_argument('--stores', required=True, help='private JSON object with manager/before/after/source descriptors')
    args = parser.parse_args(argv)
    previous = signal.getsignal(signal.SIGTERM)
    def terminate(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    try:
        plan_raw = c.read_private(args.plan)
        if args.action == 'capture':
            require(args.lab and sys.platform == 'linux', 'LAB_LINUX_REQUIRED')
            result = capture(plan_raw, args.cycle, args.kind, args.store)
        elif args.action == 'export':
            result = export(args.store, args.sha256, plan_raw, args.cycle, args.kind)
        else:
            stores = c.m.strict_json(c.read_private(args.stores).decode())
            c.keys(stores, 'manager before after source', 'BIND_STORES')
            result = bind(plan_raw, c.read_private(args.request), **stores)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0 if result.get('status') != 'failed' else 2
    except KeyboardInterrupt:
        print('UC01_CAPTURE_INTERRUPTED', file=sys.stderr); return 130
    except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError):
        print('UC01_COLLECTION_REJECTED', file=sys.stderr); return 2
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
