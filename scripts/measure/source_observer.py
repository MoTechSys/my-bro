#!/usr/bin/env python3
"""M2-A prospective, read-only file evidence observer (Linux, private local FS).

Exports action_confirmed only: neither a source timestamp nor AR causality.
No target writes, commands, network, retries or authenticity claims. See tests/README.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import signal
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('_source_visibility', Path(__file__).with_name('visibility_observer.py'))
v = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(v)
r = v.r
require = v.require
MAX_FILE = 65536
PRODUCER = 'soc-source-file-v1'
SPEC_KEYS = {'schema_version', 'run_id', 'trial_id', 'device', 'clock_ref',
             'directory', 'filename', 'expected_sha256', 'seconds', 'precision_ms'}
STAT_KEYS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
             'st_size', 'st_mtime_ns', 'st_ctime_ns')
FAILURES = {'SCHEDULING_GAP', 'POLL_GAP', 'CLOCK_JUMP', 'READ_OVERRUN',
            'PRIVATE_SOURCE_REQUIRED', 'SOURCE_CHANGED', 'SOURCE_TOO_LARGE',
            'WRONG_CONTENT', 'SOURCE_DIRECTORY_CHANGED'}


def check_spec(s):
    require(isinstance(s, dict) and set(s) == SPEC_KEYS, 'SPEC_KEYS')
    require(type(s['schema_version']) is int and s['schema_version'] == 1, 'SPEC_VERSION')
    for key in ('run_id', 'trial_id', 'device', 'clock_ref'):
        require(isinstance(s[key], str) and 1 <= len(s[key]) <= 256 and
                all(ord(c) >= 32 for c in s[key]), 'SPEC_TEXT')
    path = s['directory']
    require(isinstance(path, str) and path.startswith('/') and path != '/' and
            len(path) <= 4096 and all(ord(c) >= 32 for c in path) and
            all(p not in ('', '.', '..') for p in path.split('/')[1:]), 'CANONICAL_DIRECTORY')
    r.filename(s['filename']); r.e.sha256(s['expected_sha256'])
    require(type(s['seconds']) is int and 2 <= s['seconds'] <= 120, 'OBSERVATION_LIMIT')
    require(type(s['precision_ms']) is int and 1 <= s['precision_ms'] <= 100, 'CLOCK_PRECISION')
    return s


def target(s):
    return {'syscheck.path': s['directory'] + '/' + s['filename']}


def source_hashes():
    paths = [Path(__file__), Path(v.__file__), *(ROOT/'ai_agent'/n for n in r.SOURCE_NAMES)]
    return {str(p.relative_to(ROOT)): r.digest(p.read_bytes()) for p in paths}


def identity(info):
    return {key: getattr(info, key) for key in STAT_KEYS}


def check_identity(info, size):
    require(isinstance(info, dict) and set(info) == set(STAT_KEYS) and
            all(type(n) is int for n in info.values()), 'SOURCE_CHANGED')
    require(stat.S_ISREG(info['st_mode']) and info['st_nlink'] == 1 and
            info['st_uid'] == os.geteuid() and not info['st_mode'] & 0o077,
            'PRIVATE_SOURCE_REQUIRED')
    require(0 <= info['st_size'] <= MAX_FILE and info['st_size'] == size, 'SOURCE_TOO_LARGE')


def read_source(fd, name):
    """Pinned directory; absent name is distinct from invalid/symlink/FIFO content."""
    try:
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return None, None
    check_identity(identity(before), before.st_size)
    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    with os.fdopen(child, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(identity(before) == identity(opened), 'SOURCE_CHANGED')
        raw = stream.read(MAX_FILE + 1)
        after = os.fstat(stream.fileno())
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        require(identity(before) == identity(after) == identity(named), 'SOURCE_CHANGED')
    check_identity(identity(after), len(raw))
    return raw, identity(after)


def classify(s, polls):
    """Validate recorded timing, not filesystem mtime; first positive is censored."""
    previous = None
    for i, p in enumerate(polls):
        require(set(p) == {'start_ms', 'end_ms', 'start_ns', 'end_ns', 'found', 'sha256', 'identity'}, 'POLL_KEYS')
        require(all(type(p[k]) is int and p[k] >= 0 for k in ('start_ms', 'end_ms', 'start_ns', 'end_ns')),
                'POLL_TIME')
        require(type(p['found']) is bool, 'POLL_FOUND')
        elapsed = p['end_ns'] - p['start_ns']
        require(0 <= elapsed <= int(v.REQUEST_SECONDS * 1e9), 'READ_OVERRUN')
        require(p['end_ms'] >= p['start_ms'] and
                abs((p['end_ms'] - p['start_ms']) * 1e6 - elapsed) <= v.JITTER_NS, 'CLOCK_JUMP')
        if previous is not None:
            gap = p['start_ns'] - previous['start_ns']
            require(abs(gap - v.POLL_NS) <= v.JITTER_NS and p['start_ns'] >= previous['end_ns'], 'POLL_GAP')
            require(abs((p['start_ms'] - previous['start_ms']) * 1e6 - gap) <= v.JITTER_NS, 'CLOCK_JUMP')
        if p['found']:
            require(i == len(polls) - 1 and p['sha256'] == s['expected_sha256'], 'WRONG_CONTENT')
            check_identity(p['identity'], p['identity']['st_size'])
            if previous is None:
                return 'preexisting', None
            return 'observed', {'producer': PRODUCER, 'run_id': s['run_id'], 'trial_id': s['trial_id'],
                'device': s['device'], 'clock_ref': s['clock_ref'], 'stage': 'event', 'kind': 'action_confirmed',
                'timestamp_ms': p['end_ms'], 'precision_ms': p['end_ms'] - previous['start_ms'] + s['precision_ms'],
                'last_negative_start_ms': previous['start_ms'], 'first_positive_end_ms': p['end_ms'],
                'poll_interval_ms': 1000, 'evidence_ref': 'sha256:' + p['sha256'],
                'source_spec_sha256': r.digest(r.json_bytes(s)), 'target_key': target(s)}
        require(p['sha256'] is None and p['identity'] is None, 'ABSENCE_METADATA')
        previous = p
    return 'not_observed', None


def observe(s, store):
    check_spec(s); v.alarm_contract()
    store_path = os.path.abspath(store)
    require(os.path.commonpath([store_path, s['directory']]) not in (store_path, s['directory']),
            'STORE_SOURCE_OVERLAP')
    with r.store_lock(store) as out:
        require(not os.listdir(out), 'NEW_EMPTY_STORE_REQUIRED')
        intent = {'schema_version': 1, 'spec': s, 'source_sha256': source_hashes(), 'acceptance_approved': False}
        intent_raw = r.json_bytes(intent)
        r.write_once(out, 'intent.json', intent_raw)  # durable before any source directory/file access
        terminal = {'status': 'failed', 'reason': 'INTERRUPTED', 'observer': None,
                    'intent_sha256': r.digest(intent_raw), 'poll_count': 0}
        polls = []
        source = None
        try:
            source = v.deadline_call(lambda: r.directory(s['directory']))
            pinned = os.fstat(source)
            start = time.monotonic_ns()
            for i in range(s['seconds'] + 1):
                due = start + i * v.POLL_NS
                time.sleep(max(0, (due - time.monotonic_ns()) / 1e9))
                ns = time.monotonic_ns()
                require(0 <= ns - due <= v.JITTER_NS, 'SCHEDULING_GAP')
                before = time.time_ns() // 1_000_000
                def sample():
                    # Rewalk the trusted path to detect directory replacement between polls.
                    current = r.directory(s['directory'])
                    try:
                        info = os.fstat(current)
                        require((info.st_dev, info.st_ino) == (pinned.st_dev, pinned.st_ino), 'SOURCE_DIRECTORY_CHANGED')
                        return read_source(source, s['filename'])
                    finally:
                        os.close(current)
                raw, info = v.deadline_call(sample)
                after = time.time_ns() // 1_000_000
                end = time.monotonic_ns()
                if raw is not None:
                    r.write_once(out, f'poll-{i:03d}.bin', raw)
                poll = {'start_ms': before, 'end_ms': after, 'start_ns': ns, 'end_ns': end,
                        'found': raw is not None, 'sha256': r.digest(raw) if raw is not None else None, 'identity': info}
                r.write_once(out, f'poll-{i:03d}.json', r.json_bytes(poll))
                polls.append(poll)
                status, row = classify(s, polls)
                terminal.update(status=status, reason=None, observer=row, poll_count=len(polls))
                if status != 'not_observed':
                    break
        except (Exception, v.RequestDeadline) as exc:
            code = 'READ_DEADLINE' if isinstance(exc, v.RequestDeadline) else 'OBSERVATION_FAILED'
            if isinstance(exc, ValueError) and len(exc.args) == 1 and exc.args[0] in FAILURES:
                code = exc.args[0]
            terminal.update(status='failed', reason=code, observer=None, poll_count=len(polls))
        except KeyboardInterrupt:
            terminal.update(status='failed', reason='INTERRUPTED', observer=None, poll_count=len(polls))
            raise
        finally:
            if source is not None:
                os.close(source)
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                r.write_once(out, 'terminal.json', r.json_bytes(terminal))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        return {'status': terminal['status'], 'intent_sha256': terminal['intent_sha256'], 'acceptance_approved': False}


def export(store, expected, *, summary=False):
    """Offline replay of stored bytes only. Failed/partial stores can never emit an event."""
    r.e.sha256(expected)
    with r.store_lock(store) as fd:
        raw = r.read_at(fd, 'intent.json')
        require(r.digest(raw) == expected, 'INTENT_HASH_MISMATCH')
        intent = r.a.strict_json(raw)
        require(isinstance(intent, dict) and set(intent) == {'schema_version', 'spec', 'source_sha256', 'acceptance_approved'}
                and type(intent['schema_version']) is int and intent['schema_version'] == 1
                and intent['acceptance_approved'] is False, 'INTENT_SCHEMA')
        s = check_spec(intent['spec'])
        require(intent['source_sha256'] == source_hashes(), 'SOURCE_CODE_CHANGED')
        try:
            terminal = r.a.strict_json(r.read_at(fd, 'terminal.json'))
        except FileNotFoundError:
            terminal = {'status': 'failed', 'reason': 'INTERRUPTED', 'observer': None,
                        'intent_sha256': expected, 'poll_count': 0}
        require(isinstance(terminal, dict) and set(terminal) == {'status', 'reason', 'observer', 'intent_sha256', 'poll_count'}
                and terminal['intent_sha256'] == expected, 'TERMINAL_SCHEMA')
        n = terminal['poll_count']
        require(type(n) is int and 0 <= n <= s['seconds'] + 1, 'POLL_COUNT')
        if terminal['status'] == 'failed':
            require(terminal['observer'] is None and terminal['reason'] in FAILURES |
                    {'READ_DEADLINE', 'OBSERVATION_FAILED', 'INTERRUPTED'}, 'FAILURE_SCHEMA')
            require(summary, 'INCOMPLETE_OBSERVATION')
            return dict(terminal, acceptance_approved=False, artifacts_verified=False)
        require(terminal['reason'] is None and n > 0, 'INCOMPLETE_OBSERVATION')
        allowed = {'intent.json', 'terminal.json'}
        polls = []
        for i in range(n):
            name = f'poll-{i:03d}'
            allowed.add(name + '.json')
            poll = r.a.strict_json(r.read_at(fd, name + '.json'))
            if poll['found']:
                allowed.add(name + '.bin')
                data = r.read_at(fd, name + '.bin', MAX_FILE)
                require(r.digest(data) == poll['sha256'] == s['expected_sha256'], 'WRONG_CONTENT')
                check_identity(poll['identity'], len(data))
            polls.append(poll)
        require(set(os.listdir(fd)) == allowed, 'UNEXPECTED_STORE_ENTRY')
        status, row = classify(s, polls)
        require(status != 'not_observed' or n == s['seconds'] + 1, 'TRUNCATED_OBSERVATION')
        require(terminal['status'] == status and terminal['observer'] == row, 'TERMINAL_MISMATCH')
        if row is not None:
            row = dict(row, source_intent_sha256=expected)
        if summary:
            return {'status': status, 'observer': row, 'intent_sha256': expected,
                    'acceptance_approved': False, 'artifacts_verified': True}
        return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    preview = commands.add_parser('preview'); preview.add_argument('--spec', required=True)
    run = commands.add_parser('observe'); run.add_argument('--spec', required=True)
    run.add_argument('--store', required=True); run.add_argument('--lab', action='store_true', required=True)
    out = commands.add_parser('export'); out.add_argument('--store', required=True)
    out.add_argument('--intent-sha256', required=True); out.add_argument('--summary', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'preview':
            s = check_spec(v.private_json(args.spec))
            result = {'source_spec_sha256': r.digest(r.json_bytes(s)), 'target_key': target(s), 'source_read': False}
        elif args.action == 'observe':
            result = observe(v.private_json(args.spec), args.store)
        else:
            result = export(args.store, args.intent_sha256, summary=args.summary)
            if result is None:
                return 0
        print(r.json_bytes(result).decode('ascii'), end='')
        return 2 if result.get('status') in ('failed', 'preexisting', 'not_observed') else 0
    except (Exception, v.RequestDeadline):
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
