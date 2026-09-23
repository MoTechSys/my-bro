#!/usr/bin/env python3
"""Offline, non-destructive recovery of a stopped trial_runner pending intent.

Never executes commands, removes pending, modifies the original journal, infers
execution/exit time, or certifies process cleanup. See tests/README recovery.
"""
import argparse
import copy
import fcntl
import importlib.util
import os
from pathlib import Path
import signal
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('_recovery_trial', Path(__file__).with_name('trial_runner.py'))
t = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(t)
r, m = t.so.r, t.m
require = t.so.require
MAX_INPUT = 2 * 1024 * 1024
INPUTS = ('journal.jsonl', 'pending.json', 'manifest.json')
MUTABLE = set(m.TIMES) | {'time_refs', 'missing_reasons', 'event_valid', 'source_ref',
    'source_precision_ms', 'timestamp_precision_ms', 'match_start', 'window_start',
    'window_ref', 'observe_until', 'exclusion_reason', 'reason', 'runner',
    'collected_inputs', 'completion_kind'}


def source_hashes():
    result = t.so.source_hashes()
    for path in (Path(__file__), Path(t.__file__), Path(m.__file__)):
        result[str(path.relative_to(ROOT))] = r.digest(path.read_bytes())
    return result


def read_fd(fd, parent, name):
    before = os.fstat(fd)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            before.st_uid == os.geteuid() and not before.st_mode & 0o077,
            'PRIVATE_REGULAR_INPUT_REQUIRED')
    require(before.st_size <= MAX_INPUT, 'INPUT_TOO_LARGE')
    raw = bytearray()
    while len(raw) <= MAX_INPUT:
        chunk = os.read(fd, min(65536, MAX_INPUT + 1 - len(raw)))
        if not chunk:
            break
        raw.extend(chunk)
    require(len(raw) <= MAX_INPUT, 'INPUT_TOO_LARGE')
    after = os.fstat(fd)
    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(t.so.identity(before) == t.so.identity(after) == t.so.identity(named)
            and len(raw) == before.st_size, 'INPUT_CHANGED')
    return bytes(raw)


def private_read(path):
    path = Path(path).absolute()
    parent = r.directory(path.parent)
    try:
        fd = os.open(r.filename(path.name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        try:
            return read_fd(fd, parent, path.name)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def rows(raw, *, single=False):
    require(len(raw) <= MAX_INPUT, 'INPUT_TOO_LARGE')
    require(not raw or raw.endswith(b'\n'), 'PARTIAL_INPUT_LINE')
    lines = raw.splitlines(keepends=True)
    require(len(lines) <= 20000 and (not single or len(lines) == 1), 'INPUT_ROW_COUNT')
    result = []
    for line in lines:
        require(line.endswith(b'\n'), 'PARTIAL_INPUT_LINE')
        value = r.a.strict_json(line)
        require(isinstance(value, dict), 'INPUT_OBJECT_REQUIRED')
        result.append(value)
    return result


def plan(data, allow_legacy=False, *, journal_path=None):
    """Recompute a full journal; never replace a published row by a failed guess."""
    journal = rows(data['journal.jsonl'])
    pending = rows(data['pending.json'], single=True)[0]
    manifest = r.a.strict_json(data['manifest.json'])
    require(isinstance(manifest, dict), 'MANIFEST_OBJECT_REQUIRED')
    require(type(allow_legacy) is bool, 'LEGACY_FLAG')
    runner = pending.get('runner')
    require(isinstance(runner, dict) and runner.get('state') == 'PREPARED_NOT_COMPLETED'
            and runner.get('mode') in ('lab', 'replay') and isinstance(runner.get('command'), list)
            and all(isinstance(arg, str) for arg in runner['command']), 'PENDING_RUNNER_REQUIRED')
    require(pending.get('event_valid') is False and all(pending.get(k) is None for k in m.TIMES if k != 't0')
            and not {'exit_code', 'timed_out'} & set(runner), 'PENDING_NOT_UNFINISHED')
    expected = runner.get('manifest_sha256')
    if expected is None:
        require(allow_legacy, 'LEGACY_MANIFEST_UNBOUND')
        binding = 'operator_pinned_legacy'
    else:
        r.e.sha256(expected)
        require(expected == r.digest(r.json_bytes(manifest)), 'PENDING_MANIFEST_MISMATCH')
        binding = 'pending_canonical_manifest'
    journal_fields = {'journal_path', 'journal_prefix_bytes', 'journal_prefix_sha256'}
    if not journal_fields & set(runner):
        require(allow_legacy, 'LEGACY_JOURNAL_UNBOUND')
        journal_binding = 'operator_pinned_legacy'
    else:
        require(journal_fields <= set(runner), 'PARTIAL_JOURNAL_BINDING')
        require(isinstance(runner['journal_path'], str) and journal_path is not None and
                runner['journal_path'] == os.path.abspath(journal_path), 'PENDING_JOURNAL_PATH_MISMATCH')
        n = runner['journal_prefix_bytes']
        require(type(n) is int and 0 <= n <= len(data['journal.jsonl']), 'PENDING_JOURNAL_PREFIX_LENGTH')
        r.e.sha256(runner['journal_prefix_sha256'])
        prefix = data['journal.jsonl'][:n]
        require(r.digest(prefix) == runner['journal_prefix_sha256'], 'PENDING_JOURNAL_PREFIX_MISMATCH')
        rows(prefix)
        suffix = rows(data['journal.jsonl'][n:])
        require(len(suffix) <= 1 and all((row.get('run_id'), row.get('trial_id')) ==
                (pending.get('run_id'), pending.get('trial_id')) for row in suffix), 'JOURNAL_SUFFIX_CONFLICT')
        require(not any((row.get('run_id'), row.get('trial_id')) ==
                (pending.get('run_id'), pending.get('trial_id')) for row in rows(prefix)), 'PENDING_ALREADY_IN_PREFIX')
        journal_binding = 'pending_path_and_prefix'
    pending_hash = r.digest(data['pending.json'])
    identity = (pending.get('run_id'), pending.get('trial_id'))
    seen = set()
    existing = None
    for row in journal:
        key = (row.get('run_id'), row.get('trial_id'))
        require(key not in seen, 'DUPLICATE_JOURNAL_IDENTITY')
        seen.add(key)
        if key == identity:
            existing = row
    recovered = copy.deepcopy(pending)
    recovered.update(event_valid=False, source_ref='recovery:sha256:' + pending_hash,
                     exclusion_reason=pending.get('exclusion_reason') or 'INVALID',
                     reason=pending.get('reason') if pending.get('exclusion_reason') else 'INTERRUPTED_AFTER_PREPARED_INTENT')
    recovered['runner'].update(state='RECOVERED_INTERRUPTED', exit_code=None, timed_out=None)
    recovered['recovery'] = {'schema_version': 1, 'pending_sha256': pending_hash,
        'journal_sha256': r.digest(data['journal.jsonl']), 'manifest_sha256': r.digest(data['manifest.json']),
        'manifest_binding': binding, 'journal_binding': journal_binding, 'execution_started': None, 'process_cleanup_verified': False,
        'window_kind': 'predeclared_not_observed'}
    # Only the original t0 is retained. Other timestamps and times of failure are never invented.
    for key in m.TIMES:
        if key != 't0':
            recovered[key] = None
            recovered['time_refs'].pop(key, None)
            recovered['missing_reasons'][key] = 'INTERRUPTED_NOT_OBSERVED'
    if existing is not None:
        require({k: v for k, v in pending.items() if k not in MUTABLE} ==
                {k: existing.get(k) for k in pending if k not in MUTABLE}, 'EXISTING_TRIAL_CONFLICT')
        require(existing.get('t0') == pending.get('t0'), 'EXISTING_TRIAL_CONFLICT')
        er = existing.get('runner', {})
        require(er.get('state') in ('COLLECTED', 'COLLECTION_FAILED', 'RECOVERED_INTERRUPTED') and
                all(er.get(k) == runner.get(k) for k in ('mode', 'command', 'manifest_sha256', 'journal_path',
                                                           'journal_prefix_bytes', 'journal_prefix_sha256')), 'EXISTING_RUNNER_CONFLICT')
        if er.get('state') == 'RECOVERED_INTERRUPTED':
            require(existing.get('recovery', {}).get('pending_sha256') == pending_hash, 'EXISTING_RECOVERY_CONFLICT')
        disposition, output, combined = 'already_recorded', data['journal.jsonl'], journal
    else:
        disposition, output, combined = 'appended_interrupted', data['journal.jsonl'] + t.encoded(recovered), journal + [recovered]
    require(len(output) <= r.MAX_ARTIFACT, 'OUTPUT_TOO_LARGE')
    require(all(row.get('phase') != 'BASELINE' and row.get('uc') != 'UC-01' for row in combined), 'ACTION_JOURNAL_ONLY')
    # Validate the pending row even when already recorded. No metrics/report is
    # emitted here: original alert exports are intentionally not read by recovery.
    m.analyze_v2([(recovered, 'pending')], [], manifest)
    m.analyze_v2([(row, 'journal:' + str(i)) for i, row in enumerate(combined)], [], manifest)
    return output, {'disposition': disposition, 'row_count': len(combined), 'pending_sha256': pending_hash,
                    'manifest_binding': binding, 'journal_binding': journal_binding, 'output_sha256': r.digest(output)}


def recover(journal, manifest, store, pins, *, operator_stopped=False, allow_legacy=False):
    require(operator_stopped is True, 'STOPPED_OPERATOR_ASSERTION_REQUIRED')
    require(type(allow_legacy) is bool and isinstance(pins, dict) and set(pins) == set(INPUTS), 'PINS_REQUIRED')
    for digest in pins.values(): r.e.sha256(digest)
    journal, manifest, store = (Path(p).absolute() for p in (journal, manifest, store))
    pending = Path(str(journal) + '.pending')
    require(all(os.path.commonpath([str(store), str(p)]) != str(store) for p in (journal, pending, manifest)),
            'STORE_INPUT_OVERLAP')
    with r.store_lock(store) as out:
        require(not os.listdir(out), 'NEW_EMPTY_STORE_REQUIRED')
        intent = {'schema_version': 1, 'journal_path': str(journal), 'manifest_path': str(manifest),
                  'pins': pins, 'source_sha256': source_hashes(), 'operator_asserted_stopped': True,
                  'allow_legacy': allow_legacy, 'process_cleanup_verified': False, 'acceptance_approved': False}
        raw = r.json_bytes(intent)
        r.write_once(out, 'intent.json', raw)
        terminal = {'status': 'failed', 'reason': 'RECOVERY_INCOMPLETE', 'intent_sha256': r.digest(raw), 'result': None}
        try:
            parent = r.directory(journal.parent)
            try:
                fd = os.open(r.filename(journal.name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    data = {'journal.jsonl': read_fd(fd, parent, journal.name),
                            'pending.json': private_read(pending), 'manifest.json': private_read(manifest)}
                    require(all(r.digest(data[name]) == pins[name] for name in INPUTS), 'INPUT_HASH_MISMATCH')
                    for name in INPUTS: r.write_once(out, name, data[name])
                    output, result = plan(data, allow_legacy, journal_path=str(journal))
                    r.write_once(out, 'attempts.jsonl', output)
                    terminal.update(status='completed', reason=None, result=result)
                finally:
                    os.close(fd)
            finally:
                os.close(parent)
        except Exception:
            terminal.update(status='failed', reason='RECOVERY_REJECTED', result=None)
        except KeyboardInterrupt:
            terminal.update(status='failed', reason='RECOVERY_INTERRUPTED', result=None)
            raise
        finally:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try: r.write_once(out, 'terminal.json', r.json_bytes(terminal))
            finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        return {'status': terminal['status'], 'intent_sha256': terminal['intent_sha256'], 'acceptance_approved': False}


def export(store, expected, *, summary=False, output_path=None):
    require(not (summary and output_path is not None), 'CHOOSE_SUMMARY_OR_OUTPUT')
    r.e.sha256(expected)
    with r.store_lock(store) as fd:
        raw = r.read_at(fd, 'intent.json')
        require(r.digest(raw) == expected, 'INTENT_HASH_MISMATCH')
        intent = r.a.strict_json(raw)
        require(isinstance(intent, dict) and set(intent) == {'schema_version', 'journal_path', 'manifest_path',
                'pins', 'source_sha256', 'operator_asserted_stopped', 'allow_legacy', 'process_cleanup_verified',
                'acceptance_approved'} and type(intent['schema_version']) is int and intent['schema_version'] == 1
                and intent['operator_asserted_stopped'] is True and intent['process_cleanup_verified'] is False
                and intent['acceptance_approved'] is False and type(intent['allow_legacy']) is bool, 'INTENT_SCHEMA')
        require(intent['source_sha256'] == source_hashes() and set(intent['pins']) == set(INPUTS), 'CODE_OR_PINS_CHANGED')
        for digest in intent['pins'].values(): r.e.sha256(digest)
        try: terminal = r.a.strict_json(r.read_at(fd, 'terminal.json'))
        except FileNotFoundError:
            terminal = {'status': 'failed', 'reason': 'RECOVERY_INCOMPLETE', 'intent_sha256': expected, 'result': None}
        require(isinstance(terminal, dict) and set(terminal) == {'status', 'reason', 'intent_sha256', 'result'}
                and terminal['intent_sha256'] == expected, 'TERMINAL_SCHEMA')
        if terminal['status'] == 'failed':
            require(summary and terminal['result'] is None and terminal['reason'] in
                    ('RECOVERY_INCOMPLETE', 'RECOVERY_REJECTED', 'RECOVERY_INTERRUPTED'), 'INCOMPLETE_RECOVERY')
            return dict(terminal, artifacts_verified=False, acceptance_approved=False)
        require(terminal['status'] == 'completed' and terminal['reason'] is None, 'TERMINAL_STATE')
        require(set(os.listdir(fd)) == {'intent.json', 'terminal.json', 'attempts.jsonl', *INPUTS}, 'UNEXPECTED_STORE_ENTRY')
        data = {name: r.read_at(fd, name, MAX_INPUT) for name in INPUTS}
        require(all(r.digest(data[name]) == intent['pins'][name] for name in INPUTS), 'INPUT_HASH_MISMATCH')
        output, result = plan(data, intent['allow_legacy'], journal_path=intent['journal_path'])
        require(result == terminal['result'] and output == r.read_at(fd, 'attempts.jsonl'), 'RECOVERY_OUTPUT_MISMATCH')
        if output_path is not None:
            destination = Path(os.path.abspath(output_path))
            sealed = os.path.abspath(store)
            require(os.path.commonpath([sealed, str(destination)]) != sealed, 'OUTPUT_INSIDE_RECOVERY_STORE')
            forbidden = {os.path.abspath(intent['journal_path']), os.path.abspath(intent['manifest_path']),
                         os.path.abspath(intent['journal_path'] + '.pending')}
            require(str(destination) not in forbidden, 'OUTPUT_ALIASES_ORIGINAL')
            parent = r.directory(destination.parent)
            try:
                name = r.filename(destination.name)
                try: os.stat(name + '.pending', dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: pass
                else: raise ValueError('DESTINATION_PENDING_EXISTS')
                r.write_once(parent, name, output)
            finally:
                os.close(parent)
            return {'status': 'completed', 'intent_sha256': expected, 'output_sha256': result['output_sha256'],
                    'row_count': result['row_count'], 'acceptance_approved': False}
        if summary:
            return {'status': 'completed', 'intent_sha256': expected, 'result': result,
                    'artifacts_verified': True, 'process_cleanup_verified': False, 'acceptance_approved': False}
        return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    run = commands.add_parser('recover')
    for key in ('journal', 'manifest', 'store', 'journal-sha256', 'pending-sha256', 'manifest-sha256'):
        run.add_argument('--' + key, required=True)
    run.add_argument('--operator-stopped', action='store_true', required=True)
    run.add_argument('--allow-legacy-unbound', action='store_true')
    out = commands.add_parser('export'); out.add_argument('--store', required=True)
    out.add_argument('--intent-sha256', required=True)
    destination = out.add_mutually_exclusive_group()
    destination.add_argument('--summary', action='store_true')
    destination.add_argument('--output', help='new private continuation journal; never overwrite originals or store')
    args = parser.parse_args(argv)
    try:
        if args.action == 'recover':
            result = recover(args.journal, args.manifest, args.store,
                dict(zip(INPUTS, (args.journal_sha256, args.pending_sha256, args.manifest_sha256))),
                operator_stopped=args.operator_stopped, allow_legacy=args.allow_legacy_unbound)
        else:
            result = export(args.store, args.intent_sha256, summary=args.summary, output_path=args.output)
        if isinstance(result, bytes): sys.stdout.buffer.write(result); return 0
        print(r.json_bytes(result).decode('ascii'), end='')
        return 0 if result['status'] == 'completed' else 2
    except Exception:
        print('{"status":"rejected","acceptance_approved":false}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    def interrupted(*_): raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    try: raise SystemExit(main())
    except KeyboardInterrupt: raise SystemExit(130)
