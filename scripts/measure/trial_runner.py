#!/usr/bin/env python3
"""Guarded Linux orchestrator for T-11; stdlib only, not native lab acceptance.

Read TEST_PLAN section 3.4 before use. Local/exported logs only; no SSH,
credentials or implicit observer execution. --replay never runs a command.
"""
import argparse
import copy
from datetime import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

_spec = importlib.util.spec_from_file_location('measurement', Path(__file__).with_name('mttd.py'))
m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(m)


def document(path):
    with open(path, 'rb') as stream:
        raw = stream.read(m.MAX_LINE + 1)
    m.require(len(raw) <= m.MAX_LINE, 'configuration exceeds size bound')
    result = m.strict_json(raw.decode('utf-8'))
    m.require(isinstance(result, dict), 'configuration must be an object')
    return result


def snapshot(paths):
    """Explicit rotation paths; hash exactly the bytes parsed, never skip errors."""
    rows, provenance, total = [], [], 0
    for path in paths:
        digest = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, 'rb') as stream:
            m.require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'logs must be regular files')
            for line, raw in enumerate(iter(lambda: stream.readline(m.MAX_LINE + 1), b''), 1):
                total += len(raw)
                m.require(len(raw) <= m.MAX_LINE and total <= m.MAX_BYTES, 'log size bound exceeded')
                m.require(raw.endswith(b'\n'), 'incomplete log line; retain invalid attempt and review export')
                digest.update(raw)
                rows.append((raw.decode('utf-8').rstrip('\r\n'), f'{path}:{line}'))
                m.require(len(rows) <= m.MAX_RECORDS, 'log record bound exceeded')
        provenance.append({'path': str(path), 'sha256': digest.hexdigest()})
    return rows, provenance


def exact(row, target):
    return all(type(m.field(row, k)) is type(v) and m.field(row, k) == v for k, v in target.items())


def source_events(config, lines):
    """JSON/EVE (exact fields), audit serial+PID, Apache exact request URI.

    Generic JSON requires a reviewed event timestamp, never mtime/stat. Plain
    audit serial and PID must be independently obtained, not guessed in advance.
    """
    kind = config['format']
    events = []
    for raw, ref in lines:
        if kind == 'json':
            row = m.strict_json(raw)
            m.require(isinstance(row, dict), 'source JSON must be object')
            if not exact(row, config['target_key']):
                continue
            value = m.field(row, config['timestamp_field'])
            at = m.epoch_ms(value) if config.get('timestamp_unit') == 'epoch_ms' else m.to_ms(value)
        elif kind == 'audit':
            match = re.search(r'\bmsg=audit\((\d+)(?:\.(\d{1,9}))?:(\d+)\)', raw)
            pid = re.search(r'(?:^|\s)pid=(\d+)(?:\s|$)', raw)
            if not match or not pid or match[3] != config['serial'] or pid[1] != config['pid']:
                continue
            at = int(match[1]) * 1000 + int(((match[2] or '') + '000')[:3])
        elif kind == 'apache':
            match = re.match(r'^(\S+) .*?\[([^]]+)\] "([A-Z]+) (\S+) HTTP/[^"]+"', raw)
            if not match or match[1] != config['client_ip'] or match[4] != config['request_uri']:
                continue
            at = m.to_ms(datetime.strptime(match[2], '%d/%b/%Y:%H:%M:%S %z').isoformat())
        else:
            raise m.InputError('unsupported source format')
        events.append((at, ref))
    return events


def set_time(trial, stage, value, ref):
    trial[stage] = value
    trial['time_refs'][stage] = ref
    trial['missing_reasons'].pop(stage, None)


def collect(trial, run, source, sources, alerts, observers):
    """Collect within the declared observation window, preserving missing data."""
    provenance = []
    visibility_identity = None
    trial['timestamp_precision_ms'] = {}
    start = m.to_ms(trial.get('match_start', trial['window_start']))
    end = m.to_ms(trial['observe_until'])
    manager_offset = trial['ntp_offset_ms'][run['clock_map']['t2']]

    def in_window(value, device):
        manager_time = value - trial['ntp_offset_ms'][device] + manager_offset
        return start <= manager_time <= end

    if source:
        lines, hashes = snapshot(sources); provenance.extend(hashes)
        found = [(at, ref) for at, ref in source_events(source, lines)
                 if in_window(at, run['clock_map']['t1'])]
        if found:
            at, ref = min(found)
            set_time(trial, 't1', at, ref)
            trial.update(event_valid=True, source_ref=ref,
                         source_precision_ms=source['precision_ms'])
            trial['timestamp_precision_ms']['t1'] = source['precision_ms']
    if observers:
        lines, hashes = snapshot(observers); provenance.extend(hashes)
        kinds = {'t1': 'source_event', 't3': 'indexer_first_visible',
                 't4': 'endpoint_start', 't5': 'independent_observation',
                 'event': 'action_confirmed'}
        candidates = {}
        for raw, ref in lines:
            row = m.strict_json(raw)
            m.require(isinstance(row, dict), 'observer must be object')
            if (row.get('run_id'), row.get('trial_id')) != (trial['run_id'], trial['trial_id']):
                continue
            stage = row.get('stage')
            m.require(stage in kinds and row.get('kind') == kinds[stage], 'invalid observer stage/kind')
            device = row.get('device')
            m.require(device in run['devices'], 'unknown observer clock')
            if stage != 'event':
                m.require(device == run['clock_map'][stage], 'observer clock disagrees with clock_map')
            at = m.epoch_ms(row.get('timestamp_ms'))
            m.text(row.get('evidence_ref'), 'observer evidence_ref')
            m.number(row.get('precision_ms'), 'observer precision', 0)
            if stage == 't3':
                m.require(row.get('poll_interval_ms') == 1000, 'visibility observer must poll every second')
            if not in_window(at, device):
                continue
            if stage in candidates and candidates[stage][0] != row:
                trial.update(exclusion_reason='AMBIGUOUS', reason='CONFLICTING_OBSERVER_STAGE:' + stage)
                continue
            candidates[stage] = (row, ref)
        for stage, (row, ref) in candidates.items():
            if stage in {'event', 't1'}:
                trial.update(event_valid=True, source_ref=ref)
            if stage == 'event':
                continue
            else:
                if trial[stage] is not None and trial[stage] != row['timestamp_ms']:
                    trial.update(exclusion_reason='AMBIGUOUS', reason='SOURCE_OBSERVER_DISAGREEMENT:' + stage)
                else:
                    set_time(trial, stage, row['timestamp_ms'], ref)
                trial['timestamp_precision_ms'][stage] = row['precision_ms']
                if stage == 't3':
                    visibility_identity = (row.get('manager_name'), row.get('alert_id'))
                if stage == 't5':
                    trial['completion_kind'] = 'independent_observation'
    lines, hashes = snapshot(alerts); provenance.extend(hashes)
    alert_rows = [(m.strict_json(raw), ref) for raw, ref in lines]
    normalized, _ = m.normalize_alerts(alert_rows)
    for stage, selector in trial['stage_selectors'].items():
        found = [a for a in normalized if a['raw']['manager']['name'] == run['manager_name']
                 and a['raw']['agent']['id'] == run['agent_id']
                 and a['raw']['agent']['name'] == run['agent_name']
                 and a['raw']['rule']['id'] in selector['rule_ids']
                 and a['raw']['rule']['level'] in selector['levels']
                 and start <= m.to_ms(a['raw']['timestamp']) <= end
                 and exact(a['raw'], selector['target_key'])]
        if found:
            set_time(trial, stage, m.to_ms(found[0]['raw']['timestamp']), found[0]['refs'][0])
        if stage == 't2' and visibility_identity is not None:
            m.require(found and visibility_identity == found[0]['key'],
                      'visibility observer must reference the selected t2 alert identity')
    trial['collected_inputs'] = provenance
    # An exit code alone never establishes ground truth; sensor misses need an
    # independent action_confirmed observer to remain valid detection attempts.
    if not trial.get('event_valid') and trial['exclusion_reason'] is None:
        trial.update(exclusion_reason='INVALID', reason='EVENT_NOT_INDEPENDENTLY_VERIFIED')
    return alert_rows


def secure_open(path, flags):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise m.InputError('output must be a regular single-link file')
    return fd


def write_all(fd, data):
    while data:
        count = os.write(fd, data)
        m.require(count > 0, 'short output write')
        data = data[count:]
    os.fsync(fd)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def execute(command, timeout):
    """No shell/eval. Bound the direct child and clean its entire process group."""
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        return {'exit_code': child.wait(timeout=timeout), 'timed_out': False}
    except subprocess.TimeoutExpired:
        return {'exit_code': None, 'timed_out': True}
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


def prepare_eicar(trial, directory, source=None):
    """Bind one immutable session/run/trial identity to argv and exact selectors.

    No file creation here. The reviewed script retains the approved-root and
    no-follow/exclusive guards. Same identity replays the same path; never rerun
    an old identity after cleanup. Independent journals must not reuse identities.
    """
    m.require(trial['uc'] == 'UC-03', '--eicar-dir is UC-03 only')
    m.require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', trial['trial_id'], re.ASCII),
              'EICAR trial_id requires 1..64 safe ASCII characters')
    root = '/home/kali/SOCfile'
    m.require(directory == root or directory.startswith(root + '/'), 'EICAR directory outside approved root')
    m.require(all(part not in {'', '.', '..'} and not any(ord(c) < 32 for c in part)
                  for part in directory.split('/')[1:]), 'non-canonical EICAR directory')
    identity = json.dumps([trial['session_id'], trial['run_id'], trial['trial_id']], ensure_ascii=True)
    key = trial['trial_id'][:32] + '_' + hashlib.sha256(identity.encode('utf-8')).hexdigest()[:32]
    path = directory + '/eicar_' + key + '.com'
    selectors = [trial['target_key']] + [s['target_key'] for s in trial['stage_selectors'].values()]
    if source is not None:
        m.require(source.get('format') == 'json', 'EICAR source requires JSON or external observers')
        selectors.append(source['target_key'])
    for target in selectors:
        for field, value in target.items():
            if value == '__EICAR_PATH__':
                target[field] = path
    m.require(trial['target_key'].get('data.virustotal.source.file') == path,
              'EICAR final target must use the generated path')
    for stage, field in [('t2', 'syscheck.path'), ('t2_prime', 'data.virustotal.source.file')]:
        m.require(trial['stage_selectors'].get(stage, {}).get('target_key', {}).get(field) == path,
                  'EICAR ' + stage + ' selector must use generated path')
    for target in selectors:
        for field in ('path', 'syscheck.path', 'data.virustotal.source.file', 'data.yara_scanned_file'):
            m.require(field not in target or target[field] == path, 'EICAR correlation path disagreement')
    trial['eicar_path'] = path
    trial['eicar_trial_key'] = key
    return [str(Path(__file__).resolve().parents[1] / 'attack-emulation/eicar_test.sh'),
            '--lab', directory, key]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--lab', action='store_true', help='explicit authorization for reviewed isolated-lab command')
    mode.add_argument('--replay', action='store_true', help='collect recorded evidence only; never execute')
    parser.add_argument('--spec', required=True, help='object: attempt, optional source adapter')
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--output', required=True, help='append-only attempts JSONL outside monitored paths')
    parser.add_argument('--alerts', required=True, nargs='+', help='explicit local/exported rotation files')
    parser.add_argument('--source', nargs='*', default=[])
    parser.add_argument('--observers', nargs='*', default=[])
    parser.add_argument('--eicar-dir', help='UC-03 built-in unique EICAR attempt, replaces command; existing approved directory')
    parser.add_argument('--device', help='live runner clock device; must equal clock_map.t0')
    parser.add_argument('--timeout', type=float, default=60, help='child timeout seconds, max 3600')
    parser.add_argument('--wait', type=float, default=300, help='post-command evidence window seconds, max 3600')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    pending = None
    try:
        command = args.command[1:] if args.command[:1] == ['--'] else args.command
        m.require((args.lab and (command or args.eicar_dir)) or (args.replay and not command), 'command needs --lab; replay forbids commands')
        m.require(not (args.eicar_dir and command), '--eicar-dir cannot be combined with arbitrary command')
        for value in (args.timeout, args.wait):
            m.number(value, 'timeout/wait', 0.001)
            m.require(value <= 3600, 'timeout/wait exceeds one hour')
        spec, manifest = document(args.spec), document(args.manifest)
        trial = copy.deepcopy(spec['attempt'])
        run = next(r for r in manifest['runs'] if r['run_id'] == trial['run_id'])
        source = spec.get('source')
        if args.eicar_dir:
            eicar_command = prepare_eicar(trial, args.eicar_dir, source)
            if args.lab:
                command = eicar_command
        m.require(bool(source) == bool(args.source), 'source adapter and source files must be supplied together')
        if source:
            m.require(source['format'] in {'json', 'audit', 'apache'}, 'unsupported source format')
            m.number(source.get('precision_ms'), 'source precision_ms', 0)
            required = {'json': ('target_key', 'timestamp_field'), 'audit': ('serial', 'pid'),
                        'apache': ('client_ip', 'request_uri')}[source['format']]
            m.require(all(source.get(k) for k in required), 'source correlation fields required')
            if source['format'] == 'json':
                target = source['target_key']
                m.require(isinstance(target, dict) and all(isinstance(k, str) and type(v) in (str, int)
                                                          for k, v in target.items()), 'invalid source exact fields')
                m.require('path' in target or 'syscheck.path' in target or len(target) >= 2,
                          'source needs unique path or at least two exact fields')
                m.require(source.get('timestamp_unit', 'iso8601') in {'iso8601', 'epoch_ms'},
                          'unknown source timestamp unit')
        # Validate before executing anything. Null out measured stages so caller
        # cannot inject pre-filled success evidence into a newly collected trial.
        for key in m.TIMES:
            if key != 't0':
                trial[key] = None
        trial['time_refs'] = {'t0': trial.get('time_refs', {}).get('t0', 'runner pending')}
        trial['missing_reasons'] = {k: 'NOT_OBSERVED_OR_NOT_APPLICABLE' for k in m.TIMES}
        trial['event_valid'] = True  # structural validation only; reset before collection
        trial['source_ref'] = 'preflight structure only'
        m.require(trial['phase'] != 'BASELINE' and trial['uc'] != 'UC-01', 'runner handles action trials only')
        checked = m.analyze_v2([(trial, args.spec)], [], manifest)
        if trial['session_id'] in checked['rejected_sessions']:
            trial.update(exclusion_reason='INVALID', reason='SESSION_CLOCK_LIMIT_EXCEEDED')
        if args.lab:
            m.require(args.device == run['clock_map']['t0'], 'live --device must equal clock_map.t0')
            m.require(args.wait >= trial['window_s'], 'wait must cover the detection window')
            offsets = trial['ntp_offset_ms']
            shift = -offsets[run['clock_map']['t0']] + offsets[run['clock_map']['t2']]
            now = time.time_ns() // 1000000 + shift
            m.require(m.to_ms(run['coverage_start']) <= now and
                      now + (args.timeout + args.wait + 5) * 1000 <= m.to_ms(run['coverage_end']),
                      'manifest coverage must span planned live execution and observation')
        trial['event_valid'] = False
        output = Path(args.output).absolute()
        inputs = [args.spec, args.manifest] + args.alerts + args.source + args.observers
        m.require(all(output.resolve() != Path(p).resolve() for p in inputs), 'output aliases an input')
        fd = secure_open(output, os.O_CREAT | os.O_RDWR | os.O_APPEND)
        with os.fdopen(fd, 'r+b', buffering=0) as journal:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            # Lock is held through execution; same-output concurrent runs fail closed.
            existing, _ = m.read_jsonl([output])
            m.require(not any((r.get('run_id'), r.get('trial_id')) == (trial['run_id'], trial['trial_id'])
                              for r, _ in existing), 'duplicate trial; no rerun with same identity')
            prior = m.analyze_v2(existing + [(dict(trial, event_valid=True), 'preflight')], [], manifest)
            if trial['session_id'] in prior['rejected_sessions']:
                trial.update(exclusion_reason='INVALID', reason='SESSION_CLOCK_LIMIT_EXCEEDED')
            # Never join a partially written last line after a prior crash.
            if os.fstat(fd).st_size:
                journal.seek(-1, os.SEEK_END)
                m.require(journal.read(1) == b'\n', 'incomplete output journal; manual recovery required')
            pending = Path(str(output) + '.pending')
            pfd = secure_open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(pfd, 'wb', buffering=0):
                if args.lab:
                    trial['t0'] = time.time_ns() // 1000000
                    trial['time_refs']['t0'] = str(output) + '#' + trial['run_id'] + '/' + trial['trial_id'] + '/t0'
                trial['runner'] = {'mode': 'lab' if args.lab else 'replay', 'command': command,
                                   'state': 'PREPARED_NOT_COMPLETED'}
                write_all(pfd, encoded(trial))  # durable launch intent BEFORE command
            try:
                if args.lab and trial['exclusion_reason'] is None:
                    trial['runner'].update(execute(command, args.timeout))
                    offsets = trial['ntp_offset_ms']
                    shift = -offsets[run['clock_map']['t0']] + offsets[run['clock_map']['t2']]
                    start = trial['t0'] + shift
                    anchor = time.time_ns() // 1000000 + shift if trial['uc'] == 'UC-04' else start
                    trial.update(match_start=m.iso_ms(round(start)), window_start=m.iso_ms(round(anchor)),
                                 window_ref=trial['time_refs']['t0'])
                    time.sleep(args.wait)
                    trial['observe_until'] = m.iso_ms(round(time.time_ns() // 1000000 + shift))
                alert_rows = collect(trial, run, source, args.source, args.alerts, args.observers)
                # Include previous trials: a new offset violation invalidates ALL
                # rows in the report, without rewriting the append-only raw journal.
                result = m.analyze_v2(existing + [(trial, 'runner')], alert_rows, manifest)
                current = result['trials'][-1]
                trial['exclusion_reason'] = current['exclusion_reason']
                if trial['exclusion_reason']:
                    trial['reason'] = current['reason']
                trial['runner']['state'] = 'COLLECTED'
            except (OSError, ValueError, KeyError, TypeError, OverflowError, KeyboardInterrupt) as exc:
                trial.update(exclusion_reason='INVALID', reason='RUNNER_ERROR:' + str(exc))
                trial['runner']['state'] = 'COLLECTION_FAILED'
            write_all(fd, encoded(trial))
            pending.unlink()
        print(json.dumps({'run_id': trial['run_id'], 'trial_id': trial['trial_id'],
                          'exclusion_reason': trial['exclusion_reason'], 'output': str(output)}))
        return 2 if trial['exclusion_reason'] else 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError, StopIteration) as exc:
        print('trial runner error: ' + str(exc), file=sys.stderr)
        return 2


def interrupted(signum, frame):
    """Allow process-group cleanup and failed-attempt persistence on SIGTERM."""
    raise KeyboardInterrupt('termination requested')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    raise SystemExit(main())
