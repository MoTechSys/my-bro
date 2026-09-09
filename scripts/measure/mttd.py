#!/usr/bin/env python3
"""T-11 detection core. Owner: ASTRA; 2026-09-09; local candidate.
Source: tests/TEST_PLAN.md. Offline only; not a source-evidence verifier.
AR, baseline adjudication and UC-01 connection metrics are explicitly pending.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import sys

MAX_LINE = 2 * 1024 * 1024
MAX_RECORDS = 200000
MAX_BYTES = 64 * 1024 * 1024
MAX_COMPARISONS = 5000000
PHASES = {'PILOT', 'MEASURED', 'BASELINE', 'SUPPRESSION_CONTROL'}
EXCLUDED = {'BLOCKED', 'INVALID', 'INTERFERED', 'AMBIGUOUS'}
PENDING = ['AR metrics', 'baseline adjudication and FP/hour',
           'UC-01 connection verification', 'native source evidence adapters',
           'independent review and real laboratory acceptance']


class InputError(ValueError):
    """Invalid input must prevent publication of a successful report."""


def require(condition, message):
    if not condition:
        raise InputError(message)


def text(value, label):
    require(isinstance(value, str) and bool(value.strip()), label + ': string required')
    return value


def number(value, label, minimum=None):
    require(type(value) in (int, float) and math.isfinite(value), label + ': finite number required')
    require(minimum is None or value >= minimum, label + ': below minimum')
    return value


def stamp(value):
    text(value, 'timestamp')
    require(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:?\d{2})', value),
            'timestamp: ISO 8601 with timezone and <=6 fractional digits required')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(result.utcoffset() is not None, 'timestamp: timezone required')
        return result.astimezone(timezone.utc)
    except ValueError as exc:
        raise InputError('timestamp: invalid calendar/time value') from exc


def field(record, key):
    value = record
    for part in key.split('.'):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(_):
        raise InputError('non-finite JSON constant')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def read_jsonl(paths):
    """Read exact supplied rotation files; no wildcard expansion or silent skips."""
    rows, provenance = [], []
    total_bytes = 0
    for path in paths:
        digest = hashlib.sha256()
        with Path(path).open('rb') as stream:
            line_no = 0
            while True:
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    break
                line_no += 1
                ref = f'{path}:{line_no}'
                require(len(raw) <= MAX_LINE, ref + ': line too large')
                total_bytes += len(raw)
                require(total_bytes <= MAX_BYTES, "input byte bound exceeded")
                digest.update(raw)
                try:
                    row = strict_json(raw.decode('utf-8'))
                    require(isinstance(row, dict), 'object required; blank lines are invalid')
                except (ValueError, UnicodeError) as exc:
                    raise InputError(ref + ': ' + str(exc)) from exc
                rows.append((row, ref))
                require(len(rows) <= MAX_RECORDS, 'input record bound exceeded')
        provenance.append({'path': str(path), 'sha256': digest.hexdigest(), 'lines': line_no})
    return rows, provenance


def load_runs(manifest):
    require(isinstance(manifest, dict) and type(manifest.get('version')) is int and manifest['version'] == 1, 'manifest version must be 1')
    require(isinstance(manifest.get('runs'), list) and manifest['runs'], 'manifest.runs required')
    runs = {}
    for run in manifest['runs']:
        require(isinstance(run, dict), 'run must be object')
        for key in ('run_id', 'agent_id', 'agent_name', 'manager_name', 'os',
                    'config_commit', 'config_sha256', 'timing_definition', 'coverage_ref'):
            text(run.get(key), 'run.' + key)
        require(re.fullmatch('[0-9a-f]{40}', run['config_commit']), 'full git commit required')
        require(re.fullmatch('[0-9a-f]{64}', run['config_sha256']), 'config SHA256 required')
        require(run.get('latency_kind') in {'DETECTION', 'INTEGRATION'}, 'latency_kind must be DETECTION or INTEGRATION')
        require(run['run_id'] not in runs, 'duplicate run_id')
        require(stamp(run['coverage_start']) < stamp(run['coverage_end']), 'invalid coverage interval')
        require(type(run.get('clock_verified')) is bool, 'clock_verified must be boolean')
        if run['clock_verified']:
            text(run.get('clock_ref'), 'clock_ref')
            number(run.get('clock_offset_ms'), 'clock_offset_ms')
            number(run.get('clock_uncertainty_ms'), 'clock_uncertainty_ms', 0)
        runs[run['run_id']] = run
    return runs


def normalize_alerts(rows):
    alerts, seen, duplicate_count = [], {}, 0
    for raw, ref in rows:
        for key in ('id', 'manager.name', 'agent.id', 'agent.name', 'rule.id'):
            text(field(raw, key), ref + ':' + key)
        number(field(raw, 'rule.level'), ref + ':rule.level', 0)
        require(type(field(raw, 'rule.level')) is int and field(raw, 'rule.level') <= 16,
                ref + ':rule.level must be integer 0..16')
        at = stamp(raw.get('timestamp'))
        key = (raw['manager']['name'], raw['id'])
        if key in seen:
            require(seen[key]['raw'] == raw, ref + ': conflicting duplicate alert identity')
            seen[key]['refs'].append(ref)
            duplicate_count += 1
            continue
        item = {'raw': raw, 'at': at, 'key': key, 'refs': [ref]}
        seen[key] = item
        alerts.append(item)
    return sorted(alerts, key=lambda a: (a['at'], a['key'])), duplicate_count


def validate_trial(trial, runs):
    for key in ('run_id', 'trial_id', 'uc', 'variant', 'phase', 'status'):
        text(trial.get(key), 'trial.' + key)
    require(trial['run_id'] in runs, 'unknown run_id')
    require(trial['phase'] in PHASES, 'unknown phase')
    require(trial['status'] in EXCLUDED | {'READY'}, 'input status must be READY or explicit exclusion')
    require(re.fullmatch('UC-0[1-8]', trial['uc']), 'core supports UC-01..08 only')
    if trial['status'] != 'READY':
        text(trial.get('reason'), 'excluded trial reason')
        return
    if trial['phase'] == 'BASELINE' or trial['uc'] == 'UC-01':
        return  # Retained as NOT_EVALUATED, never counted as successful.
    require(trial.get('event_valid') is True, 'READY requires independent positive event confirmation')
    text(trial.get('source_ref'), 'source_ref')
    text(trial.get('window_ref'), 'window_ref')
    require(isinstance(trial.get('expected_rule_ids'), list) and trial['expected_rule_ids'], 'expected_rule_ids required')
    require(all(isinstance(i, str) and i.isdecimal() for i in trial['expected_rule_ids']), 'rule IDs must be strings')
    levels = trial.get('expected_levels')
    require(isinstance(levels, list) and levels and all(type(i) is int and 0 <= i <= 16 for i in levels), 'expected_levels required')
    target = trial.get('target_key')
    require(isinstance(target, dict) and target, 'target_key must be exact field/value object')
    for key, value in target.items():
        require(key.startswith(('data.', 'syscheck.')), 'target_key needs source-specific fields')
        require(type(value) in (str, int) and value != '', 'target_key requires nonempty strings or integers')
        require(not re.search(r'(?:md5|sha\d*|hash)', key, re.I), 'hash alone is not a trial identity')
    path_keys = {'syscheck.path', 'data.virustotal.source.file', 'data.yara_scanned_file'}
    require(bool(path_keys.intersection(target)) or len(target) >= 2,
            'need a unique path or at least two exact source correlation fields')
    start = stamp(trial.get('window_start'))
    require(trial['uc'] != 'UC-04' or 'match_start' in trial, 'UC-04 needs scan match_start separate from window_start at scan end')
    match_start = stamp(trial.get('match_start', trial['window_start']))
    require(match_start <= start, 'match_start must not follow window anchor')
    duration = number(trial.get('window_s'), 'window_s', 0.000001)
    end = stamp(trial.get('observe_until'))
    require(end >= start + timedelta(seconds=duration), 'observation does not cover declared window')
    run = runs[trial['run_id']]
    for key in ('agent_id', 'agent_name', 'manager_name', 'os', 'config_commit', 'config_sha256', 'timing_definition'):
        require(key not in trial or trial[key] == run[key], 'trial conflicts with run manifest: ' + key)
    require(stamp(run['coverage_start']) <= match_start and end <= stamp(run['coverage_end']), 'trial outside declared alert coverage')


def timing(trial, run, alert):
    result = {'timing_status': 'TIMING_UNVERIFIED', 'source_to_alert_s': None,
              'action_interval_s': None, 'uncertainty_ms': None}
    if alert is None:
        result['timing_status'] = 'NO_ALERT'
        return result
    if not run['clock_verified'] or run.get('clock_uncertainty_ms', math.inf) > 100:
        return result
    try:
        offset = timedelta(milliseconds=run['clock_offset_ms'])
        precision = number(trial.get('source_precision_ms'), 'source_precision_ms', 0)
        result['uncertainty_ms'] = run['clock_uncertainty_ms'] + precision
        if trial.get('t_source') is not None:
            source = stamp(trial['t_source']) - offset
            delta = (alert['at'] - source).total_seconds()
            require(delta >= 0, 'negative source-to-alert time')
            result.update(timing_status='TIMING_VALID', source_to_alert_s=delta)
        elif trial.get('t_before') is not None and trial.get('t_after') is not None:
            before, after = stamp(trial['t_before']) - offset, stamp(trial['t_after']) - offset
            require(before <= after and alert['at'] >= before, 'invalid action interval')
            result.update(timing_status='INTERVAL_ONLY', action_interval_s=[
                (alert['at'] - after).total_seconds(), (alert['at'] - before).total_seconds()])
    except (InputError, OverflowError) as exc:
        result.update(timing_status='TIMING_INVALID', timing_reason=str(exc))
    return result


def analyze(journal, alert_rows, manifest):
    require(len(journal) * len(alert_rows) <= MAX_COMPARISONS, 'comparison bound exceeded; partition complete runs, never drop failed trials')
    runs = load_runs(manifest)
    alerts, duplicates = normalize_alerts(alert_rows)
    candidates, output, owners, keys = {}, [], defaultdict(list), set()
    protocols = {}
    for trial, ref in journal:
        validate_trial(trial, runs)
        identity = (trial['run_id'], trial['trial_id'])
        require(identity not in keys, 'duplicate trial identity')
        keys.add(identity)
        run = runs[trial['run_id']]
        out = {'run_id': trial['run_id'], 'trial_id': trial['trial_id'], 'uc': trial['uc'],
               'variant': trial['variant'], 'phase': trial['phase'], 'journal_ref': ref,
               'input': trial, 'status': trial['status'], 'reason': trial.get('reason'),
               'late_detected': False, 'alert_refs': [], 'matching_alert_count': 0,
               'eligible': False}
        output.append(out)
        if trial['status'] != 'READY':
            continue
        if trial['phase'] == 'BASELINE' or trial['uc'] == 'UC-01':
            out.update(status='NOT_EVALUATED', reason='PENDING_SPECIALIZED_METRIC')
            continue
        protocol_key = (trial['run_id'], trial['uc'], trial['variant'])
        signature = (tuple(sorted(trial['expected_rule_ids'])), tuple(sorted(trial['expected_levels'])), trial['window_s'])
        require(protocol_key not in protocols or protocols[protocol_key] == signature,
                'changed rule/level/window within same run/UC/variant; use a new run')
        protocols[protocol_key] = signature
        start, end = stamp(trial['window_start']), stamp(trial['observe_until'])
        match_start = stamp(trial.get('match_start', trial['window_start']))
        if trial['uc'] == 'UC-08' and trial['phase'] == 'MEASURED':
            lookback = start - timedelta(seconds=930)
            if stamp(run['coverage_start']) > lookback:
                out.update(status='NOT_EVALUATED', reason='SUPPRESSION_LOOKBACK_NOT_COVERED')
                continue
            if any(a['raw']['manager']['name'] == run['manager_name'] and
                   a['raw']['rule']['id'] == '100051' and lookback < a['at'] < start for a in alerts):
                out.update(status='INTERFERED', reason='NETCAT_SUPPRESSION_LOOKBACK')
                continue
        matches = []
        for a in alerts:
            raw = a['raw']
            if (raw['manager']['name'] == run['manager_name'] and
                raw['agent']['id'] == run['agent_id'] and raw['agent']['name'] == run['agent_name'] and
                raw['rule']['id'] in trial['expected_rule_ids'] and
                raw['rule']['level'] in trial['expected_levels'] and match_start <= a['at'] <= end and
                all(type(field(raw, k)) is type(v) and field(raw, k) == v for k, v in trial['target_key'].items())):
                matches.append(a)
                owners[a['key']].append(identity)
        candidates[identity] = matches
    for out in output:
        identity = (out['run_id'], out['trial_id'])
        if identity not in candidates:
            continue
        trial, run = out['input'], runs[out['run_id']]
        matches = candidates[identity]
        out['matching_alert_count'] = len(matches)
        out['alert_refs'] = [ref for a in matches for ref in a['refs']]
        if any(len(owners[a['key']]) > 1 for a in matches):
            out.update(status='AMBIGUOUS', reason='ALERT_MATCHES_MULTIPLE_TRIALS')
            continue
        first = matches[0] if matches else None
        deadline = stamp(trial['window_start']) + timedelta(seconds=trial['window_s'])
        detected = first is not None and first['at'] <= deadline
        out.update(status='DETECTED' if detected else 'MISSED',
                   reason=None if detected else ('LATE_ALERT' if first else 'NO_MATCH_IN_OBSERVATION'),
                   late_detected=first is not None and not detected,
                   eligible=trial['phase'] == 'MEASURED',
                   alert_id=first['raw']['id'] if first else None,
                   manager_name=run['manager_name'],
                   t_alert=first['raw']['timestamp'] if first else None)
        out.update(timing(trial, run, first))
    groups = defaultdict(list)
    for row in output:
        if row['phase'] == 'MEASURED':
            groups[(row['run_id'], row['uc'], row['variant'])].append(row)
    summaries = []
    for (run_id, uc, variant), rows in sorted(groups.items()):
        counts = Counter(row['status'] for row in rows)
        denominator = sum(row['eligible'] for row in rows)
        values = [row['source_to_alert_s'] for row in rows if row['eligible'] and
                  row['status'] == 'DETECTED' and row.get('timing_status') == 'TIMING_VALID']
        summaries.append({'run_id': run_id, 'uc': uc, 'variant': variant,
                          'run_manifest': runs[run_id], 'counts': dict(counts),
                          'denominator': denominator,
                          'detection_rate': counts['DETECTED'] / denominator if denominator else None,
                          'late_count': sum(row['late_detected'] for row in rows),
                          'n_timed': len(values),
                          'mean_source_to_alert_s': statistics.mean(values) if values else None,
                          'mttd_s': statistics.mean(values) if values and runs[run_id]['latency_kind'] == 'DETECTION' else None,
                          'median_s': statistics.median(values) if values else None,
                          'min_s': min(values) if values else None, 'max_s': max(values) if values else None,
                          'warnings': ['FEWER_THAN_TEN_VALID_TRIALS'] if denominator < 10 else []})
    return {'schema_version': 1, 'scope': 'detection_core_only', 'pending_features': PENDING,
            'evidence_notice': 'Source/config/clock/coverage references are operator attestations, not independently verified by this core.',
            'duplicate_alert_lines': duplicates, 'trials': output, 'summaries': summaries}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--journal', required=True, help='attempt journal JSONL')
    parser.add_argument('--alerts', nargs='+', required=True, help='explicit alert JSONL rotation files')
    parser.add_argument('--manifest', required=True, help='run/clock/config manifest JSON')
    args = parser.parse_args(argv)
    try:
        journal, journal_provenance = read_jsonl([args.journal])
        require(journal, 'empty attempt journal')
        alerts, alert_provenance = read_jsonl(args.alerts)
        with Path(args.manifest).open('rb') as stream:
            raw = stream.read(MAX_LINE + 1)
        require(len(raw) <= MAX_LINE, 'manifest too large')
        report = analyze(journal, alerts, strict_json(raw.decode('utf-8')))
        report['inputs'] = journal_provenance + alert_provenance + [
            {'path': args.manifest, 'sha256': hashlib.sha256(raw).hexdigest()}]
        report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        print(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, OverflowError, RecursionError) as exc:
        print('measurement input error: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
