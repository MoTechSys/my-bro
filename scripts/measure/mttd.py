#!/usr/bin/env python3
"""T-11 v3 measurement candidate. Owner: ASTRA; 2026-09-09.
Sources: MASTER_PLAN_v3_DETAILED.md section 5 and tests/TEST_PLAN.md.
Explicit v2 timeline/statistics; legacy v1 core retained for historical inputs.
Native instrumentation, independent review and laboratory PILOT remain required.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import itertools
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
MIN_MEASURED_N = 30  # v3.1 section 9 A2; all UCs, not only AR cases.
MIN_BASELINE_HOURS = 12  # v3.1 section 9 A3; per OS/config run.
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


def sample_size(sigma_hat, margin=1.0):
    """Pilot SD in seconds; planning heuristic, not guaranteed precision/power."""
    number(sigma_hat, 'sigma_hat', 0)
    number(margin, 'margin')
    require(margin > 0, 'margin must be positive')
    try:
        value = (1.96 * sigma_hat / margin) ** 2
    except OverflowError as exc:
        raise InputError('sample size overflow') from exc
    require(math.isfinite(value), 'sample size overflow')
    return max(MIN_MEASURED_N, math.ceil(value))


def wilson(k, n):
    """Two-sided Wilson score 95%, matching plan_math (no Wald interval)."""
    require(type(n) is int and type(k) is int and 0 <= k <= n, 'invalid binomial counts')
    if not n:
        return None
    z = 1.959963984540054
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [max(0.0, c - h), min(1.0, c + h)]


def percentile(values, q):
    """Linear interpolation/type 7, including singleton and empty samples."""
    number(q, 'quantile', 0)
    require(q <= 1, 'quantile exceeds one')
    data = sorted(number(v, 'sample') for v in values)
    if not data:
        return None
    h = (len(data) - 1) * q
    lo = int(h)
    return data[lo] + (data[min(lo + 1, len(data) - 1)] - data[lo]) * (h - lo)


def describe(values):
    data = [number(v, 'latency sample', 0) for v in values]
    q1, q3 = percentile(data, .25), percentile(data, .75)
    return {'n': len(data), 'median': statistics.median(data) if data else None,
            'q1': q1, 'q3': q3, 'iqr': q3 - q1 if data else None,
            'p95': percentile(data, .95), 'min': min(data) if data else None,
            'max': max(data) if data else None,
            'mean': statistics.mean(data) if data else None,
            'sd': statistics.stdev(data) if len(data) > 1 else None}


def poisson_upper(k, hours, alpha=.05):
    """One-sided exact Poisson limit: invert P(X<=k|mu)=alpha / exposure.

    Equivalent to chi-square(2*(k+1), 1-alpha)/2/hours. Log-sum-exp
    avoids underflow at large k; bounded bisection, no normal approximation.
    """
    require(type(k) is int and 0 <= k <= 100000, 'Poisson count outside 0..100000')
    number(hours, 'hours', 0.000000001)
    number(alpha, 'alpha', 0.000000001)
    require(alpha < 1, 'alpha must be less than one')
    if k == 0:
        return -math.log(alpha) / hours

    def log_cdf(mu):
        # In the upper-limit search mu>k, term k is the largest term.
        term = -mu + k * math.log(mu) - math.lgamma(k + 1)
        ratio = total = 1.0
        for j in range(k, 0, -1):
            ratio *= j / mu
            total += ratio
            if ratio < total * 1e-16:
                break
        return term + math.log(total)

    low, high = float(k), float(k + 1)
    target = math.log(alpha)
    while log_cdf(high) > target:
        high *= 2
    for _ in range(100):
        mid = (low + high) / 2
        if log_cdf(mid) > target:
            low = mid
        else:
            high = mid
    return (low + high) / (2 * hours)


def mann_whitney_u(hardened, official):
    """One-sided greater: hardened latencies tend to exceed official.

    Small samples: exact inclusive permutation of midranks, including ties.
    Larger samples: normal approximation with tie and continuity correction.
    A large p-value is NOT evidence of non-inferiority by a one-second margin.
    """
    x = [number(v, 'hardened', 0) for v in hardened]
    y = [number(v, 'official', 0) for v in official]
    require(x and y and len(x) + len(y) <= 10000, 'MWU needs two bounded nonempty groups')
    n, m = len(x), len(y)
    indexed = sorted(enumerate(x + y), key=lambda item: item[1])
    ranks, ties = [0.0] * (n + m), []
    i = 0
    while i < len(indexed):
        j = i + 1
        while j < len(indexed) and indexed[j][1] == indexed[i][1]:
            j += 1
        for position, _ in indexed[i:j]:
            ranks[position] = (i + 1 + j) / 2
        ties.append(j - i)
        i = j
    rank_sum = sum(ranks[:n])
    u = rank_sum - n * (n + 1) / 2
    permutations = math.comb(n + m, n)
    if permutations <= 100000:
        extreme = sum(sum(choice) >= rank_sum for choice in itertools.combinations(ranks, n))
        p, method = extreme / permutations, 'exact_permutation_midrank'
    else:
        size = n + m
        correction = sum(t ** 3 - t for t in ties) / (size * (size - 1))
        variance = n * m / 12 * (size + 1 - correction)
        p = (0.5 * math.erfc((u - n * m / 2 - .5) / math.sqrt(2 * variance))
             if variance > 0 else 1.0)
        method = 'asymptotic_tie_and_continuity_corrected'
    return {'u': u, 'p_value': min(1.0, max(0.0, p)), 'alternative': 'greater',
            'method': method, 'n_hardened': n, 'n_official': m, 'alpha': .05,
            'delta_median_s': statistics.median(x) - statistics.median(y),
            'notice': 'Not a non-inferiority test; failure to reject does not establish H4.'}


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
    require(re.fullmatch(r'UC-(?:0[1-9]|1[0-3])', trial['uc']), 'supported UC range is 01..13')
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


TIMES = tuple('t' + str(i) for i in range(7)) + ('t2_prime',)
METRICS = {'D_source': ('t1', 't0'), 'MTTD': ('t2', 't1'),
           'MTTD_e2e': ('t2', 't0'), 'L_vis': ('t3', 't2'),
           'L_AR_trigger': ('t4', 't2'), 'L_AR_complete': ('t5', 't4'),
           'L_AR_e2e': ('t5', 't0'), 'L_confirm': ('t6', 't5')}


def epoch_ms(value):
    require(type(value) is int and 0 <= value <= 253402300799999,
            'UTC timestamp must be integer epoch milliseconds, not seconds/float/bool')
    return value


def iso_ms(value):
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) +
            timedelta(milliseconds=epoch_ms(value))).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def to_ms(value):
    delta = stamp(value) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000


def validate_v2(trial, run):
    require(trial.get('schema_version') == 2 and type(trial['schema_version']) is int,
            'v2 manifest requires schema_version=2 on every attempt')
    require(trial.get('session_id') == run['session_id'], 'session_id disagrees with run')
    require('exclusion_reason' in trial and trial['exclusion_reason'] in EXCLUDED | {None},
            'exclusion_reason must be explicit null or exclusion enum')
    require('status' not in trial, 'v2 input uses exclusion_reason, not computed status')
    if trial['exclusion_reason']:
        text(trial.get('reason'), 'exclusion detail')
    offsets = trial.get('ntp_offset_ms')
    require(isinstance(offsets, dict) and set(offsets) == set(run['devices']),
            'each attempt requires offsets for ALL session devices')
    for device, offset in offsets.items():
        number(offset, 'ntp_offset_ms.' + device)
    refs, missing = trial.get('time_refs'), trial.get('missing_reasons')
    require(isinstance(refs, dict) and isinstance(missing, dict), 'time_refs/missing_reasons objects required')
    for key in TIMES:
        require(key in trial, key + ' required (nullable)')
        if trial[key] is None:
            text(missing.get(key), 'missing reason for ' + key)
        else:
            epoch_ms(trial[key])
            text(refs.get(key), 'evidence reference for ' + key)
    require(trial.get('poll_interval_ms') == 1000 and type(trial['poll_interval_ms']) is int,
            'v3 visibility polling interval must be 1000ms')
    require(trial['uc'] == 'UC-03' or trial['t2_prime'] is None, 'D_VT is UC-03 only')
    if trial['t5'] is not None:
        require(trial.get('completion_kind') == 'independent_observation',
                't5 must be independently observed, not an AR success log')
    stages = trial.get('stage_selectors', {})
    require(isinstance(stages, dict) and set(stages) <= {'t2', 't2_prime', 't6'}, 'unknown alert stage')
    if trial['t6'] is not None:
        require('t6' in stages, 'non-null t6 requires raw manager confirmation selector')
    if trial['exclusion_reason'] is None and trial['phase'] != 'BASELINE' and trial['uc'] != 'UC-01':
        require('t2' in stages, 't2 stage selector required')
        if trial['uc'] == 'UC-03':
            require('t2_prime' in stages, 'UC-03 needs explicit VT selector')
            require(set(stages['t2'].get('rule_ids', [])) <= {'100200', '100201'}, 'UC-03 t2 must be FIM')
            require(stages['t2_prime'].get('rule_ids') == ['87105'], 'UC-03 t2_prime must be 87105')
    for key, selector in stages.items():
        require(isinstance(selector, dict), 'stage selector object required')
        # Reuse the strict exact-match contract; stage targets may use different field paths.
        probe = dict(trial, status='READY', expected_rule_ids=selector.get('rule_ids'),
                     expected_levels=selector.get('levels'), target_key=selector.get('target_key'))
        if trial['exclusion_reason'] is None and trial['phase'] != 'BASELINE' and trial['uc'] != 'UC-01':
            validate_trial(probe, {run['run_id']: run})


def timeline_metrics(trial, run):
    corrected = {k: (trial[k] - trial['ntp_offset_ms'][run['clock_map'][k]]
                     if trial[k] is not None else None) for k in TIMES}
    definitions = dict(METRICS)
    if trial['uc'] == 'UC-03':
        definitions['D_VT'] = ('t2_prime', 't2')
    metrics, states = {}, {}
    for name, (end, start) in definitions.items():
        if corrected[end] is None or corrected[start] is None:
            metrics[name], states[name] = None, 'MISSING_TIMESTAMP'
        elif corrected[end] < corrected[start]:
            metrics[name], states[name] = None, 'INVALID_ORDER'
        else:
            metrics[name] = (corrected[end] - corrected[start]) / 1000
            states[name] = 'VALID'
    return metrics, states


def baseline_summary(trials, runs, alerts):
    """Union exposure per run (no cross-OS/config pooling), reviewed alerts only."""
    groups = defaultdict(list)
    for row in trials:
        if row['phase'] == 'BASELINE':
            groups[row['run_id']].append(row)
    summaries = []
    for run_id, rows in sorted(groups.items()):
        run = runs[run_id]
        intervals, reviews = [], {}
        for row in rows:
            if row['exclusion_reason']:
                continue
            trial = row['input']
            b = trial.get('baseline')
            require(isinstance(b, dict), 'BASELINE requires baseline exposure and adjudications')
            start, end = epoch_ms(b.get('start_ms')), epoch_ms(b.get('end_ms'))
            require(to_ms(run['coverage_start']) <= start < end <= to_ms(run['coverage_end']),
                    'baseline outside run coverage')
            text(b.get('activity_ref'), 'baseline activity_ref')
            require(isinstance(b.get('adjudications'), list), 'baseline adjudications list required')
            intervals.append((start, end))
            for review in b['adjudications']:
                identity = (text(review.get('manager_name'), 'review manager'), text(review.get('alert_id'), 'review alert'))
                require(type(review.get('is_false_threat_alert')) is bool or review.get('is_false_threat_alert') is None,
                        'review classification must be boolean/null')
                text(review.get('reason'), 'review reason'); text(review.get('ref'), 'review evidence')
                require(identity not in reviews or reviews[identity] == review, 'conflicting baseline adjudication')
                reviews[identity] = review
        merged = []
        for start, end in sorted(intervals):
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(end, merged[-1][1])
            else:
                merged.append([start, end])
        hours = sum(end - start for start, end in merged) / 3600000
        if not intervals:
            summaries.append({'run_id': run_id, 'hours': 0, 'fp_upper_95': None, 'status': 'INVALID_OR_EXCLUDED'})
            continue
        ids = run.get('baseline_rule_ids')
        require(isinstance(ids, list) and ids and all(isinstance(i, str) and i.isdecimal() for i in ids),
                'baseline_rule_ids predeclared scope required')
        covered = {a['key']: a for a in alerts if a['raw']['manager']['name'] == run['manager_name'] and
                   a['raw']['agent']['id'] == run['agent_id'] and a['raw']['agent']['name'] == run['agent_name'] and
                   a['raw']['rule']['id'] in ids and any(start <= to_ms(a['raw']['timestamp']) < end for start, end in merged)}
        require(set(reviews) <= set(covered), 'baseline review references alert outside exposure/scope')
        fp = sum(reviews.get(k, {}).get('is_false_threat_alert') is True for k in covered)
        unknown = sum(reviews.get(k, {}).get('is_false_threat_alert') is None for k in covered)
        summaries.append({'run_id': run_id, 'hours': hours, 'exposure_intervals_ms': merged,
                          'false_alerts': fp, 'unresolved': unknown, 'fp_per_hour': fp / hours,
                          'fp_upper_95': poisson_upper(fp, hours) if not unknown else None,
                          'upper_if_all_unresolved_false': poisson_upper(fp + unknown, hours),
                          'status': 'ADJUDICATION_PENDING' if unknown else 'EVALUATED',
                          'minimum_hours': MIN_BASELINE_HOURS,
                          'warnings': ['LESS_THAN_TWELVE_HOURS'] if hours < MIN_BASELINE_HOURS else []})
    return summaries


def analyze_v2(journal, alert_rows, manifest):
    """Explicit v2 contract; legacy v1 is never silently upgraded to v3 evidence."""
    require(type(manifest.get('version')) is int and manifest['version'] == 2, 'manifest version must be 2')
    require(len(journal) * len(alert_rows) * 4 <= MAX_COMPARISONS, 'v2 comparison bound exceeded')
    raw_runs = manifest.get('runs')
    require(isinstance(raw_runs, list) and raw_runs, 'runs required')
    runs, session_devices, rejected = {}, {}, set()
    for raw in raw_runs:
        run = dict(raw)
        session = text(run.get('session_id'), 'session_id')
        devices = run.get('devices')
        require(isinstance(devices, dict) and devices, 'session devices required')
        require(session not in session_devices or session_devices[session] == set(devices),
                'all runs of a session must declare the same complete device set')
        session_devices[session] = set(devices)
        for name, device in devices.items():
            text(name, 'device'); require(isinstance(device, dict), 'device clock object required')
            offset = number(device.get('ntp_offset_ms'), 'device ntp_offset_ms')
            text(device.get('clock_ref'), 'clock measurement evidence')
            number(device.get('uncertainty_ms'), 'clock uncertainty', 0)
            if abs(offset) > 100 or device['uncertainty_ms'] > 100:
                rejected.add(session)
        mapping = run.get('clock_map')
        require(isinstance(mapping, dict) and set(mapping) == set(TIMES) and
                all(v in devices for v in mapping.values()), 'clock_map must assign all timestamps to session devices')
        require(mapping['t2'] == mapping['t2_prime'] == mapping['t6'],
                'all raw manager alert stages must use the same manager clock')
        run.update(clock_verified=True, clock_offset_ms=0, clock_uncertainty_ms=0, clock_ref='v2 per-device')
        require(run['run_id'] not in runs, 'duplicate run_id')
        runs[run['run_id']] = run
    load_runs({'version': 1, 'runs': list(runs.values())})
    for trial, _ in journal:
        require(trial.get('run_id') in runs, 'unknown run_id')
        run = runs[trial['run_id']]
        validate_v2(trial, run)
        if any(abs(offset) > 100 for offset in trial['ntp_offset_ms'].values()):
            rejected.add(run['session_id'])
    legacy = []
    for trial, ref in journal:
        copy = dict(trial, status=trial['exclusion_reason'] or 'READY')
        if trial['session_id'] in rejected:
            copy.update(status='INVALID', reason='SESSION_CLOCK_LIMIT_EXCEEDED')
        copy['t_source'] = None  # v2 metrics are calculated below, not by v1 clock convention.
        legacy.append((copy, ref))
    result = analyze(legacy, alert_rows, {'version': 1, 'runs': list(runs.values())})
    alerts, _ = normalize_alerts(alert_rows)
    stage_owners = defaultdict(set)
    by_ref = {ref: a['key'] for a in alerts for ref in a['refs']}
    protocols = {}
    for row in result['trials']:
        # Final and intermediate roles share ownership: a FIM alert cannot be
        # another trial's final detection while also triggering this trial.
        for ref in row['alert_refs']:
            stage_owners[by_ref[ref]].add((row['run_id'], row['trial_id']))
    original = {(t['run_id'], t['trial_id']): t for t, _ in journal}
    for row in result['trials']:
        identity = (row['run_id'], row['trial_id'])
        trial, run = dict(original[identity]), runs[row['run_id']]
        trial['time_refs'] = dict(trial['time_refs'])
        row['input'] = original[identity]
        for key in ('source_to_alert_s', 'action_interval_s', 'timing_status', 'timing_reason', 'uncertainty_ms'):
            row.pop(key, None)  # No legacy clock-convention metrics in v2 output.
        if row.get('reason') == 'SUPPRESSION_LOOKBACK_NOT_COVERED':
            row.update(status='INVALID', eligible=False)
        row['session_id'] = trial['session_id']
        row['exclusion_reason'] = row['status'] if row['status'] in EXCLUDED else None
        row['stage_alert_refs'] = {}
        if row['exclusion_reason'] is None and trial['phase'] != 'BASELINE' and trial['uc'] != 'UC-01':
            signature = tuple(sorted((stage, tuple(sorted(s['rule_ids'])), tuple(sorted(s['levels'])),
                                      tuple(sorted(s['target_key'])))
                                     for stage, s in trial.get('stage_selectors', {}).items()))
            protocol = (row['run_id'], row['uc'], row['variant'])
            require(protocol not in protocols or protocols[protocol] == signature,
                    'changed stage protocol within run/UC/variant; use a new run')
            protocols[protocol] = signature
            start = stamp(trial.get('match_start', trial['window_start']))
            end = stamp(trial['observe_until'])
            for stage, selector in trial.get('stage_selectors', {}).items():
                matches = [a for a in alerts if a['raw']['manager']['name'] == run['manager_name'] and
                           a['raw']['agent']['id'] == run['agent_id'] and a['raw']['agent']['name'] == run['agent_name'] and
                           a['raw']['rule']['id'] in selector['rule_ids'] and a['raw']['rule']['level'] in selector['levels'] and
                           start <= a['at'] <= end and all(type(field(a['raw'], k)) is type(v) and field(a['raw'], k) == v
                                                         for k, v in selector['target_key'].items())]
                for a in matches:
                    stage_owners[a['key']].add(identity)
                first = matches[0] if matches else None
                value = to_ms(first['raw']['timestamp']) if first else None
                if trial[stage] is not None and trial[stage] != value:
                    row.update(exclusion_reason='INVALID', status='INVALID', eligible=False,
                               reason='CLAIMED_TIMESTAMP_DIFFERS_FROM_RAW_ALERT:' + stage)
                trial[stage] = value
                row['stage_alert_refs'][stage] = [r for a in matches for r in a['refs']]
        row['timeline_ms'] = {key: trial[key] for key in TIMES}
        row['ntp_offset_ms'] = trial['ntp_offset_ms']
        row['metrics_s'], row['metric_status'] = timeline_metrics(trial, run)
        row['visibility_uncertainty_ms'] = 1000
    ambiguous = {identity for ids in stage_owners.values() if len(ids) > 1 for identity in ids}
    for row in result['trials']:
        if (row['run_id'], row['trial_id']) in ambiguous:
            row.update(exclusion_reason='AMBIGUOUS', status='AMBIGUOUS', eligible=False, reason='STAGE_MATCHES_MULTIPLE_TRIALS')
        if row['exclusion_reason']:
            row['metrics_s'] = {k: None for k in row['metrics_s']}
            row['metric_status'] = {k: 'EXCLUDED' for k in row['metrics_s']}
    summaries = []
    groups = defaultdict(list)
    for row in result['trials']:
        groups[(row['run_id'], row['uc'], row['variant'], row['phase'])].append(row)
    for (run_id, uc, variant, phase), rows in sorted(groups.items()):
        if phase == 'BASELINE':
            continue
        applicable = [r for r in rows if r['status'] != 'NOT_EVALUATED']
        successes = sum(r['status'] == 'DETECTED' for r in applicable)
        valid = sum(r['status'] in {'DETECTED', 'MISSED'} for r in applicable)
        total = len(rows)
        names = list(METRICS) + (['D_VT'] if uc == 'UC-03' else [])
        stats = {name: describe([r['metrics_s'][name] for r in rows if r['status'] == 'DETECTED' and
                                r['metrics_s'][name] is not None]) for name in names}
        floor = MIN_MEASURED_N
        minimum = runs[run_id].get('planned_n', floor)
        require(type(minimum) is int and minimum >= floor, 'planned_n below protocol floor')
        recommended = {k: max(minimum, sample_size(v['sd'])) if v['sd'] is not None and v['n'] >= 5 else None
                       for k, v in stats.items()} if phase == 'PILOT' else None
        summaries.append({'run_id': run_id, 'uc': uc, 'variant': variant, 'phase': phase,
                          'counts': dict(Counter(r['status'] for r in rows)),
                          'denominator_all_attempts': total, 'denominator_valid': valid,
                          'detection_rate_all_attempts': successes / total if uc != 'UC-01' else None,
                          'wilson_95_all_attempts': wilson(successes, total) if uc != 'UC-01' else None,
                          'detection_rate_valid': successes / valid if valid else None,
                          'wilson_95_valid': wilson(successes, valid), 'metrics_s': stats,
                          'pilot_recommended_n': recommended, 'minimum_measured_n': minimum,
                          'warnings': ['BELOW_PLANNED_MINIMUM'] if phase == 'MEASURED' and valid < minimum else []})
    h4 = []
    for comparison in manifest.get('h4_comparisons', []):
        a, b = comparison['hardened_run_id'], comparison['official_run_id']
        require(a in runs and b in runs and a != b, 'H4 requires distinct known runs')
        require(runs[a]['os'] == runs[b]['os'] and runs[a]['timing_definition'] == runs[b]['timing_definition'],
                'H4 cannot pool OS or timing definitions')
        text(comparison.get('design_ref'), 'H4 independent-group design reference')
        def samples(run_id):
            return [r['metrics_s']['L_AR_complete'] for r in result['trials'] if r['run_id'] == run_id and
                    r['uc'] == comparison['uc'] and r['variant'] == comparison['variant'] and
                    r['phase'] == 'MEASURED' and r['status'] == 'DETECTED' and
                    r['metrics_s']['L_AR_complete'] is not None]
        x, y = samples(a), samples(b)
        h4.append({'comparison': comparison, 'result': mann_whitney_u(x, y) if x and y else None,
                   'status': 'CALCULATED_NOT_H4_PROOF' if x and y else 'INSUFFICIENT_DATA'})
    return {'schema_version': 2, 'scope': 'v3_measurement_candidate', 'rejected_sessions': sorted(rejected),
            'trials': result['trials'], 'summaries': summaries, 'h4': h4,
            'baseline': baseline_summary(result['trials'], runs, alerts),
            'duplicate_alert_lines': result['duplicate_alert_lines'],
            'pending_features': ['native source/AR/visibility instrumentation acceptance',
                                 'UC-01 connection verification', 'independent review and laboratory PILOT'],
            'evidence_notice': 'Raw alert stages verified; other time/clock/config references are attestations unless supplied by a reviewed observer. Metrics in seconds; raw clocks are device-minus-UTC milliseconds.'}


def inspect_alert_timestamps(alert_rows):
    """G2 first check: inspect raw serialization, NOT clock accuracy or native resolution.

    Decimal digits can be padding; all-zero subsecond parts are not proof of
    second-resolution clocks. Keep original strings and provenance for review.
    """
    alerts, duplicates = normalize_alerts(alert_rows)
    require(alerts, 'timestamp inspection requires at least one raw alert')
    groups = defaultdict(list)
    for alert in alerts:
        groups[alert['raw']['manager']['name']].append(alert)
    reports = []
    for manager, items in sorted(groups.items()):
        digits, fractions, examples = Counter(), [], []
        for item in items:
            raw = item['raw']['timestamp']
            match = re.search(r'T\d{2}:\d{2}:\d{2}(?:\.(\d+))?', raw)
            fraction = match[1] or ''
            digits[len(fraction)] += 1
            fractions.append(bool(fraction) and int(fraction) != 0)
            if len(examples) < 3:
                examples.append({'timestamp': raw, 'refs': item['refs']})
        reports.append({'manager_name': manager, 'n_alerts': len(items),
                        'fraction_digits_counts': dict(sorted(digits.items())),
                        'coarsest_serialized_quantum_ms': 1000 / 10 ** min(digits),
                        'has_nonzero_fraction': any(fractions), 'examples': examples,
                        'status': 'FORMAT_OBSERVED_NATIVE_RESOLUTION_UNVERIFIED'})
    return {'scope': 'G2_ALERT_TIMESTAMP_FIRST_CHECK', 'managers': reports,
            'duplicate_alert_lines': duplicates,
            'notice': 'Inspect native alerts.json before PILOT. Digits are representation, not accuracy; '
                      'verify timestamp generation/resolution and clock uncertainty independently. '
                      'Epoch-ms conversion cannot create subsecond precision.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspect-alert-timestamps', action='store_true', help='G2 read-only first check; needs only --alerts')
    parser.add_argument('--journal', help='attempt journal JSONL')
    parser.add_argument('--alerts', nargs='+', required=True, help='explicit alert JSONL rotation files')
    parser.add_argument('--manifest', help='run/clock/config manifest JSON')
    args = parser.parse_args(argv)
    try:
        if args.inspect_alert_timestamps:
            require(not args.journal and not args.manifest, 'inspection accepts --alerts only')
            alerts, provenance = read_jsonl(args.alerts)
            report = inspect_alert_timestamps(alerts)
            report['inputs'] = provenance
            report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
            print(json.dumps(report, ensure_ascii=False, allow_nan=False, indent=2))
            return 0
        require(args.journal and args.manifest, '--journal and --manifest required for analysis')
        journal, journal_provenance = read_jsonl([args.journal])
        require(journal, 'empty attempt journal')
        alerts, alert_provenance = read_jsonl(args.alerts)
        with Path(args.manifest).open('rb') as stream:
            raw = stream.read(MAX_LINE + 1)
        require(len(raw) <= MAX_LINE, 'manifest too large')
        manifest = strict_json(raw.decode('utf-8'))
        require(isinstance(manifest, dict), 'manifest must be object')
        analyze_fn = analyze_v2 if manifest.get('version') == 2 else analyze
        report = analyze_fn(journal, alerts, manifest)
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
