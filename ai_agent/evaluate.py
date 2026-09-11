#!/usr/bin/env python3
"""Offline C4 normalized-evidence evaluator; AI, 2026-09-11; ADR-014.

No inference, network, raw-log ingestion or execution. Declarations and artifact
hashes are not authenticated by this tool. A valid report is never acceptance.
See docs/lab/UC-14_ai_analyst.md for the strict three-file contract.
"""
import argparse
import hashlib
import importlib.util
import math
from pathlib import Path
import re
import statistics
import sys

_spec = importlib.util.spec_from_file_location('_c4_contracts', Path(__file__).with_name('analyst.py'))
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)
MAX_CASES = 1000
PROVENANCE = {'code_sha256', 'model_sha256', 'prompt_sha256', 'knowledge_sha256',
              'rules_sha256', 'configuration_sha256', 'rubric_sha256'}
STATUSES = ('completed', 'failed', 'rejected', 'abstained')


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError('INVALID_KEYS')


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}', value):
        raise ValueError('INVALID_IDENTIFIER')
    return value


def sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value):
        raise ValueError('INVALID_SHA256')
    return value


def boolean(value):
    if type(value) is not bool:
        raise ValueError('INVALID_BOOLEAN')


def integer(value, maximum=1000000):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('INVALID_COUNT')
    return value


def rows(value, allow_empty=True):
    if not isinstance(value, list) or not (0 if allow_empty else 1) <= len(value) <= MAX_CASES:
        raise ValueError('INVALID_ROW_COUNT')
    return value


def techniques(value):
    if not isinstance(value, list) or len(value) > 20:
        raise ValueError('INVALID_TECHNIQUES')
    if any(not isinstance(v, str) or not a.TECHNIQUE.fullmatch(v) for v in value):
        raise ValueError('INVALID_TECHNIQUE')
    if len(set(value)) != len(value):
        raise ValueError('DUPLICATE_TECHNIQUE')
    return set(value)


def prediction(value):
    exact(value, {'classification', 'mitre_ids'})
    if value['classification'] not in a.CLASSIFICATIONS:
        raise ValueError('INVALID_CLASSIFICATION')
    techniques(value['mitre_ids'])


def wilson(k, n):
    """Two-sided 95% Wilson score interval, conditional on Bernoulli independence."""
    if not n:
        return None
    z = 1.959963984540054
    p, z2 = k / n, z * z
    center = (p + z2 / (2 * n)) / (1 + z2 / n)
    radius = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n)
    return [max(0., center - radius), min(1., center + radius)]


def rate(k, n, intervals=False):
    return {'numerator': k, 'denominator': n, 'value': k / n if n else None,
            'wilson_95': wilson(k, n) if intervals else None}


def latency(values):
    """Nearest-rank p95; no synthetic latency for missing/untimed attempts."""
    ordered = sorted(values)
    return {'n': len(values), 'mean_seconds': statistics.mean(values) if values else None,
            'median_seconds': statistics.median(values) if values else None,
            'p95_seconds': ordered[math.ceil(.95 * len(ordered)) - 1] if values else None,
            'p95_method': 'nearest_rank'}


def evaluate(manifest, attempts, reviews):
    # Copy and apply strict numeric/size parsing even to trusted Python callers.
    packed = a.encoded([manifest, attempts, reviews])
    if len(packed) > a.MAX_INPUT:
        raise ValueError('EVALUATION_TOO_LARGE')
    manifest, attempts, reviews = a.strict_json(packed)
    exact(manifest, {'schema_version', 'evaluation_id', 'dataset_kind', 'independent_human_labels',
                     'independent_cases', 'provenance', 'cases'})
    if type(manifest['schema_version']) is not int or manifest['schema_version'] != 1:
        raise ValueError('INVALID_VERSION')
    identifier(manifest['evaluation_id'])
    if manifest['dataset_kind'] not in ('synthetic', 'real'):
        raise ValueError('INVALID_DATASET_KIND')
    for key in ('independent_human_labels', 'independent_cases'):
        boolean(manifest[key])
    exact(manifest['provenance'], PROVENANCE)
    for value in manifest['provenance'].values():
        sha256(value)
    cases, identities, clusters = {}, set(), set()
    for case in rows(manifest['cases'], allow_empty=False):
        exact(case, {'case_id', 'batch_id', 'alert_ref', 'cluster_id', 'input_sha256', 'labeler_ref', 'gold'})
        for key in ('case_id', 'batch_id', 'alert_ref', 'cluster_id', 'labeler_ref'):
            identifier(case[key])
        if not re.fullmatch(r'A[1-9][0-9]{0,2}', case['alert_ref']):
            raise ValueError('INVALID_ALERT_REF')
        sha256(case['input_sha256'])
        prediction(case['gold'])
        identity = (case['batch_id'], case['alert_ref'])
        if case['case_id'] in cases or identity in identities:
            raise ValueError('DUPLICATE_CASE_OR_BATCH_REF')
        cases[case['case_id']] = case
        identities.add(identity)
        clusters.add(case['cluster_id'])
    batch_hashes = {}
    for case in cases.values():
        old = batch_hashes.setdefault(case['batch_id'], case['input_sha256'])
        if old != case['input_sha256']:
            raise ValueError('CONFLICTING_BATCH_INPUT_HASH')
    recorded = {}
    for attempt in rows(attempts):
        exact(attempt, {'case_id', 'input_sha256', 'provenance', 'status', 'prediction',
                        'output_sha256', 'latency_seconds'})
        cid = identifier(attempt['case_id'])
        if cid not in cases or cid in recorded:
            raise ValueError('UNKNOWN_OR_REPEATED_ATTEMPT')
        if attempt['input_sha256'] != cases[cid]['input_sha256'] or attempt['provenance'] != manifest['provenance']:
            raise ValueError('ATTEMPT_PROVENANCE_MISMATCH')
        if attempt['status'] not in STATUSES:
            raise ValueError('INVALID_ATTEMPT_STATUS')
        seconds = attempt['latency_seconds']
        if seconds is not None and (type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 <= seconds <= 86400):
            raise ValueError('INVALID_LATENCY')
        if attempt['status'] == 'completed':
            prediction(attempt['prediction'])
            sha256(attempt['output_sha256'])
            if seconds is None:
                raise ValueError('COMPLETED_LATENCY_REQUIRED')
        else:
            if attempt['prediction'] is not None:
                raise ValueError('NONCOMPLETED_PREDICTION')
            if attempt['output_sha256'] is not None:
                sha256(attempt['output_sha256'])
        recorded[cid] = attempt
    adjudications = {}
    for review in rows(reviews):
        exact(review, {'case_id', 'output_sha256', 'reviewer_ref', 'independent', 'claims', 'unsupported_claims'})
        cid = identifier(review['case_id'])
        if cid not in recorded or cid in adjudications or recorded[cid]['status'] != 'completed':
            raise ValueError('INVALID_REVIEW_CASE')
        identifier(review['reviewer_ref'])
        boolean(review['independent'])
        sha256(review['output_sha256'])
        if review['output_sha256'] != recorded[cid]['output_sha256']:
            raise ValueError('REVIEW_OUTPUT_MISMATCH')
        if integer(review['unsupported_claims']) > integer(review['claims']):
            raise ValueError('INVALID_UNSUPPORTED_COUNT')
        adjudications[cid] = review
    n = len(cases)
    counts = {status: sum(v['status'] == status for v in recorded.values()) for status in STATUSES}
    counts['missing'] = n - len(recorded)
    # Multiple alerts from one inference batch share context and generation.
    intervals = manifest['independent_cases'] and len(clusters) == n and len(batch_hashes) == n
    correct = exact_mitre = tp = fp = fn = label_abstentions = 0
    case_results = []
    confusion = {label: {pred: 0 for pred in a.CLASSIFICATIONS} for label in a.CLASSIFICATIONS}
    for cid, case in cases.items():
        attempt = recorded.get(cid)
        status = attempt['status'] if attempt else 'missing'
        outcome = {'case_id': cid, 'status': status, 'classification_correct': False, 'mitre_exact': False}
        if status == 'completed':
            pred, gold = attempt['prediction'], case['gold']
            outcome['classification_correct'] = pred['classification'] == gold['classification']
            outcome['mitre_exact'] = set(pred['mitre_ids']) == set(gold['mitre_ids'])
            correct += outcome['classification_correct']
            exact_mitre += outcome['mitre_exact']
            label_abstentions += pred['classification'] == 'insufficient_evidence'
            confusion[gold['classification']][pred['classification']] += 1
            expected, actual = set(gold['mitre_ids']), set(pred['mitre_ids'])
            tp += len(expected & actual); fp += len(actual - expected); fn += len(expected - actual)
        case_results.append(outcome)
    completed = counts['completed']
    claim_total = sum(v['claims'] for v in adjudications.values())
    unsupported = sum(v['unsupported_claims'] for v in adjudications.values())
    reviewed_positive = [v for v in adjudications.values() if v['claims'] > 0]
    return {'schema_version': 1, 'evaluation_id': manifest['evaluation_id'],
            'dataset_kind': manifest['dataset_kind'], 'acceptance_approved': False,
            'artifact_contents_verified': False, 'human_independence_verified': False,
            'provenance': manifest['provenance'],
            'gates': {'minimum_30_planned': n >= 30, 'minimum_30_completed': completed >= 30,
                      'real_data_declared': manifest['dataset_kind'] == 'real',
                      'independent_labels_declared': manifest['independent_human_labels'],
                      'all_planned_completed': completed == n,
                      'all_completed_reviewed': completed > 0 and len(adjudications) == completed,
                      'all_reviews_independent_declared': bool(adjudications) and all(v['independent'] for v in adjudications.values())},
            'planned_cases': n, 'counts': counts, 'completed_insufficient_evidence': label_abstentions,
            'classification_all_planned': rate(correct, n, intervals),
            'classification_completed_only': rate(correct, completed, intervals),
            'completion_rate': rate(completed, n, intervals),
            'mitre_exact_all_planned': rate(exact_mitre, n, intervals),
            'mitre_exact_completed_only': rate(exact_mitre, completed, intervals),
            'mitre_micro_completed_only': {'tp': tp, 'fp': fp, 'fn': fn,
                                          'precision': rate(tp, tp + fp), 'recall': rate(tp, tp + fn),
                                          'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None},
            'completed_confusion_matrix': confusion,
            'human_review': {'reviewed_cases': len(adjudications), 'unreviewed_completed': completed - len(adjudications),
                             'zero_claim_reviews': len(adjudications) - len(reviewed_positive),
                             'unsupported_claim_rate_reviewed_only': rate(unsupported, claim_total),
                             'cases_with_unsupported_claims_reviewed_positive_claims_only': rate(
                                 sum(v['unsupported_claims'] > 0 for v in reviewed_positive), len(reviewed_positive), intervals)},
            'latency_by_status': {status: latency([v['latency_seconds'] for v in recorded.values()
                                                if v['status'] == status and v['latency_seconds'] is not None]) for status in STATUSES},
            'untimed_recorded_attempts': sum(v['latency_seconds'] is None for v in recorded.values()),
            'intervals': {'method': 'wilson_95' if intervals else 'suppressed', 'cluster_count': len(clusters),
                          'batch_count': len(batch_hashes),
                          'reason': 'Conditional on declared independent Bernoulli cases; not verified.' if intervals else
                                    'Independence undeclared or repeated clusters/batches; no cluster-adjusted interval implemented.'},
            'limitations': ['Normalized records require external audit against private source artifacts.',
                            'One predeclared attempt per case; retries must use a separate evaluation, never replace failures.',
                            'Completed-only, reviewed-only and latency metrics are conditional and may have selection bias.',
                            'Claims within a narrative are dependent; no claim-level Wilson interval.',
                            'Per-status latency is per case; shared batch durations are repeated, not independent calls.',
                            'No automatic hallucination judgement, acceptance decision or native SOC proof.'],
            'cases': case_results}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('manifest', 'attempts', 'reviews'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        texts = {name: a.read_file(getattr(args, name)) for name in ('manifest', 'attempts', 'reviews')}
        result = evaluate(*(a.strict_json(texts[name]) for name in ('manifest', 'attempts', 'reviews')))
        result['input_file_sha256'] = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in texts.items()}
        print(a.encoded(result).decode('ascii'))
        return 0
    except (ValueError, OSError, UnicodeError, OverflowError):
        print('{"status":"rejected","acceptance_approved":false}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
