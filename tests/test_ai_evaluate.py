"""Synthetic C4 contract/statistical tests, not human labels or model results."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('c4_tests_module', ROOT / 'ai_agent/evaluate.py')
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
HASH = 'a' * 64


def fixture(n=3):
    manifest = {'schema_version': 1, 'evaluation_id': 'synthetic-test', 'dataset_kind': 'synthetic',
                'independent_human_labels': False, 'independent_cases': True,
                'provenance': {name: HASH for name in e.PROVENANCE}, 'cases': []}
    attempts, reviews = [], []
    for i in range(n):
        cid = 'case-' + str(i)
        pred = {'classification': 'suspicious', 'mitre_ids': ['T1059']}
        manifest['cases'].append({'case_id': cid, 'batch_id': 'batch-' + str(i), 'alert_ref': 'A1',
                                  'cluster_id': 'cluster-' + str(i), 'input_sha256': HASH,
                                  'labeler_ref': 'synthetic-labeler', 'gold': copy.deepcopy(pred)})
        attempts.append({'case_id': cid, 'input_sha256': HASH, 'provenance': dict(manifest['provenance']),
                         'status': 'completed', 'prediction': copy.deepcopy(pred), 'output_sha256': HASH,
                         'latency_seconds': i + 1.})
        reviews.append({'case_id': cid, 'output_sha256': HASH, 'reviewer_ref': 'synthetic-reviewer',
                        'independent': False, 'claims': 2, 'unsupported_claims': 0})
    return manifest, attempts, reviews


class Evaluation(unittest.TestCase):
    def test_perfect_fixture_is_not_acceptance(self):
        result = e.evaluate(*fixture(30))
        self.assertFalse(result['acceptance_approved'])
        self.assertFalse(result['artifact_contents_verified'])
        self.assertFalse(result['gates']['real_data_declared'])
        self.assertFalse(result['gates']['independent_labels_declared'])
        self.assertEqual(result['classification_all_planned']['value'], 1)
        self.assertAlmostEqual(result['classification_all_planned']['wilson_95'][0], .8864866068)

    def test_all_planned_denominator_keeps_missing_failed_rejected_abstained(self):
        m, attempts, _ = fixture(5)
        attempts.pop()
        for value, status in zip(attempts[1:], ('failed', 'rejected', 'abstained')):
            value.update(status=status, prediction=None, output_sha256=None)
        result = e.evaluate(m, attempts, [])
        self.assertEqual(result['counts'], dict(completed=1, failed=1, rejected=1, abstained=1, missing=1))
        self.assertEqual(result['classification_all_planned']['value'], .2)
        self.assertEqual(result['classification_completed_only']['value'], 1)
        self.assertEqual(result['mitre_exact_all_planned']['value'], .2)
        self.assertEqual(len(result['cases']), 5)

    def test_all_missing_is_zero_not_success_and_conditionals_null(self):
        m, _, _ = fixture()
        r = e.evaluate(m, [], [])
        self.assertEqual(r['classification_all_planned']['value'], 0)
        self.assertIsNone(r['classification_completed_only']['value'])
        self.assertIsNone(r['human_review']['unsupported_claim_rate_reviewed_only']['value'])
        self.assertFalse(r['gates']['all_completed_reviewed'])

    def test_completed_insufficient_evidence_is_explicit_label(self):
        m, attempts, _ = fixture(1)
        m['cases'][0]['gold']['classification'] = 'insufficient_evidence'
        attempts[0]['prediction']['classification'] = 'insufficient_evidence'
        r = e.evaluate(m, attempts, [])
        self.assertEqual(r['completed_insufficient_evidence'], 1)
        self.assertEqual(r['classification_all_planned']['value'], 1)
        self.assertEqual(r['counts']['abstained'], 0)

    def test_mitre_micro_and_exact_distinct(self):
        m, attempts, _ = fixture(1)
        attempts[0]['prediction']['mitre_ids'] = ['T1059', 'T1571']
        r = e.evaluate(m, attempts, [])
        self.assertEqual(r['mitre_exact_all_planned']['value'], 0)
        self.assertEqual(r['mitre_micro_completed_only']['precision']['value'], .5)
        self.assertEqual(r['mitre_micro_completed_only']['recall']['value'], 1)
        self.assertAlmostEqual(r['mitre_micro_completed_only']['f1'], 2 / 3)

    def test_empty_mitre_sets_exact_but_micro_undefined(self):
        m, attempts, _ = fixture(1)
        m['cases'][0]['gold']['mitre_ids'] = []
        attempts[0]['prediction']['mitre_ids'] = []
        r = e.evaluate(m, attempts, [])
        self.assertEqual(r['mitre_exact_all_planned']['value'], 1)
        self.assertIsNone(r['mitre_micro_completed_only']['f1'])

    def test_human_reviews_not_schema_based_hallucination(self):
        m, attempts, reviews = fixture(3)
        reviews.pop()
        reviews[0]['unsupported_claims'] = 1
        reviews[1]['claims'] = 0
        r = e.evaluate(m, attempts, reviews)['human_review']
        self.assertEqual(r['unreviewed_completed'], 1)
        self.assertEqual(r['zero_claim_reviews'], 1)
        self.assertEqual(r['unsupported_claim_rate_reviewed_only']['value'], .5)
        self.assertIsNone(r['unsupported_claim_rate_reviewed_only']['wilson_95'])
        self.assertEqual(r['cases_with_unsupported_claims_reviewed_positive_claims_only']['denominator'], 1)

    def test_wilson_suppressed_for_clusters_or_no_declaration(self):
        for repeated in (False, True):
            m, attempts, reviews = fixture()
            if repeated:
                m['cases'][1]['cluster_id'] = m['cases'][0]['cluster_id']
            else:
                m['independent_cases'] = False
            r = e.evaluate(m, attempts, reviews)
            self.assertEqual(r['intervals']['method'], 'suppressed')
            self.assertIsNone(r['classification_all_planned']['wilson_95'])

    def test_shared_batch_suppresses_intervals_despite_distinct_clusters(self):
        m, attempts, reviews = fixture(2)
        m['cases'][1].update(batch_id='batch-0', alert_ref='A2')
        result = e.evaluate(m, attempts, reviews)
        self.assertEqual(result['intervals']['batch_count'], 1)
        self.assertEqual(result['intervals']['cluster_count'], 2)
        self.assertEqual(result['intervals']['method'], 'suppressed')
        self.assertIsNone(result['classification_all_planned']['wilson_95'])

    def test_wilson_known_values_and_zero(self):
        self.assertIsNone(e.wilson(0, 0))
        self.assertAlmostEqual(e.wilson(0, 30)[1], .11351339317)
        self.assertAlmostEqual(e.wilson(15, 30)[0], .3315412564)

    def test_latency_failure_and_missing_are_not_dropped_silently(self):
        m, attempts, _ = fixture(4)
        attempts[1].update(status='failed', prediction=None, latency_seconds=50.)
        attempts[2].update(status='rejected', prediction=None, latency_seconds=None)
        attempts.pop()
        r = e.evaluate(m, attempts, [])
        self.assertEqual(r['latency_by_status']['failed']['mean_seconds'], 50)
        self.assertEqual(r['latency_by_status']['completed']['n'], 1)
        self.assertEqual(r['untimed_recorded_attempts'], 1)
        self.assertEqual(r['counts']['missing'], 1)
        self.assertEqual(e.latency(list(range(1, 21)))['p95_seconds'], 19)

    def test_batch_local_alert_refs_can_repeat_across_batches_not_within(self):
        m, attempts, reviews = fixture(2)
        e.evaluate(m, attempts, reviews)
        m['cases'][1]['batch_id'] = m['cases'][0]['batch_id']
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_CASE_OR_BATCH_REF'):
            e.evaluate(m, attempts, reviews)

    def test_shared_batch_must_have_one_input_hash(self):
        m, attempts, _ = fixture(2)
        m['cases'][1].update(batch_id='batch-0', alert_ref='A2', input_sha256='b' * 64)
        with self.assertRaisesRegex(ValueError, 'CONFLICTING_BATCH_INPUT_HASH'): e.evaluate(m, attempts, [])

    def test_retries_unknown_ids_and_duplicate_reviews_rejected(self):
        for target in ('attempt_duplicate', 'attempt_unknown', 'review_duplicate', 'review_unknown'):
            m, attempts, reviews = fixture()
            if target == 'attempt_duplicate': attempts.append(copy.deepcopy(attempts[0]))
            if target == 'attempt_unknown': attempts[0]['case_id'] = 'absent'
            if target == 'review_duplicate': reviews.append(copy.deepcopy(reviews[0]))
            if target == 'review_unknown': reviews[0]['case_id'] = 'absent'
            with self.subTest(target=target), self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)

    def test_frozen_provenance_and_output_review_binding(self):
        for field in ('input_sha256', 'provenance', 'output_sha256'):
            m, attempts, reviews = fixture()
            if field == 'provenance': attempts[0]['provenance']['model_sha256'] = 'b' * 64
            else: attempts[0][field] = 'b' * 64
            with self.subTest(field=field), self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)

    def test_exact_keys_and_strict_versions(self):
        for location in ('manifest', 'case', 'gold', 'attempt', 'prediction', 'review', 'provenance'):
            m, attempts, reviews = fixture()
            targets = {'manifest': m, 'case': m['cases'][0], 'gold': m['cases'][0]['gold'],
                       'attempt': attempts[0], 'prediction': attempts[0]['prediction'],
                       'review': reviews[0], 'provenance': m['provenance']}
            targets[location]['secret'] = 'not-for-output'
            with self.subTest(location=location), self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)
        m, attempts, reviews = fixture(); m['schema_version'] = True
        with self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)

    def test_invalid_types_hashes_enums_ids_and_techniques(self):
        for value in ('', '../secret', True, [], None):
            m, attempts, reviews = fixture(); m['evaluation_id'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)
        for value in (['T1059', 'T1059'], ['T999'], ['T1059', 1], 'T1059'):
            m, attempts, reviews = fixture(); m['cases'][0]['gold']['mitre_ids'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)
        for value in (True, 'true', None):
            m, attempts, reviews = fixture(); m['independent_cases'] = value
            if value is not True:
                with self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)
        for field, value in (('input_sha256', 'bad'), ('alert_ref', 'A0')):
            m, attempts, reviews = fixture(); m['cases'][0][field] = value
            with self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)

    def test_noncompleted_cannot_carry_prediction_or_review(self):
        m, attempts, reviews = fixture(1)
        attempts[0]['status'] = 'failed'
        with self.assertRaises(ValueError): e.evaluate(m, attempts, [])
        attempts[0]['prediction'] = None
        with self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)

    def test_invalid_latency_and_counts(self):
        for value in (-1, True, float('nan'), float('inf'), 86401, None, '2'):
            m, attempts, reviews = fixture(); attempts[0]['latency_seconds'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)
        for value in (-1, True, 3, 1.5):
            m, attempts, reviews = fixture(); reviews[0]['unsupported_claims'] = value
            with self.subTest(value=value), self.assertRaises(ValueError): e.evaluate(m, attempts, reviews)

    def test_limits_and_empty_manifest(self):
        m, attempts, reviews = fixture(); m['cases'] = []
        with self.assertRaises(ValueError): e.evaluate(m, [], [])
        with patch.object(e, 'MAX_CASES', 2), self.assertRaises(ValueError): e.evaluate(*fixture())
        with patch.object(e.a, 'MAX_INPUT', 10), self.assertRaises(ValueError): e.evaluate(*fixture())

    def test_no_input_mutation(self):
        values = fixture(); before = copy.deepcopy(values)
        result = e.evaluate(*values); result['provenance'].clear()
        self.assertEqual(values, before)

    def test_cli_success_and_input_file_hashes(self):
        with tempfile.TemporaryDirectory(prefix='c4-tests-', dir=ROOT / '.git') as directory:
            command = [sys.executable, '-I', '-B', str(ROOT / 'ai_agent/evaluate.py')]
            for name, value in zip(('manifest', 'attempts', 'reviews'), fixture()):
                path = Path(directory) / (name + '.json'); path.write_text(json.dumps(value))
                command += ['--' + name, str(path)]
            run = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(set(json.loads(run.stdout)['input_file_sha256']), {'manifest', 'attempts', 'reviews'})

    def test_cli_generic_error_no_private_details(self):
        with patch.object(e.a, 'read_file', side_effect=OSError('PRIVATE-SECRET')):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = e.main(['--manifest', 'private', '--attempts', 'private', '--reviews', 'private'])
            self.assertEqual(code, 1)
            self.assertNotIn('PRIVATE', err.getvalue())
            self.assertFalse(json.loads(err.getvalue())['acceptance_approved'])

    def test_duplicate_json_and_nonfinite_numbers_rejected(self):
        for text in ('{"a":1,"a":2}', '{"a":1e999}', '{"a":NaN}'):
            with self.assertRaises(ValueError): e.a.strict_json(text)


if __name__ == '__main__':
    unittest.main()
