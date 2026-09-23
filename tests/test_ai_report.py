"""Private offline report regressions; all evidence is synthetic, no network."""
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

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

p = load('report_tests', ROOT/'ai_agent/report.py')
f = load('report_fixture', ROOT/'tests/test_ai_runner.py')
r = p.r


class Reports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT/'.git', prefix='report-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.store = self.base/'store'; self.store.mkdir(mode=0o700)
        self.manifest, self.inputs, self.response = f.fixture(2)
        self.manifest_bytes = r.json_bytes(self.manifest)

    def run_batch(self, reason='OK', output=None):
        with patch.object(r, 'bounded_process', return_value={'reason':reason, 'returncode':0 if reason=='OK' else None,
                  'latency_seconds':.25, 'output':self.response if output is None else output}):
            r.run_batch(self.store, self.manifest_bytes, 'batch-1', self.inputs, infer=True)

    def build(self):
        return p.build(self.store, r.digest(self.manifest_bytes), no_reviews=True)

    def reviews(self, values=None):
        values = values if values is not None else [{'case_id':'case-0', 'output_sha256':r.digest(self.response),
            'reviewer_ref':'PRIVATE-REVIEWER', 'independent':True, 'claims':3, 'unsupported_claims':1}]
        path = self.base/'reviews.json'; raw = r.json_bytes(values)
        path.write_bytes(raw); path.chmod(0o600)
        return path, r.digest(raw)

    def test_verified_report_preserves_evaluator_semantics(self):
        self.run_batch(); report = self.build()
        e = report['evaluation']
        self.assertEqual(e['planned_cases'], 2)
        self.assertEqual(e['counts']['completed'], 2)
        self.assertEqual(e['classification_all_planned']['value'], 0)
        self.assertFalse(e['artifact_contents_verified'])  # evaluator alone still cannot authenticate inputs
        self.assertTrue(report['evidence_verification']['stored_artifact_bytes_verified'])
        for key in ('acceptance_approved', 'human_independence_verified', 'model_runtime_identity_verified'):
            self.assertFalse(report[key])

    def test_reviews_require_explicit_omission_or_hash_bound_file(self):
        self.run_batch()
        with self.assertRaises(ValueError): p.build(self.store, r.digest(self.manifest_bytes))
        path, sha = self.reviews()
        with self.assertRaises(ValueError): p.build(self.store, r.digest(self.manifest_bytes), path)
        with self.assertRaises(ValueError): p.build(self.store, r.digest(self.manifest_bytes), path, sha, no_reviews=True)

    def test_real_review_file_changes_only_review_metrics(self):
        self.run_batch(); path, sha = self.reviews()
        report = p.build(self.store, r.digest(self.manifest_bytes), path, sha)
        self.assertEqual(report['evaluation']['human_review']['reviewed_cases'], 1)
        self.assertEqual(report['evaluation']['human_review']['unreviewed_completed'], 1)
        self.assertEqual(report['evaluation']['human_review']['unsupported_claim_rate_reviewed_only']['value'], 1/3)
        self.assertEqual(report['evidence_verification']['reviews_file_sha256'], sha)
        self.assertNotIn('PRIVATE-REVIEWER', json.dumps(report))
        self.assertFalse(report['human_independence_verified'])

    def test_review_wrong_digest_or_output_binding_is_rejected(self):
        self.run_batch(); path, sha = self.reviews()
        with self.assertRaisesRegex(ValueError, 'REVIEW_HASH_MISMATCH'):
            p.build(self.store, r.digest(self.manifest_bytes), path, 'b'*64)
        rows = json.loads(path.read_bytes()); rows[0]['output_sha256'] = 'b'*64
        path, sha = self.reviews(rows)
        with self.assertRaisesRegex(ValueError, 'REVIEW_OUTPUT_MISMATCH'):
            p.build(self.store, r.digest(self.manifest_bytes), path, sha)

    def test_review_file_permissions_symlink_and_hardlink_are_rejected(self):
        self.run_batch(); path, sha = self.reviews()
        path.chmod(0o644)
        with self.assertRaises(ValueError): p.build(self.store, r.digest(self.manifest_bytes), path, sha)
        path.chmod(0o600)
        link = self.base/'alias'; link.symlink_to(path)
        with self.assertRaises(OSError): p.build(self.store, r.digest(self.manifest_bytes), link, sha)
        r.os.link(path, self.base/'hard')
        with self.assertRaises(ValueError): p.build(self.store, r.digest(self.manifest_bytes), path, sha)

    def test_source_artifact_corruption_refuses_report(self):
        self.run_batch()
        path = next(self.store.glob('batch-*'))/'alerts.jsonl'
        path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaises(ValueError): self.build()

    def test_manifest_expected_hash_is_not_read_from_untrusted_store(self):
        self.run_batch()
        with self.assertRaisesRegex(ValueError, 'MANIFEST_HASH_MISMATCH'):
            p.build(self.store, 'b'*64, no_reviews=True)

    def test_missing_batch_remains_in_denominator_and_html(self):
        extra = copy.deepcopy(self.manifest['cases'][0])
        extra.update(case_id='missing-case', batch_id='not-run', input_sha256='b'*64)
        self.manifest['cases'].append(extra); self.manifest_bytes = r.json_bytes(self.manifest)
        self.run_batch(); report = self.build()
        self.assertEqual(report['evaluation']['counts']['missing'], 1)
        self.assertEqual(report['evaluation']['completion_rate']['denominator'], 3)
        self.assertIn('missing-case', p.render(report))
        self.assertIn('2 / 3', p.render(report))

    def test_unknown_latency_is_not_rendered_as_zero(self):
        with patch.object(r, 'bounded_process', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                r.run_batch(self.store, self.manifest_bytes, 'batch-1', self.inputs, infer=True)
        report = self.build()
        self.assertEqual(report['evaluation']['untimed_recorded_attempts'], 2)
        self.assertIsNone(report['evaluation']['latency_by_status']['failed']['mean_seconds'])
        self.assertIn('INTERRUPTED_AFTER_INTENT', p.render(report))

    def test_orphan_output_warning_not_laundered_to_verified(self):
        self.run_batch(); (next(self.store.glob('batch-*'))/'terminal.json').unlink()
        report = self.build()
        self.assertFalse(report['evidence_verification']['stored_artifact_bytes_verified'])
        text = p.render(report)
        self.assertIn('output.bin', text)
        self.assertIn('لا تحقق شامل', text)

    def test_no_human_reviews_is_not_zero_hallucinations(self):
        self.run_batch(); report = self.build()
        value = report['evaluation']['human_review']['unsupported_claim_rate_reviewed_only']
        self.assertIsNone(value['value']); self.assertEqual(value['denominator'], 0)
        self.assertIn('مقام صفر', p.render(report))

    def test_html_is_self_contained_and_escapes_all_dynamic_content(self):
        self.run_batch(); report = self.build()
        report['evaluation']['evaluation_id'] = '<script>alert("x")</script>'
        report['notice'] = '<img src=x onerror=alert(1)>'
        text = p.render(report)
        self.assertIn('&lt;script&gt;', text); self.assertNotIn('<script', text)
        self.assertNotIn('<img ', text); self.assertNotIn(' src=', text.replace('&lt;img src=', ''))
        self.assertIn("default-src 'none'", text)
        self.assertNotIn('<form', text); self.assertNotIn('<iframe', text)
        self.assertNotIn('href=', text)
        self.assertIn('lang="ar" dir="rtl"', text)

    def test_raw_logs_gold_and_reviewer_identity_absent_from_interface(self):
        self.run_batch(); path, sha = self.reviews()
        text = p.render(p.build(self.store, r.digest(self.manifest_bytes), path, sha))
        for marker in ('NEVER-SEND', 'PRIVATE-REVIEWER', 'likely_benign', 'private-manager'):
            self.assertNotIn(marker, text)

    def test_no_model_call_or_input_mutation(self):
        self.run_batch()
        before = {str(path):path.read_bytes() for path in self.store.rglob('*') if path.is_file()}
        with patch.object(r.a.Ollama, '__call__', side_effect=AssertionError('network forbidden')):
            self.build()
        after = {str(path):path.read_bytes() for path in self.store.rglob('*') if path.is_file()}
        self.assertEqual(before, after)

    def test_cli_json_and_html_from_same_verified_store(self):
        self.run_batch()
        command = [sys.executable, '-I', '-B', str(ROOT/'ai_agent/report.py'), '--store', str(self.store),
                   '--manifest-sha256', r.digest(self.manifest_bytes), '--no-reviews']
        result = subprocess.run(command, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['evaluation']['counts']['completed'], 2)
        result = subprocess.run(command+['--format', 'html'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith(b'<!doctype html>'))

    def test_cli_failure_is_generic_and_emits_no_partial_report(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = p.main(['--store', str(self.base/'PRIVATE-MISSING'), '--manifest-sha256', 'b'*64, '--no-reviews'])
        self.assertEqual(code, 1); self.assertEqual(out.getvalue(), '')
        self.assertNotIn('PRIVATE', err.getvalue())


if __name__ == '__main__':
    unittest.main()
