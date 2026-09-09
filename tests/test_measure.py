"""Synthetic T-11 regressions, not lab results. ASTRA; 2026-09-09.
Source: tests/TEST_PLAN.md; status: local detection-core tests.
"""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mttd', ROOT / 'scripts/measure/mttd.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def manifest():
    return {'version': 1, 'runs': [{
        'run_id': 'synthetic', 'agent_id': '002', 'agent_name': 'kali1',
        'manager_name': 'manager-a', 'os': 'Linux', 'config_commit': 'a' * 40,
        'config_sha256': 'b' * 64, 'latency_kind': 'DETECTION', 'timing_definition': 'synthetic-source-to-manager',
        'coverage_start': '2026-09-09T00:00:00Z', 'coverage_end': '2026-09-09T02:00:00Z',
        'coverage_ref': 'fixture coverage', 'clock_verified': True,
        'clock_ref': 'fixture clock', 'clock_offset_ms': 0, 'clock_uncertainty_ms': 10}]}


def trial(**changes):
    result = {'run_id': 'synthetic', 'trial_id': 'one', 'uc': 'UC-02', 'variant': 'create',
              'phase': 'MEASURED', 'status': 'READY', 'event_valid': True,
              'source_ref': 'fixture source:1', 'window_ref': 'fixture window:1',
              'expected_rule_ids': ['554'], 'expected_levels': [5],
              'target_key': {'syscheck.path': '/fixture/one.txt'},
              'window_start': '2026-09-09T01:00:00Z', 'window_s': 120,
              'observe_until': '2026-09-09T01:05:00Z',
              't_source': '2026-09-09T01:00:00Z', 'source_precision_ms': 1}
    result.update(changes)
    return result


def alert(**changes):
    result = {'id': 'alert-1', 'manager': {'name': 'manager-a'},
              'agent': {'id': '002', 'name': 'kali1'}, 'rule': {'id': '554', 'level': 5},
              'timestamp': '2026-09-09T01:00:02Z', 'syscheck': {'path': '/fixture/one.txt'}}
    result.update(changes)
    return result


def rows(items):
    return [(item, f'fixture:{i}') for i, item in enumerate(items, 1)]


def report(trials=None, alerts=None, config=None):
    return m.analyze(rows([trial()] if trials is None else trials),
                     rows([alert()] if alerts is None else alerts), config or manifest())


class Correlation(unittest.TestCase):
    def test_detected_has_exact_source_time(self):
        r = report()
        self.assertEqual(r['trials'][0]['status'], 'DETECTED')
        self.assertEqual(r['summaries'][0]['mttd_s'], 2)
        self.assertEqual(r['summaries'][0]['denominator'], 1)

    def test_missing_and_late_remain_in_denominator(self):
        for alerts, late in [([], False), ([alert(timestamp='2026-09-09T01:03:00Z')], True)]:
            with self.subTest(late=late):
                r = report(alerts=alerts)
                self.assertEqual(r['trials'][0]['status'], 'MISSED')
                self.assertEqual(r['trials'][0]['late_detected'], late)
                self.assertEqual(r['summaries'][0]['denominator'], 1)
                self.assertEqual(r['summaries'][0]['detection_rate'], 0)
                self.assertIsNone(r['summaries'][0]['mttd_s'])

    def test_scan_detection_during_action_is_not_missed(self):
        t = trial(uc='UC-04', window_start='2026-09-09T01:00:05Z', match_start='2026-09-09T01:00:00Z')
        self.assertEqual(report([t])['trials'][0]['status'], 'DETECTED')
        with self.assertRaises(m.InputError):
            report([trial(uc='UC-04')])

    def test_deadline_inclusive(self):
        self.assertEqual(report(alerts=[alert(timestamp='2026-09-09T01:02:00Z')])['trials'][0]['status'], 'DETECTED')

    def test_wrong_path_agent_manager_rule_level_do_not_match(self):
        cases = [dict(syscheck={'path': '/fixture/two.txt'}), dict(agent={'id': '001', 'name': 'kali1'}),
                 dict(manager={'name': 'manager-b'}), dict(rule={'id': '550', 'level': 5}),
                 dict(rule={'id': '554', 'level': 7})]
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(report(alerts=[alert(**case)])['trials'][0]['status'], 'MISSED')

    def test_hash_is_not_correlation_identity(self):
        with self.assertRaises(m.InputError):
            report([trial(target_key={'data.md5': 'same-hash'})])

    def test_distinct_paths_same_hash_are_distinct(self):
        a = alert(data={'md5': 'same'})
        b = alert(id='alert-2', syscheck={'path': '/fixture/two.txt'}, data={'md5': 'same'})
        r = report([trial(), trial(trial_id='two', target_key={'syscheck.path': '/fixture/two.txt'})], [a, b])
        self.assertEqual(r['summaries'][0]['counts'], {'DETECTED': 2})

    def test_first_final_alert_chosen_not_input_order(self):
        r = report(alerts=[alert(id='later', timestamp='2026-09-09T01:00:09Z'), alert()])
        self.assertEqual(r['trials'][0]['alert_id'], 'alert-1')
        self.assertEqual(r['trials'][0]['matching_alert_count'], 2)

    def test_rotation_dedup_keeps_all_refs(self):
        r = report(alerts=[alert(), alert()])
        self.assertEqual(r['duplicate_alert_lines'], 1)
        self.assertEqual(r['trials'][0]['matching_alert_count'], 1)
        self.assertEqual(len(r['trials'][0]['alert_refs']), 2)

    def test_same_id_different_managers_not_deduplicated(self):
        r = report(alerts=[alert(), alert(manager={'name': 'manager-b'})])
        self.assertEqual(r['duplicate_alert_lines'], 0)

    def test_conflicting_duplicate_is_fatal(self):
        with self.assertRaises(m.InputError):
            report(alerts=[alert(), alert(timestamp='2026-09-09T01:00:03Z')])

    def test_one_alert_cannot_satisfy_two_trials(self):
        r = report([trial(), trial(trial_id='two')])
        self.assertEqual([t['status'] for t in r['trials']], ['AMBIGUOUS', 'AMBIGUOUS'])
        self.assertIsNone(r['summaries'][0]['detection_rate'])

    def test_duplicate_trial_invalid(self):
        with self.assertRaises(m.InputError):
            report([trial(), trial()])

    def test_explicit_exclusions_are_visible(self):
        r = report([trial(status='BLOCKED', reason='before event'), trial(trial_id='two')])
        self.assertEqual(r['summaries'][0]['counts'], {'BLOCKED': 1, 'DETECTED': 1})
        self.assertEqual(r['summaries'][0]['denominator'], 1)

    def test_pilot_and_suppression_controls_not_in_main_rate(self):
        for phase in ('PILOT', 'SUPPRESSION_CONTROL'):
            self.assertEqual(report([trial(phase=phase)])['summaries'], [])

    def test_baseline_and_uc01_explicitly_pending(self):
        for change in ({'phase': 'BASELINE'}, {'uc': 'UC-01'}):
            r = report([trial(**change)])
            self.assertEqual(r['trials'][0]['status'], 'NOT_EVALUATED')
            self.assertTrue(r['pending_features'])

    def test_netcat_lookback_is_manager_wide_not_pid(self):
        old = alert(id='old', timestamp='2026-09-09T00:59:00Z',
                    rule={'id': '100051', 'level': 7}, agent={'id': '001', 'name': 'win1'})
        r = report([trial(uc='UC-08')], [old, alert()])
        self.assertEqual(r['trials'][0]['status'], 'INTERFERED')
        self.assertEqual(r['trials'][0]['reason'], 'NETCAT_SUPPRESSION_LOOKBACK')

    def test_netcat_needs_coverage_before_window(self):
        cfg = manifest(); cfg['runs'][0]['coverage_start'] = '2026-09-09T00:59:00Z'
        self.assertEqual(report([trial(uc='UC-08')], config=cfg)['trials'][0]['status'], 'NOT_EVALUATED')

    def test_protocol_changes_require_new_run(self):
        with self.assertRaises(m.InputError):
            report([trial(), trial(trial_id='two', window_s=60)])

    def test_trial_cannot_override_configuration(self):
        with self.assertRaises(m.InputError):
            report([trial(os='Windows')])

    def test_comparison_bound_is_explicit_error(self):
        with patch.object(m, 'MAX_COMPARISONS', 0), self.assertRaises(m.InputError):
            report()

    def test_observation_and_ground_truth_required(self):
        for change in ({'observe_until': '2026-09-09T01:00:03Z'}, {'event_valid': False},
                       {'window_ref': ''}, {'source_ref': ''}, {'window_s': -1}):
            with self.subTest(change=change), self.assertRaises(m.InputError):
                report([trial(**change)])


class Timing(unittest.TestCase):
    def test_timezone_equivalence_and_offset_sign(self):
        cfg = manifest(); cfg['runs'][0]['clock_offset_ms'] = 50
        r = report([trial(t_source='2026-09-09T04:00:00+03:00')], config=cfg)
        self.assertAlmostEqual(r['summaries'][0]['mttd_s'], 2.05)

    def test_missing_clock_does_not_hide_detected_trial(self):
        cfg = manifest(); cfg['runs'][0]['clock_verified'] = False
        r = report(config=cfg)
        self.assertEqual(r['summaries'][0]['detection_rate'], 1)
        self.assertIsNone(r['summaries'][0]['mttd_s'])
        self.assertEqual(r['trials'][0]['timing_status'], 'TIMING_UNVERIFIED')

    def test_missing_source_not_replaced_with_alert_at_timestamp(self):
        r = report([trial(t_source=None)], [alert(**{'@timestamp': '2026-09-09T01:00:04Z'})])
        self.assertIsNone(r['summaries'][0]['mttd_s'])

    def test_negative_or_naive_source_time_is_invalid_not_zero(self):
        for source in ('2026-09-09T01:00:03Z', '2026-09-09T01:00:00'):
            r = report([trial(t_source=source)])
            self.assertEqual(r['trials'][0]['timing_status'], 'TIMING_INVALID')
            self.assertEqual(r['summaries'][0]['n_timed'], 0)
            self.assertEqual(r['summaries'][0]['denominator'], 1)

    def test_negative_lower_action_bound_is_valid_interval(self):
        r = report([trial(t_source=None, t_before='2026-09-09T01:00:00Z', t_after='2026-09-09T01:00:04Z')])
        self.assertEqual(r['trials'][0]['action_interval_s'], [-2, 2])
        self.assertEqual(r['trials'][0]['timing_status'], 'INTERVAL_ONLY')
        self.assertIsNone(r['summaries'][0]['mttd_s'])

    def test_naive_alert_time_rejected(self):
        with self.assertRaises(m.InputError):
            report(alerts=[alert(timestamp='2026-09-09T01:00:00')])

    def test_integration_latency_is_not_called_mttd(self):
        cfg = manifest(); cfg['runs'][0]['latency_kind'] = 'INTEGRATION'
        r = report(config=cfg)
        self.assertEqual(r['summaries'][0]['mean_source_to_alert_s'], 2)
        self.assertIsNone(r['summaries'][0]['mttd_s'])

    def test_runs_are_never_pooled(self):
        cfg = manifest(); other = copy.deepcopy(cfg['runs'][0]); other.update(run_id='other', os='Windows')
        cfg['runs'].append(other)
        r = report([trial(), trial(run_id='other')], [], cfg)
        self.assertEqual(len(r['summaries']), 2)


class InputIO(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=ROOT / '.git', prefix='measure-tests-')
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)

    def write(self, name, content):
        path = self.home / name
        path.write_text(content, encoding='utf-8')
        return str(path)

    def test_invalid_json_duplicate_keys_and_nonobjects(self):
        for raw in ('{', '\n', '[]', '{"x":1,"x":2}', '{"x":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(m.InputError):
                m.read_jsonl([self.write('bad.jsonl', raw)])

    def test_input_size_bounds(self):
        path = self.write('bounded.jsonl', '{}\n{}\n')
        with patch.object(m, 'MAX_BYTES', 4), self.assertRaises(m.InputError):
            m.read_jsonl([path])
        with patch.object(m, 'MAX_LINE', 1), self.assertRaises(m.InputError):
            m.read_jsonl([path])
        with patch.object(m, 'MAX_RECORDS', 1), self.assertRaises(m.InputError):
            m.read_jsonl([path])

    def test_cli_success_includes_provenance(self):
        args = ['--journal', self.write('journal.jsonl', json.dumps(trial())),
                '--alerts', self.write('alerts.jsonl', json.dumps(alert())),
                '--manifest', self.write('manifest.json', json.dumps(manifest()))]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(m.main(args), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(len(result['inputs']), 3)
        self.assertEqual(len(result['tool_sha256']), 64)

    def test_cli_fatal_input_has_no_partial_stdout_report(self):
        args = ['--journal', self.write('journal.jsonl', json.dumps(trial())),
                '--alerts', self.write('alerts.jsonl', '{'),
                '--manifest', self.write('manifest.json', json.dumps(manifest()))]
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            self.assertEqual(m.main(args), 2)
        self.assertEqual(output.getvalue(), '')
        self.assertIn('measurement input error:', error.getvalue())


if __name__ == '__main__':
    unittest.main()
