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


def manifest_v2():
    cfg = manifest(); cfg['version'] = 2
    run = cfg['runs'][0]
    run.update(session_id='session-a',
               devices={name: {'ntp_offset_ms': 0, 'uncertainty_ms': 1, 'clock_ref': 'fixture clock'}
                        for name in ('attacker', 'endpoint', 'manager', 'observer')},
               clock_map={'t0': 'attacker', 't1': 'endpoint', 't2': 'manager', 't3': 'observer',
                          't4': 'endpoint', 't5': 'observer', 't6': 'manager', 't2_prime': 'manager'})
    return cfg


def trial_v2(**changes):
    t = trial(); t.pop('status')
    base = m.to_ms('2026-09-09T01:00:00Z')
    t.update(schema_version=2, session_id='session-a', exclusion_reason=None,
             ntp_offset_ms={name: 0 for name in ('attacker', 'endpoint', 'manager', 'observer')},
             time_refs={key: 'fixture evidence:' + key for key in m.TIMES},
             missing_reasons={key: 'not observed' for key in m.TIMES}, poll_interval_ms=1000,
             completion_kind='independent_observation',
             stage_selectors={'t2': {'rule_ids': ['554'], 'levels': [5],
                                     'target_key': {'syscheck.path': '/fixture/one.txt'}}})
    t.update({key: base + i*1000 for i, key in enumerate(m.TIMES)})
    t['t2_prime'] = None
    t['t6'] = None
    t.update(changes)
    return t


def report_v2(trials=None, alerts=None, config=None):
    return m.analyze_v2(rows([trial_v2()] if trials is None else trials),
                        rows([alert()] if alerts is None else alerts), config or manifest_v2())


class TimelineV2(unittest.TestCase):
    def test_eight_exact_metric_formulas(self):
        t = trial_v2(t6=m.to_ms('2026-09-09T01:00:06Z'))
        t['stage_selectors']['t6'] = {'rule_ids': ['657'], 'levels': [3], 'target_key': t['target_key']}
        confirmation = alert(id='confirmation', rule={'id': '657', 'level': 3}, timestamp='2026-09-09T01:00:06Z')
        r = report_v2([t], [alert(), confirmation]); row = r['trials'][0]
        self.assertEqual(row['metrics_s'], {'D_source': 1, 'MTTD': 1, 'MTTD_e2e': 2,
            'L_vis': 1, 'L_AR_trigger': 2, 'L_AR_complete': 1, 'L_AR_e2e': 5, 'L_confirm': 1})
        for name in m.METRICS:
            self.assertEqual(r['summaries'][0]['metrics_s'][name]['median'], row['metrics_s'][name])

    def test_confirmation_requires_raw_selector(self):
        with self.assertRaises(m.InputError):
            report_v2([trial_v2(t6=1788915606000)])

    def test_manager_stages_share_clock(self):
        cfg = manifest_v2(); cfg['runs'][0]['clock_map']['t6'] = 'observer'
        with self.assertRaises(m.InputError): report_v2(config=cfg)

    def test_stage_protocol_cannot_change_within_run(self):
        a, b = trial_v2(), trial_v2(trial_id='two')
        b['stage_selectors']['t2']['rule_ids'] = ['550']
        with self.assertRaises(m.InputError): report_v2([a, b], [])

    def test_final_and_intermediate_stage_share_ownership(self):
        a, b = trial_v2(), trial_v2(trial_id='two', uc='UC-07', expected_rule_ids=['108001'], expected_levels=[12])
        b['stage_selectors']['t2']['rule_ids'] = ['554']
        final = alert(id='yara', rule={'id': '108001', 'level': 12})
        result = report_v2([a, b], [alert(), final])
        self.assertTrue(all(r['exclusion_reason'] == 'AMBIGUOUS' for r in result['trials']))

    def test_missing_netcat_lookback_is_explicit_invalid(self):
        cfg = manifest_v2(); cfg['runs'][0]['coverage_start'] = '2026-09-09T00:59:00Z'
        row = report_v2([trial_v2(uc='UC-08')], config=cfg)['trials'][0]
        self.assertEqual(row['exclusion_reason'], 'INVALID')
        self.assertNotIn('source_to_alert_s', row)

    def test_seven_nullable_fields_required(self):
        for key in m.TIMES:
            t = trial_v2(); del t[key]
            with self.subTest(key=key), self.assertRaises(m.InputError): report_v2([t])

    def test_epoch_ms_strict_and_roundtrip(self):
        self.assertEqual(m.to_ms(m.iso_ms(1788915600123)), 1788915600123)
        for value in [True, -1, 1.5, '2026-09-09T01:00:00Z']:
            t = trial_v2(t1=value)
            with self.assertRaises(m.InputError): report_v2([t])

    def test_null_times_are_not_fabricated(self):
        r = report_v2([trial_v2(t1=None, t3=None, t4=None, t5=None, t6=None)])
        self.assertIsNone(r['trials'][0]['metrics_s']['MTTD'])
        self.assertIsNone(r['summaries'][0]['metrics_s']['L_AR_complete']['median'])
        self.assertEqual(r['trials'][0]['metrics_s']['MTTD_e2e'], 2)

    def test_missing_reason_and_evidence_required(self):
        for changes in [dict(t1=None, missing_reasons={}), dict(time_refs={})]:
            with self.assertRaises(m.InputError): report_v2([trial_v2(**changes)])

    def test_t5_is_not_success_log(self):
        with self.assertRaises(m.InputError): report_v2([trial_v2(completion_kind='script_log')])

    def test_device_offsets_corrected_once_with_sign(self):
        t = trial_v2(); t['ntp_offset_ms'].update(endpoint=50, manager=-50)
        r = report_v2([t])['trials'][0]
        self.assertAlmostEqual(r['metrics_s']['MTTD'], 1.1)
        self.assertAlmostEqual(r['metrics_s']['D_source'], .95)

    def test_exact_100_ms_is_accepted(self):
        for offset in [-100, 100]:
            t = trial_v2(); t['ntp_offset_ms']['endpoint'] = offset
            self.assertEqual(report_v2([t])['rejected_sessions'], [])

    def test_offset_spike_invalidates_entire_session_across_runs(self):
        cfg = manifest_v2(); other = copy.deepcopy(cfg['runs'][0]); other['run_id'] = 'other'; cfg['runs'].append(other)
        a = trial_v2(); b = trial_v2(run_id='other'); b['ntp_offset_ms']['observer'] = -101
        r = report_v2([a, b], config=cfg)
        self.assertEqual(r['rejected_sessions'], ['session-a'])
        self.assertTrue(all(t['exclusion_reason'] == 'INVALID' for t in r['trials']))
        self.assertTrue(all(all(v is None for v in t['metrics_s'].values()) for t in r['trials']))

    def test_manifest_offset_alone_invalidates_session(self):
        cfg = manifest_v2(); cfg['runs'][0]['devices']['attacker']['ntp_offset_ms'] = 100.001
        self.assertEqual(report_v2(config=cfg)['trials'][0]['exclusion_reason'], 'INVALID')

    def test_clock_uncertainty_limit_and_other_session(self):
        cfg = manifest_v2(); other = copy.deepcopy(cfg['runs'][0]); other.update(run_id='other', session_id='session-b')
        cfg['runs'][0]['devices']['observer']['uncertainty_ms'] = 101; cfg['runs'].append(other)
        r = report_v2([trial_v2(), trial_v2(run_id='other', session_id='session-b')], config=cfg)
        self.assertEqual(r['rejected_sessions'], ['session-a'])
        self.assertEqual(r['trials'][1]['status'], 'DETECTED')

    def test_all_session_devices_must_have_offsets(self):
        t = trial_v2(); del t['ntp_offset_ms']['observer']
        with self.assertRaises(m.InputError): report_v2([t])

    def test_exclusion_enum_and_input_status(self):
        for changes in [dict(exclusion_reason='BAD'), dict(status='DETECTED')]:
            with self.assertRaises(m.InputError): report_v2([trial_v2(**changes)])
        for reason in m.EXCLUDED:
            r = report_v2([trial_v2(exclusion_reason=reason, reason='operator evidence')])
            self.assertEqual(r['trials'][0]['exclusion_reason'], reason)

    def test_both_denominators_and_wilson_are_named(self):
        r = report_v2([trial_v2(), trial_v2(trial_id='blocked', exclusion_reason='BLOCKED', reason='preflight')])
        s = r['summaries'][0]
        self.assertEqual(s['detection_rate_all_attempts'], .5)
        self.assertEqual(s['detection_rate_valid'], 1)
        self.assertEqual(s['wilson_95_all_attempts'], m.wilson(1, 2))

    def test_vt_separate_t2_and_t2_prime(self):
        t = trial_v2(uc='UC-03', t2=None, t2_prime=None, expected_rule_ids=['87105'], expected_levels=[12],
                     target_key={'data.virustotal.source.file': '/fixture/one.txt'})
        t['stage_selectors'] = {
            't2': {'rule_ids': ['100201'], 'levels': [7], 'target_key': {'syscheck.path': '/fixture/one.txt'}},
            't2_prime': {'rule_ids': ['87105'], 'levels': [12], 'target_key': t['target_key']}}
        a = alert(rule={'id': '100201', 'level': 7})
        b = alert(id='vt', timestamp='2026-09-09T01:00:03Z', rule={'id': '87105', 'level': 12},
                  data={'virustotal': {'source': {'file': '/fixture/one.txt'}}})
        r = report_v2([t], [b, a]); v = r['trials'][0]['metrics_s']
        self.assertEqual(v['D_VT'], 1)
        self.assertEqual(v['L_AR_trigger'], 2)  # Do NOT silently subtract t2_prime.
        self.assertEqual(r['summaries'][0]['minimum_measured_n'], 30)

    def test_missing_vt_is_null_not_zero(self):
        t = trial_v2(uc='UC-03', t2=None, t2_prime=None)
        t['stage_selectors']['t2']['rule_ids'] = ['100201']
        t['stage_selectors']['t2_prime'] = {'rule_ids': ['87105'], 'levels': [12], 'target_key': t['target_key']}
        self.assertIsNone(report_v2([t], [])['trials'][0]['metrics_s']['D_VT'])

    def test_claimed_t2_must_match_raw_alert(self):
        t = trial_v2(); t['t2'] += 1
        self.assertEqual(report_v2([t])['trials'][0]['exclusion_reason'], 'INVALID')

    def test_raw_stage_fills_null_t2_and_retains_refs(self):
        row = report_v2([trial_v2(t2=None)])['trials'][0]
        self.assertEqual(row['timeline_ms']['t2'], m.to_ms(alert()['timestamp']))
        self.assertTrue(row['stage_alert_refs']['t2'])

    def test_negative_interval_is_invalid_not_clamped(self):
        t = trial_v2(); t['t1'] = t['t2'] + 1
        row = report_v2([t])['trials'][0]
        self.assertIsNone(row['metrics_s']['MTTD'])
        self.assertEqual(row['metric_status']['MTTD'], 'INVALID_ORDER')

    def test_phase_summaries_remain_separate(self):
        for phase in m.PHASES - {'BASELINE'}:
            r = report_v2([trial_v2(phase=phase)])
            self.assertEqual(r['summaries'][0]['phase'], phase)

    def test_pilot_requires_five_samples_for_n_recommendation(self):
        r = report_v2([trial_v2(phase='PILOT')])
        self.assertIsNone(r['summaries'][0]['pilot_recommended_n']['MTTD'])

    def test_polling_interval_contract(self):
        with self.assertRaises(m.InputError): report_v2([trial_v2(poll_interval_ms=500)])
        self.assertEqual(report_v2()['trials'][0]['visibility_uncertainty_ms'], 1000)

    def test_uc11_and_planned_n(self):
        r = report_v2([trial_v2(uc='UC-11')])
        self.assertEqual(r['summaries'][0]['minimum_measured_n'], 30)
        cfg = manifest_v2(); cfg['runs'][0]['planned_n'] = 35
        self.assertEqual(report_v2(config=cfg)['summaries'][0]['minimum_measured_n'], 35)

    def test_baseline_union_and_exact_upper(self):
        cfg = manifest_v2(); cfg['runs'][0]['baseline_rule_ids'] = ['554']
        base = m.to_ms('2026-09-09T00:00:00Z')
        b = {'start_ms': base, 'end_ms': base+7200000, 'activity_ref': 'benign journal',
             'adjudications': [{'manager_name': 'manager-a', 'alert_id': 'alert-1',
                               'is_false_threat_alert': True, 'reason': 'adjudicated false', 'ref': 'review'}]}
        r = report_v2([trial_v2(phase='BASELINE', baseline=b),
                       trial_v2(trial_id='overlap', phase='BASELINE', baseline=b)], config=cfg)
        s = r['baseline'][0]
        self.assertEqual((s['hours'], s['false_alerts']), (2, 1))
        self.assertAlmostEqual(s['fp_upper_95'], m.poisson_upper(1, 2))

    def test_baseline_unreviewed_not_reported_as_zero_fp(self):
        cfg = manifest_v2(); cfg['runs'][0]['baseline_rule_ids'] = ['554']
        base = m.to_ms('2026-09-09T00:00:00Z')
        t = trial_v2(phase='BASELINE', baseline={'start_ms': base, 'end_ms': base+7200000,
                     'activity_ref': 'benign', 'adjudications': []})
        r = report_v2([t], config=cfg)['baseline'][0]
        self.assertEqual(r['unresolved'], 1)
        self.assertIsNone(r['fp_upper_95'])

    def test_five_pilot_samples_produce_size_recommendation(self):
        trials, alerts = [], []
        for i, delta in enumerate([1, 2, 3, 4, 15]):
            path = '/fixture/pilot-' + str(i)
            t = trial_v2(trial_id=str(i), phase='PILOT', t2=None, target_key={'syscheck.path': path})
            t['stage_selectors']['t2']['target_key'] = t['target_key']
            trials.append(t)
            alerts.append(alert(id=str(i), syscheck={'path': path}, timestamp=m.iso_ms(t['t1']+delta*1000)))
        summary = report_v2(trials, alerts)['summaries'][0]
        self.assertEqual(summary['metrics_s']['MTTD']['n'], 5)
        self.assertEqual(summary['pilot_recommended_n']['MTTD'], m.sample_size(m.statistics.stdev([1,2,3,4,15])))

    def test_h4_computes_independent_comparable_groups(self):
        cfg = manifest_v2(); other = copy.deepcopy(cfg['runs'][0]); other.update(run_id='official'); cfg['runs'].append(other)
        cfg['h4_comparisons'] = [{'hardened_run_id':'synthetic','official_run_id':'official',
                                 'uc':'UC-02','variant':'create','design_ref':'synthetic independent groups'}]
        x, y = trial_v2(), trial_v2(run_id='official', t5=1788915604500)
        y['target_key'] = {'syscheck.path':'/fixture/official'}
        y['stage_selectors']['t2']['target_key'] = y['target_key']
        result = report_v2([x,y], [alert(), alert(id='official', syscheck={'path':'/fixture/official'})], cfg)['h4'][0]
        self.assertEqual(result['status'], 'CALCULATED_NOT_H4_PROOF')
        self.assertEqual(result['result']['delta_median_s'], .5)
        self.assertEqual(result['result']['alternative'], 'greater')

    def test_cli_v2_dispatch_provenance(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.git') as directory:
            base = Path(directory)
            (base/'j').write_text(json.dumps(trial_v2())+'\n')
            (base/'a').write_text(json.dumps(alert())+'\n')
            (base/'m').write_text(json.dumps(manifest_v2()))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(m.main(['--journal',str(base/'j'),'--alerts',str(base/'a'),'--manifest',str(base/'m')]),0)
            result = json.loads(output.getvalue())
            self.assertEqual(result['schema_version'], 2)
            self.assertEqual(len(result['inputs']), 3)

    def test_h4_no_implicit_pooling(self):
        cfg = manifest_v2(); other = copy.deepcopy(cfg['runs'][0]); other.update(run_id='official', os='Windows'); cfg['runs'].append(other)
        cfg['h4_comparisons'] = [{'hardened_run_id': 'synthetic', 'official_run_id': 'official',
                                  'uc': 'UC-02', 'variant': 'create', 'design_ref': 'randomized independent trials'}]
        with self.assertRaises(m.InputError): report_v2(config=cfg)


class PlanV31(unittest.TestCase):
    def test_floor_thirty_for_every_uc_and_reject_twenty(self):
        for uc in ['UC-%02d' % i for i in range(1, 14)]:
            trial = trial_v2(uc=uc, exclusion_reason='BLOCKED', reason='synthetic preflight')
            self.assertEqual(report_v2([trial], [])['summaries'][0]['minimum_measured_n'], 30)
            cfg = manifest_v2(); cfg['runs'][0]['planned_n'] = 20
            with self.assertRaises(m.InputError): report_v2([trial], [], cfg)

    def test_twelve_hour_baseline_boundary_and_exact_one_fp(self):
        for hours in [6, 11.99, 12]:
            cfg = manifest_v2(); cfg['runs'][0].update(coverage_end='2026-09-10T00:00:00Z', baseline_rule_ids=['554'])
            start = m.to_ms(cfg['runs'][0]['coverage_start'])
            baseline = {'start_ms':start, 'end_ms':start+int(hours*3600000), 'activity_ref':'fixture',
                        'adjudications':[{'manager_name':'manager-a','alert_id':'alert-1',
                        'is_false_threat_alert':True,'reason':'synthetic FP','ref':'fixture review'}]}
            out = report_v2([trial_v2(phase='BASELINE',baseline=baseline)], config=cfg)['baseline'][0]
            self.assertEqual(out['minimum_hours'],12)
            self.assertEqual(bool(out['warnings']),hours<12)
            self.assertAlmostEqual(out['fp_upper_95'],4.743864518390578/hours)

    def test_timestamp_inspection_seconds_milliseconds_and_padding(self):
        for stamp, digits, fraction in [('2026-09-09T01:00:02Z',0,False),
                                        ('2026-09-09T04:00:02.123+0300',3,True),
                                        ('2026-09-09T01:00:02.000Z',3,False)]:
            result = m.inspect_alert_timestamps(rows([alert(timestamp=stamp)]))['managers'][0]
            self.assertEqual(result['fraction_digits_counts'],{digits:1})
            self.assertEqual(result['has_nonzero_fraction'],fraction)
            self.assertIn('UNVERIFIED',result['status'])
            self.assertEqual(result['coarsest_serialized_quantum_ms'],1000/10**digits)

    def test_timestamp_inspection_mixed_precision_and_empty(self):
        result = m.inspect_alert_timestamps(rows([alert(),alert(id='fraction',timestamp='2026-09-09T01:00:02.123456Z')]))
        self.assertEqual(result['managers'][0]['coarsest_serialized_quantum_ms'],1000)
        with self.assertRaises(m.InputError): m.inspect_alert_timestamps([])

    def test_timestamp_inspection_cli_needs_no_journal(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.git') as home:
            path=Path(home)/'alerts'; path.write_text(json.dumps(alert())+'\n')
            output=io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(m.main(['--inspect-alert-timestamps','--alerts',str(path)]),0)
            result=json.loads(output.getvalue())
            self.assertEqual(result['scope'],'G2_ALERT_TIMESTAMP_FIRST_CHECK')
            self.assertEqual(len(result['inputs'][0]['sha256']),64)


class PlanStatistics(unittest.TestCase):
    def test_sample_size_floor_and_formula(self):
        self.assertEqual(m.sample_size(0), 30)
        self.assertEqual(m.sample_size(2), 30)
        self.assertEqual(m.sample_size(3), 35)
        self.assertEqual(m.sample_size(5), 97)
        self.assertEqual(m.sample_size(3, .5), 139)

    def test_sample_size_invalid(self):
        for sigma, margin in [(-1, 1), (True, 1), (float('nan'), 1), (2, 0), (2, -1)]:
            with self.subTest(sigma=sigma, margin=margin), self.assertRaises(m.InputError):
                m.sample_size(sigma, margin)

    def test_wilson_matches_plan_math(self):
        spec = importlib.util.spec_from_file_location('plan_math', ROOT / 'scripts/measure/plan_math.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        for k, n in [(0, 20), (20, 20), (10, 20), (30, 30)]:
            for got, expected in zip(m.wilson(k, n), module.wilson(k, n)):
                self.assertAlmostEqual(got, expected, places=12)
        self.assertAlmostEqual(m.wilson(20, 20)[0], .83887484, places=7)

    def test_wilson_empty_and_invalid(self):
        self.assertIsNone(m.wilson(0, 0))
        for k, n in [(2, 1), (-1, 1), (1, -1), (True, 2)]:
            with self.assertRaises(m.InputError): m.wilson(k, n)

    def test_quantile_convention_and_stats(self):
        s = m.describe([1, 2, 3, 4])
        self.assertEqual((s['median'], s['q1'], s['q3'], s['iqr']), (2.5, 1.75, 3.25, 1.5))
        self.assertAlmostEqual(s['p95'], 3.85)
        self.assertEqual((s['min'], s['max'], s['mean'], s['n']), (1, 4, 2.5, 4))
        self.assertAlmostEqual(s['sd'], (5/3)**.5)

    def test_empty_and_singleton_stats(self):
        self.assertEqual(m.describe([])['n'], 0)
        self.assertIsNone(m.describe([])['p95'])
        self.assertEqual(m.describe([7])['iqr'], 0)
        self.assertIsNone(m.describe([7])['sd'])

    def test_stats_reject_nonfinite_and_negative(self):
        for value in [-1, True, float('inf')]:
            with self.assertRaises(m.InputError): m.describe([value])
        with self.assertRaises(m.InputError): m.percentile([1], 2)

    def test_poisson_zero(self):
        self.assertAlmostEqual(m.poisson_upper(0, 6), .4992887122589985, places=12)

    def test_poisson_nonzero_exact_reference_values(self):
        # One-sided Garwood count limits (chi-square 0.95 with 2*(k+1) df /2).
        self.assertAlmostEqual(m.poisson_upper(1, 1), 4.743864518390578, places=10)
        self.assertAlmostEqual(m.poisson_upper(2, 1), 6.295793621871988, places=10)
        self.assertAlmostEqual(m.poisson_upper(10, 6), 16.9622192357219/6, places=9)

    def test_poisson_invalid_and_large_count(self):
        for k, h in [(-1, 1), (True, 1), (1, 0), (100001, 1)]:
            with self.assertRaises(m.InputError): m.poisson_upper(k, h)
        self.assertGreater(m.poisson_upper(10000, 1), 10000)

    def test_mwu_exact_direction(self):
        r = m.mann_whitney_u([4, 5, 6], [1, 2, 3])
        self.assertEqual(r['u'], 9)
        self.assertAlmostEqual(r['p_value'], .05)
        self.assertEqual(m.mann_whitney_u([1, 2, 3], [4, 5, 6])['p_value'], 1)

    def test_mwu_ties_are_exact_midrank_permutations(self):
        r = m.mann_whitney_u([2, 2], [1, 2])
        self.assertEqual(r['u'], 3)
        self.assertEqual(r['p_value'], .5)
        self.assertEqual(r['method'], 'exact_permutation_midrank')
        self.assertEqual(m.mann_whitney_u([1, 1], [1, 1])['p_value'], 1)

    def test_mwu_large_samples_and_degenerate_ties(self):
        r = m.mann_whitney_u(list(range(31, 61)), list(range(1, 31)))
        self.assertLess(r['p_value'], .000001)
        self.assertIn('asymptotic', r['method'])
        self.assertEqual(m.mann_whitney_u([1]*30, [1]*30)['p_value'], 1)

    def test_mwu_rejects_empty_and_nonfinite(self):
        for a, b in [([], [1]), ([1], []), ([float('nan')], [1])]:
            with self.assertRaises(m.InputError): m.mann_whitney_u(a, b)


class Runner(unittest.TestCase):
    """Synthetic replay and harmless process tests, never SOC attacks."""
    def setUp(self):
        spec = importlib.util.spec_from_file_location('runner', ROOT / 'scripts/measure/trial_runner.py')
        self.r = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.r)
        self.directory = tempfile.TemporaryDirectory(dir=ROOT / '.git', prefix='runner-tests-')
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)
        self.output = self.home / 'attempts.jsonl'
        self.cfg = manifest_v2()
        self.t = trial_v2()
        self.source = {'format': 'json', 'timestamp_field': 'timestamp',
                       'target_key': {'path': '/fixture/one.txt'}, 'precision_ms': 1}
        self.write('source.jsonl', json.dumps({'timestamp': '2026-09-09T01:00:01Z', 'path': '/fixture/one.txt'})+'\n')
        self.write('alerts.jsonl', json.dumps(alert())+'\n')

    def write(self, name, value):
        path = self.home / name
        path.write_text(value, encoding='utf-8')
        return str(path)

    def args(self, mode='--replay'):
        return [mode, '--spec', self.write('spec.json', json.dumps({'attempt': self.t, 'source': self.source})),
                '--manifest', self.write('manifest.json', json.dumps(self.cfg)),
                '--output', str(self.output), '--alerts', str(self.home/'alerts.jsonl'),
                '--source', str(self.home/'source.jsonl')]

    def invoke(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return self.r.main(args)

    def result(self):
        return json.loads(self.output.read_text().splitlines()[-1])

    def observer(self, stage, kind, at, device, **extra):
        return dict(run_id='synthetic', trial_id='one', stage=stage, kind=kind,
                    timestamp_ms=m.to_ms(at), device=device, evidence_ref='synthetic observer evidence',
                    precision_ms=1, **extra)

    def test_replay_one_record_source_alert_and_missing_stages(self):
        with patch.object(self.r, 'execute') as execute:
            self.assertEqual(self.invoke(self.args()), 0)
            execute.assert_not_called()
        t = self.result()
        self.assertEqual((t['t0'], t['t1'], t['t2']), (self.t['t0'], self.t['t0']+1000, self.t['t0']+2000))
        self.assertIsNone(t['t4']); self.assertIn('t4', t['missing_reasons'])
        self.assertEqual(len(self.output.read_text().splitlines()), 1)
        self.assertTrue(t['collected_inputs'])
        self.assertEqual(report_v2([t])['trials'][0]['status'], 'DETECTED')

    def test_no_lab_flag_never_executes(self):
        with patch.object(self.r, 'execute') as execute, self.assertRaises(SystemExit):
            self.invoke(self.args()[1:]+['--', '/not-executed'])
        execute.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_replay_rejects_command(self):
        with patch.object(self.r, 'execute') as execute:
            self.assertEqual(self.invoke(self.args()+['--', '/not-executed']), 2)
            execute.assert_not_called()

    def test_shell_entrypoint_no_lab_rejects_real_benign_marker_command(self):
        import subprocess
        marker = self.home/'must-not-exist'
        result = subprocess.run(['bash', str(ROOT/'scripts/measure/trial_runner.sh')]+self.args()[1:]+
                                ['--', sys.executable, '-c', 'import pathlib; pathlib.Path('+repr(str(marker))+').touch()'],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(marker.exists())

    def test_duplicate_identity_does_not_append_or_launch(self):
        args = self.args(); self.assertEqual(self.invoke(args), 0)
        before = self.output.read_bytes()
        self.assertEqual(self.invoke(args), 2)
        self.assertEqual(self.output.read_bytes(), before)

    def test_pending_attempt_blocks_rerun(self):
        self.write('attempts.jsonl.pending', '{"unresolved":"launch"}\n')
        self.assertEqual(self.invoke(self.args()), 2)
        self.assertEqual(self.output.read_text(), '')

    def test_symlink_output_is_rejected(self):
        target = self.home/'untouched'; target.write_text('unchanged')
        self.output.symlink_to(target)
        self.assertEqual(self.invoke(self.args()), 2)
        self.assertEqual(target.read_text(), 'unchanged')

    def test_hardlink_output_is_rejected(self):
        import os
        target = self.home/'untouched'; target.write_text('unchanged')
        os.link(target, self.output)
        self.assertEqual(self.invoke(self.args()), 2)
        self.assertEqual(target.read_text(), 'unchanged')

    def test_output_input_alias_is_rejected(self):
        self.output = self.home/'alerts.jsonl'
        before = self.output.read_bytes()
        self.assertEqual(self.invoke(self.args()), 2)
        self.assertEqual(self.output.read_bytes(), before)

    def test_truncated_log_preserves_invalid_attempt(self):
        self.write('alerts.jsonl', json.dumps(alert()))
        self.assertEqual(self.invoke(self.args()), 2)
        self.assertEqual(self.result()['exclusion_reason'], 'INVALID')
        self.assertIn('incomplete log line', self.result()['reason'])

    def test_malformed_log_preserves_invalid_attempt(self):
        self.write('source.jsonl', '{bad}\n')
        self.assertEqual(self.invoke(self.args()), 2)
        self.assertEqual(self.result()['runner']['state'], 'COLLECTION_FAILED')

    def test_rotation_and_first_alert(self):
        args = self.args()
        earlier = self.write('old.jsonl', json.dumps(alert())+'\n')
        args.insert(args.index('--source'), earlier)
        self.write('alerts.jsonl', json.dumps(alert(id='later', timestamp='2026-09-09T01:00:05Z'))+'\n')
        self.assertEqual(self.invoke(args), 0)
        self.assertEqual(self.result()['t2'], self.t['t0']+2000)
        self.assertIn('old.jsonl', self.result()['time_refs']['t2'])

    def test_wrong_source_correlation_is_not_ground_truth(self):
        self.write('source.jsonl', '{"timestamp":"2026-09-09T01:00:01Z","path":"/other"}\n')
        self.assertEqual(self.invoke(self.args()), 2)
        self.assertIsNone(self.result()['t1'])
        self.assertEqual(self.result()['reason'], 'EVENT_NOT_INDEPENDENTLY_VERIFIED')

    def test_sensor_miss_with_independent_event_remains_missed(self):
        self.write('source.jsonl', ''); self.write('alerts.jsonl', '')
        event = self.observer('event', 'action_confirmed', '2026-09-09T01:00:01Z', 'attacker')
        obs = self.write('observer.jsonl', json.dumps(event)+'\n')
        self.assertEqual(self.invoke(self.args()+['--observers', obs]), 0)
        t = self.result()
        self.assertIsNone(t['t1'])
        self.assertEqual(report_v2([t], [])['trials'][0]['status'], 'MISSED')

    def test_observer_stages_and_raw_confirmation(self):
        self.t['stage_selectors']['t6'] = {'rule_ids': ['657'], 'levels': [3], 'target_key': self.t['target_key']}
        a = alert(id='confirm', timestamp='2026-09-09T01:00:06Z', rule={'id': '657', 'level': 3})
        self.write('alerts.jsonl', json.dumps(alert())+'\n'+json.dumps(a)+'\n')
        obs = [self.observer('t3', 'indexer_first_visible', '2026-09-09T01:00:03Z', 'observer',
                             poll_interval_ms=1000, manager_name='manager-a', alert_id='alert-1'),
               self.observer('t4', 'endpoint_start', '2026-09-09T01:00:04Z', 'endpoint'),
               self.observer('t5', 'independent_observation', '2026-09-09T01:00:05Z', 'observer')]
        path = self.write('observer.jsonl', ''.join(json.dumps(o)+'\n' for o in obs))
        self.assertEqual(self.invoke(self.args()+['--observers', path]), 0)
        t = self.result()
        self.assertEqual([t[k]-t['t0'] for k in ['t3','t4','t5','t6']], [3000,4000,5000,6000])
        self.assertEqual(t['completion_kind'], 'independent_observation')

    def test_ar_success_log_is_not_independent_completion(self):
        row = self.observer('t5', 'script_success', '2026-09-09T01:00:05Z', 'observer')
        path = self.write('observer.jsonl', json.dumps(row)+'\n')
        self.assertEqual(self.invoke(self.args()+['--observers', path]), 2)
        self.assertIsNone(self.result()['t5'])

    def test_visibility_must_reference_exact_alert_identity(self):
        row = self.observer('t3', 'indexer_first_visible', '2026-09-09T01:00:03Z', 'observer',
                            poll_interval_ms=1000, manager_name='other', alert_id='alert-1')
        path = self.write('observer.jsonl', json.dumps(row)+'\n')
        self.assertEqual(self.invoke(self.args()+['--observers', path]), 2)
        self.assertIn('selected t2', self.result()['reason'])

    def test_conflicting_observers_are_ambiguous(self):
        obs = [self.observer('t4', 'endpoint_start', at, 'endpoint')
               for at in ['2026-09-09T01:00:04Z','2026-09-09T01:00:05Z']]
        path = self.write('observer.jsonl', ''.join(json.dumps(o)+'\n' for o in obs))
        self.assertEqual(self.invoke(self.args()+['--observers', path]), 2)
        self.assertEqual(self.result()['exclusion_reason'], 'AMBIGUOUS')

    def test_audit_adapter_exact_serial_pid_and_millisecond_conversion(self):
        config = {'format': 'audit', 'serial': '42', 'pid': '123'}
        lines = [('type=SYSCALL msg=audit(1788915601.123456:42): pid=123 auid=1000', 'a:1'),
                 ('type=SYSCALL msg=audit(1788915602.111:43): pid=123 auid=1000', 'a:2')]
        self.assertEqual(self.r.source_events(config, lines), [(1788915601123,'a:1')])

    def test_apache_adapter_exact_uri_ip_and_timezone(self):
        config = {'format':'apache','client_ip':'192.168.100.108','request_uri':'/?soc_trial=one'}
        line = '192.168.100.108 - - [09/Sep/2026:04:00:01 +0300] "GET /?soc_trial=one HTTP/1.1" 200 10'
        self.assertEqual(self.r.source_events(config, [(line, 'a:1')]), [(self.t['t0']+1000,'a:1')])
        config['request_uri'] = '/?soc_trial=on'
        self.assertEqual(self.r.source_events(config, [(line,'a:1')]), [])

    def test_source_epoch_ms_and_bounds(self):
        cfg = dict(self.source, timestamp_unit='epoch_ms')
        row = {'timestamp':1788915601123,'path':'/fixture/one.txt'}
        self.assertEqual(self.r.source_events(cfg, [(json.dumps(row),'s:1')])[0][0], row['timestamp'])
        with patch.object(self.r.m, 'MAX_BYTES', 1), self.assertRaises(self.r.m.InputError):
            self.r.snapshot([self.home/'source.jsonl'])

    def test_offset_rejection_retained(self):
        self.t['ntp_offset_ms']['observer'] = 101
        self.assertEqual(self.invoke(self.args()), 2)
        self.assertEqual(self.result()['exclusion_reason'], 'INVALID')

    def test_live_t0_persisted_before_mock_command_and_nonzero_not_auto_missed(self):
        args = self.args('--lab')+['--device','attacker','--wait','120','--','/mock-only']
        times = iter([self.t['t0']*1000000, self.t['t0']*1000000, (self.t['t0']+121000)*1000000])
        def command(argv, timeout):
            launch = json.loads(Path(str(self.output)+'.pending').read_text())
            self.assertEqual(launch['t0'], self.t['t0'])
            self.assertEqual(launch['runner']['state'], 'PREPARED_NOT_COMPLETED')
            return {'exit_code': 7, 'timed_out': False}
        with patch.object(self.r.time, 'time_ns', side_effect=lambda: next(times)), \
             patch.object(self.r.time, 'sleep'), patch.object(self.r, 'execute', side_effect=command):
            self.assertEqual(self.invoke(args), 0)
        self.assertEqual(self.result()['runner']['exit_code'], 7)

    def test_timeout_is_recorded_and_ground_truth_still_controls_detection(self):
        args = self.args('--lab')+['--device','attacker','--wait','120','--','/mock-only']
        times = iter([self.t['t0']*1000000, self.t['t0']*1000000, (self.t['t0']+121000)*1000000])
        with patch.object(self.r.time, 'time_ns', side_effect=lambda: next(times)), \
             patch.object(self.r.time, 'sleep'), \
             patch.object(self.r, 'execute', return_value={'exit_code':None,'timed_out':True}):
            self.assertEqual(self.invoke(args), 0)
        self.assertTrue(self.result()['runner']['timed_out'])

    def test_harmless_child_timeout_and_argv_without_shell(self):
        outcome = self.r.execute([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)'], .05)
        self.assertTrue(outcome['timed_out'])
        result = self.r.execute([sys.executable, '-I', '-B', '-c',
                                 'import sys; sys.exit(0 if sys.argv[1] == "a; b" else 1)', 'a; b'], 5)
        self.assertEqual(result['exit_code'], 0)

    def test_prior_session_clock_rejection_prevents_launch(self):
        previous = trial_v2(trial_id='previous', exclusion_reason='INVALID', reason='clock')
        previous['ntp_offset_ms']['observer'] = -101
        self.output.write_text(json.dumps(previous)+'\n')
        args = self.args('--lab')+['--device','attacker','--','/mock-only']
        with patch.object(self.r.time,'time_ns',return_value=self.t['t0']*1000000), patch.object(self.r,'execute') as execute:
            self.assertEqual(self.invoke(args),2)
            execute.assert_not_called()
        self.assertEqual(len(self.output.read_text().splitlines()),2)
        self.assertEqual(self.result()['reason'],'SESSION_CLOCK_LIMIT_EXCEEDED')

    def test_fifo_log_rejected_without_blocking(self):
        import os
        path = self.home/'pipe'; os.mkfifo(path)
        with self.assertRaises(self.r.m.InputError): self.r.snapshot([path])

    def test_source_timestamp_unit_typo_fails_before_execution(self):
        self.source['timestamp_unit']='seconds'
        with patch.object(self.r,'execute') as execute:
            self.assertEqual(self.invoke(self.args('--lab')+['--device','attacker','--','/mock-only']),2)
            execute.assert_not_called()

    def eicar_trial(self, **changes):
        t = trial_v2(uc='UC-03', t2=None, t2_prime=None, expected_rule_ids=['87105'], expected_levels=[12], **changes)
        t['target_key'] = {'data.virustotal.source.file':'__EICAR_PATH__'}
        t['stage_selectors'] = {
            't2': {'rule_ids':['100201'], 'levels':[7], 'target_key':{'syscheck.path':'__EICAR_PATH__'}},
            't2_prime': {'rule_ids':['87105'], 'levels':[12], 'target_key':{'data.virustotal.source.file':'__EICAR_PATH__'}}}
        return t

    def test_eicar_names_unique_across_trial_run_and_session(self):
        paths=[]
        for change in [{},{'trial_id':'two'},{'run_id':'other'},{'session_id':'other-session'}]:
            t=self.eicar_trial(**change)
            argv=self.r.prepare_eicar(t,'/home/kali/SOCfile')
            self.assertEqual(Path(argv[0]).name,'eicar_test.sh')
            self.assertEqual(t['eicar_path'],'/home/kali/SOCfile/eicar_'+argv[-1]+'.com')
            self.assertEqual(t['target_key']['data.virustotal.source.file'],t['eicar_path'])
            paths.append(t['eicar_path'])
        self.assertEqual(len(set(paths)),4)

    def test_eicar_replay_identity_is_deterministic(self):
        a,b=self.eicar_trial(),self.eicar_trial()
        self.assertEqual(self.r.prepare_eicar(a,'/home/kali/SOCfile'),self.r.prepare_eicar(b,'/home/kali/SOCfile'))

    def test_eicar_bad_paths_and_identity_rejected(self):
        for path in ['/tmp/other','/home/kali/SOCfile/../escape','/home/kali/SOCfile//bad']:
            with self.assertRaises(self.r.m.InputError): self.r.prepare_eicar(self.eicar_trial(),path)
        with self.assertRaises(self.r.m.InputError): self.r.prepare_eicar(self.eicar_trial(trial_id='../bad'),'/home/kali/SOCfile')

    def test_eicar_stale_selector_rejected(self):
        t=self.eicar_trial(); t['target_key']['data.virustotal.source.file']='/home/kali/SOCfile/eicar.com'
        with self.assertRaises(self.r.m.InputError): self.r.prepare_eicar(t,'/home/kali/SOCfile')

    def test_eicar_mode_rejects_arbitrary_command_and_missing_lab(self):
        self.t=self.eicar_trial(); self.source['target_key']['path']='__EICAR_PATH__'
        args=self.args('--lab')+['--eicar-dir','/home/kali/SOCfile','--','/mock-only']
        with patch.object(self.r,'execute') as execute:
            self.assertEqual(self.invoke(args),2)
            execute.assert_not_called()
        with self.assertRaises(SystemExit): self.invoke(args[1:-2])

    def test_eicar_replay_binds_all_paths_without_execution(self):
        self.t=self.eicar_trial(); self.source['target_key']['path']='__EICAR_PATH__'
        generated=copy.deepcopy(self.t); self.r.prepare_eicar(generated,'/home/kali/SOCfile')
        path=generated['eicar_path']
        self.write('source.jsonl',json.dumps({'path':path,'timestamp':'2026-09-09T01:00:01Z'})+'\n')
        a=alert(rule={'id':'100201','level':7},syscheck={'path':path},timestamp='2026-09-09T01:00:01Z')
        b=alert(id='vt',rule={'id':'87105','level':12},data={'virustotal':{'source':{'file':path}}})
        self.write('alerts.jsonl',json.dumps(a)+'\n'+json.dumps(b)+'\n')
        with patch.object(self.r,'execute') as execute:
            self.assertEqual(self.invoke(self.args()+['--eicar-dir','/home/kali/SOCfile']),0)
            execute.assert_not_called()
        result=self.result()
        self.assertEqual(result['eicar_path'],path)
        self.assertEqual(result['t2_prime']-result['t2'],1000)

    def test_eicar_live_command_uses_persisted_path(self):
        self.t=self.eicar_trial(); self.source['target_key']['path']='__EICAR_PATH__'
        args=self.args('--lab')+['--device','attacker','--wait','120','--eicar-dir','/home/kali/SOCfile']
        times=iter([self.t['t0']*1000000,self.t['t0']*1000000,(self.t['t0']+121000)*1000000])
        def command(argv,timeout):
            launch=json.loads(Path(str(self.output)+'.pending').read_text())
            self.assertTrue(launch['eicar_path'].endswith('eicar_'+argv[-1]+'.com'))
            self.assertEqual(launch['runner']['command'],argv)
            return {'exit_code':0,'timed_out':False}
        with patch.object(self.r.time,'time_ns',side_effect=lambda:next(times)), \
             patch.object(self.r.time,'sleep'),patch.object(self.r,'execute',side_effect=command) as execute:
            self.invoke(args)  # old source fixture intentionally lacks new-path evidence
            execute.assert_called_once()
        self.assertEqual(self.result()['exclusion_reason'],'INVALID')

    def test_live_stale_coverage_prevents_execution(self):
        with patch.object(self.r, 'execute') as execute, patch.object(self.r.time, 'time_ns', return_value=0):
            self.assertEqual(self.invoke(self.args('--lab')+['--device','attacker','--','/mock-only']), 2)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
