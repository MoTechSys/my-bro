"""Synthetic AR evidence denominators; never laboratory outcome data."""
import copy
import contextlib
import io
import json
import tempfile
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ar_fixture_base', ROOT/'tests/test_measure.py')
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
m = f.m
BASE = m.to_ms('2026-09-09T01:00:00Z')


def policy():
    return {'window_s': 120, 'protocol_ref': 'synthetic predeclared protocol',
            'precision_ms': {'t0': 1, 'trigger': 1, 't4': 1, 't5': 1},
            'independent_trials': False}


def config():
    c = f.manifest_v2()
    c['runs'][0]['ar_policies'] = {uc: policy() for uc in ('UC-03', 'UC-07')}
    return c


def case(uc='UC-07', name='one', **changes):
    path = '/fixture/'+name+'.txt'
    t = f.trial_v2(uc=uc, trial_id=name, variant='response', target_key={'syscheck.path': path})
    t['stage_selectors']['t2']['target_key'] = {'syscheck.path': path}
    if uc == 'UC-03':
        t['expected_rule_ids'], t['expected_levels'] = ['87105'], [12]
        t['stage_selectors']['t2']['rule_ids'] = ['100201']
        t['stage_selectors']['t2']['levels'] = [7]
        t['stage_selectors']['t2_prime'] = {'rule_ids': ['87105'], 'levels': [12],
                                          'target_key': {'syscheck.path': path}}
        trigger_id, trigger_level = '100201', 7
        final_at = BASE+3000
    else:
        t['expected_rule_ids'], t['expected_levels'] = ['108001'], [12]
        t['stage_selectors']['t2']['rule_ids'] = ['100301']
        t['stage_selectors']['t2']['levels'] = [7]
        trigger_id, trigger_level = '100301', 7
        final_at = BASE+6000
    alerts = [f.alert(id=name+'-fim', rule={'id': trigger_id, 'level': trigger_level},
                      syscheck={'path': path}),
              f.alert(id=name+'-result', timestamp=m.iso_ms(final_at),
                      rule={'id': t['expected_rule_ids'][0], 'level': 12}, syscheck={'path': path})]
    t.update(changes)
    return t, alerts


def evaluate(t=None, alerts=None, cfg=None):
    if t is None:
        t, default = case()
    else:
        _, default = case(t['uc'], t['trial_id'])
    return m.analyze_v2(f.rows([t]), f.rows(default if alerts is None else alerts), cfg or config())


class ARDenominatorTests(unittest.TestCase):
    def test_both_supported_use_cases_complete(self):
        for uc, expected in [('UC-03', 2), ('UC-07', 3)]:
            with self.subTest(uc=uc):
                t, alerts = case(uc)
                r = evaluate(t, alerts); a = r['trials'][0]['ar']; summary = r['summaries'][0]['ar']
                self.assertEqual(a['state'], 'COMPLETED_WITHIN_WINDOW')
                self.assertEqual(a['completion_from_trigger_s'], expected)
                self.assertEqual(a['execution_s'], 1)
                self.assertEqual(summary['documented_completion_rate_all_attempts'], 1)
                self.assertFalse(summary['acceptance_approved'])
                self.assertFalse(summary['causality_authenticated'])

    def test_no_policy_never_implies_success(self):
        t, alerts = case(); r = evaluate(t, alerts, f.manifest_v2())
        self.assertEqual(r['trials'][0]['ar']['state'], 'POLICY_NOT_DECLARED')
        self.assertIsNone(r['summaries'][0]['ar']['documented_completion_rate_all_attempts'])

    def test_non_ar_use_case_unchanged(self):
        r = evaluate(f.trial_v2(), [f.alert()])
        self.assertEqual(r['trials'][0]['ar']['state'], 'NOT_APPLICABLE')
        self.assertIsNone(r['summaries'][0]['ar'])

    def test_full_recorded_denominator_keeps_all_failures(self):
        cycles, alerts = [], []
        for name, changes in [('good', {}), ('start', {'t4': None, 't5': None}),
                              ('complete', {'t5': None}),
                              ('blocked', {'exclusion_reason': 'BLOCKED', 'reason': 'fixture safety gate'})]:
            t, a = case(name=name, **changes); cycles.append(t); alerts.extend(a)
        t, _ = case(name='no_trigger', t2=None, t4=None, t5=None); cycles.append(t)
        r = m.analyze_v2(f.rows(cycles), f.rows(alerts), config())['summaries'][0]['ar']
        self.assertEqual(r['denominator_all_recorded_attempts'], 5)
        self.assertEqual(r['denominator_observed_triggers'], 3)
        self.assertEqual(r['documented_completion_rate_all_attempts'], .2)
        self.assertAlmostEqual(r['documented_completion_rate_triggered_only'], 1/3)
        self.assertEqual(r['counts'], {'COMPLETED_WITHIN_WINDOW': 1, 'NO_START_OBSERVED': 1,
                                     'NO_COMPLETION_OBSERVED': 1, 'EXCLUDED': 1, 'NO_TRIGGER_OBSERVED': 1})

    def test_all_exclusion_types_remain_in_denominator(self):
        for reason in m.EXCLUDED:
            t, a = case(exclusion_reason=reason, reason='fixture excluded')
            r = evaluate(t, a)['summaries'][0]['ar']
            self.assertEqual(r['counts'], {'EXCLUDED': 1})
            self.assertEqual(r['denominator_all_recorded_attempts'], 1)
            self.assertEqual(r['documented_completion_rate_all_attempts'], 0)

    def test_uc03_requires_vt_not_just_fim_trigger(self):
        t, a = case('UC-03', t4=None, t5=None)
        r = evaluate(t, a[:1])
        self.assertEqual(r['trials'][0]['ar']['state'], 'NO_TRIGGER_OBSERVED')

    def test_start_without_trigger_is_unbound(self):
        t, _ = case(t2=None)
        self.assertEqual(evaluate(t, [])['trials'][0]['ar']['state'], 'UNBOUND_RESPONSE_EVIDENCE')

    def test_confirmation_never_substitutes_for_completion(self):
        t, a = case(t5=None, t6=BASE+6000)
        t['stage_selectors']['t6'] = {'rule_ids': ['108001'], 'levels': [12], 'target_key': t['target_key']}
        self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'NO_COMPLETION_OBSERVED')

    def test_completion_without_start(self):
        t, a = case(t4=None)
        self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'COMPLETION_WITHOUT_START')

    def test_missing_launch_timestamp_not_fabricated(self):
        t, a = case(t0=None)
        self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'MISSING_LAUNCH_TIMESTAMP')

    def test_invalid_temporal_order_never_success(self):
        for changes in [dict(t4=BASE+1000), dict(t5=BASE+3000), dict(t0=BASE+3000)]:
            t, a = case(**changes)
            self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'INVALID_TIMELINE')

    def test_uncertain_order_is_not_proven(self):
        t, a = case(t4=BASE+2001)
        self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'TIMING_UNCERTAIN')

    def test_deadline_straddling_is_uncertain(self):
        t, a = case(t5=BASE+122000)
        ar = evaluate(t, a)['trials'][0]['ar']
        self.assertEqual(ar['state'], 'TIMING_UNCERTAIN')
        self.assertLess(ar['completion_interval_s'][0], 120)
        self.assertGreater(ar['completion_interval_s'][1], 120)

    def test_proven_late_is_not_success_but_retains_latency(self):
        t, a = case(t5=BASE+123000)
        r = evaluate(t, a); ar = r['summaries'][0]['ar']
        self.assertEqual(r['trials'][0]['ar']['state'], 'COMPLETED_LATE')
        self.assertEqual(ar['documented_completion_rate_all_attempts'], 0)
        self.assertEqual(ar['completion_from_trigger_s']['n'], 1)

    def test_short_observation_not_success_even_with_early_completion(self):
        t, a = case(observe_until=m.iso_ms(BASE+121000))
        self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'OBSERVATION_INCOMPLETE')

    def test_timestamp_outside_observation_refused_as_outcome(self):
        t, a = case(t5=BASE+301000)
        self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'OUTSIDE_OBSERVATION')

    def test_completion_uncertainty_outside_coverage(self):
        t, a = case(t5=BASE+300000)
        self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'TIMING_UNCERTAIN')

    def test_clock_offsets_applied_once(self):
        t, a = case(); t['ntp_offset_ms'].update(manager=-50, endpoint=50, observer=25)
        r = evaluate(t, a)['trials'][0]['ar']; cfg=config()['runs'][0]
        trigger=BASE+2000-t['ntp_offset_ms'][cfg['clock_map']['t2']]
        finish=t['t5']-t['ntp_offset_ms'][cfg['clock_map']['t5']]
        self.assertEqual(r['completion_from_trigger_s'], (finish-trigger)/1000)

    def test_session_rejection_precedes_ar_classification(self):
        t, a = case(); t['ntp_offset_ms']['observer']=101
        r = evaluate(t, a)
        self.assertEqual(r['trials'][0]['ar']['state'], 'EXCLUDED')
        self.assertEqual(r['summaries'][0]['ar']['documented_completion_rate_all_attempts'], 0)

    def test_ambiguous_trigger_does_not_count_twice(self):
        t,a=case(); other=copy.deepcopy(t); other['trial_id']='two'
        r=m.analyze_v2(f.rows([t,other]),f.rows(a),config())
        self.assertTrue(all(row['ar']['state']=='EXCLUDED' for row in r['trials']))
        self.assertEqual(r['summaries'][0]['ar']['denominator_all_recorded_attempts'],2)

    def test_detection_miss_is_separate_from_ar_completion(self):
        t,a=case(); r=evaluate(t,a[:1])
        self.assertEqual(r['trials'][0]['status'],'MISSED')
        self.assertEqual(r['trials'][0]['ar']['state'],'COMPLETED_WITHIN_WINDOW')
        self.assertEqual(r['summaries'][0]['detection_rate_all_attempts'],0)

    def test_phase_groups_are_not_pooled(self):
        t,a=case(name='pilot',phase='PILOT'); other,b=case(name='measured')
        r=m.analyze_v2(f.rows([t,other]),f.rows(a+b),config())
        self.assertEqual(len(r['summaries']),2)
        self.assertTrue(all(s['ar']['denominator_all_recorded_attempts']==1 for s in r['summaries']))

    def test_missing_policy_fields_scope_types_and_precision_rejected(self):
        bad=[None, [], {'UC-02':policy()}, {'UC-03':None}]
        for value in bad:
            c=config();c['runs'][0]['ar_policies']=value
            with self.subTest(value=value), self.assertRaises(m.InputError):evaluate(cfg=c)
        for key,value in [('window_s',True),('window_s',0),('window_s',3601),
                          ('precision_ms',{'t0':1}),('independent_trials',1),('protocol_ref','')]:
            c=config();c['runs'][0]['ar_policies']['UC-07'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(m.InputError):evaluate(cfg=c)
        for value in [0,-1,True,1.2,60001]:
            c=config();c['runs'][0]['ar_policies']['UC-07']['precision_ms']['t5']=value
            with self.subTest(value=value),self.assertRaises(m.InputError):evaluate(cfg=c)

    def test_wilson_requires_explicit_independence_and_is_conditional(self):
        c=config();self.assertIsNone(evaluate(cfg=c)['summaries'][0]['ar']['wilson_95_all_attempts'])
        c['runs'][0]['ar_policies']['UC-07']['independent_trials']=True
        summary=evaluate(cfg=c)['summaries'][0]['ar']
        self.assertEqual(summary['wilson_95_all_attempts'],m.wilson(1,1))
        self.assertFalse(summary['independence_verified'])

    def test_input_not_mutated_and_no_policy_invented(self):
        t,a=case();c=config();original=copy.deepcopy((t,a,c));evaluate(t,a,c)
        self.assertEqual((t,a,c),original)

    def test_empty_journal_does_not_invent_planned_attempts(self):
        self.assertEqual(m.analyze_v2([],[],config())['summaries'],[])

    def test_raw_t5_success_log_rejected_before_summary(self):
        t,a=case(completion_kind='script_log')
        with self.assertRaises(m.InputError):evaluate(t,a)

    def test_uc07_opt_in_rejects_non_fim_trigger_and_wrong_level(self):
        for rule, level in [('87105', 7), ('108001', 12), ('554', 7), ('100301', 12)]:
            t, a = case()
            t['stage_selectors']['t2'].update(rule_ids=[rule], levels=[level])
            a[0]['rule'] = {'id': rule, 'level': level}
            with self.subTest(rule=rule, level=level), self.assertRaisesRegex(m.InputError, 'UC-07 AR t2'):
                evaluate(t, a)

    def test_uc07_supported_linux_and_windows_fim_rules(self):
        for rule in ['100300', '100301', '100303', '100304']:
            t, a = case(); t['stage_selectors']['t2']['rule_ids'] = [rule]; a[0]['rule']['id'] = rule
            self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'COMPLETED_WITHIN_WINDOW')

    def test_uc07_without_policy_preserves_existing_stage_contract(self):
        t, a = case(); t['stage_selectors']['t2']['rule_ids'] = ['554']; a[0]['rule']['id'] = '554'
        self.assertEqual(evaluate(t, a, f.manifest_v2())['trials'][0]['ar']['state'], 'POLICY_NOT_DECLARED')

    def test_legacy_policy_rejected_in_core_and_cli(self):
        c = f.manifest(); c['runs'][0]['ar_policies'] = {'UC-07': policy()}
        with self.assertRaisesRegex(m.InputError, 'manifest version 2'):
            m.analyze(f.rows([f.trial()]), f.rows([f.alert()]), c)
        with tempfile.TemporaryDirectory(dir=ROOT/'build') as directory:
            paths = {}
            for name, value in [('manifest', c), ('journal', f.trial()), ('alerts', f.alert())]:
                paths[name] = Path(directory)/name
                paths[name].write_text(json.dumps(value)+'\n')
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = m.main([item for name, path in paths.items() for item in ['--'+name, str(path)]])
            self.assertEqual(code, 2); self.assertEqual(out.getvalue(), '')
            self.assertIn('ar_policies requires manifest version 2', err.getvalue())

    def test_attempt_policy_override_rejected(self):
        t, a = case(); t['ar_policies'] = {'UC-07': policy()}
        with self.assertRaisesRegex(m.InputError, 'belongs to run'):
            evaluate(t, a)

    def test_ambiguous_claim_keeps_diagnostics_without_assigning_shared_evidence(self):
        t, a = case(); other = copy.deepcopy(t)
        other.update(trial_id='two', variant='separate-final', t2=BASE+9999, expected_rule_ids=['108000'])
        r = m.analyze_v2(f.rows([t, other]), f.rows(a), config())
        self.assertTrue(all(row['status'] == 'AMBIGUOUS' for row in r['trials']))
        self.assertIn('CLAIMED_TIMESTAMP_DIFFERS_FROM_RAW_ALERT:t2', r['trials'][1]['exclusion_details'])
        self.assertIn('STAGE_MATCHES_MULTIPLE_TRIALS', r['trials'][1]['exclusion_details'])
        self.assertTrue(all(row['ar']['state'] == 'EXCLUDED' for row in r['trials']))

    def test_attempt_clock_correction_is_explicit_not_silent_run_override(self):
        t, a = case(t5=BASE+122000)
        self.assertEqual(evaluate(t, a)['trials'][0]['ar']['state'], 'TIMING_UNCERTAIN')
        t['ntp_offset_ms']['observer'] = 99
        ar = evaluate(t, a)['trials'][0]['ar']
        self.assertEqual(ar['state'], 'COMPLETED_WITHIN_WINDOW')
        self.assertEqual(ar['clock_correction_source'], 'attempt.ntp_offset_ms')
        self.assertEqual(ar['clock_offsets_differ_from_run'], ['observer'])
        self.assertFalse(ar['acceptance_approved'])

    def test_raw_manager_window_and_corrected_coverage_are_consistent(self):
        t, a = case(t5=BASE+299900)
        c = config(); c['runs'][0]['devices']['manager']['ntp_offset_ms'] = 90
        t['ntp_offset_ms']['manager'] = 90
        # Last raw alert is inside the raw manager window. Offset is applied
        # to BOTH its timestamp and observe_until, not by parsing ISO strings.
        a[1]['timestamp'] = m.iso_ms(BASE+300000)
        r = evaluate(t, a, c); row = r['trials'][0]
        self.assertEqual(row['ar']['state'], 'COMPLETED_LATE')
        self.assertEqual(row['ar']['completion_from_trigger_s'], (299900-1910)/1000)
        self.assertTrue(row['alert_refs'])
        self.assertEqual(row['status'], 'MISSED')  # outside detection deadline, inside observation

    def test_conditional_trigger_scope_explicit_for_exclusions(self):
        t, a = case(name='good'); other, b = case(name='blocked', exclusion_reason='BLOCKED', reason='fixture')
        ar = m.analyze_v2(f.rows([t, other]), f.rows(a+b), config())['summaries'][0]['ar']
        self.assertEqual(ar['documented_completion_rate_all_attempts'], .5)
        self.assertEqual(ar['documented_completion_rate_triggered_only'], 1)
        self.assertEqual(ar['observed_trigger_denominator_scope'], 'non_excluded_trials_with_validated_raw_trigger')

    def test_missing_event_confirmation_has_v2_diagnostic(self):
        t, a = case(); t.pop('event_valid')
        with self.assertRaisesRegex(m.InputError, 'v2 non-excluded attempt requires event_valid=true'):
            evaluate(t, a)

    def test_policy_unknown_fields_fail_closed(self):
        for location in ['policy', 'precision']:
            c = config(); p = c['runs'][0]['ar_policies']['UC-07']
            (p if location == 'policy' else p['precision_ms'])['future_field'] = 1
            with self.subTest(location=location), self.assertRaises(m.InputError):
                evaluate(cfg=c)

    def test_inconsistent_internal_trigger_invariant_remains_fatal(self):
        row = evaluate()['trials'][0]; row['timeline_ms']['t2'] = None
        with self.assertRaisesRegex(m.InputError, 'AR trigger reference without timestamp'):
            m.ar_outcome(row, config()['runs'][0])


if __name__ == '__main__':
    unittest.main()
