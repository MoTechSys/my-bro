"""UC-01 synthetic evidence only; no service restarts or SOC acceptance."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('connection_measure', ROOT/'scripts/measure/connection_measure.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
BASE = c.m.to_ms('2026-09-23T01:00:00Z')


def plan():
    return {'schema_version': 1, 'kind': 'uc01_connection_plan', 'run_id': 'synthetic-run',
            'protocol_ref': 'synthetic predeclared protocol',
            'identity': {'manager_name': 'manager', 'agent_id': '001', 'agent_name': 'endpoint',
                         'os': 'linux', 'config_sha256': 'a'*64},
            'clocks': {role: {'offset_ms': 0, 'uncertainty_ms': 1, 'precision_ms': 1, 'ref': 'synthetic clock'}
                       for role in c.CLOCKS},
            'window_s': 300, 'poll_interval_ms': 5000,
            'coverage': {'start_ms': BASE-60000, 'end_ms': BASE+3600000, 'ref': 'synthetic coverage'},
            'cycles': [{'cycle_id': f'cycle-{i}', 'target_path': f'/fixture/cycle-{i}.txt',
                        'rule_ids': ['554'], 'levels': [5]} for i in range(5)]}


def record(index=0):
    base = BASE + index*400000
    return {'schema_version': 1, 'run_id': 'synthetic-run', 'cycle_id': f'cycle-{index}',
            'exclusion_reason': None, 'reason': None,
            'restart': {'request_ms': base, 'command_end_ms': base+2000,
                        'old_instance': f'old-{index}', 'new_instance': f'new-{index}',
                        'service_started_ms': base+1000, 'service_running': True,
                        'ref': f'synthetic service log:{index}'},
            'canary': {'created_ms': base+8000, 'path': f'/fixture/cycle-{index}.txt',
                       'source_ref': f'synthetic source:{index}'},
            'polls': [{'start_ms': base+t, 'end_ms': base+t+100,
                       'start_monotonic_ms': 100000+t, 'end_monotonic_ms': 100100+t,
                       'status': 'active' if t >= 10000 else 'pending',
                       'manager_name': 'manager', 'agent_id': '001', 'agent_name': 'endpoint',
                       'ref': f'synthetic poll:{index}:{t}'} for t in range(-5000, 305001, 5000)]}


def alert(index=0, at=None):
    return {'id': f'alert-{index}', 'timestamp': c.m.iso_ms(BASE+index*400000+12000 if at is None else at),
            'manager': {'name': 'manager'}, 'agent': {'id': '001', 'name': 'endpoint'},
            'rule': {'id': '554', 'level': 5}, 'syscheck': {'path': f'/fixture/cycle-{index}.txt'}}


def report(p=None, records=None, alerts=None):
    return c.evaluate(plan() if p is None else p,
                      [record()] if records is None else records,
                      [(a, f'alerts:{i}') for i, a in enumerate([alert()] if alerts is None else alerts, 1)])


def state(r=None, p=None, alerts=None):
    return report(p=p, records=[record() if r is None else r], alerts=alerts)['cycles'][0]['state']


class ConnectionContract(unittest.TestCase):
    def test_success_is_functional_evidence_not_detection_or_acceptance(self):
        out = report(); row = out['cycles'][0]
        self.assertEqual(row['state'], 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW')
        self.assertEqual(row['connection_state'], 'TRANSITION_OBSERVED')
        self.assertEqual(row['transition_interval_s'], [4.996, 10.104])
        self.assertEqual(row['functional_confirmation_interval_s'], [11.996, 12.004])
        self.assertEqual(out['documented_functional_rate'], .2)
        self.assertFalse(out['acceptance_approved']); self.assertFalse(row['causality_authenticated'])
        self.assertNotIn('MTTD', out); self.assertIsNone(out['wilson_95'])

    def test_empty_record_file_retains_all_planned_missing_cycles(self):
        out = report(records=[], alerts=[])
        self.assertEqual(out['counts'], {'MISSING_RECORD': 5})
        self.assertEqual(out['recorded_cycles'], 0)
        self.assertEqual(out['denominator_planned_cycles'], 5)
        self.assertEqual(out['documented_functional_rate'], 0)

    def test_full_five_cycle_plan_can_complete_without_pooling_other_runs(self):
        out = report(records=[record(i) for i in range(5)], alerts=[alert(i) for i in range(5)])
        self.assertEqual(out['documented_functional_count'], 5)
        self.assertEqual(out['documented_functional_rate'], 1)

    def test_exclusions_remain_in_denominator(self):
        for why in c.EXCLUDED:
            r = record(); r.update(exclusion_reason=why, reason='synthetic safety gate', restart=None, canary=None, polls=[])
            out = report(records=[r]); self.assertEqual(out['denominator_planned_cycles'], 5)
            self.assertEqual(out['cycles'][0]['state'], 'EXCLUDED')
            self.assertEqual(out['cycles'][0]['exclusion_reason'], why)

    def test_duplicate_records_fail_closed(self):
        with self.assertRaisesRegex(c.m.InputError, 'DUPLICATE_RECORD'):
            report(records=[record(), record()])

    def test_unknown_cycle_or_run_rejected(self):
        for key in ['cycle_id', 'run_id']:
            r = record(); r[key] = 'unknown'
            with self.subTest(key=key), self.assertRaises(c.m.InputError):
                report(records=[r])

    def test_duplicate_planned_ids_and_paths_refused(self):
        for key in ['cycle_id', 'target_path']:
            p = plan(); p['cycles'][1][key] = p['cycles'][0][key]
            with self.subTest(key=key), self.assertRaises(c.m.InputError):
                report(p=p)

    def test_windows_case_alias_plan_refused(self):
        p = plan(); p['identity']['os'] = 'windows'
        for i, cycle in enumerate(p['cycles']):
            cycle['target_path'] = f'C:\\fixture\\cycle-{i}.txt'
        c.check_plan(p)
        p['cycles'][1]['target_path'] = p['cycles'][0]['target_path'].upper()
        with self.assertRaises(c.m.InputError):
            c.check_plan(p)

    def test_noncanonical_paths_refused(self):
        for path in ['relative', '/', '/a//b', '/a/../b', '/a/./b', '/a/b/', '/a\nsecret']:
            p = plan(); p['cycles'][0]['target_path'] = path
            with self.subTest(path=path), self.assertRaises(c.m.InputError):
                c.check_plan(p)

    def test_plan_scope_and_fixed_protocol(self):
        for key, value in [('schema_version', True), ('kind', 'detection'), ('window_s', 120),
                           ('poll_interval_ms', 1000), ('cycles', []), ('protocol_ref', '')]:
            p = plan(); p[key] = value
            with self.subTest(key=key), self.assertRaises(c.m.InputError):
                c.check_plan(p)

    def test_whitespace_only_provenance_rejected(self):
        p = plan(); p['protocol_ref'] = '   '
        with self.assertRaises(c.m.InputError): report(p=p)
        r = record(); r['canary']['source_ref'] = '   '
        with self.assertRaises(c.m.InputError): report(records=[r])

    def test_unknown_fields_rejected(self):
        for target in ['plan', 'record', 'restart', 'poll', 'canary']:
            p, r = plan(), record()
            obj = {'plan': p, 'record': r, 'restart': r['restart'], 'poll': r['polls'][0], 'canary': r['canary']}[target]
            obj['extra'] = True
            with self.subTest(target=target), self.assertRaises(c.m.InputError):
                report(p=p, records=[r])

    def test_clock_types_and_bounds(self):
        for key, value in [('offset_ms', True), ('offset_ms', 60001), ('uncertainty_ms', -1),
                           ('precision_ms', 0), ('precision_ms', 60001), ('ref', '')]:
            p = plan(); p['clocks']['observer'][key] = value
            with self.subTest(key=key), self.assertRaises(c.m.InputError):
                report(p=p)

    def test_session_clock_limit_never_drops_planned_cycles(self):
        for key in ['offset_ms', 'uncertainty_ms']:
            p = plan(); p['clocks']['endpoint'][key] = 101
            out = report(p=p)
            self.assertEqual(out['cycles'][0]['state'], 'SESSION_CLOCK_LIMIT_EXCEEDED')
            self.assertEqual(out['counts']['MISSING_RECORD'], 4)
            self.assertEqual(out['documented_functional_rate'], 0)

    def test_clock_offsets_applied_once_to_all_roles(self):
        p, r, a = plan(), record(), alert()
        offsets = {'controller': -50, 'endpoint': 25, 'manager': 90, 'observer': -75}
        for role, offset in offsets.items():
            p['clocks'][role]['offset_ms'] = offset
        for key in ['request_ms', 'command_end_ms']:
            r['restart'][key] += offsets['controller']
        r['restart']['service_started_ms'] += offsets['endpoint']; r['canary']['created_ms'] += offsets['endpoint']
        for q in r['polls']:
            q['start_ms'] += offsets['observer']; q['end_ms'] += offsets['observer']
        a['timestamp'] = c.m.iso_ms(BASE+12000+offsets['manager'])
        for key in ['start_ms', 'end_ms']:
            p['coverage'][key] += offsets['manager']
        self.assertEqual(report(p=p, records=[r], alerts=[a])['cycles'][0]['functional_confirmation_interval_s'], [11.996, 12.004])

    def test_false_bool_and_float_timestamps_rejected(self):
        for value in [True, 1.5, -1, 'timestamp']:
            r = record(); r['restart']['request_ms'] = value
            with self.subTest(value=value), self.assertRaises(c.m.InputError):
                report(records=[r])

    def test_missing_or_same_service_instance_is_not_new_start(self):
        for value in [None, 'old-0']:
            r = record(); r['restart']['new_instance'] = value
            self.assertEqual(state(r), 'RESTART_UNPROVEN')
        r = record(); r['restart'] = None
        self.assertEqual(state(r), 'MISSING_RESTART_EVIDENCE')

    def test_service_not_running_or_command_incomplete(self):
        for key, value in [('service_running', False), ('command_end_ms', None), ('service_started_ms', None)]:
            r = record(); r['restart'][key] = value
            self.assertEqual(state(r), 'RESTART_UNPROVEN')

    def test_old_service_start_never_proves_restart(self):
        r = record(); r['restart']['service_started_ms'] = BASE-1000
        self.assertEqual(state(r), 'INVALID_TIMELINE')

    def test_restart_order_uncertainty_not_success(self):
        r = record(); r['restart']['service_started_ms'] = BASE+1
        self.assertEqual(state(r), 'TIMING_UNCERTAIN')

    def test_stale_active_alone_never_functional_success(self):
        r = record(); r['canary'] = None
        for q in r['polls']: q['status'] = 'active'
        out = report(records=[r])['cycles'][0]
        self.assertEqual(out['state'], 'CANARY_NOT_SUPPLIED')
        self.assertEqual(out['connection_state'], 'ACTIVE_WITHOUT_TRANSITION_BRACKET')
        self.assertIsNone(out['transition_interval_s'])

    def test_functional_evidence_without_transition_has_no_reconnection_time(self):
        r = record()
        for q in r['polls']: q['status'] = 'active'
        out = report(records=[r])['cycles'][0]
        self.assertEqual(out['state'], 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW')
        self.assertIsNone(out['transition_interval_s'])

    def test_no_active_even_with_canary_is_not_functional_success(self):
        r = record()
        for q in r['polls']: q['status'] = 'pending'
        self.assertEqual(state(r), 'NO_ACTIVE_OBSERVED')

    def test_poll_errors_are_not_negative_connection_observations(self):
        r = record(); r['polls'][2]['status'] = 'error'
        self.assertEqual(state(r), 'POLL_ERROR')

    def test_identity_change_at_any_poll_refused(self):
        for key in ['agent_id', 'agent_name', 'manager_name']:
            r = record(); r['polls'][-1][key] = 'other'
            self.assertEqual(state(r), 'IDENTITY_CHANGED')

    def test_late_started_or_short_poll_capture_refused(self):
        for drop in ['head', 'tail', 'all']:
            r = record(); r['polls'] = r['polls'][2:] if drop == 'head' else r['polls'][:-2] if drop == 'tail' else []
            self.assertEqual(state(r), 'OBSERVATION_INCOMPLETE')

    def test_manager_coverage_must_cover_entire_window(self):
        for key, value in [('start_ms', BASE), ('end_ms', BASE+300000)]:
            p = plan(); p['coverage'][key] = value
            self.assertEqual(state(p=p), 'OBSERVATION_INCOMPLETE')

    def test_deleted_reordered_or_overlapping_polls_refused(self):
        for mode in ['delete', 'reverse', 'overlap']:
            r = record()
            if mode == 'delete': del r['polls'][10]
            elif mode == 'reverse': r['polls'].reverse()
            else: r['polls'][1]['start_monotonic_ms'] = r['polls'][0]['end_monotonic_ms']-1
            self.assertIn(state(r), ['POLL_GAP', 'POLL_TIMING_INVALID'])

    def test_wall_clock_jump_and_accumulated_drift_refused(self):
        for mode in ['jump', 'drift']:
            r = record()
            for i, q in enumerate(r['polls']):
                shift = (2000 if i > 10 else 0) if mode == 'jump' else i*100
                q['start_ms'] += shift; q['end_ms'] += shift
            self.assertEqual(state(r), 'CLOCK_JUMP')

    def test_scheduler_tolerance_does_not_authorize_wall_clock_error(self):
        r = record()
        for q in r['polls'][10:]:
            q['start_ms'] += 900; q['end_ms'] += 900
        self.assertEqual(state(r), 'CLOCK_JUMP')

    def test_wall_precision_boundary_is_conservative(self):
        for delta, expected in [(4, 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW'), (5, 'CLOCK_JUMP')]:
            r = record(); r['polls'][10]['end_ms'] += delta
            self.assertEqual(state(r), expected)

    def test_subthreshold_step_drift_is_bounded_globally(self):
        r = record()
        for i, q in enumerate(r['polls']):
            q['start_ms'] += i; q['end_ms'] += i
        self.assertEqual(state(r), 'CLOCK_JUMP')

    def test_request_overrun_and_negative_duration_refused(self):
        for duration in [-1, 2001]:
            r = record(); r['polls'][2]['end_monotonic_ms'] = r['polls'][2]['start_monotonic_ms']+duration
            self.assertEqual(state(r), 'POLL_TIMING_INVALID')

    def test_canary_wrong_target_or_before_restart_refused(self):
        r = record(); r['canary']['path'] = '/fixture/other.txt'
        self.assertEqual(state(r), 'CANARY_TARGET_MISMATCH')
        r = record(); r['canary']['created_ms'] = BASE-1000
        self.assertEqual(state(r), 'INVALID_TIMELINE')

    def test_canary_uncertain_order_refused(self):
        r = record(); r['canary']['created_ms'] = BASE+2001
        self.assertEqual(state(r), 'TIMING_UNCERTAIN')

    def test_missing_alert_never_inferred_from_active(self):
        self.assertEqual(state(alerts=[]), 'CANARY_ALERT_NOT_OBSERVED')

    def test_alert_identity_path_rule_and_level_are_exact(self):
        for obj, key, value in [('agent', 'id', '002'), ('agent', 'name', 'other'),
                                ('manager', 'name', 'other'), ('syscheck', 'path', '/fixture/other.txt'),
                                ('rule', 'id', '550'), ('rule', 'level', 7)]:
            a = alert(); a[obj][key] = value
            self.assertEqual(state(alerts=[a]), 'CANARY_ALERT_NOT_OBSERVED')

    def test_canary_rule_semantics_cannot_be_replaced_by_vt_or_deletion(self):
        for rid, levels in [('87105', [12]), ('553', [7]), ('550', [7]), ('554', [7])]:
            p = plan(); p['cycles'][0].update(rule_ids=[rid], levels=levels)
            with self.subTest(rule=rid), self.assertRaisesRegex(c.m.InputError, 'CANARY_CREATION_RULES'):
                report(p=p)

    def test_mixed_rule_levels_do_not_form_cross_product_matches(self):
        p = plan(); p['cycles'][0].update(rule_ids=['554', '100301'], levels=[5, 7])
        a = alert(); a['rule']['level'] = 7
        self.assertEqual(state(p=p, alerts=[a]), 'CANARY_ALERT_NOT_OBSERVED')
        a['rule']['id'] = '100301'
        self.assertEqual(state(p=p, alerts=[a]), 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW')

    def test_windows_canary_plan_and_record_are_separate_from_linux(self):
        p = plan(); p['identity']['os'] = 'windows'
        for i, cycle in enumerate(p['cycles']):
            cycle.update(target_path=f'C:\\fixture\\cycle-{i}.txt', rule_ids=['100304'], levels=[7])
        r, a = record(), alert(); r['canary']['path'] = p['cycles'][0]['target_path']
        a['syscheck']['path'] = r['canary']['path']; a['rule'] = {'id': '100304', 'level': 7}
        self.assertEqual(state(r, p, [a]), 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW')
        p['cycles'][0]['rule_ids'] = ['100301']
        with self.assertRaises(c.m.InputError): report(p=p)

    def test_preexisting_matching_alert_not_skipped_for_later_good_one(self):
        old = alert(at=BASE-1000); old['id'] = 'old'
        self.assertEqual(state(alerts=[old, alert()]), 'PREEXISTING_CANARY_ALERT')

    def test_alert_creation_uncertainty_never_counts_success(self):
        self.assertEqual(state(alerts=[alert(at=BASE+8001)]), 'TIMING_UNCERTAIN')

    def test_deadline_uncertain_late_and_within(self):
        for offset, expected in [(299990, 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW'),
                                 (300000, 'TIMING_UNCERTAIN'), (300010, 'FUNCTIONAL_EVIDENCE_LATE')]:
            self.assertEqual(state(alerts=[alert(at=BASE+offset)]), expected)

    def test_same_alert_bytes_deduplicated_but_conflicts_fail(self):
        out = report(alerts=[alert(), alert()]); self.assertEqual(out['duplicate_alert_lines'], 1)
        self.assertEqual(out['documented_functional_count'], 1)
        bad = alert(at=BASE+13000)
        with self.assertRaises(c.m.InputError): report(alerts=[alert(), bad])

    def test_reused_instance_or_source_witness_is_ambiguous(self):
        for mode in ['instance', 'restart', 'canary']:
            a, b = record(0), record(1)
            if mode == 'canary': b['canary']['source_ref'] = a['canary']['source_ref']
            else:
                key = 'new_instance' if mode == 'instance' else 'ref'
                b['restart'][key] = a['restart'][key]
            out = report(records=[a, b], alerts=[alert(0), alert(1)])
            self.assertTrue(all(x['state'] == 'AMBIGUOUS_EVIDENCE' for x in out['cycles'][:2]))
            self.assertEqual(out['documented_functional_count'], 0)

    def test_overlapping_cycles_preserved_but_not_counted(self):
        a, b = record(0), record(1); b['restart']['request_ms'] = BASE+200000
        out = report(records=[a, b], alerts=[alert(0), alert(1)])
        self.assertTrue(all(x['state'] == 'OVERLAPPING_CYCLE' for x in out['cycles'][:2]))
        self.assertEqual(out['denominator_planned_cycles'], 5)

    def test_excluded_record_does_not_release_shared_evidence(self):
        a, b = record(0), record(1); b.update(exclusion_reason='INVALID', reason='synthetic')
        b['restart']['new_instance'] = a['restart']['new_instance']
        out = report(records=[a, b], alerts=[alert(0), alert(1)])
        self.assertEqual(out['cycles'][0]['state'], 'AMBIGUOUS_EVIDENCE')
        self.assertEqual(out['cycles'][1]['exclusion_reason'], 'INVALID')

    def test_input_objects_not_mutated(self):
        p, r, a = plan(), [record()], [alert()]; before = copy.deepcopy((p, r, a))
        report(p, r, a); self.assertEqual((p, r, a), before)

    def test_bounded_cycles_polls_alerts(self):
        r = record(); r['polls'] *= 3
        with self.assertRaises(c.m.InputError): report(records=[r])
        with patch.object(c, 'MAX_ALERTS', 0), self.assertRaises(c.m.InputError): report()


class ConnectionCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='.connection-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.files = {}
        for name, data in [('plan', json.dumps(plan())), ('records', json.dumps(record())+'\n'),
                           ('alerts', json.dumps(alert())+'\n')]:
            p = self.root/name; p.write_text(data); p.chmod(0o600); self.files[name] = p

    def run_cli(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = c.main([item for name, p in self.files.items() for item in ['--'+name, str(p)]])
        return code, out.getvalue(), err.getvalue()

    def test_cli_private_inputs_and_receipts(self):
        code, out, err = self.run_cli(); self.assertEqual(code, 0); self.assertEqual(err, '')
        parsed = json.loads(out); self.assertEqual(set(parsed['input_sha256']), {'plan', 'records', 'alerts'})
        self.assertEqual(set(parsed['source_sha256']), {'connection_measure.py', 'mttd.py'})
        self.assertEqual(parsed['documented_functional_count'], 1)

    def test_empty_records_and_alerts_are_missing_not_malformed(self):
        for key in ['records', 'alerts']: self.files[key].write_text('')
        code, out, _ = self.run_cli(); self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['counts'], {'MISSING_RECORD': 5})

    def test_invalid_json_and_blank_lines_do_not_leak_content(self):
        for data in ['SECRET invalid', '\n', '{"schema_version":1,"schema_version":1}', 'NaN', 'null']:
            self.files['records'].write_text(data)
            code, out, err = self.run_cli(); self.assertEqual(code, 2); self.assertEqual(out, '')
            self.assertEqual(err, 'UC01_INPUT_REJECTED\n')

    def test_nonprivate_input_is_rejected(self):
        self.files['alerts'].chmod(0o644)
        self.assertEqual(self.run_cli(), (2, '', 'UC01_INPUT_REJECTED\n'))

    def test_symlink_and_hardlink_inputs_are_rejected(self):
        original = self.files['alerts']
        for kind in ['symlink', 'hardlink']:
            link = self.root/kind
            if kind == 'symlink': link.symlink_to(original)
            else: os.link(original, link)
            self.files['alerts'] = link
            self.assertEqual(self.run_cli()[0], 2)
            link.unlink()
        self.files['alerts'] = original

    def test_fifo_does_not_block_and_directory_rejected(self):
        fifo = self.root/'fifo'; os.mkfifo(fifo, 0o600)
        for path in [fifo, self.root]:
            self.files['alerts'] = path
            self.assertEqual(self.run_cli()[0], 2)

    def test_line_count_limited_before_json_parse(self):
        with patch.object(c.m, 'strict_json', side_effect=AssertionError('parser called')):
            with self.assertRaisesRegex(c.m.InputError, 'INPUT_LINE_LIMIT'):
                c.parse_lines(b'{}\n'*101, 100)

    def test_jsonl_crlf_and_literal_unicode_separator(self):
        self.assertEqual(c.parse_lines(b'{}\r\n', 1), [{}])
        self.assertEqual(c.parse_lines('"one\u2028two"\n'.encode(), 1), ['one\u2028two'])
        with self.assertRaises(c.m.InputError): c.parse_lines(b'{}\n{}', 1)

    def test_excess_record_lines_cli_fail_closed(self):
        self.files['records'].write_text('{}\n'*101)
        self.assertEqual(self.run_cli(), (2, '', 'UC01_INPUT_REJECTED\n'))

    def test_input_size_limit(self):
        with patch.object(c, 'MAX_BYTES', 10):
            self.assertEqual(self.run_cli()[0], 2)

    def test_changed_input_detected(self):
        original = c.os.fstat; calls = []
        def changed(fd):
            result = original(fd); calls.append(fd)
            if len(calls) == 2:
                self.files['plan'].write_text(self.files['plan'].read_text()+' ')
                return original(fd)
            return result
        with patch.object(c.os, 'fstat', side_effect=changed):
            self.assertEqual(self.run_cli()[0], 2)


if __name__ == '__main__':
    unittest.main()
