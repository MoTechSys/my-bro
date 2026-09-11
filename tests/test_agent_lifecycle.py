"""Synthetic health/supervision regressions; no Docker, network or real services.

All fixtures live under the repository's .git directory and are cleaned up.
Native canary, service recovery and rollback remain separate acceptance gates.
"""
import contextlib
import copy
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts/lab' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = load('health_test', 'agent_health.py')
life = load('lifecycle_test', 'agent_lifecycle.py')
AT = datetime(2026, 9, 11, 10, tzinfo=timezone.utc).timestamp()


def healthy(offset=0):
    return {'at': AT + offset, 'monotonic': 1000 + offset, 'timezone': 'UTC',
            'pid1': 'docker-init', 'zombies': 0, 'errors': [],
            'processes': [dict(name=name, pid=100 + i, state='S', start_ticks=10 + i, identity_ok=True)
                          for i, name in enumerate(h.DAEMONS)],
            'agent': {'status': 'connected', 'ack_epoch': AT + offset - 5,
                      'msg_count': 100 + int(offset), 'msg_sent': 200 + int(offset), 'msg_buffer': 0},
            'collector': {'start_epoch': AT - 1000, 'end_epoch': AT + offset - 10,
                          'events': 50 + int(offset), 'drops': 0}}


def stat_line(pid, name, state='S', ticks=42):
    return f'{pid} ({name}) ' + ' '.join([state, '1'] + ['0'] * 17 + [str(ticks)]) + '\n'


class Parsers(unittest.TestCase):
    def test_stat_handles_parentheses_and_spaces_in_comm(self):
        value = h.parse_stat(stat_line(7, 'a ) b', ticks=123))
        self.assertEqual((value['pid'], value['name'], value['start_ticks']), (7, 'a ) b', 123))

    def test_stat_rejects_short_and_negative_ticks(self):
        for value in ('bad', '1 (x) S 0', stat_line(1, 'x', ticks=-1)):
            with self.subTest(value=value), self.assertRaises(ValueError): h.parse_stat(value)

    def test_state_never_evaluates_shell_content(self):
        for value in ("x=$(touch nope)", "x='one'\nx='two'", "status='connected'\nmsg_count='-1'"):
            with self.subTest(value=value), self.assertRaises(h.HealthError): h.parse_agent_state(value)

    def test_json_rejects_duplicate_nonfinite_and_invalid(self):
        for value in ('{"a":1,"a":2}', '{"a":NaN}', '{'):
            with self.subTest(value=value), self.assertRaises(ValueError): h.strict_json(value)

    def test_numbers_reject_bool_negative_and_float(self):
        for value in (True, -1, 1.1):
            with self.assertRaises(h.HealthError): h.integer(value, 'TEST')

    def test_explicit_timezone_conversion(self):
        self.assertEqual(h.epoch('2026-09-11 13:00:00', h.ZoneInfo('Asia/Aden')), AT)
        self.assertEqual(h.epoch('2026-09-11 10:00:00', h.ZoneInfo('UTC')), AT)

    def test_empty_report_cannot_be_healthy(self):
        for samples in ([], [healthy()] * 3):
            with self.assertRaises(h.HealthError): h.report(samples)


class Collection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.git', prefix='agent-health-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.proc, self.state = self.base / 'proc', self.base / 'state'
        self.proc.mkdir(); self.state.mkdir()
        self.process(1, 'docker-init')
        for i, name in enumerate(h.DAEMONS): self.process(100 + i, name)
        self.agent = "status='connected'\nlast_ack='2026-09-11 09:59:55'\nmsg_count='100'\nmsg_sent='200'\nmsg_buffer='0'\n"
        (self.state / 'wazuh-agentd.state').write_text(self.agent)
        self.collector = {'global': {'start': '2026-09-11 09:00:00', 'end': '2026-09-11 09:59:50',
                                    'files': [{'location': 'process list', 'events': 12,
                                               'targets': [{'name': 'agent', 'drops': 0}]}]}}
        self.write_collector()

    def process(self, pid, name, state='S', ticks=42):
        directory = self.proc / str(pid); directory.mkdir(exist_ok=True)
        (directory / 'stat').write_text(stat_line(pid, name[:15], state, ticks))
        (directory / 'cmdline').write_text('/var/ossec/bin/' + name + '\x00')

    def write_collector(self):
        (self.state / 'wazuh-logcollector.state').write_text(json.dumps(self.collector))

    def sample(self):
        with patch.object(h.time, 'time', return_value=AT), patch.object(h.time, 'monotonic', return_value=1000):
            return h.collect(self.proc, self.state)

    def test_healthy_snapshot_and_truncated_logcollector_name(self):
        result = self.sample()
        self.assertEqual(h.assess(result), [])
        self.assertIn('wazuh-logcollector', [p['name'] for p in result['processes']])

    def test_zombie_plus_live_is_not_zero_live_but_still_unhealthy(self):
        self.process(500, 'wazuh-agentd', 'Z')
        result = self.sample()
        self.assertEqual(result['zombies'], 1)
        self.assertEqual(h.assess(result), ['ZOMBIES_PRESENT'])

    def test_zombie_only_is_missing_live_daemon(self):
        self.process(101, 'wazuh-agentd', 'Z')
        self.assertIn('LIVE_PROCESS_COUNT:wazuh-agentd', h.assess(self.sample()))

    def test_duplicate_live_process_fails(self):
        self.process(501, 'wazuh-agentd')
        self.assertIn('LIVE_PROCESS_COUNT:wazuh-agentd', h.assess(self.sample()))

    def test_mismatched_argv0_is_not_trusted(self):
        (self.proc / '101/cmdline').write_text('/tmp/wazuh-agentd\x00')
        self.assertIn('PROCESS_NOT_HEALTHY:wazuh-agentd', h.assess(self.sample()))

    def test_missing_state_fails_closed(self):
        (self.state / 'wazuh-agentd.state').unlink()
        self.assertTrue(self.sample()['errors'])

    def test_missing_process_list_source_fails(self):
        self.collector['global']['files'][0]['location'] = 'other'
        self.write_collector(); self.assertTrue(self.sample()['errors'])

    def test_duplicate_source_fails(self):
        self.collector['global']['files'] *= 2
        self.write_collector(); self.assertTrue(self.sample()['errors'])

    def test_bool_counter_fails(self):
        self.collector['global']['files'][0]['events'] = True
        self.write_collector(); self.assertTrue(self.sample()['errors'])

    def test_missing_agent_target_fails(self):
        self.collector['global']['files'][0]['targets'] = []
        self.write_collector(); self.assertTrue(self.sample()['errors'])

    def test_state_reader_bounds_size(self):
        with patch.object(h, 'MAX_BYTES', 5), self.assertRaises(h.HealthError):
            h.bounded_text(self.state / 'wazuh-agentd.state')

    def test_fifo_is_rejected_without_blocking(self):
        path = self.base / 'pipe'; os.mkfifo(path)
        with self.assertRaises(h.HealthError): h.bounded_text(path)

    def test_symlink_state_rejected(self):
        path = self.base / 'link'; path.symlink_to(self.state / 'wazuh-agentd.state')
        with self.assertRaises(OSError): h.bounded_text(path)

    def test_proc_population_bound(self):
        with patch.object(h, 'MAX_PROCESSES', 1): self.assertTrue(self.sample()['errors'])

    def test_normal_scheduler_state_change_is_allowed(self):
        original = h.bounded_text
        reads = 0
        def read(path):
            nonlocal reads
            if path == self.proc / '101/stat':
                reads += 1
                return stat_line(101, 'wazuh-agentd', 'S' if reads == 1 else 'R')
            return original(path)
        with patch.object(h, 'bounded_text', side_effect=read):
            self.assertEqual(h.assess(self.sample()), [])

    def test_process_reuse_during_read_fails(self):
        original = h.bounded_text
        reads = 0
        def read(path):
            nonlocal reads
            if path == self.proc / '101/stat':
                reads += 1
                return stat_line(101, 'wazuh-agentd', ticks=reads)
            return original(path)
        with patch.object(h, 'bounded_text', side_effect=read): self.assertTrue(self.sample()['errors'])


class HealthPolicy(unittest.TestCase):
    def test_healthy_single_sample_never_claims_progress_or_canary(self):
        value = h.report([healthy()])
        self.assertTrue(value['healthy'])
        self.assertFalse(value['progress_verified'])
        self.assertFalse(value['canary_verified'])
        self.assertFalse(value['deployment_approved'])

    def test_tail_pid1_rejected(self):
        value = healthy(); value['pid1'] = 'tail'
        self.assertIn('PID1_NOT_RECOGNIZED_INIT', h.assess(value))

    def test_stopped_or_uninterruptible_daemon_rejected(self):
        for state in ('T', 't', 'D', 'X'):
            value = healthy(); value['processes'][0]['state'] = state
            self.assertTrue(h.assess(value))

    def test_ack_age_bound_and_future(self):
        for age in (61, -1):
            value = healthy(); value['agent']['ack_epoch'] = AT - age
            self.assertIn('ACK_STALE_OR_FUTURE', h.assess(value))
        value = healthy(); value['agent']['ack_epoch'] = AT - 60
        self.assertEqual(h.assess(value), [])

    def test_connection_buffer_and_drops(self):
        value = healthy(); value['agent'].update(status='disconnected', msg_buffer=1)
        value['collector']['drops'] = 1
        reasons = h.assess(value)
        for reason in ('AGENT_NOT_CONNECTED', 'AGENT_BUFFER_NOT_EMPTY', 'COLLECTOR_DROPS_PRESENT'):
            self.assertIn(reason, reasons)

    def test_stale_and_future_collector_state(self):
        for age in (121, -1):
            value = healthy(); value['collector']['end_epoch'] = AT - age
            self.assertIn('COLLECTOR_STATE_STALE_OR_FUTURE', h.assess(value))

    def test_advancing_two_sample_report(self):
        value = h.report([healthy(), healthy(65)])
        self.assertTrue(value['healthy']); self.assertTrue(value['progress_verified'])
        self.assertFalse(value['canary_verified'])

    def test_frozen_counters_not_healthy_even_with_fresh_ack(self):
        first, last = healthy(), healthy(65)
        last['collector']['events'] = first['collector']['events']
        last['agent']['msg_count'] = first['agent']['msg_count']
        reasons = h.assess_progress(first, last)
        self.assertIn('PROCESS_LIST_NOT_ADVANCING', reasons)
        self.assertIn('AGENT_COUNTER_NOT_ADVANCING:msg_count', reasons)

    def test_restart_and_counter_reset_detected(self):
        first, last = healthy(), healthy(65)
        last['processes'][0]['start_ticks'] += 1
        last['collector']['start_epoch'] += 1
        reasons = h.assess_progress(first, last)
        self.assertIn('DAEMON_RESTARTED_DURING_WINDOW', reasons)
        self.assertIn('COLLECTOR_RESET_OR_NOT_UPDATED', reasons)

    def test_clock_jump_timezone_and_window_detected(self):
        first, last = healthy(), healthy(65)
        last['at'] += 10; last['timezone'] = 'Asia/Aden'; last['monotonic'] += 1000
        reasons = h.assess_progress(first, last)
        for reason in ('WALL_CLOCK_JUMP', 'TIMEZONE_CHANGED', 'PROGRESS_WINDOW_OUTSIDE_60_180_SECONDS'):
            self.assertIn(reason, reasons)

    def test_missing_progress_inputs(self):
        first, last = healthy(), healthy(65); del last['collector']
        self.assertIn('PROGRESS_INPUT_MISSING', h.assess_progress(first, last))

    def test_health_cli_exit_codes_and_progress(self):
        for bad in (False, True):
            value = healthy(); value['pid1'] = 'tail' if bad else 'tini'
            with patch.object(h, 'collect', return_value=value), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(h.main(['--state-timezone', 'UTC']), int(bad))
        with patch.object(h, 'collect', side_effect=[healthy(), healthy(65)]), \
             patch.object(h.time, 'sleep') as sleep, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(h.main(['--state-timezone', 'UTC', '--progress']), 0)
            sleep.assert_called_once_with(65)

    def test_health_cli_rejects_implicit_or_unknown_timezone(self):
        for args in ([], ['--state-timezone', 'invalid/timezone']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit): h.main(args)


class Lifecycle(unittest.TestCase):
    def test_no_opt_in_never_touches_services(self):
        with patch.object(life, 'guard') as guard, patch.object(life, 'run') as run, \
             contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            life.main([])
        guard.assert_not_called(); run.assert_not_called()

    def test_failed_preflight_never_starts(self):
        with patch.object(life, 'guard', side_effect=ValueError('bad')), patch.object(life, 'run') as run, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(life.main(['--lab']), 2)
        run.assert_not_called()

    def test_host_is_rejected_without_start(self):
        with patch.object(life.os, 'geteuid', return_value=1000), self.assertRaises(ValueError): life.guard()

    def guarded_fixture(self, pid1='docker-init', parent=1, snapshot=None):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(life.os, 'geteuid', return_value=0))
        stack.enter_context(patch.object(life.os, 'getppid', return_value=parent))
        stack.enter_context(patch.object(life, 'protected'))
        stack.enter_context(patch.object(life.health, 'bounded_text', return_value=stat_line(1, pid1)))
        stack.enter_context(patch.object(life.health, 'collect', return_value=snapshot or
                                        {'processes': [], 'zombies': 0, 'pid1': pid1,
                                         'errors': ['SNAPSHOT_INCOMPLETE_OR_INVALID']}))
        stack.enter_context(patch.object(life.Path, 'iterdir', return_value=iter([Path('/proc/1')])) )

    def test_prestart_absent_state_files_do_not_block_clean_process_table(self):
        self.guarded_fixture()
        life.guard()  # First connection has not created state files yet.

    def test_noninit_or_nondirect_child_is_rejected(self):
        for pid1, parent in [('tail', 1), ('tini', 42)]:
            with self.subTest(pid1=pid1, parent=parent):
                self.guarded_fixture(pid1, parent)
                with self.assertRaises(ValueError): life.guard()

    def test_preexisting_agent_or_zombie_is_rejected(self):
        for change in ({'processes': [healthy()['processes'][0]]}, {'zombies': 1}):
            state = dict(processes=[], zombies=0, pid1='tini', errors=[])
            state.update(change)
            self.guarded_fixture(snapshot=state)
            with self.assertRaises(ValueError): life.guard()

    def test_installation_permission_guards(self):
        for uid, mode, regular, accepted in [(0, 0o644, True, True), (1000, 0o644, True, False),
                                              (0, 0o664, True, False), (0, 0o644, False, False)]:
            source, resolved = Mock(), Mock()
            source.resolve.return_value = resolved
            source.parents = resolved.parents = ()
            source.stat.return_value = resolved.stat.return_value = Mock(st_uid=uid, st_mode=mode)
            resolved.is_file.return_value = regular
            with self.subTest(uid=uid, mode=mode, regular=regular), patch.object(life, 'Path', return_value=source):
                if accepted: life.protected('/fixture')
                else:
                    with self.assertRaises(ValueError): life.protected('/fixture')

    def test_signal_handlers_request_clean_shutdown(self):
        handlers = {}
        def register(sig, handler): handlers[sig] = handler
        def run(stopped):
            self.assertFalse(stopped())
            handlers[life.signal.SIGTERM](None, None)
            self.assertTrue(stopped())
            return 0
        with patch.object(life, 'guard'), patch.object(life, 'run', side_effect=run), \
             patch.object(life.signal, 'signal', side_effect=register), patch.object(life.time, 'tzset'), \
             patch.dict(life.os.environ):
            self.assertEqual(life.main(['--lab']), 0)
        self.assertIn(life.signal.SIGINT, handlers)

    def test_shutdown_requested_between_service_starts(self):
        calls = []
        stop = iter([False, True])
        result = life.run(lambda: next(stop), lambda *args: calls.append(args), Mock(), lambda *a, **kw: None)
        self.assertEqual(result, 0)
        self.assertEqual([(p, a) for p, a, _ in calls], [(life.APACHE, 'start'), (life.APACHE, 'stop')])

    def test_monitor_failure_still_cleans_both_services(self):
        calls = []
        result = life.run(lambda: False, lambda *args: calls.append(args),
                          Mock(side_effect=RuntimeError('synthetic')), lambda *a, **kw: None)
        self.assertEqual(result, 1)
        self.assertEqual([a for _, a, _ in calls], ['start', 'start', 'stop', 'stop'])

    def test_fixed_argv_no_shell_and_clean_environment(self):
        with patch.object(life.subprocess, 'run', return_value=Mock(returncode=0)) as execute:
            life.service(life.CONTROL, 'start', 45)
        self.assertEqual(execute.call_args.args[0], [life.CONTROL, 'start'])
        self.assertEqual(execute.call_args.kwargs['env']['TZ'], 'UTC')
        self.assertNotIn('shell', execute.call_args.kwargs)
        self.assertEqual(execute.call_args.kwargs['timeout'], 45)

    def test_arbitrary_service_action_rejected(self):
        for program, action in (('/bin/sh', 'start'), (life.CONTROL, 'restart;id')):
            with patch.object(life.subprocess, 'run') as execute, self.assertRaises(ValueError):
                life.service(program, action, 1)
            execute.assert_not_called()

    def test_service_nonzero_is_error(self):
        with patch.object(life.subprocess, 'run', return_value=Mock(returncode=1)), self.assertRaises(RuntimeError):
            life.service(life.CONTROL, 'start', 45)

    def test_shutdown_reverse_order(self):
        calls = []
        result = life.run(lambda: False, start_stop=lambda *args: calls.append(args),
                          monitor=lambda stop: 0, log=lambda *args, **kw: None)
        self.assertEqual(result, 0)
        self.assertEqual([(p, a) for p, a, _ in calls], [(life.APACHE, 'start'), (life.CONTROL, 'start'),
                                                       (life.CONTROL, 'stop'), (life.APACHE, 'stop')])

    def test_partial_start_timeout_is_cleaned_up(self):
        calls = []
        def service(p, action, timeout):
            calls.append((p, action))
            if p == life.CONTROL and action == 'start': raise subprocess.TimeoutExpired(p, timeout)
        monitor = Mock()
        self.assertEqual(life.run(lambda: False, service, monitor, lambda *a, **kw: None), 1)
        monitor.assert_not_called()
        self.assertEqual(calls[-2:], [(life.CONTROL, 'stop'), (life.APACHE, 'stop')])

    def test_failed_shutdown_never_returns_success(self):
        def service(p, action, timeout):
            if action == 'stop': raise RuntimeError('failed')
        self.assertEqual(life.run(lambda: False, service, lambda stop: 0, lambda *a, **kw: None), 1)

    def test_stop_before_start_does_not_invoke_services(self):
        service = Mock()
        self.assertEqual(life.run(lambda: True, service, Mock(), lambda *a, **kw: None), 0)
        service.assert_not_called()

    def simulated_watch(self, make_sample, stop_at=200, startup=15):
        clock = [0.0]
        def wait(seconds): clock[0] += seconds
        def sample(): return make_sample(clock[0])
        return life.watch(lambda: clock[0] >= stop_at, sample, wait, lambda: clock[0],
                          startup_seconds=startup, poll_seconds=5, failure_limit=3,
                          log=lambda *a, **kw: None), clock[0]

    def test_startup_grace_is_bounded(self):
        def sample(t):
            value = healthy(t); value['pid1'] = 'tail'; return value
        result, elapsed = self.simulated_watch(sample)
        self.assertEqual((result, elapsed), (1, 15))

    def test_healthy_watch_shuts_down_cleanly(self):
        result, elapsed = self.simulated_watch(healthy, stop_at=80)
        self.assertEqual((result, elapsed), (0, 80))

    def test_daemon_failure_exits_after_consecutive_failures(self):
        def sample(t):
            value = healthy(t)
            if t >= 10: value['processes'] = value['processes'][1:]
            return value
        result, elapsed = self.simulated_watch(sample)
        self.assertEqual((result, elapsed), (1, 20))

    def test_transient_failure_recovers(self):
        def sample(t):
            value = healthy(t)
            if t == 10: value['agent']['status'] = 'pending'
            return value
        self.assertEqual(self.simulated_watch(sample, stop_at=40)[0], 0)

    def test_alive_but_stalled_collector_exits(self):
        def sample(t):
            value = healthy(t); value['collector']['events'] = 50; return value
        result, elapsed = self.simulated_watch(sample)
        self.assertEqual((result, elapsed), (1, 75))

    def test_invalid_watch_intervals_rejected(self):
        for value in (0, -1, float('nan'), True):
            with self.assertRaises(ValueError): life.watch(lambda: True, startup_seconds=value)


if __name__ == '__main__':
    unittest.main()
