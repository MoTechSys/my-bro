"""M1 synthetic regressions; no Indexer credentials or native network calls."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


v = load('visibility_test', ROOT/'scripts/measure/visibility_observer.py')


def spec():
    return {'schema_version': 1, 'run_id': 'synthetic', 'trial_id': 'one', 'device': 'observer',
            'manager_name': 'mgr', 'agent_id': '001', 'alert_id': 'a1',
            'index': 'wazuh-alerts-4.x-2026.09.09', 'seconds': 3, 'precision_ms': 1,
            'clock_ref': 'SYNTHETIC_CLOCK_NOT_NATIVE'}


def config():
    return {'schema_version': 1, 'endpoint': 'https://127.0.0.1:9200',
            'username': 'SYNTHETIC_USER', 'password': 'SYNTHETIC_SECRET', 'ca_pem': None}


def response(found=False):
    s = spec()
    return {'timed_out': False, '_shards': {'total': 1, 'successful': 1, 'failed': 0},
            'hits': {'total': {'value': int(found), 'relation': 'eq'},
                     'hits': [{'_index': s['index'], '_source': {'id': s['alert_id'],
                              'manager': {'name': s['manager_name']}, 'agent': {'id': s['agent_id']}}}] if found else []}}


class Clock:
    def __init__(self):
        self.ns = 10_000_000_000
        self.base = 1788915601000 * 1_000_000  # fixture only
    def monotonic_ns(self): return self.ns
    def time_ns(self): return self.base + self.ns - 10_000_000_000
    def sleep(self, seconds): self.ns += round(seconds * 1e9)


class Visibility(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT/'.git', prefix='visibility-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.store = self.base/'store'; self.store.mkdir(mode=0o700)
        self.s, self.c = spec(), config()

    def run_observer(self, values=(False, True)):
        clock = Clock(); queue = iter(values)
        def transport(*_):
            self.assertTrue((self.store/'intent.json').exists())
            clock.sleep(.1)
            value = next(queue)
            if isinstance(value, BaseException): raise value
            return v.r.json_bytes(response(value)) if type(value) is bool else value
        with patch.object(v, 'time', clock), patch.object(v, 'fetch', side_effect=transport):
            return v.observe(self.s, self.c, self.store)

    def private(self, name, value):
        p = self.base/name; p.write_bytes(v.r.json_bytes(value)); p.chmod(0o600); return p

    def test_negative_then_positive_exports_bracket_not_server_timestamp(self):
        result = self.run_observer(); row = v.export(self.store, result['intent_sha256'])
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(row['stage'], 't3'); self.assertEqual(row['precision_ms'], 1101)
        self.assertEqual(row['timestamp_ms'], row['first_positive_response_end_ms'])
        self.assertEqual(row['timestamp_ms'] - row['last_negative_request_start_ms'], 1100)
        self.assertEqual(row['poll_interval_ms'], 1000)
        self.assertFalse(result['acceptance_approved'])

    def test_initial_positive_is_left_censored_and_emits_no_t3(self):
        result = self.run_observer((True,))
        self.assertEqual(result['status'], 'preexisting'); self.assertIsNone(v.export(self.store, result['intent_sha256']))

    def test_negative_full_window_is_not_observed_not_detection_miss(self):
        result = self.run_observer((False, False, False, False))
        self.assertEqual(result['status'], 'not_observed'); self.assertIsNone(v.export(self.store, result['intent_sha256']))
        first = json.loads((self.store/'poll-000.meta.json').read_text())
        last = json.loads((self.store/'poll-003.meta.json').read_text())
        self.assertEqual(last['start_ms'] - first['start_ms'], 3000)

    def test_transport_error_retained_and_no_retry_allowed(self):
        result = self.run_observer((OSError('SECRET'),))
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('SECRET', (self.store/'terminal.json').read_text())
        with self.assertRaises(ValueError): v.export(self.store, result['intent_sha256'])
        with patch.object(v, 'fetch') as fetch, self.assertRaises(ValueError):
            v.observe(self.s, self.c, self.store)
        fetch.assert_not_called()

    def test_cancellation_retains_failed_terminal(self):
        with self.assertRaises(KeyboardInterrupt): self.run_observer((KeyboardInterrupt(),))
        terminal = json.loads((self.store/'terminal.json').read_text())
        self.assertEqual(terminal['reason'], 'INTERRUPTED'); self.assertIsNone(terminal['observer'])

    def test_fsync_failure_prevents_first_request(self):
        with patch.object(v.r.os, 'fsync', side_effect=OSError), patch.object(v, 'fetch') as fetch:
            with self.assertRaises(OSError): v.observe(self.s, self.c, self.store)
        fetch.assert_not_called()

    def test_credentials_never_saved_in_store(self):
        self.run_observer()
        for p in self.store.iterdir():
            text = p.read_text()
            self.assertNotIn('SYNTHETIC_SECRET', text); self.assertNotIn('SYNTHETIC_USER', text)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_private_config_permissions_and_links(self):
        p = self.private('config.json', self.c); self.assertEqual(v.private_json(p), self.c)
        p.chmod(0o644)
        with self.assertRaises(ValueError): v.private_json(p)
        p.chmod(0o600); link = self.base/'link'; link.symlink_to(p)
        with self.assertRaises(OSError): v.private_json(link)
        os.link(p, self.base/'hard')
        with self.assertRaises(ValueError): v.private_json(p)

    def test_store_lock_rejects_concurrent_writer(self):
        with v.r.store_lock(self.store):
            with self.assertRaises(BlockingIOError): v.observe(self.s, self.c, self.store)

    def test_spec_limits_and_query_are_exact(self):
        for key, value in [('seconds', True), ('seconds', 121), ('index', '*'), ('index', '../_all'),
                           ('precision_ms', 0), ('alert_id', 'x\n'), ('extra', 1)]:
            s = spec(); s[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): v.check_spec(s)
        q = v.query(self.s)
        self.assertEqual(q['size'], 2); self.assertTrue(q['track_total_hits'])
        self.assertEqual(q['_source'], ['id', 'manager.name', 'agent.id'])
        self.assertIn({'term': {'id': 'a1'}}, q['query']['bool']['filter'])

    def test_endpoint_and_config_guards(self):
        for endpoint in ('http://127.0.0.1', 'https://example.com', 'https://8.8.8.8',
                         'https://169.254.169.254', 'https://u:p@10.0.0.1', 'https://10.0.0.1/x',
                         'https://10.0.0.1?x=1', 'https://10.0.0.1:99999', 'https://@127.0.0.1'):
            c = config(); c['endpoint'] = endpoint
            with self.subTest(endpoint=endpoint), self.assertRaises((ValueError, TypeError)): v.check_config(c)
        c = config(); c['username'] = 'x:y'
        with self.assertRaises(ValueError): v.check_config(c)

    def test_partial_ambiguous_and_wrong_responses_rejected(self):
        variants = []
        d = response(); d['timed_out'] = True; variants.append(d)
        d = response(); d['_shards']['failed'] = 1; variants.append(d)
        d = response(); d['_shards']['total'] = 0; variants.append(d)
        d = response(); d['hits']['total']['relation'] = 'gte'; variants.append(d)
        d = response(); d['hits']['total']['value'] = 2; variants.append(d)
        d = response(True); d['hits']['hits'][0]['_source']['id'] = 'wrong'; variants.append(d)
        d = response(True); d['hits']['hits'][0]['_index'] = 'wrong'; variants.append(d)
        d = response(); del d['_shards']; variants.append(d)
        for d in variants:
            with self.subTest(d=d), self.assertRaises(ValueError): v.match(v.r.json_bytes(d), self.s)
        with self.assertRaises(ValueError): v.match(b'{"timed_out":false,"timed_out":false}', self.s)

    def test_malformed_response_retained_but_never_exported(self):
        result = self.run_observer((b'not JSON',))
        self.assertEqual(result['status'], 'failed'); self.assertTrue((self.store/'poll-000.json').exists())
        with self.assertRaises(ValueError): v.export(self.store, result['intent_sha256'])

    def test_export_detects_raw_and_terminal_tampering(self):
        result = self.run_observer(); p = self.store/'poll-001.json'; p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(ValueError): v.export(self.store, result['intent_sha256'])

    def test_export_detects_observer_field_tampering(self):
        result = self.run_observer(); p = self.store/'terminal.json'; d = json.loads(p.read_text())
        d['observer']['timestamp_ms'] += 1; p.write_bytes(v.r.json_bytes(d))
        with self.assertRaises(ValueError): v.export(self.store, result['intent_sha256'])

    def test_export_rejects_unknown_missing_and_wrong_hash(self):
        result = self.run_observer()
        with self.assertRaises(ValueError): v.export(self.store, '0'*64)
        p = self.store/'unknown'; p.write_text('x')
        with self.assertRaises(ValueError): v.export(self.store, result['intent_sha256'])
        p.unlink(); (self.store/'terminal.json').unlink()
        with self.assertRaises(OSError): v.export(self.store, result['intent_sha256'])

    def test_clock_jump_gap_and_overrun_never_become_t3(self):
        result = self.run_observer()
        polls = [json.loads((self.store/f'poll-{i:03d}.meta.json').read_text()) for i in range(2)]
        for key, delta in [('end_ms', 5000), ('start_ns', 200_000_000), ('end_ns', 1_000_000_000)]:
            values = copy.deepcopy(polls); values[1][key] += delta
            with self.subTest(key=key), self.assertRaises(ValueError): v.classify(self.s, values)

    def test_export_source_revision_change_rejected(self):
        result = self.run_observer()
        with patch.object(v, 'source_hashes', return_value={}):
            with self.assertRaises(ValueError): v.export(self.store, result['intent_sha256'])

    def test_real_alarm_bounds_slow_call_and_restores_signal_state(self):
        start = time.monotonic()
        with patch.object(v, 'REQUEST_SECONDS', .05), self.assertRaises(v.RequestDeadline):
            v.deadline_call(lambda: time.sleep(5))
        self.assertLess(time.monotonic()-start, 1)
        self.assertEqual(signal.getsignal(signal.SIGALRM), signal.SIG_DFL)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_alarm_contract_refuses_other_timer_owner(self):
        old = signal.signal(signal.SIGALRM, lambda *_: None)
        try:
            with self.assertRaises(ValueError): v.alarm_contract()
        finally: signal.signal(signal.SIGALRM, old)

    def test_alarm_contract_refuses_inherited_blocked_sigalrm(self):
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        try:
            with self.assertRaises(ValueError): v.alarm_contract()
        finally: signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def test_late_alarm_during_disarm_is_drained_and_handler_restored(self):
        setter = signal.setitimer
        def pending_alarm(which, seconds, *args):
            if seconds == 0:
                os.kill(os.getpid(), signal.SIGALRM)
            return setter(which, seconds, *args)
        with patch.object(v.signal, 'setitimer', side_effect=pending_alarm):
            self.assertEqual(v.deadline_call(lambda: 'complete'), 'complete')
        self.assertNotIn(signal.SIGALRM, signal.sigpending())
        self.assertEqual(signal.getsignal(signal.SIGALRM), signal.SIG_DFL)

    def test_terminal_write_defers_sigterm_until_record_is_complete(self):
        write = v.r.write_once
        def interrupted(*_): raise KeyboardInterrupt()
        previous = signal.signal(signal.SIGTERM, interrupted)
        def write_with_signal(fd, name, data):
            if name == 'terminal.json':
                os.kill(os.getpid(), signal.SIGTERM)
                os.kill(os.getpid(), signal.SIGTERM)
            return write(fd, name, data)
        try:
            with patch.object(v.r, 'write_once', side_effect=write_with_signal):
                with self.assertRaises(KeyboardInterrupt): self.run_observer()
            terminal = json.loads((self.store/'terminal.json').read_text())
            self.assertEqual(terminal['status'], 'observed')
        finally: signal.signal(signal.SIGTERM, previous)

    def test_approved_failure_code_retained_without_arbitrary_exception_text(self):
        d = response(True); d['hits']['hits'][0]['_source']['id'] = 'wrong'
        result = self.run_observer((v.r.json_bytes(d),))
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(json.loads((self.store/'terminal.json').read_text())['reason'], 'WRONG_IDENTITY')

    def test_request_deadline_has_distinct_constant_code(self):
        self.run_observer((v.RequestDeadline(),))
        self.assertEqual(json.loads((self.store/'terminal.json').read_text())['reason'], 'REQUEST_DEADLINE')

    def test_principal_and_ca_are_bound_without_password_hash(self):
        self.run_observer(); first = json.loads((self.store/'intent.json').read_text())
        self.store = self.base/'second'; self.store.mkdir(mode=0o700)
        self.c.update(username='other-principal', ca_pem='BEGIN CERTIFICATE synthetic mock only')
        self.run_observer(); second = json.loads((self.store/'intent.json').read_text())
        self.assertNotEqual(first['principal_sha256'], second['principal_sha256'])
        self.assertIsNone(first['ca_sha256']); self.assertEqual(second['trust_mode'], 'explicit_ca')
        self.assertNotEqual(first['ca_sha256'], second['ca_sha256'])
        self.assertNotIn('password_sha256', second)

    def test_summary_distinguishes_preexisting_without_changing_jsonl(self):
        result = self.run_observer((True,))
        summary = v.export(self.store, result['intent_sha256'], summary=True)
        self.assertEqual(summary['status'], 'preexisting'); self.assertIsNone(summary['observer'])
        self.assertIsNone(v.export(self.store, result['intent_sha256']))

    def test_https_transport_minimal_query_and_default_verification(self):
        raw = v.r.json_bytes(response())
        class Response(io.BytesIO): status = 200
        with patch.object(v.urllib.request, 'build_opener') as build:
            build.return_value.open.return_value = Response(raw)
            self.assertEqual(v.fetch(self.c, self.s), raw)
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {}); self.assertIsInstance(handlers[1], v.NoRedirect)
        ctx = handlers[2]._context
        self.assertTrue(ctx.check_hostname); self.assertEqual(ctx.verify_mode, v.ssl.CERT_REQUIRED)
        req = build.return_value.open.call_args.args[0]
        self.assertEqual(req.method, 'POST'); self.assertTrue(req.full_url.endswith('/_search'))
        self.assertEqual(json.loads(req.data), v.query(self.s))
        self.assertIsNone(v.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://other.invalid'))

    def test_response_byte_limit_and_http_failure(self):
        class Response(io.BytesIO): status = 200
        for raw, status in [(b'x'*(v.MAX_RESPONSE+1), 200), (b'', 403)]:
            resp = Response(raw); resp.status = status
            with patch.object(v.urllib.request, 'build_opener') as build:
                build.return_value.open.return_value = resp
                with self.assertRaises(ValueError): v.fetch(self.c, self.s)

    def test_cli_preview_export_and_generic_error(self):
        p = self.private('spec.json', self.s)
        command = [sys.executable, '-I', '-B', str(ROOT/'scripts/measure/visibility_observer.py')]
        out = subprocess.run(command+['preview', '--spec', str(p)], capture_output=True, timeout=5)
        self.assertEqual(out.returncode, 0, out.stderr); self.assertFalse(json.loads(out.stdout)['network_used'])
        result = self.run_observer()
        out = subprocess.run(command+['export', '--store', str(self.store), '--intent-sha256', result['intent_sha256']],
                             capture_output=True, timeout=5)
        self.assertEqual(out.returncode, 0, out.stderr); self.assertEqual(json.loads(out.stdout)['stage'], 't3')
        out = subprocess.run(command+['export', '--store', str(self.base/'PRIVATE'), '--intent-sha256', '0'*64],
                             capture_output=True, timeout=5)
        self.assertEqual(out.returncode, 1); self.assertEqual(out.stdout, b''); self.assertNotIn(b'PRIVATE', out.stderr)

    def test_export_imports_into_existing_trial_runner(self):
        f = load('visibility_measure_fixtures', ROOT/'tests/test_measure.py')
        runner = load('visibility_trial_runner', ROOT/'scripts/measure/trial_runner.py')
        alert = f.alert(); self.s.update(manager_name=alert['manager']['name'], agent_id=alert['agent']['id'],
                                         alert_id=alert['id'], clock_ref='fixture clock')
        # Build response with the actual existing synthetic t2 identity.
        def reply(found):
            d = response(found)
            if found: d['hits']['hits'][0]['_source'] = {k: alert[k] for k in ('id', 'manager', 'agent')}
            return v.r.json_bytes(d)
        result = self.run_observer((reply(False), reply(True)))
        row = v.export(self.store, result['intent_sha256'])
        obs = self.private('observer.jsonl', row); logs = self.private('alerts.jsonl', alert)
        trial = f.trial_v2(); trial['t3'] = None
        runner.collect(trial, f.manifest_v2()['runs'][0], None, [], [logs], [obs])
        self.assertEqual(trial['t3'], row['timestamp_ms'])
        self.assertEqual(trial['timestamp_precision_ms']['t3'], row['precision_ms'])


if __name__ == '__main__': unittest.main()
