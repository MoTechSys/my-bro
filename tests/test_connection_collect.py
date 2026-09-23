"""Synthetic UC-01 collection: real private stores, no native commands/restarts."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_connection_measure import BASE, plan, alert
from test_visibility_observer import ROOT, Clock, load

cc = load('connection_collect_test', ROOT/'scripts/measure/connection_collect.py')
BOOT = '12345678-1234-1234-1234-123456789abc'


def manager(status='Active'):
    return cc.r.json_bytes({'error': 0, 'data': {'id': '001', 'name': 'endpoint', 'status': status}})


def service(invocation='a'*32, started='Wed 2026-09-23 00:50:00 UTC'):
    return ('ActiveState=active\nSubState=running\nInvocationID=' + invocation +
            '\nMainPID=123\nExecMainStartTimestamp=' + started + '\n').encode()


class CaptureClock(Clock):
    def __init__(self, start=BASE-5000):
        super().__init__()
        self.base = start * 1000000
    def monotonic(self):
        return self.monotonic_ns()/1e9


class Collector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='.collect-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source_dir = self.base/'source'; self.source_dir.mkdir(mode=0o700)
        self.p = plan()
        self.p['clocks']['endpoint']['precision_ms'] = 1100
        self.p['cycles'][0]['target_path'] = str(self.source_dir/'canary.dat')
        self.raw = cc.r.json_bytes(self.p)
        self.cid = 'cycle-0'
        self.serial = 0

    def private(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o600)
        return path

    def capture(self, kind='manager', start=BASE-5000, payload=None, failure=None):
        self.serial += 1
        store = self.base/f'store-{self.serial}'
        store.mkdir(mode=0o700)
        clock = CaptureClock(start)
        def query(*_):
            self.assertTrue((store/'intent.json').exists())
            self.assertEqual((store/'plan.json').read_bytes(), self.raw)
            clock.sleep(.1)
            if failure:
                raise failure
            raw = payload if payload is not None else (manager() if kind == 'manager' else service())
            return raw, 'manager' if kind == 'manager' else 'endpoint', None if kind == 'manager' else BOOT
        with patch.object(cc, 'time', clock), patch.object(cc, 'native_sample', side_effect=query):
            result = cc.capture(self.raw, self.cid, kind, store)
        return {'path': str(store), 'sha256': result['intent_sha256']}, result

    def export(self, desc, kind='manager'):
        return cc.export(desc['path'], desc['sha256'], self.raw, self.cid, kind)

    def mutate(self, desc, name, change):
        path = Path(desc['path'])/name
        obj = json.loads(path.read_bytes())
        change(obj)
        path.write_bytes(cc.r.json_bytes(obj))

    def source_store(self, mode='observed'):
        store = self.base/'source-store'; store.mkdir(mode=0o700)
        target = self.source_dir/'canary.dat'; data = b'SYNTHETIC UC01 CANARY'
        spec = {'schema_version': 1, 'run_id': self.p['run_id'], 'trial_id': self.cid,
                'device': 'endpoint', 'clock_ref': self.p['clocks']['endpoint']['ref'],
                'directory': str(self.source_dir), 'filename': target.name,
                'expected_sha256': cc.r.digest(data), 'seconds': 2, 'precision_ms': 1}
        clock = CaptureClock(BASE+12000); actual = cc.s.read_source; calls = 0
        if mode == 'preexisting': self.private(target, data)
        def read(fd, name):
            nonlocal calls
            if calls == 1 and mode in ('observed', 'wrong'):
                self.private(target, data if mode == 'observed' else b'wrong')
            calls += 1
            value = actual(fd, name); clock.sleep(.05)
            return value
        with patch.object(cc.s, 'time', clock), patch.object(cc.s, 'read_source', side_effect=read):
            result = cc.s.observe(spec, store)
        return {'path': str(store), 'sha256': result['intent_sha256']}

    def binding(self, mode='observed'):
        mgr, _ = self.capture()
        before, _ = self.capture('service', start=BASE-5000)
        after, _ = self.capture('service', start=BASE+8000,
                                payload=service('b'*32, 'Wed 2026-09-23 01:00:03 UTC'))
        source = self.source_store(mode)
        request = {'schema_version': 1, 'run_id': self.p['run_id'], 'cycle_id': self.cid,
                   'request_ms': BASE, 'command_end_ms': BASE+5000,
                   'controller_ref': 'synthetic attestation, not native execution'}
        return request, dict(manager=mgr, before=before, after=after, source=source)

    def test_manager_schedule_and_raw_replay(self):
        desc, result = self.capture(payload=manager('Pending'))
        out = self.export(desc)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(len(out['samples']), 64)
        self.assertEqual(out['samples'][-1]['start_ms']-out['samples'][0]['start_ms'], 315000)
        self.assertTrue(all(x['status'] == 'pending' for x in out['samples']))
        self.assertTrue(out['stored_bytes_verified'])
        self.assertFalse(out['authenticity_verified']); self.assertFalse(out['acceptance_approved'])
        for path in Path(desc['path']).iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_service_capture_nonce_distinguishes_identical_snapshots(self):
        one, _ = self.capture('service'); two, _ = self.capture('service')
        self.assertNotEqual(one['sha256'], two['sha256'])
        self.assertEqual(self.export(one, 'service')['samples'][0]['instance'], BOOT+':'+'a'*32)

    def test_no_overwrite_or_second_query(self):
        desc, _ = self.capture('service')
        with patch.object(cc, 'native_sample') as query, self.assertRaises(ValueError):
            cc.capture(self.raw, self.cid, 'service', desc['path'])
        query.assert_not_called()

    def test_failed_query_has_terminal_but_no_success_export(self):
        desc, result = self.capture(failure=ValueError('private failure text'))
        self.assertEqual(result['reason'], 'CAPTURE_FAILED')
        self.assertNotIn('private failure', json.dumps(result))
        with self.assertRaises(ValueError): self.export(desc)

    def test_interrupt_leaves_failed_terminal(self):
        with self.assertRaises(KeyboardInterrupt): self.capture(failure=KeyboardInterrupt())
        terminal = json.loads((self.base/'store-1/terminal.json').read_bytes())
        self.assertEqual(terminal['status'], 'failed'); self.assertEqual(terminal['count'], 0)

    def test_raw_mutation_rejected(self):
        desc, _ = self.capture()
        (Path(desc['path'])/'sample-000.bin').write_bytes(manager('Disconnected'))
        with self.assertRaisesRegex(ValueError, 'SAMPLE_BYTES'): self.export(desc)

    def test_extra_entry_rejected(self):
        desc, _ = self.capture('service')
        self.private(Path(desc['path'])/'extra', b'extra')
        with self.assertRaises(ValueError): self.export(desc, 'service')

    def test_missing_terminal_rejected(self):
        desc, _ = self.capture('service'); (Path(desc['path'])/'terminal.json').unlink()
        with self.assertRaises((OSError, ValueError)): self.export(desc, 'service')

    def test_wrong_hash_plan_cycle_and_kind_rejected(self):
        desc, _ = self.capture()
        for digest, raw, cycle, kind in [('f'*64, self.raw, self.cid, 'manager'),
                (desc['sha256'], self.raw+b' ', self.cid, 'manager'),
                (desc['sha256'], self.raw, 'cycle-1', 'manager'),
                (desc['sha256'], self.raw, self.cid, 'service')]:
            with self.subTest(kind=kind, cycle=cycle), self.assertRaises(ValueError):
                cc.export(desc['path'], digest, raw, cycle, kind)

    def test_changed_source_code_hash_rejected(self):
        desc, _ = self.capture('service')
        with patch.object(cc, 'source_hashes', return_value={}), self.assertRaises(ValueError):
            self.export(desc, 'service')

    def test_metadata_clock_jump_rejected(self):
        desc, _ = self.capture()
        self.mutate(desc, 'sample-001.json', lambda q: q.update(start_ms=q['start_ms']+900, end_ms=q['end_ms']+900))
        with self.assertRaisesRegex(ValueError, 'CLOCK_JUMP'): self.export(desc)

    def test_metadata_query_overrun_rejected(self):
        desc, _ = self.capture()
        self.mutate(desc, 'sample-000.json', lambda q: q.update(end_monotonic_ms=q['start_monotonic_ms']+2001))
        with self.assertRaisesRegex(ValueError, 'QUERY_OVERRUN'): self.export(desc)

    def test_store_file_types_and_permissions_rejected(self):
        for kind in ('public', 'hardlink', 'symlink', 'fifo'):
            with self.subTest(kind=kind):
                desc, _ = self.capture('service'); path = Path(desc['path'])/'sample-000.bin'
                if kind == 'public': path.chmod(0o644)
                elif kind == 'hardlink': os.link(path, self.base/'link')
                else:
                    path.unlink()
                    if kind == 'symlink': path.symlink_to(self.private(self.base/'target', service()))
                    else: os.mkfifo(path, 0o600)
                with self.assertRaises((OSError, ValueError)): self.export(desc, 'service')

    def test_real_stores_bind_and_evaluate_with_full_denominator(self):
        request, stores = self.binding()
        row = cc.bind(self.raw, cc.r.json_bytes(request), **stores)
        raw_alert = alert(at=BASE+17000); raw_alert['syscheck']['path'] = self.p['cycles'][0]['target_path']
        result = cc.c.evaluate(self.p, [row], [(raw_alert, 'synthetic raw alert')])
        self.assertEqual(result['cycles'][0]['state'], 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW')
        self.assertEqual(result['denominator_planned_cycles'], 5)
        self.assertFalse(result['acceptance_approved'])
        self.assertFalse(result['causality_authenticated'])

    def test_source_absence_preexistence_and_wrong_bytes_cannot_bind(self):
        request, stores = self.binding(mode='absent')
        with self.assertRaises((ValueError, TypeError)):
            cc.bind(self.raw, cc.r.json_bytes(request), **stores)

    def test_wrong_controller_run_and_unplanned_cycle_rejected(self):
        request, stores = self.binding()
        for key, value in [('run_id', 'other'), ('cycle_id', 'other'), ('schema_version', True), ('controller_ref', ' ')]:
            bad = dict(request, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                cc.bind(self.raw, cc.r.json_bytes(bad), **stores)

    def test_reused_snapshot_store_rejected(self):
        request, stores = self.binding(); stores['after'] = stores['before']
        with self.assertRaisesRegex(ValueError, 'DISTINCT_STORES'):
            cc.bind(self.raw, cc.r.json_bytes(request), **stores)

    def test_before_snapshot_must_precede_request(self):
        request, stores = self.binding(); request['request_ms'] = BASE-6000
        with self.assertRaisesRegex(ValueError, 'SNAPSHOT_ORDER'):
            cc.bind(self.raw, cc.r.json_bytes(request), **stores)

    def test_after_snapshot_must_follow_command_end(self):
        request, stores = self.binding(); request['command_end_ms'] = BASE+9000
        with self.assertRaisesRegex(ValueError, 'SNAPSHOT_ORDER'):
            cc.bind(self.raw, cc.r.json_bytes(request), **stores)

    def test_cli_requires_lab_and_preserves_signal_handler(self):
        path = self.private(self.base/'plan.json', self.raw)
        with patch.object(cc, 'capture') as capture, contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = cc.main(['capture', '--plan', str(path), '--cycle', self.cid, '--kind', 'manager', '--store', str(self.base/'no-store')])
        self.assertEqual(code, 2); capture.assert_not_called()
        self.assertEqual(stderr.getvalue(), 'UC01_COLLECTION_REJECTED\n')


class NativeParsing(unittest.TestCase):
    def test_fixed_commands(self):
        self.assertEqual(cc.command('manager', plan()), ['/var/ossec/bin/agent_control', '-i', '001', '-j'])
        self.assertEqual(cc.command('service', plan())[:4], ['/usr/bin/systemctl', 'show', 'wazuh-agent.service', '--no-pager'])
        with self.assertRaises(ValueError): cc.command('restart', plan())

    def test_all_four_manager_states(self):
        for native, normalized in cc.STATUS.items():
            self.assertEqual(cc.normalize('manager', manager(native), 'manager', None, plan())['status'], normalized)

    def test_manager_wrong_identity_status_error_and_duplicate_keys(self):
        for raw in (b'{"error":false,"data":{}}', b'{"error":0,"error":0,"data":{}}',
                    manager().replace(b'001', b'002'), manager('unknown'), manager()+b'x'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                cc.normalize('manager', raw, 'manager', None, plan())

    def test_wrong_hostname_and_manager_boot_rejected(self):
        for host, boot in [('wrong', None), ('manager', BOOT)]:
            with self.assertRaises(ValueError): cc.normalize('manager', manager(), host, boot, plan())

    def test_service_precision_and_instance(self):
        result = cc.normalize('service', service(), 'endpoint', BOOT, plan())
        self.assertTrue(result['running']); self.assertEqual(result['precision_ms'], 1000)
        self.assertEqual(result['started_ms'], BASE-600000)

    def test_service_inactive_and_missing_incarnation_are_not_success(self):
        raw = service('', '').replace(b'active\n', b'inactive\n').replace(b'MainPID=123', b'MainPID=0')
        out = cc.normalize('service', raw, 'endpoint', BOOT, plan())
        self.assertFalse(out['running']); self.assertIsNone(out['instance']); self.assertIsNone(out['started_ms'])

    def test_service_bad_property_boot_pid_invocation_timestamp(self):
        values = [service()+b'MainPID=999\n', service().replace(b'123\n', b'-1\n'),
                  service('bad'), service(started='2026-09-23T00:50:00Z'), service()+b'Other=x\n']
        for raw in values:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                cc.normalize('service', raw, 'endpoint', BOOT, plan())
        with self.assertRaises(ValueError): cc.normalize('service', service(), 'endpoint', 'bad', plan())

    def test_windows_service_adapter_rejected(self):
        p = plan(); p['identity']['os'] = 'windows'
        with self.assertRaises(ValueError): cc.normalize('service', service(), 'endpoint', BOOT, p)

    def test_oversized_raw_and_nonbytes_rejected(self):
        for raw in (b'x'*(cc.LIMIT+1), 'text'):
            with self.assertRaises(ValueError): cc.normalize('manager', raw, 'manager', None, plan())

    def test_native_query_fixed_argv_and_deadline(self):
        result = {'reason': 'OK', 'returncode': 0, 'output': manager()}
        with patch.object(cc, 'trusted_binary'), patch.object(cc.socket, 'gethostname', return_value='manager'), patch.object(cc.r, 'bounded_process', return_value=result) as process:
            cc.native_sample('manager', plan())
        process.assert_called_once_with(cc.command('manager', plan()), 1.5)

    def test_native_query_failure_output_cap_and_host(self):
        for result in ({'reason': 'TIMEOUT', 'returncode': None, 'output': b''},
                       {'reason': 'OK', 'returncode': 1, 'output': b''},
                       {'reason': 'OK', 'returncode': 0, 'output': b'x'*(cc.LIMIT+1)}):
            with patch.object(cc, 'trusted_binary'), patch.object(cc.socket, 'gethostname', return_value='manager'), patch.object(cc.r, 'bounded_process', return_value=result), self.assertRaises(ValueError):
                cc.native_sample('manager', plan())


if __name__ == '__main__':
    unittest.main()
