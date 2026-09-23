"""Synthetic procfs fixtures only; never read host processes or restart services."""
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import test_connection_collect as f
from test_connection_measure import BASE, alert

p = f.cc.p
cc = f.cc
BOOT = f.BOOT


def proc_stat(pid=101, name='wazuh-agentd', ticks=100, state='S'):
    fields = [state] + ['0']*19
    fields[19] = str(ticks)
    return f'{pid} ({name[:15]}) ' + ' '.join(fields) + '\n'


def row(name, index, ticks=100, pid_base=100):
    metadata = [1, 200+index, 0, stat.S_IFREG | 0o755]
    return {'name': name, 'stat': proc_stat(pid_base+index, name, ticks),
            'exe_link': '/var/ossec/bin/'+name, 'exe_stat': metadata,
            'binary_stat': list(metadata)}


def evidence(ticks=100, pid_base=100):
    rows = [row(name, i, ticks, pid_base) for i, name in enumerate(p.DAEMONS)]
    return {'schema_version': 1, 'boot_id': BOOT, 'clk_tck': 100,
            'namespaces_before': {'pid': 'pid:[123]', 'time': 'time:[456]'},
            'namespaces_after': {'pid': 'pid:[123]', 'time': 'time:[456]'},
            'btime_before': f'btime {BASE//1000-60}\n', 'btime_after': f'btime {BASE//1000-60}\n',
            'first': rows, 'second': copy.deepcopy(rows)}


class ProcParser(unittest.TestCase):
    def test_complete_identity_and_birth_precision(self):
        result = p.normalize(evidence(6300), BOOT)
        self.assertTrue(result['running']); self.assertEqual(result['started_ms'], BASE+3000)
        self.assertEqual(result['precision_ms'], 1010)
        self.assertEqual(len(result['daemon_instances']), 5)
        self.assertEqual(result['start_semantics'], 'latest_required_daemon_birth_not_service_readiness')

    def test_latest_and_earliest_required_daemon_birth(self):
        obj = evidence(6300)
        for scan in ('first', 'second'):
            obj[scan][0]['stat'] = proc_stat(100, p.DAEMONS[0], 6350)
        result = p.normalize(obj, BOOT)
        self.assertEqual(result['started_ms'], BASE+3500)
        self.assertEqual(result['earliest_started_ms'], BASE+3000)

    def test_pid_reuse_changes_identity(self):
        a, b = p.normalize(evidence(100), BOOT), p.normalize(evidence(6300), BOOT)
        self.assertNotEqual(a['instance'], b['instance'])
        self.assertFalse(set(a['daemon_instances'].values()) & set(b['daemon_instances'].values()))

    def test_wall_boot_estimate_not_part_of_incarnation_identity(self):
        obj = evidence(); a = p.normalize(obj, BOOT)
        obj['btime_before'] = obj['btime_after'] = f'btime {BASE//1000-59}\n'
        b = p.normalize(obj, BOOT)
        self.assertEqual(a['instance'], b['instance'])
        self.assertEqual(b['started_ms']-a['started_ms'], 1000)

    def test_missing_duplicate_or_extra_daemon_rejected(self):
        for variant in ('missing', 'duplicate', 'extra'):
            obj = evidence()
            if variant == 'missing': obj['first'].pop()
            if variant == 'duplicate': obj['first'][0] = copy.deepcopy(obj['first'][1])
            if variant == 'extra': obj['first'].append(copy.deepcopy(obj['first'][0]))
            with self.subTest(variant=variant), self.assertRaises(ValueError): p.normalize(obj, BOOT)

    def test_dead_stopped_or_blocked_process_rejected(self):
        for state in ['Z', 'T', 't', 'D', 'X']:
            obj = evidence(); obj['first'][0]['stat'] = proc_stat(100, p.DAEMONS[0], state=state)
            with self.subTest(state=state), self.assertRaisesRegex(ValueError, 'NOT_LIVE'): p.normalize(obj, BOOT)

    def test_regular_scheduling_change_is_not_identity_change(self):
        obj = evidence(); obj['second'][0]['stat'] = proc_stat(100, p.DAEMONS[0], state='R')
        self.assertTrue(p.normalize(obj, BOOT)['running'])

    def test_wrong_executable_path_inode_owner_and_mode(self):
        for change in ('path', 'inode', 'owner', 'writable', 'nonregular'):
            obj = evidence(); target = obj['first'][0]
            if change == 'path': target['exe_link'] += ' (deleted)'
            if change == 'inode': target['exe_stat'][1] += 1
            if change == 'owner': target['exe_stat'][2] = 1000
            if change == 'writable': target['exe_stat'][3] |= 0o020
            if change == 'nonregular': target['exe_stat'][3] = stat.S_IFDIR | 0o755
            with self.subTest(change=change), self.assertRaises(ValueError): p.normalize(obj, BOOT)

    def test_changed_pid_start_or_executable_across_scans(self):
        for change in ('pid', 'ticks', 'exe'):
            obj = evidence(); r = obj['second'][0]
            if change == 'pid': r['stat'] = proc_stat(999, p.DAEMONS[0])
            if change == 'ticks': r['stat'] = proc_stat(100, p.DAEMONS[0], 200)
            if change == 'exe': r['exe_stat'][1] += 99; r['binary_stat'][1] += 99
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'CHANGED_DURING_SCAN'): p.normalize(obj, BOOT)

    def test_duplicate_pid_and_wrong_comm_rejected(self):
        for raw in [proc_stat(101, p.DAEMONS[0]), proc_stat(100, 'other')]:
            obj = evidence(); obj['first'][0]['stat'] = raw
            with self.assertRaises(ValueError): p.normalize(obj, BOOT)

    def test_namespace_and_boot_changes_rejected(self):
        for key, value in [('namespaces_after', {'pid': 'pid:[999]', 'time': 'time:[456]'}),
                           ('boot_id', 'bad'), ('btime_after', f'btime {BASE//1000}\n')]:
            obj = evidence(); obj[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): p.normalize(obj, BOOT)

    def test_schema_types_and_unknown_fields_rejected(self):
        for key, value in [('schema_version', True), ('clk_tck', True), ('clk_tck', 0),
                           ('clk_tck', 1.5), ('extra', 0), ('first', {}), ('namespaces_before', [])]:
            obj = evidence(); obj[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): p.normalize(obj, BOOT)

    def test_stat_framing_and_bounded_numbers(self):
        for raw in ['x', proc_stat(ticks=-1), proc_stat(pid=0), proc_stat(pid=2**31), proc_stat(ticks=2**63)]:
            with self.subTest(raw=raw), self.assertRaises(ValueError): p.process_stat(raw)
        self.assertEqual(p.process_stat(proc_stat(name='odd ) name'))['name'], 'odd ) name')

    def test_zero_start_ticks_unrelated_kernel_task_is_parseable(self):
        self.assertEqual(p.process_stat(proc_stat(name='kthreadd', ticks=0))['ticks'], 0)

    def test_birth_conversion_accounts_for_tick_rounding(self):
        obj = evidence(); obj['clk_tck'] = 128
        result = p.normalize(obj, BOOT)
        self.assertEqual(result['precision_ms'], 1008)
        self.assertEqual(result['started_ms'], BASE-60000+781)


class ProcStores(unittest.TestCase):
    setUp = f.Collector.setUp
    private = f.Collector.private
    capture = f.Collector.capture
    source_store = f.Collector.source_store

    def binding(self, before=None, after=None):
        manager, _ = self.capture()
        old, _ = self.capture('linuxproc', payload=cc.r.json_bytes(evidence() if before is None else before))
        new, _ = self.capture('linuxproc', start=BASE+8000,
                              payload=cc.r.json_bytes(evidence(6300, 200) if after is None else after))
        old['kind'] = new['kind'] = 'linuxproc'
        source = self.source_store()
        request = {'schema_version': 1, 'run_id': self.p['run_id'], 'cycle_id': self.cid,
                   'request_ms': BASE, 'command_end_ms': BASE+5000, 'controller_ref': 'synthetic attestation'}
        return cc.r.json_bytes(request), dict(manager=manager, before=old, after=new, source=source)

    def test_real_private_stores_bind_through_evaluator(self):
        request, stores = self.binding()
        record = cc.bind(self.raw, request, **stores)
        event = alert(at=BASE+17000); event['syscheck']['path'] = self.p['cycles'][0]['target_path']
        result = cc.c.evaluate(self.p, [record], [(event, 'synthetic')])
        self.assertEqual(result['cycles'][0]['state'], 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW')
        self.assertEqual(result['denominator_planned_cycles'], 5)
        self.assertFalse(result['acceptance_approved'])
        self.assertTrue(record['restart']['new_instance'].startswith('linux-proc:'))

    def test_partial_daemon_restart_not_full_service_restart(self):
        new = evidence(6300, 200)
        for scan in ('first', 'second'): new[scan][0] = copy.deepcopy(evidence()[scan][0])
        request, stores = self.binding(after=new)
        with self.assertRaisesRegex(ValueError, 'PARTIAL_DAEMON_RESTART'): cc.bind(self.raw, request, **stores)

    def test_all_new_daemons_must_be_after_request(self):
        new = evidence(100, 200)
        request, stores = self.binding(after=new)
        with self.assertRaisesRegex(ValueError, 'DAEMONS_NOT_AFTER_REQUEST'): cc.bind(self.raw, request, **stores)

    def test_cross_namespace_container_recreation_rejected(self):
        new = evidence(6300, 200)
        new['namespaces_before']['pid'] = new['namespaces_after']['pid'] = 'pid:[999]'
        request, stores = self.binding(after=new)
        with self.assertRaisesRegex(ValueError, 'PROC_NAMESPACE_CHAIN'): cc.bind(self.raw, request, **stores)

    def test_backend_mismatch_rejected(self):
        request, stores = self.binding(); stores['after']['kind'] = 'service'
        with self.assertRaisesRegex(ValueError, 'SERVICE_BACKEND_BINDING'): cc.bind(self.raw, request, **stores)

    def test_export_replays_raw_identity_not_derived_claim(self):
        desc, _ = self.capture('linuxproc', payload=cc.r.json_bytes(evidence()))
        target = Path(desc['path'])/'sample-000.bin'; target.write_bytes(cc.r.json_bytes(evidence(200)))
        with self.assertRaisesRegex(ValueError, 'SAMPLE_BYTES'):
            cc.export(desc['path'], desc['sha256'], self.raw, self.cid, 'linuxproc')

    def test_invalid_proc_capture_has_no_success_export(self):
        desc, terminal = self.capture('linuxproc', payload=b'{}')
        self.assertEqual(terminal['status'], 'failed')
        with self.assertRaises(ValueError): cc.export(desc['path'], desc['sha256'], self.raw, self.cid, 'linuxproc')

    def test_proc_native_path_never_executes_commands(self):
        with patch.object(cc.socket, 'gethostname', return_value='endpoint'), patch.object(p, 'collect', return_value=(b'bytes', BOOT)) as collect, patch.object(cc.r, 'bounded_process') as execute:
            self.assertEqual(cc.native_sample('linuxproc', self.p), (b'bytes', 'endpoint', BOOT))
        execute.assert_not_called(); collect.assert_called_once_with(cc.trusted_binary)


class ProcReads(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=f.ROOT, prefix='.proc-tests-')
        self.addCleanup(self.tmp.cleanup); self.base = Path(self.tmp.name)

    def write(self, name, text):
        target = self.base/name; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text); return target

    def test_regular_read_limit_and_symlink_fifo_rejection(self):
        target = self.write('stat', 'data')
        with patch.object(p.time, 'monotonic', return_value=0):
            self.assertEqual(p.read_text(target, 1), 'data')
            target.write_text('x'*(p.MAX_TEXT+1))
            with self.assertRaises(ValueError): p.read_text(target, 1)
            target.unlink(); target.symlink_to('absent')
            with self.assertRaises(OSError): p.read_text(target, 1)
            target.unlink(); os.mkfifo(target, 0o600)
            with self.assertRaises(ValueError): p.read_text(target, 1)

    def test_deadline_rejected_before_read(self):
        with patch.object(p.time, 'monotonic', return_value=2), patch.object(p.os, 'open') as open_file, self.assertRaisesRegex(ValueError, 'DEADLINE'):
            p.read_text(self.base/'unused', 1)
        open_file.assert_not_called()

    def test_two_scan_capture_with_real_proc_metadata_files(self):
        self.write('self/stat', proc_stat(os.getpid(), 'python'))
        self.write('sys/kernel/random/boot_id', BOOT+'\n')
        self.write('stat', f'cpu 1 2 3\nbtime {BASE//1000-60}\n')
        (self.base/'self/ns').mkdir()
        for name, value in evidence()['namespaces_before'].items(): (self.base/'self/ns'/name).symlink_to(value)
        obj = evidence()
        with patch.object(p, 'scan', side_effect=[obj['first'], obj['second']]) as scan, patch.object(p.os, 'sysconf', return_value=100):
            raw, boot = p.collect(lambda _: None, self.base)
        self.assertEqual(scan.call_count, 2)
        self.assertEqual(p.normalize(json.loads(raw), boot)['instance'], p.normalize(obj, BOOT)['instance'])

    def test_scan_uses_executable_not_argv_and_requires_protected_path(self):
        obj = evidence()
        for index, daemon in enumerate(p.DAEMONS): self.write(f'{100+index}/stat', proc_stat(100+index, daemon))
        original_stat = p.os.stat
        def fake_stat(path, *args, **kwargs):
            if str(path).endswith('/exe') or str(path).startswith('/var/ossec/bin/'):
                return os.stat_result((stat.S_IFREG|0o755, 201, 1, 1, 0, 0, 1, 0, 0, 0))
            return original_stat(path, *args, **kwargs)
        def exe_link(path): return '/var/ossec/bin/'+p.DAEMONS[int(Path(path).parent.name)-100]
        with patch.object(p.os, 'stat', side_effect=fake_stat), patch.object(p.os, 'readlink', side_effect=exe_link), patch.object(p.time, 'monotonic', return_value=0):
            calls = []; rows = p.scan(self.base, 1, calls.append)
        self.assertEqual(calls, ['/var/ossec/bin/'+name for name in p.DAEMONS])
        self.assertEqual(len(rows), 5)
        self.assertTrue(all('cmdline' not in r for r in rows))

    def test_process_count_limit_rejected(self):
        for index in range(3): (self.base/str(index+1)).mkdir()
        with patch.object(p, 'MAX_PROCESSES', 2), patch.object(p.time, 'monotonic', return_value=0), self.assertRaisesRegex(ValueError, 'PROCESS_LIMIT'):
            p.scan(self.base, 1, lambda _: None)

    def test_pid_path_mismatch_rejected(self):
        self.write('100/stat', proc_stat(101))
        with patch.object(p.time, 'monotonic', return_value=0), self.assertRaisesRegex(ValueError, 'PID_PATH'):
            p.scan(self.base, 1, lambda _: None)


if __name__ == '__main__':
    unittest.main()
