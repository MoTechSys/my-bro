"""Synthetic M2-A evidence regressions; no native SOC or AR claims."""
import copy
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

from test_visibility_observer import ROOT, Clock, load

s = load('source_test', ROOT/'scripts/measure/source_observer.py')


class Source(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='.source-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.store = self.base/'store'; self.store.mkdir(mode=0o700)
        self.source = self.base/'source'; self.source.mkdir(mode=0o700)
        self.file = self.source/'test.dat'
        self.data = b'SYNTHETIC\r\nEVIDENCE\x00\xff'
        self.spec = {'schema_version': 1, 'run_id': 'run1', 'trial_id': 'trial1',
                     'device': 'endpoint', 'clock_ref': 'clock-fixture',
                     'directory': str(self.source), 'filename': self.file.name,
                     'expected_sha256': s.r.digest(self.data), 'seconds': 2, 'precision_ms': 1}

    def create(self, raw=None):
        self.file.write_bytes(self.data if raw is None else raw)
        self.file.chmod(0o600)

    def observe(self, on_poll=None):
        clock = Clock(); actual = s.read_source; count = 0
        def read(fd, name):
            nonlocal count
            self.assertTrue((self.store/'intent.json').exists())
            if on_poll:
                on_poll(count)
            elif count == 1:
                self.create()
            count += 1
            value = actual(fd, name)
            clock.sleep(.05)
            return value
        with patch.object(s, 'time', clock), patch.object(s, 'read_source', side_effect=read):
            return s.observe(self.spec, self.store)

    def saved(self, name):
        return json.loads((self.store/name).read_bytes())

    def replace(self, name, value):
        (self.store/name).write_bytes(s.r.json_bytes(value))

    def test_absence_then_matching_bytes_event_only(self):
        result = self.observe(); row = s.export(self.store, result['intent_sha256'])
        self.assertEqual(result['status'], 'observed')
        self.assertEqual((row['stage'], row['kind']), ('event', 'action_confirmed'))
        self.assertEqual(row['timestamp_ms'] - row['last_negative_start_ms'], 1050)
        self.assertEqual(row['precision_ms'], 1051)
        self.assertEqual(row['target_key'], {'syscheck.path': str(self.file)})
        self.assertEqual((self.store/'poll-001.bin').read_bytes(), self.data)
        self.assertEqual(row['source_spec_sha256'], s.r.digest(s.r.json_bytes(self.spec)))
        self.assertEqual(row['source_intent_sha256'], result['intent_sha256'])
        self.assertFalse({'t1', 't4', 't5'} & set(row))
        for p in self.store.iterdir():
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_preexisting_never_emits_event(self):
        self.create(); before = s.identity(self.file.stat())
        result = self.observe(lambda _: None)
        self.assertEqual(result['status'], 'preexisting')
        self.assertIsNone(s.export(self.store, result['intent_sha256']))
        self.assertEqual(s.identity(self.file.stat()), before)
        self.assertEqual(self.file.read_bytes(), self.data)

    def test_absent_full_window_not_observed(self):
        result = self.observe(lambda _: None)
        self.assertEqual(result['status'], 'not_observed')
        self.assertIsNone(s.export(self.store, result['intent_sha256']))
        self.assertFalse(self.file.exists())
        self.assertEqual(self.saved('terminal.json')['poll_count'], 3)

    def test_wrong_bytes_retained_failed_without_retry(self):
        result = self.observe(lambda i: self.create(b'wrong') if i == 1 else None)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.saved('terminal.json')['reason'], 'WRONG_CONTENT')
        self.assertEqual((self.store/'poll-001.bin').read_bytes(), b'wrong')
        with self.assertRaises(ValueError): s.export(self.store, result['intent_sha256'])
        summary = s.export(self.store, result['intent_sha256'], summary=True)
        self.assertFalse(summary['artifacts_verified']); self.assertIsNone(summary['observer'])
        with patch.object(s, 'read_source') as read, self.assertRaises(ValueError):
            s.observe(self.spec, self.store)
        read.assert_not_called()

    def test_symlink_fifo_hardlink_public_and_oversized_refused(self):
        for kind in ('symlink', 'fifo', 'hardlink', 'public', 'large'):
            with self.subTest(kind=kind):
                if kind == 'symlink': self.file.symlink_to(self.base/'missing')
                elif kind == 'fifo': os.mkfifo(self.file, 0o600)
                else:
                    self.create(b'x' * (s.MAX_FILE + 1) if kind == 'large' else None)
                    if kind == 'hardlink': os.link(self.file, self.source/'other')
                    if kind == 'public': self.file.chmod(0o644)
                fd = s.r.directory(self.source)
                try:
                    with self.assertRaises((ValueError, OSError)): s.read_source(fd, self.file.name)
                finally:
                    os.close(fd); self.file.unlink()
                    (self.source/'other').unlink(missing_ok=True)

    def test_owner_guard(self):
        self.create(); info = s.identity(self.file.stat()); info['st_uid'] += 1
        with self.assertRaisesRegex(ValueError, 'PRIVATE_SOURCE'): s.check_identity(info, len(self.data))

    def test_file_replacement_during_read_rejected(self):
        self.create(); fd = s.r.directory(self.source); actual = os.fstat; count = 0
        def replaced(n):
            nonlocal count
            count += 1
            if count == 2:
                self.file.unlink(); self.create()
            return actual(n)
        try:
            with patch.object(s.os, 'fstat', side_effect=replaced), self.assertRaisesRegex(ValueError, 'SOURCE_CHANGED'):
                s.read_source(fd, self.file.name)
        finally:
            os.close(fd)

    def test_mutation_during_read_rejected(self):
        self.create(); fd = s.r.directory(self.source); actual = os.fstat; count = 0
        def changed(n):
            nonlocal count
            count += 1
            if count == 2: self.create(b'changed')
            return actual(n)
        try:
            with patch.object(s.os, 'fstat', side_effect=changed), self.assertRaises(ValueError):
                s.read_source(fd, self.file.name)
        finally: os.close(fd)

    def test_directory_replacement_fails_closed(self):
        def replace(i):
            if i == 0:
                self.source.rename(self.base/'old')
                self.source.mkdir(mode=0o700)
        result = self.observe(replace)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.saved('terminal.json')['reason'], 'SOURCE_DIRECTORY_CHANGED')

    def test_private_source_directory_and_ancestors_required(self):
        self.source.chmod(0o755)
        result = self.observe()
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(self.file.exists())

    def test_source_and_store_overlap_rejected_before_intent(self):
        self.spec['directory'] = str(self.store)
        with self.assertRaisesRegex(ValueError, 'OVERLAP'): s.observe(self.spec, self.store)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_spec_rejects_paths_bounds_and_booleans(self):
        for key, value in [('directory', '/x/../y'), ('directory', '/x//y'), ('directory', 'relative'),
                           ('filename', '../x'), ('filename', '.'), ('seconds', True), ('seconds', 121),
                           ('precision_ms', 0), ('expected_sha256', 'x'), ('clock_ref', 'x\n'), ('extra', 1)]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                s.check_spec(dict(self.spec, **{key: value}))

    def test_export_never_reads_source_or_calls_timer(self):
        result = self.observe(); self.file.unlink(); self.source.rmdir()
        with patch.object(s, 'read_source', side_effect=AssertionError), patch.object(s.v, 'deadline_call', side_effect=AssertionError):
            self.assertIsNotNone(s.export(self.store, result['intent_sha256']))

    def test_changed_snapshot_even_with_rehashed_metadata_rejected(self):
        result = self.observe(); (self.store/'poll-001.bin').write_bytes(b'wrong')
        p = self.saved('poll-001.json'); p['sha256'] = s.r.digest(b'wrong'); p['identity']['st_size'] = 5
        self.replace('poll-001.json', p)
        with self.assertRaisesRegex(ValueError, 'WRONG_CONTENT'): s.export(self.store, result['intent_sha256'])

    def test_metadata_size_tampering_rejected(self):
        result = self.observe(); p = self.saved('poll-001.json'); p['identity']['st_size'] += 1
        self.replace('poll-001.json', p)
        with self.assertRaises(ValueError): s.export(self.store, result['intent_sha256'])

    def test_changed_spec_or_code_or_expected_intent_rejected(self):
        result = self.observe()
        with self.assertRaises(ValueError): s.export(self.store, 'a' * 64)
        with patch.object(s, 'source_hashes', return_value={}):
            with self.assertRaisesRegex(ValueError, 'SOURCE_CODE_CHANGED'): s.export(self.store, result['intent_sha256'])
        intent = self.saved('intent.json'); intent['spec']['filename'] = 'other'
        self.replace('intent.json', intent)
        with self.assertRaisesRegex(ValueError, 'INTENT_HASH'): s.export(self.store, result['intent_sha256'])

    def test_clock_jump_gap_overrun_and_forged_absence_rejected(self):
        result = self.observe(); p = self.saved('poll-001.json')
        for key, value in [('start_ms', p['start_ms'] + 1000), ('start_ns', p['start_ns'] + 300_000_000),
                           ('end_ns', p['end_ns'] + 1_000_000_000), ('found', False)]:
            with self.subTest(key=key):
                self.replace('poll-001.json', dict(p, **{key: value}))
                with self.assertRaises(ValueError): s.export(self.store, result['intent_sha256'])
        self.replace('poll-001.json', p)

    def test_scheduling_gap_is_failed(self):
        clock = Clock(); original = clock.sleep
        clock.sleep = lambda seconds: original(seconds + .2)
        with patch.object(s, 'time', clock), patch.object(s, 'read_source') as read:
            result = s.observe(self.spec, self.store)
        read.assert_not_called(); self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.saved('terminal.json')['reason'], 'SCHEDULING_GAP')

    def test_interruption_and_recovery_without_terminal(self):
        def stop(_): raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt): self.observe(stop)
        self.assertEqual(self.saved('terminal.json')['reason'], 'INTERRUPTED')
        (self.store/'terminal.json').unlink()
        expected = s.r.digest((self.store/'intent.json').read_bytes())
        summary = s.export(self.store, expected, summary=True)
        self.assertEqual(summary['status'], 'failed'); self.assertIsNone(summary['observer'])
        with self.assertRaises(ValueError): s.export(self.store, expected)

    def test_fsync_failure_prevents_source_read(self):
        with patch.object(s.r.os, 'fsync', side_effect=OSError), patch.object(s, 'read_source') as read:
            with self.assertRaises(OSError): s.observe(self.spec, self.store)
        read.assert_not_called()

    def test_partial_artifact_failure_is_never_success(self):
        actual = s.r.write_once
        def fail(fd, name, data):
            if name == 'poll-001.bin':
                actual(fd, name, data[:2]); raise OSError('private error')
            actual(fd, name, data)
        with patch.object(s.r, 'write_once', side_effect=fail): result = self.observe()
        self.assertEqual(result['status'], 'failed')
        self.assertNotIn('private error', (self.store/'terminal.json').read_text())
        with self.assertRaises(ValueError): s.export(self.store, result['intent_sha256'])

    def test_success_rejects_extra_files_and_terminal_tampering(self):
        result = self.observe(); extra = self.store/'extra'; extra.write_bytes(b''); extra.chmod(0o600)
        with self.assertRaises(ValueError): s.export(self.store, result['intent_sha256'])
        extra.unlink(); terminal = self.saved('terminal.json'); terminal['observer']['timestamp_ms'] += 1
        self.replace('terminal.json', terminal)
        with self.assertRaisesRegex(ValueError, 'TERMINAL_MISMATCH'): s.export(self.store, result['intent_sha256'])

    def test_full_absent_window_cannot_be_shortened(self):
        result = self.observe(lambda _: None)
        terminal = self.saved('terminal.json'); terminal['poll_count'] = 2
        self.replace('terminal.json', terminal); (self.store/'poll-002.json').unlink()
        with self.assertRaisesRegex(ValueError, 'TRUNCATED'): s.export(self.store, result['intent_sha256'])

    def test_store_lock_blocks_observe_and_export(self):
        with s.r.store_lock(self.store):
            with self.assertRaises(BlockingIOError): s.observe(self.spec, self.store)
            with self.assertRaises(BlockingIOError): s.export(self.store, 'a' * 64)

    def test_actual_read_deadline_is_retained(self):
        with patch.object(s, 'read_source', side_effect=lambda *_: time.sleep(2)):
            result = s.observe(self.spec, self.store)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(self.saved('terminal.json')['reason'], 'READ_DEADLINE')
        self.assertEqual(signal.getsignal(signal.SIGALRM), signal.SIG_DFL)

    def measurement(self):
        from test_measure import manifest_v2, trial_v2
        runner = load('source_trial_test', ROOT/'scripts/measure/trial_runner.py')
        manifest = manifest_v2(); run = manifest['runs'][0]
        trial = trial_v2(event_valid=False, source_ref='', **{k: None for k in runner.m.TIMES if k != 't0'})
        self.spec.update(run_id=trial['run_id'], trial_id=trial['trial_id'], clock_ref='fixture clock')
        result = self.observe()
        trial['target_key'] = {'syscheck.path': str(self.file)}
        trial['stage_selectors']['t2']['target_key'] = dict(trial['target_key'])
        trial['source_binding'] = {'source_spec_sha256': s.r.digest(s.r.json_bytes(self.spec)),
                                   'target_key': dict(trial['target_key'])}
        evidence = (self.store, result['intent_sha256'])
        return runner, manifest, run, trial, evidence

    def test_sensor_miss_keeps_full_denominator_without_t1(self):
        runner, manifest, run, trial, evidence = self.measurement()
        runner.collect(trial, run, None, [], [], [], evidence)
        self.assertTrue(trial['event_valid']); self.assertIsNone(trial['t1'])
        self.assertIsNone(trial['t4']); self.assertIsNone(trial['t5'])
        report = runner.m.analyze_v2([(trial, 'synthetic')], [], manifest)
        self.assertEqual(report['trials'][0]['status'], 'MISSED')
        self.assertEqual(report['summaries'][0]['denominator_all_attempts'], 1)

    def test_binding_hash_path_clock_run_and_trial_are_enforced(self):
        runner, manifest, run, trial, evidence = self.measurement()
        changes = [('spec', 'a' * 64), ('path', '/wrong'), ('clock', 'wrong'),
                   ('device', 'observer'), ('run', 'wrong'), ('trial', 'wrong'), ('selector', '/wrong')]
        for kind, value in changes:
            with self.subTest(kind=kind):
                t, config = copy.deepcopy(trial), copy.deepcopy(run)
                if kind == 'spec': t['source_binding']['source_spec_sha256'] = value
                if kind == 'path': t['source_binding']['target_key']['syscheck.path'] = value
                if kind == 'clock': config['devices']['endpoint']['clock_ref'] = value
                if kind == 'device': config['clock_map']['t1'] = value
                if kind == 'run': t['run_id'] = value
                if kind == 'trial': t['trial_id'] = value
                if kind == 'selector': t['stage_selectors']['t2']['target_key']['syscheck.path'] = value
                with self.assertRaises(ValueError): runner.collect(t, config, None, [], [], [], evidence)
                self.assertFalse(t['event_valid'])

    def test_binding_requires_store_and_refuses_plain_export(self):
        runner, manifest, run, trial, evidence = self.measurement()
        with self.assertRaisesRegex(ValueError, 'SOURCE_STORE_REQUIRED'):
            runner.collect(trial, run, None, [], [], [])
        row = s.export(*evidence); path = self.base/'observer.jsonl'; path.write_bytes(s.r.json_bytes(row))
        del trial['source_binding']
        with self.assertRaisesRegex(ValueError, 'SOURCE_STORE_REQUIRED'):
            runner.collect(trial, run, None, [], [], [path])

    def test_legacy_event_clock_ref_checked_without_breaking_legacy_absence(self):
        runner, manifest, run, trial, evidence = self.measurement()
        del trial['source_binding']
        row = s.export(*evidence)
        for key in ('producer', 'source_spec_sha256', 'source_intent_sha256', 'target_key'):
            del row[key]
        path = self.base/'observer.jsonl'
        row['clock_ref'] = 'wrong'; path.write_bytes(s.r.json_bytes(row))
        with self.assertRaisesRegex(ValueError, 'clock_ref disagrees'):
            runner.collect(trial, run, None, [], [], [path])
        del row['clock_ref']; path.write_bytes(s.r.json_bytes(row))
        runner.collect(trial, run, None, [], [], [path]); self.assertTrue(trial['event_valid'])

    def test_snapshot_tamper_is_rejected_at_trial_import(self):
        runner, manifest, run, trial, evidence = self.measurement()
        (self.store/'poll-001.bin').write_bytes(b'wrong')
        with self.assertRaises(ValueError): runner.collect(trial, run, None, [], [], [], evidence)
        self.assertFalse(trial['event_valid'])

    def test_conflicting_legacy_event_cannot_override_bound_source(self):
        runner, manifest, run, trial, evidence = self.measurement()
        row = s.export(*evidence); del row['producer']
        path = self.base/'observer.jsonl'; path.write_bytes(s.r.json_bytes(row))
        with self.assertRaisesRegex(ValueError, 'SOURCE_EVENT_CONFLICT'):
            runner.collect(trial, run, None, [], [], [path], evidence)

    def test_other_trial_observer_rows_do_not_conflict_with_bound_source(self):
        runner, manifest, run, trial, evidence = self.measurement()
        other = s.export(*evidence); other['trial_id'] = 'different-trial'
        legacy = dict(other); del legacy['producer']
        path = self.base/'rotation.jsonl'
        path.write_bytes(s.r.json_bytes(other) + s.r.json_bytes(legacy))
        runner.collect(trial, run, None, [], [], [path], evidence)
        self.assertTrue(trial['event_valid']); self.assertIsNone(trial['t1'])

    def test_output_cannot_be_created_inside_source_evidence_store(self):
        runner, manifest, run, trial, evidence = self.measurement()
        spec_path, manifest_path = self.base/'trial.json', self.base/'manifest.json'
        spec_path.write_bytes(s.r.json_bytes({'attempt': trial}))
        manifest_path.write_bytes(s.r.json_bytes(manifest))
        alerts = self.base/'alerts.jsonl'; alerts.write_bytes(b'')
        output = self.store/'attempts.jsonl'
        command = [sys.executable, '-I', '-B', str(ROOT/'scripts/measure/trial_runner.py'), '--replay',
                   '--spec', str(spec_path), '--manifest', str(manifest_path), '--alerts', str(alerts),
                   '--output', str(output), '--source-store', str(evidence[0]), '--source-intent-sha256', evidence[1]]
        result = subprocess.run(command, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'OUTPUT_INSIDE_SOURCE_STORE', result.stderr)
        self.assertFalse(output.exists())
        self.assertIsNotNone(s.export(*evidence))

    def test_cli_bound_replay_preserves_sensor_miss(self):
        runner, manifest, run, trial, evidence = self.measurement()
        spec_path, manifest_path = self.base/'trial.json', self.base/'manifest.json'
        spec_path.write_bytes(s.r.json_bytes({'attempt': trial}))
        manifest_path.write_bytes(s.r.json_bytes(manifest))
        alerts = self.base/'alerts.jsonl'; alerts.write_bytes(b'')
        output = self.base/'attempts.jsonl'
        command = [sys.executable, '-I', '-B', str(ROOT/'scripts/measure/trial_runner.py'), '--replay',
                   '--spec', str(spec_path), '--manifest', str(manifest_path), '--alerts', str(alerts),
                   '--output', str(output), '--source-store', str(evidence[0]), '--source-intent-sha256', evidence[1]]
        result = subprocess.run(command, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        saved = json.loads(output.read_bytes())
        self.assertTrue(saved['event_valid']); self.assertIsNone(saved['t1'])
        report = runner.m.analyze_v2([(saved, 'synthetic')], [], manifest)
        self.assertEqual(report['trials'][0]['status'], 'MISSED')
        repeated = subprocess.run(command, capture_output=True, timeout=5)
        self.assertEqual(repeated.returncode, 2)
        self.assertEqual(len(output.read_text().splitlines()), 1)

    def test_cli_preview_and_preexisting_offline_export(self):
        spec_path = self.base/'spec.json'; spec_path.write_bytes(s.r.json_bytes(self.spec)); spec_path.chmod(0o600)
        command = [sys.executable, '-I', '-B', str(ROOT/'scripts/measure/source_observer.py')]
        preview = subprocess.run(command + ['preview', '--spec', str(spec_path)], capture_output=True, timeout=5)
        self.assertEqual(preview.returncode, 0); self.assertFalse(json.loads(preview.stdout)['source_read'])
        self.create()
        observe = subprocess.run(command + ['observe', '--lab', '--spec', str(spec_path), '--store', str(self.store)],
                                 capture_output=True, timeout=5)
        self.assertEqual(observe.returncode, 2)
        result = json.loads(observe.stdout)
        out = subprocess.run(command + ['export', '--store', str(self.store), '--intent-sha256', result['intent_sha256']],
                             capture_output=True, timeout=5)
        self.assertEqual(out.returncode, 0); self.assertEqual(out.stdout, b'')


if __name__ == '__main__':
    unittest.main()
