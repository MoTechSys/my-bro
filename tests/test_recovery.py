"""Synthetic stopped-journal recovery; no lab commands, original logs or model."""
import contextlib
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_visibility_observer import ROOT, load
from test_measure import manifest_v2, trial_v2

v = load('recovery_test', ROOT/'scripts/measure/recovery.py')


class Recovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT, prefix='.recovery-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.store = self.base/'store'; self.store.mkdir(mode=0o700)
        self.journal = self.base/'attempts.jsonl'
        self.pending = self.base/'attempts.jsonl.pending'
        self.manifest_path = self.base/'manifest.json'
        self.manifest = manifest_v2()
        self.trial = trial_v2(event_valid=False)
        for key in v.m.TIMES:
            if key != 't0': self.trial[key] = None
        self.trial['runner'] = {'mode': 'replay', 'command': [], 'state': 'PREPARED_NOT_COMPLETED',
                               'manifest_sha256': v.r.digest(v.r.json_bytes(self.manifest))}
        self.write(self.journal, b'')
        self.write(self.pending, v.t.encoded(self.trial))
        self.write(self.manifest_path, v.r.json_bytes(self.manifest))

    def write(self, path, raw):
        path.write_bytes(raw); path.chmod(0o600)

    def pins(self):
        return {name: v.r.digest(path.read_bytes()) for name, path in zip(v.INPUTS,
                (self.journal, self.pending, self.manifest_path))}

    def run_recovery(self, **kwargs):
        return v.recover(self.journal, self.manifest_path, self.store, self.pins(), operator_stopped=True, **kwargs)

    def exported(self, result):
        return v.export(self.store, result['intent_sha256'])

    def reject(self):
        result = self.run_recovery()
        self.assertEqual(result['status'], 'failed')
        with self.assertRaises(ValueError): self.exported(result)
        self.assertFalse(v.export(self.store, result['intent_sha256'], summary=True)['artifacts_verified'])

    def test_interrupted_row_has_no_fabricated_times_and_counts_in_full_denominator(self):
        result = self.run_recovery(); rows = v.rows(self.exported(result))
        self.assertEqual(len(rows), 1); row = rows[0]
        self.assertEqual(row['exclusion_reason'], 'INVALID')
        self.assertEqual(row['reason'], 'INTERRUPTED_AFTER_PREPARED_INTENT')
        self.assertFalse(row['event_valid']); self.assertEqual(row['t0'], self.trial['t0'])
        self.assertTrue(all(row[key] is None for key in v.m.TIMES if key != 't0'))
        self.assertIsNone(row['runner']['exit_code']); self.assertIsNone(row['runner']['timed_out'])
        self.assertIsNone(row['recovery']['execution_started'])
        report = v.m.analyze_v2([(row, 'synthetic')], [], self.manifest)
        self.assertEqual(report['summaries'][0]['denominator_all_attempts'], 1)
        self.assertEqual(report['summaries'][0]['denominator_valid'], 0)
        self.assertTrue(all(n is None for n in report['trials'][0]['metrics_s'].values()))

    def test_original_bytes_preserved_and_all_artifacts_private(self):
        before = {p: p.read_bytes() for p in (self.journal, self.pending, self.manifest_path)}
        result = self.run_recovery(); self.exported(result)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        for p in self.store.iterdir(): self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_preserves_previous_failed_rows_and_crlf_bytes(self):
        previous = trial_v2(trial_id='previous', exclusion_reason='BLOCKED', reason='approved control')
        raw = v.t.encoded(previous).replace(b'\n', b'\r\n')
        self.write(self.journal, raw)
        result = self.run_recovery(); output = self.exported(result)
        self.assertTrue(output.startswith(raw)); rows = v.rows(output)
        self.assertEqual(len(rows), 2); self.assertEqual(rows[0], previous)
        report = v.m.analyze_v2([(row, str(i)) for i, row in enumerate(rows)], [], self.manifest)
        self.assertEqual(report['summaries'][0]['denominator_all_attempts'], 2)

    def test_preflight_exclusion_reason_is_preserved(self):
        self.trial.update(exclusion_reason='BLOCKED', reason='scope refused')
        self.write(self.pending, v.t.encoded(self.trial))
        row = v.rows(self.exported(self.run_recovery()))[0]
        self.assertEqual(row['exclusion_reason'], 'BLOCKED'); self.assertEqual(row['reason'], 'scope refused')

    def test_existing_published_row_is_not_replaced_or_duplicated(self):
        existing = copy.deepcopy(self.trial)
        existing.update(event_valid=True, source_ref='synthetic action')
        existing['runner']['state'] = 'COLLECTED'
        existing['runner']['exit_code'] = 0
        raw = v.t.encoded(existing); self.write(self.journal, raw)
        result = self.run_recovery()
        self.assertEqual(self.exported(result), raw)
        self.assertEqual(v.export(self.store, result['intent_sha256'], summary=True)['result']['disposition'], 'already_recorded')

    def test_existing_identity_conflict_refused(self):
        existing = copy.deepcopy(self.trial); existing['runner']['state'] = 'COLLECTED'
        existing['target_key'] = {'syscheck.path': '/wrong'}
        self.write(self.journal, v.t.encoded(existing)); self.reject()

    def test_existing_t0_mismatch_refused(self):
        existing = copy.deepcopy(self.trial); existing['runner']['state'] = 'COLLECTED'; existing['t0'] += 1
        self.write(self.journal, v.t.encoded(existing)); self.reject()

    def test_duplicate_journal_identity_refused(self):
        previous = trial_v2(trial_id='previous')
        self.write(self.journal, v.t.encoded(previous) * 2); self.reject()

    def test_partial_journal_line_never_dropped_or_joined(self):
        self.write(self.journal, b'{"incomplete":'); before = self.journal.read_bytes()
        self.reject(); self.assertEqual(self.journal.read_bytes(), before)

    def test_partial_pending_refused_without_repair(self):
        self.write(self.pending, self.pending.read_bytes()[:-1]); self.reject()

    def test_strict_json_duplicates_invalid_utf8_and_nonobjects(self):
        for raw in (b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'[]\n', b'\xff\n', b'\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): v.rows(raw)

    def test_explicit_stopped_operator_assertion_required(self):
        with self.assertRaisesRegex(ValueError, 'STOPPED_OPERATOR'):
            v.recover(self.journal, self.manifest_path, self.store, self.pins())
        self.assertEqual(list(self.store.iterdir()), [])

    def test_wrong_input_pin_fails_closed(self):
        pins = self.pins(); pins['pending.json'] = 'a' * 64
        result = v.recover(self.journal, self.manifest_path, self.store, pins, operator_stopped=True)
        self.assertEqual(result['status'], 'failed')
        self.assertFalse((self.store/'attempts.jsonl').exists())

    def test_manifest_mismatch_refused_even_with_new_raw_pin(self):
        self.manifest['runs'][0]['planned_n'] = 31
        self.write(self.manifest_path, v.r.json_bytes(self.manifest)); self.reject()

    def test_legacy_requires_explicit_unbound_mode(self):
        del self.trial['runner']['manifest_sha256']; self.write(self.pending, v.t.encoded(self.trial))
        data = {name: p.read_bytes() for name, p in zip(v.INPUTS, (self.journal, self.pending, self.manifest_path))}
        with self.assertRaisesRegex(ValueError, 'LEGACY_MANIFEST_UNBOUND'): v.plan(data)
        result = self.run_recovery(allow_legacy=True)
        row = v.rows(self.exported(result))[0]
        self.assertEqual(row['recovery']['manifest_binding'], 'operator_pinned_legacy')
        self.assertFalse(row['recovery']['process_cleanup_verified'])

    def test_completed_pending_state_not_reinterpreted(self):
        self.trial['runner']['state'] = 'COLLECTED'; self.write(self.pending, v.t.encoded(self.trial)); self.reject()

    def test_export_does_not_read_original_files_or_execute_commands(self):
        result = self.run_recovery()
        self.journal.unlink(); self.pending.unlink(); self.manifest_path.unlink()
        with patch.object(v, 'private_read', side_effect=AssertionError), patch.object(v.t, 'execute', side_effect=AssertionError):
            self.assertEqual(len(v.rows(self.exported(result))), 1)

    def test_output_tamper_even_rehashed_terminal_is_rejected(self):
        result = self.run_recovery()
        path = self.store/'attempts.jsonl'; path.write_bytes(b'{}\n')
        terminal = json.loads((self.store/'terminal.json').read_bytes())
        terminal['result']['output_sha256'] = v.r.digest(path.read_bytes())
        (self.store/'terminal.json').write_bytes(v.r.json_bytes(terminal))
        with self.assertRaisesRegex(ValueError, 'RECOVERY_OUTPUT_MISMATCH'): self.exported(result)

    def test_snapshot_tamper_and_code_change_refused(self):
        result = self.run_recovery()
        with patch.object(v, 'source_hashes', return_value={}):
            with self.assertRaises(ValueError): self.exported(result)
        (self.store/'pending.json').write_bytes(b'{}\n')
        with self.assertRaisesRegex(ValueError, 'INPUT_HASH_MISMATCH'): self.exported(result)

    def test_live_journal_lock_prevents_snapshot(self):
        with self.journal.open('rb') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_recovery()
        self.assertEqual(result['status'], 'failed')
        self.assertFalse((self.store/'journal.jsonl').exists())

    def test_no_retry_and_destination_lock(self):
        with v.r.store_lock(self.store):
            with self.assertRaises(BlockingIOError): self.run_recovery()
        self.run_recovery()
        with self.assertRaisesRegex(ValueError, 'NEW_EMPTY_STORE_REQUIRED'): self.run_recovery()

    def test_symlink_fifo_hardlink_and_public_files_refused(self):
        alias = self.base/'alias'; alias.symlink_to(self.pending)
        with self.assertRaises(OSError): v.private_read(alias)
        alias.unlink(); os.mkfifo(alias, 0o600)
        with self.assertRaises(ValueError): v.private_read(alias)
        alias.unlink(); os.link(self.pending, alias)
        with self.assertRaises(ValueError): v.private_read(self.pending)
        alias.unlink(); self.pending.chmod(0o644)
        with self.assertRaises(ValueError): v.private_read(self.pending)

    def test_input_replacement_during_read_is_refused(self):
        real = os.read; called = False
        def changed(fd, size):
            nonlocal called
            raw = real(fd, size)
            if not called:
                called = True; self.pending.unlink(); self.write(self.pending, raw)
            return raw
        with patch.object(v.os, 'read', side_effect=changed), self.assertRaisesRegex(ValueError, 'INPUT_CHANGED'):
            v.private_read(self.pending)

    def test_oversized_input_rejected_without_reading_body(self):
        with self.pending.open('wb') as stream: stream.truncate(v.MAX_INPUT + 1)
        with patch.object(v.os, 'read') as read, self.assertRaisesRegex(ValueError, 'INPUT_TOO_LARGE'):
            v.private_read(self.pending)
        read.assert_not_called()

    def test_missing_terminal_reports_incomplete_not_success(self):
        result = self.run_recovery(); (self.store/'terminal.json').unlink()
        summary = v.export(self.store, result['intent_sha256'], summary=True)
        self.assertEqual(summary['status'], 'failed'); self.assertFalse(summary['artifacts_verified'])
        with self.assertRaises(ValueError): self.exported(result)

    def test_intent_fsync_failure_prevents_reading_inputs(self):
        with patch.object(v.r.os, 'fsync', side_effect=OSError), patch.object(v, 'read_fd') as read:
            with self.assertRaises(OSError): self.run_recovery()
        read.assert_not_called()

    def test_failure_after_each_snapshot_retains_no_success(self):
        real = v.r.write_once
        for i, target in enumerate((*v.INPUTS, 'attempts.jsonl')):
            with self.subTest(target=target):
                self.store = self.base/('fault-' + str(i)); self.store.mkdir(mode=0o700)
                def fail(fd, name, data):
                    real(fd, name, data)
                    if name == target: raise OSError('private detail')
                with patch.object(v.r, 'write_once', side_effect=fail): result = self.run_recovery()
                self.assertEqual(result['status'], 'failed')
                self.assertNotIn('private detail', (self.store/'terminal.json').read_text())
                with self.assertRaises(ValueError): self.exported(result)

    def test_cancellation_after_snapshot_retains_failed_terminal(self):
        real = v.r.write_once
        def stop(fd, name, data):
            real(fd, name, data)
            if name == 'pending.json': raise KeyboardInterrupt()
        with patch.object(v.r, 'write_once', side_effect=stop), self.assertRaises(KeyboardInterrupt): self.run_recovery()
        terminal = json.loads((self.store/'terminal.json').read_bytes())
        self.assertEqual(terminal['reason'], 'RECOVERY_INTERRUPTED')
        self.assertTrue(self.pending.exists())

    def test_actual_cli_recovery_and_export(self):
        command = [sys.executable, '-I', '-B', str(ROOT/'scripts/measure/recovery.py')]
        pins = self.pins()
        args = ['recover', '--journal', str(self.journal), '--manifest', str(self.manifest_path),
                '--store', str(self.store), '--operator-stopped']
        for flag, name in zip(('journal', 'pending', 'manifest'), v.INPUTS): args += ['--' + flag + '-sha256', pins[name]]
        result = subprocess.run(command + args, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        receipt = json.loads(result.stdout)
        out = subprocess.run(command + ['export', '--store', str(self.store), '--intent-sha256', receipt['intent_sha256']],
                             capture_output=True, timeout=5)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(len(v.rows(out.stdout)), 1)

    def test_real_runner_pending_manifest_binding_and_recovery(self):
        # Produce a real pending intent through CLI logic, cancel after durable publication.
        self.pending.unlink()
        spec_path = self.base/'spec.json'
        self.write(spec_path, v.r.json_bytes({'attempt': self.trial}))
        alerts = self.base/'alerts.jsonl'; self.write(alerts, b'')
        actual = v.t.sync_parent
        def stop(path):
            actual(path)
            if str(path).endswith('.pending'): raise KeyboardInterrupt()
        with patch.object(v.t, 'sync_parent', side_effect=stop), contextlib.redirect_stdout(io.StringIO()), \
             contextlib.redirect_stderr(io.StringIO()):
            code = v.t.main(['--replay', '--spec', str(spec_path), '--manifest', str(self.manifest_path),
                             '--output', str(self.journal), '--alerts', str(alerts)])
        self.assertEqual(code, 130)
        row = json.loads(self.pending.read_bytes())
        self.assertEqual(row['runner']['manifest_sha256'], v.r.digest(v.r.json_bytes(self.manifest)))
        self.assertEqual(self.run_recovery()['status'], 'completed')


if __name__ == '__main__': unittest.main()
