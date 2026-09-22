"""Synthetic evidence-runner tests; no live model, lab or original C4 results."""
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
spec = importlib.util.spec_from_file_location('runner_test', ROOT / 'ai_agent/runner.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class PrivateFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.git', prefix='ai-runner-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_private_exclusive_roundtrip_and_permissions(self):
        with r.store_lock(self.base) as fd:
            r.write_once(fd, 'evidence.json', b'{"synthetic":true}\n')
            self.assertEqual(r.read_at(fd, 'evidence.json'), b'{"synthetic":true}\n')
            self.assertEqual((self.base/'evidence.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): r.write_once(fd, 'evidence.json', b'changed')

    def test_lock_refuses_concurrent_open(self):
        with r.store_lock(self.base):
            with self.assertRaises(BlockingIOError):
                with r.store_lock(self.base): pass
        with r.store_lock(self.base): pass

    def test_public_leaf_and_writable_parent_rejected(self):
        self.base.chmod(0o755)
        with self.assertRaises(ValueError): r.directory(self.base)
        child = self.base/'child'; child.mkdir(mode=0o700)
        self.base.chmod(0o770)
        with self.assertRaises(ValueError): r.directory(child)
        self.base.chmod(0o700)

    def test_symlink_directory_rejected(self):
        target=self.base/'target'; target.mkdir(mode=0o700)
        alias=self.base/'alias'; alias.symlink_to(target, target_is_directory=True)
        with self.assertRaises(OSError): r.directory(alias)

    def test_artifact_symlink_fifo_hardlink_and_public_mode_rejected(self):
        with r.store_lock(self.base) as fd:
            r.write_once(fd, 'original', b'synthetic')
            (self.base/'link').symlink_to(self.base/'original')
            os.mkfifo(self.base/'fifo', mode=0o600)
            os.link(self.base/'original', self.base/'hard')
            for name in ('link', 'fifo', 'hard'):
                with self.assertRaises((ValueError, OSError)): r.read_at(fd, name)
            (self.base/'hard').unlink()
            (self.base/'original').chmod(0o644)
            with self.assertRaises(ValueError): r.read_at(fd, 'original')

    def test_names_and_size_bounds(self):
        with r.store_lock(self.base) as fd:
            for name in ('../escape', '/absolute', '', '.hidden', 'a/b'):
                with self.assertRaises(ValueError): r.write_once(fd, name, b'x')
            r.write_once(fd, 'small', b'12345')
            with self.assertRaises(ValueError): r.read_at(fd, 'small', limit=4)
            with patch.object(r, 'MAX_ARTIFACT', 2), self.assertRaises(ValueError):
                r.write_once(fd, 'large', b'123')

    def test_file_then_directory_fsync_order(self):
        with r.store_lock(self.base) as fd:
            real = r.os.fsync
            order = []
            def sync(target):
                order.append('directory' if target == fd else 'file')
                real(target)
            with patch.object(r.os, 'fsync', side_effect=sync):
                r.write_once(fd, 'durable', b'synthetic')
            self.assertEqual(order, ['file', 'directory'])

    def test_fsync_failure_leaves_non_overwritable_evidence(self):
        with r.store_lock(self.base) as fd:
            with patch.object(r.os, 'fsync', side_effect=OSError('synthetic disk failure')):
                with self.assertRaises(OSError): r.write_once(fd, 'partial', b'{}')
            with self.assertRaises(FileExistsError): r.write_once(fd, 'partial', b'{}')


class Deadline(unittest.TestCase):
    def run_python(self, code, seconds=2):
        return r.bounded_process([sys.executable, '-I', '-B', '-c', code], seconds)

    def test_success_and_nonzero_exit(self):
        out=self.run_python('print("synthetic")')
        self.assertEqual(out['reason'], 'OK')
        self.assertEqual(out['output'], b'synthetic\n')
        self.assertEqual(self.run_python('raise SystemExit(2)')['reason'], 'WORKER_FAILED')

    def test_launch_cancellation_inside_popen_and_before_assignment_cleans_child(self):
        real_execute, real_start = subprocess.Popen._execute_child, subprocess.Popen
        for sig in (signal.SIGINT, signal.SIGTERM):
            for phase in ('inside_popen', 'before_assignment'):
                with self.subTest(signal=sig, phase=phase):
                    children, delivered = [], []
                    previous = signal.getsignal(sig)
                    mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    def handler(number, frame):
                        delivered.append(number)
                        raise KeyboardInterrupt()
                    def execute(proc, *args, **kwargs):
                        real_execute(proc, *args, **kwargs)
                        children.append(proc)
                        os.kill(os.getpid(), sig)
                        os.kill(os.getpid(), sig)  # only the first cancellation is replayed
                    def start(*args, **kwargs):
                        proc = real_start(*args, **kwargs)
                        children.append(proc)
                        os.kill(os.getpid(), sig)
                        return proc
                    signal.signal(sig, handler)
                    target = (patch.object(real_start, '_execute_child', execute) if phase == 'inside_popen'
                              else patch.object(r.subprocess, 'Popen', side_effect=start))
                    try:
                        with target, self.assertRaises(KeyboardInterrupt):
                            self.run_python('import time; time.sleep(30)')
                        self.assertEqual(delivered, [sig])
                        self.assertEqual(children[0].returncode, -signal.SIGKILL)
                        self.assertTrue(children[0].stdout.closed)
                        self.assertIs(signal.getsignal(sig), handler)
                        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)
                    finally:
                        signal.signal(sig, previous)
                        for proc in children:
                            if proc.poll() is None:
                                os.killpg(proc.pid, signal.SIGKILL)
                            proc.wait(timeout=2)
                            proc.stdout.close()

    def test_launch_guard_does_not_add_blocked_signals_to_worker(self):
        result = self.run_python('import signal; print(sorted(int(s) for s in '
                                 'signal.pthread_sigmask(signal.SIG_BLOCK,set())))')
        expected = sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK, set()))
        self.assertEqual(json.loads(result['output']), expected)

    def test_launch_failure_restores_handlers_and_mask(self):
        before = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        with patch.object(r.subprocess, 'Popen', side_effect=OSError('synthetic spawn failure')):
            self.assertEqual(self.run_python('pass')['reason'], 'WORKER_START_OR_IO_FAILED')
        self.assertEqual({s: signal.getsignal(s) for s in before}, before)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)

    def test_ignored_launch_signal_stays_ignored(self):
        previous = signal.getsignal(signal.SIGTERM)
        real = r.subprocess.Popen
        def start(*args, **kwargs):
            proc = real(*args, **kwargs)
            os.kill(os.getpid(), signal.SIGTERM)
            return proc
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            with patch.object(r.subprocess, 'Popen', side_effect=start):
                self.assertEqual(self.run_python('pass')['reason'], 'OK')
            self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_IGN)
        finally:
            signal.signal(signal.SIGTERM, previous)

    def test_default_launch_signal_is_cancellable_before_cleanup(self):
        previous = signal.getsignal(signal.SIGTERM)
        real, children = r.subprocess.Popen, []
        def start(*args, **kwargs):
            proc = real(*args, **kwargs); children.append(proc)
            os.kill(os.getpid(), signal.SIGTERM)
            return proc
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        try:
            with patch.object(r.subprocess, 'Popen', side_effect=start), self.assertRaises(KeyboardInterrupt):
                self.run_python('import time; time.sleep(30)')
            self.assertEqual(children[0].returncode, -signal.SIGKILL)
            self.assertTrue(children[0].stdout.closed)
        finally:
            signal.signal(signal.SIGTERM, previous)
            for proc in children:
                if proc.poll() is None: os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=2); proc.stdout.close()

    def test_non_main_thread_refused_without_launch(self):
        failures = []
        def attempt():
            try: self.run_python('pass')
            except ValueError as exc: failures.append(str(exc))
        with patch.object(r.subprocess, 'Popen') as start:
            thread = r.threading.Thread(target=attempt)
            thread.start(); thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            start.assert_not_called()
        self.assertEqual(failures, ['MAIN_THREAD_REQUIRED'])

    def test_success_signals_group_before_reaping_leader(self):
        real_start, real_kill = r.subprocess.Popen, r.os.killpg
        processes, observed = [], []
        def start(*args, **kwargs):
            proc = real_start(*args, **kwargs); processes.append(proc); return proc
        def kill(pid, sig):
            proc = processes[-1]
            observed.append(proc.returncode is None)
            self.assertIsNotNone(os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
            return real_kill(pid, sig)
        with patch.object(r.subprocess, 'Popen', side_effect=start), patch.object(r.os, 'killpg', side_effect=kill):
            result = self.run_python('print("synthetic")')
        self.assertEqual(result['reason'], 'OK')
        self.assertEqual(observed, [True])
        self.assertEqual(processes[0].returncode, 0)
        self.assertTrue(processes[0].stdout.closed)

    def test_cleanup_timeout_is_recorded_and_closes_stdout(self):
        real_start = r.subprocess.Popen
        processes, waits = [], []
        def start(*args, **kwargs):
            proc = real_start(*args, **kwargs); processes.append(proc); waits.append(proc.wait)
            proc.wait = lambda timeout=None: (_ for _ in ()).throw(subprocess.TimeoutExpired('synthetic', timeout))
            return proc
        try:
            with patch.object(r.subprocess, 'Popen', side_effect=start):
                result = self.run_python('print("synthetic")')
            self.assertEqual(result['reason'], 'WORKER_CLEANUP_FAILED')
            self.assertEqual(result['output'], b'synthetic\n')
            self.assertTrue(processes[0].stdout.closed)
        finally:
            for wait in waits: wait(timeout=2)

    def test_first_cancellation_during_cleanup_is_deferred(self):
        real_start, real_kill = r.subprocess.Popen, r.os.killpg
        processes, closed_at_signal = [], []
        previous = signal.getsignal(signal.SIGINT)
        def start(*args, **kwargs):
            proc = real_start(*args, **kwargs); processes.append(proc); return proc
        def handler(*_):
            closed_at_signal.append(processes[0].stdout.closed)
            raise KeyboardInterrupt()
        def kill(pid, sig):
            os.kill(os.getpid(), signal.SIGINT)
            return real_kill(pid, sig)
        signal.signal(signal.SIGINT, handler)
        try:
            with patch.object(r.subprocess, 'Popen', side_effect=start), patch.object(r.os, 'killpg', side_effect=kill):
                with self.assertRaises(KeyboardInterrupt): self.run_python('pass')
            self.assertEqual(closed_at_signal, [True])
            self.assertEqual(processes[0].returncode, 0)
        finally:
            signal.signal(signal.SIGINT, previous)
            for proc in processes:
                if proc.returncode is None:
                    try: real_kill(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    proc.wait(timeout=2)
                proc.stdout.close()

    def test_custom_sigchld_reaper_is_refused_before_launch(self):
        with patch.object(r.signal, 'getsignal', return_value=signal.SIG_IGN), patch.object(r.subprocess, 'Popen') as start:
            with self.assertRaisesRegex(ValueError, 'DEFAULT_SIGCHLD_REQUIRED'): self.run_python('pass')
            start.assert_not_called()

    def test_signaled_exit_preserves_negative_return_code(self):
        result = self.run_python('import os,signal; os.kill(os.getpid(),signal.SIGTERM)')
        self.assertEqual(result['reason'], 'WORKER_FAILED')
        self.assertEqual(result['returncode'], -signal.SIGTERM)

    def test_success_still_terminates_descendants_that_closed_stdout(self):
        result = self.run_python('import subprocess,sys\np=subprocess.Popen([sys.executable,"-I","-B","-c",'
                                 '"import time; time.sleep(30)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
                                 'print(p.pid,flush=True)')
        self.assertEqual(result['reason'], 'OK')
        pid = int(result['output'])
        end = time.monotonic() + 2
        try:
            while True:
                try: state = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[0]
                except FileNotFoundError: break
                if state == 'Z': break
                self.assertLess(time.monotonic(), end, 'worker descendant still running')
                time.sleep(.01)
        finally:
            try: os.kill(pid, signal.SIGKILL)
            except ProcessLookupError: pass

    def test_silent_stall_has_total_deadline(self):
        result=self.run_python('import time; time.sleep(20)', .15)
        self.assertEqual(result['reason'], 'DEADLINE_EXCEEDED')
        self.assertLess(result['latency_seconds'], 2)

    def test_dripping_stdout_does_not_reset_deadline(self):
        result=self.run_python('import time\nfor i in range(500):\n print("x",flush=True); time.sleep(.01)', .2)
        self.assertEqual(result['reason'], 'DEADLINE_EXCEEDED')
        self.assertLess(result['latency_seconds'], 2)

    def test_closed_stdout_does_not_hide_stalled_child(self):
        result=self.run_python('import os,time; os.close(1); time.sleep(20)', .15)
        self.assertEqual(result['reason'], 'DEADLINE_EXCEEDED')
        self.assertLess(result['latency_seconds'], 2)

    def test_stdout_flood_is_bounded_and_stderr_is_discarded(self):
        with patch.object(r, 'MAX_WORKER_OUTPUT', 64):
            out=self.run_python('import os; os.write(2,b"PRIVATE"*10000); os.write(1,b"x"*100000)')
        self.assertEqual(out['reason'], 'OUTPUT_LIMIT')
        self.assertEqual(len(out['output']), 65)
        self.assertNotIn(b'PRIVATE', out['output'])

    def test_parent_secrets_not_in_worker_environment(self):
        with patch.dict(os.environ, {'PRIVATE_TEST_TOKEN':'not-forwarded'}):
            out=self.run_python('import os; print(os.getenv("PRIVATE_TEST_TOKEN"))')
        self.assertEqual(out['output'], b'None\n')

    def test_invalid_deadlines_never_start_process(self):
        for value in (0, -1, True, float('inf'), float('nan'), 121):
            with patch.object(r.subprocess, 'Popen') as start:
                with self.assertRaises(ValueError): r.bounded_process(['unused'], value)
                start.assert_not_called()

    def test_missing_executable_is_recordable_failure(self):
        out=r.bounded_process([str(ROOT/'does-not-exist')], 1)
        self.assertEqual(out['reason'], 'WORKER_START_OR_IO_FAILED')
        self.assertEqual(out['output'], b'')


def fixture(n=2):
    cfg = {'schema_version': 1, 'model': 'synthetic-model', 'endpoint': 'http://127.0.0.1:11434',
           'language': 'ar', 'window_seconds': 300, 'deadline_seconds': 1, 'inventory_sha256': None}
    alerts = [{'id': 'private-' + str(i), 'timestamp': '2026-09-18T00:00:00Z',
               'manager': {'name': 'private-manager'}, 'agent': {'id': '001'},
               'rule': {'id': '100210', 'level': 12}, 'full_log': 'NEVER-SEND-RAW'} for i in range(n)]
    inputs = {'alerts.jsonl': b''.join(r.json_bytes(row) for row in alerts),
              'rules.xml': (ROOT/'wazuh/manager/rules/local_rules.xml').read_bytes(),
              'configuration.json': r.json_bytes(cfg), 'rubric.txt': b'NEVER-SEND-RUBRIC',
              'model.json': r.json_bytes({'schema_version': 1, 'name': cfg['model'], 'sha256': 'a'*64})}
    _, context, _, provenance = r.build_bundle(inputs, '2026-09-18T01:00:00Z')
    manifest = {'schema_version': 1, 'evaluation_id': 'synthetic-evaluation', 'dataset_kind': 'synthetic',
                'independent_human_labels': False, 'independent_cases': False,
                'provenance': provenance, 'cases': [
                    {'case_id': 'case-'+str(i), 'batch_id': 'batch-1', 'alert_ref': 'A'+str(i+1),
                     'cluster_id': 'cluster-1', 'input_sha256': r.digest(inputs['alerts.jsonl']),
                     'labeler_ref': 'NEVER-SEND-LABELER',
                     'gold': {'classification': 'likely_benign', 'mitre_ids': []}} for i in range(n)]}
    response = r.json_bytes({'findings': [{'evidence_refs': [item['ref'] for item in context['alerts']],
        'classification': 'suspicious', 'assessment': 'Synthetic unverified advice.',
        'mitre_ids': ['T1059'], 'recommendation': 'investigate'}]})
    return manifest, inputs, response


class Evidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT/'.git', prefix='ai-evidence-')
        self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name)
        self.manifest, self.inputs, self.response=fixture()
        self.manifest_bytes=r.json_bytes(self.manifest)
        self.batch=self.base/r.batch_directory(self.manifest['evaluation_id'], 'batch-1')

    def run_batch(self, reason='OK', response=None, code=0):
        raw=self.response if response is None else response
        with patch.object(r, 'bounded_process', return_value={
                'reason':reason, 'returncode':code, 'latency_seconds':.25, 'output':raw}):
            return r.run_batch(self.base,self.manifest_bytes,'batch-1',self.inputs,infer=True)

    def export(self):
        return r.export_attempts(self.base,r.digest(self.manifest_bytes))

    def alter(self, path, action):
        value=json.loads(path.read_bytes()); action(value); path.write_bytes(r.json_bytes(value))

    def test_completed_batch_imports_exact_predictions_and_output_hash(self):
        result=self.run_batch()
        self.assertEqual(result['status'],'completed')
        imported=self.export()
        self.assertEqual(len(imported['attempts']),2)
        for row in imported['attempts']:
            self.assertEqual(row['prediction'],{'classification':'suspicious','mitre_ids':['T1059']})
            self.assertEqual(row['output_sha256'],r.digest(self.response))
            self.assertEqual(row['latency_seconds'],.25)
        report=r.e.evaluate(self.manifest,imported['attempts'],[])
        self.assertEqual(report['classification_all_planned']['value'],0)
        self.assertFalse(imported['model_runtime_identity_verified'])
        self.assertFalse(imported['acceptance_approved'])

    def test_no_inference_without_optin(self):
        with patch.object(r,'bounded_process') as worker:
            with self.assertRaisesRegex(ValueError,'EXPLICIT_INFERENCE_REQUIRED'):
                r.run_batch(self.base,self.manifest_bytes,'batch-1',self.inputs)
            worker.assert_not_called()
        self.assertEqual(list(self.base.iterdir()),[])

    def test_durable_intent_exists_before_worker_and_no_gold_in_arguments(self):
        def worker(command,seconds):
            self.assertTrue((self.batch/'intent.json').exists())
            self.assertTrue((self.base/'manifest.json').exists())
            self.assertEqual(command[:3],[sys.executable,'-I','-B'])
            self.assertEqual(len(command),7)
            context=Path(command[-1]).read_text()
            for marker in ('NEVER-SEND','private-manager','gold','labeler_ref'):
                self.assertNotIn(marker,context)
            self.assertNotIn('manifest',str(command)); self.assertNotIn('rubric',str(command))
            return {'reason':'OK','returncode':0,'latency_seconds':.1,'output':self.response}
        with patch.object(r,'bounded_process',side_effect=worker):
            r.run_batch(self.base,self.manifest_bytes,'batch-1',self.inputs,infer=True)

    def test_original_byte_hash_not_normalized_json_or_declared_hash(self):
        original = self.inputs['alerts.jsonl']
        changed = original.replace(b'\n', b'\r\n')
        path = self.base/'source.jsonl'
        path.write_bytes(changed)
        self.assertEqual(r.read_bytes(path), changed)
        self.assertNotEqual(r.digest(original), r.digest(changed))
        self.assertEqual(r.a.read_alerts(original.decode()), r.a.read_alerts(changed.decode()))
        inputs = dict(self.inputs, **{'alerts.jsonl': r.read_bytes(path)})
        with patch.object(r, 'bounded_process') as worker:
            with self.assertRaisesRegex(ValueError, 'FROZEN_PROVENANCE_MISMATCH'):
                r.run_batch(self.base, self.manifest_bytes, 'batch-1', inputs, infer=True)
            worker.assert_not_called()
        self.assertFalse((self.base/'manifest.json').exists())

    def test_filtered_duplicate_records_preserve_source_binding_and_reconstruction(self):
        first, second = r.a.read_alerts(self.inputs['alerts.jsonl'].decode())
        low = copy.deepcopy(first); low['id'] = 'low-level'; low['rule']['level'] = 3
        self.inputs['alerts.jsonl'] = b''.join(r.json_bytes(row) for row in (low, second, second, first))
        for case in self.manifest['cases']:
            case['input_sha256'] = r.digest(self.inputs['alerts.jsonl'])
        # Case list order must not drive projection: alert_ref is the join key.
        self.manifest['cases'].reverse()
        self.manifest_bytes = r.json_bytes(self.manifest)
        findings = []
        for ref, classification in (('A2', 'suspicious'), ('A1', 'likely_benign')):
            finding = copy.deepcopy(json.loads(self.response)['findings'][0])
            finding.update(evidence_refs=[ref], classification=classification)
            findings.append(finding)
        self.run_batch(response=r.json_bytes({'findings': findings}))
        context = json.loads((self.batch/'context.json').read_bytes())
        self.assertEqual([(row['ref'], row['source_record']) for row in context['alerts']],
                         [('A1', 2), ('A2', 4)])
        cases = {row['case_id']: row['prediction']['classification'] for row in self.export()['attempts']}
        self.assertEqual(cases, {'case-0': 'likely_benign', 'case-1': 'suspicious'})
        path = self.batch/'context.json'
        self.alter(path, lambda value: value['alerts'][0].update(source_record=4))
        self.alter(self.batch/'intent.json', lambda value: value['artifact_sha256'].update(
            {'context.json': r.digest(path.read_bytes())}))
        with self.assertRaisesRegex(ValueError, 'CONTEXT_OR_CODE_SNAPSHOT_MISMATCH'):
            self.export()

    def two_batch_plan(self):
        manifest, first, response = fixture(1)
        second = copy.deepcopy(first)
        row = r.a.read_alerts(first['alerts.jsonl'].decode())[0]
        row['id'] = 'different-private-alert'
        row['manager']['name'] = 'different-private-manager'
        second['alerts.jsonl'] = r.json_bytes(row)
        case = copy.deepcopy(manifest['cases'][0])
        case.update(case_id='case-second', batch_id='batch-2', cluster_id='cluster-2',
                    input_sha256=r.digest(second['alerts.jsonl']))
        manifest['cases'].append(case)
        self.manifest, self.inputs, self.response = manifest, first, response
        self.manifest_bytes = r.json_bytes(manifest)
        other_response = json.loads(response)
        other_response['findings'][0]['classification'] = 'likely_benign'
        return second, r.json_bytes(other_response)

    def test_same_alert_ref_across_batches_is_not_an_identity_join(self):
        second, response = self.two_batch_plan()
        self.run_batch()
        with patch.object(r, 'bounded_process', return_value={
                'reason': 'OK', 'returncode': 0, 'latency_seconds': .5, 'output': response}):
            r.run_batch(self.base, self.manifest_bytes, 'batch-2', second, infer=True)
        rows = {row['case_id']: row for row in self.export()['attempts']}
        self.assertEqual(rows['case-0']['prediction']['classification'], 'suspicious')
        self.assertEqual(rows['case-second']['prediction']['classification'], 'likely_benign')
        self.assertEqual(rows['case-0']['input_sha256'], r.digest(self.inputs['alerts.jsonl']))
        self.assertEqual(rows['case-second']['input_sha256'], r.digest(second['alerts.jsonl']))
        self.assertEqual(rows['case-second']['output_sha256'], r.digest(response))
        other = self.base/r.batch_directory(self.manifest['evaluation_id'], 'batch-2')
        temporary = self.base/'swapping'
        self.batch.rename(temporary); other.rename(self.batch); temporary.rename(other)
        with self.assertRaisesRegex(ValueError, 'INTENT_BINDING_MISMATCH'): self.export()

    def test_success_in_other_batch_never_replaces_failed_attempt_or_missing_denominator(self):
        second, response = self.two_batch_plan()
        missing = copy.deepcopy(self.manifest['cases'][0])
        missing.update(case_id='case-missing', batch_id='batch-3', input_sha256='c'*64)
        self.manifest['cases'].append(missing)
        self.manifest_bytes = r.json_bytes(self.manifest)
        self.run_batch(reason='DEADLINE_EXCEEDED', response=b'partial', code=None)
        original = {path.name: path.read_bytes() for path in self.batch.iterdir()}
        with patch.object(r, 'bounded_process', return_value={
                'reason': 'OK', 'returncode': 0, 'latency_seconds': .5, 'output': response}):
            r.run_batch(self.base, self.manifest_bytes, 'batch-2', second, infer=True)
        with patch.object(r, 'bounded_process') as worker:
            with self.assertRaises(FileExistsError):
                r.run_batch(self.base, self.manifest_bytes, 'batch-1', self.inputs, infer=True)
            worker.assert_not_called()
        self.assertEqual(original, {path.name: path.read_bytes() for path in self.batch.iterdir()})
        report = r.e.evaluate(self.manifest, self.export()['attempts'], [])
        self.assertEqual([report['counts'][s] for s in ('completed', 'failed', 'missing')], [1, 1, 1])
        self.assertEqual(report['classification_all_planned']['denominator'], 3)
        self.assertEqual(report['classification_all_planned']['numerator'], 1)

    def test_cancellation_at_launch_recovers_failed_intent_without_new_inference(self):
        real, children = r.subprocess.Popen, []
        previous = signal.getsignal(signal.SIGINT)
        def handler(*_): raise KeyboardInterrupt()
        def start(command, **kwargs):
            proc = real([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(30)'], **kwargs)
            children.append(proc)
            os.kill(os.getpid(), signal.SIGINT)
            return proc
        signal.signal(signal.SIGINT, handler)
        try:
            with patch.object(r.subprocess, 'Popen', side_effect=start), self.assertRaises(KeyboardInterrupt):
                r.run_batch(self.base, self.manifest_bytes, 'batch-1', self.inputs, infer=True)
            self.assertIsNotNone(children[0].returncode)
            self.assertTrue(children[0].stdout.closed)
            with patch.object(r.a.Ollama, '__call__', side_effect=AssertionError('no inference')):
                result = self.export()
                self.assertEqual(result, self.export())
            self.assertEqual(result['batches'][0]['reason'], 'INTERRUPTED_AFTER_INTENT')
            for row in result['attempts']:
                self.assertEqual(row['status'], 'failed')
                self.assertIsNone(row['latency_seconds'])
                self.assertIsNone(row['output_sha256'])
            with patch.object(r, 'bounded_process') as worker:
                with self.assertRaises(FileExistsError):
                    r.run_batch(self.base, self.manifest_bytes, 'batch-1', self.inputs, infer=True)
                worker.assert_not_called()
        finally:
            signal.signal(signal.SIGINT, previous)
            for proc in children:
                if proc.poll() is None: os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=2); proc.stdout.close()

    def test_crash_after_each_published_artifact_keeps_explicit_recovery_state(self):
        # Inject after durable publication, not an actual power-loss/filesystem test.
        bundle = r.build_bundle(self.inputs, '2026-09-18T01:00:00Z')[0]
        for boundary in (*bundle, 'intent.json', 'output.bin', 'terminal.json'):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(
                    dir=self.base, prefix='boundary-') as store:
                real = r.write_once
                def crash(fd, name, data):
                    real(fd, name, data)
                    if name == boundary: raise OSError('synthetic interruption')
                with patch.object(r, 'write_once', side_effect=crash), patch.object(
                        r, 'bounded_process', return_value={'reason': 'OK', 'returncode': 0,
                        'latency_seconds': .25, 'output': self.response}) as worker:
                    with self.assertRaises(OSError):
                        r.run_batch(store, self.manifest_bytes, 'batch-1', self.inputs, infer=True)
                    self.assertEqual(worker.call_count, int(boundary in ('output.bin', 'terminal.json')))
                if boundary in bundle:
                    with self.assertRaises(FileNotFoundError):
                        r.export_attempts(store, r.digest(self.manifest_bytes))
                else:
                    imported = r.export_attempts(store, r.digest(self.manifest_bytes))
                    expected = 'completed' if boundary == 'terminal.json' else 'failed'
                    self.assertTrue(all(row['status'] == expected for row in imported['attempts']))
                    report = r.e.evaluate(self.manifest, imported['attempts'], [])
                    self.assertEqual(report['classification_all_planned']['denominator'], 2)
                    if expected == 'failed':
                        self.assertTrue(all(row['latency_seconds'] is None for row in imported['attempts']))
                    self.assertEqual(imported['stored_artifact_bytes_verified'], boundary != 'output.bin')
                with patch.object(r, 'bounded_process') as worker:
                    with self.assertRaises(FileExistsError):
                        r.run_batch(store, self.manifest_bytes, 'batch-1', self.inputs, infer=True)
                    worker.assert_not_called()

    def test_prose_abstention_is_rejected_not_silently_dropped_or_classified(self):
        self.run_batch(response=b'I cannot assess these alerts.')
        imported = self.export()
        report = r.e.evaluate(self.manifest, imported['attempts'], [])
        self.assertEqual(report['counts']['rejected'], 2)
        self.assertEqual(report['counts']['missing'], 0)
        self.assertEqual(report['classification_all_planned']['denominator'], 2)
        self.assertTrue(all(row['output_sha256'] == r.digest(b'I cannot assess these alerts.')
                            for row in imported['attempts']))

    def test_retry_is_refused_without_worker_call(self):
        self.run_batch()
        with patch.object(r,'bounded_process') as worker:
            with self.assertRaises(FileExistsError):
                r.run_batch(self.base,self.manifest_bytes,'batch-1',self.inputs,infer=True)
            worker.assert_not_called()

    def test_mismatched_hash_or_coverage_fails_before_store_write(self):
        for mode in ('hash','extra_ref','missing_ref','provenance'):
            m=copy.deepcopy(self.manifest)
            if mode=='hash': m['cases'][0]['input_sha256']='b'*64
            if mode=='extra_ref': m['cases'][0]['alert_ref']='A99'
            if mode=='missing_ref': m['cases'].pop()
            if mode=='provenance': m['provenance']['prompt_sha256']='b'*64
            with patch.object(r,'bounded_process') as worker:
                with self.subTest(mode=mode), self.assertRaises(ValueError):
                    r.run_batch(self.base,r.json_bytes(m),'batch-1',self.inputs,infer=True)
                worker.assert_not_called()
            self.assertEqual(list(self.base.iterdir()),[])

    def test_disk_failure_before_intent_never_calls_worker_or_allows_retry(self):
        real=r.write_once
        def fail(fd,name,data):
            if name=='context.json': raise OSError('synthetic full disk')
            return real(fd,name,data)
        with patch.object(r,'write_once',side_effect=fail), patch.object(r,'bounded_process') as worker:
            with self.assertRaises(OSError):
                r.run_batch(self.base,self.manifest_bytes,'batch-1',self.inputs,infer=True)
            worker.assert_not_called()
        with self.assertRaises(FileNotFoundError): self.export()
        with self.assertRaises(FileExistsError): self.run_batch()

    def test_interrupted_worker_preserves_failed_attempt_with_unknown_latency(self):
        with patch.object(r,'bounded_process',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                r.run_batch(self.base,self.manifest_bytes,'batch-1',self.inputs,infer=True)
        result=self.export()
        self.assertEqual(result['batches'][0]['reason'],'INTERRUPTED_AFTER_INTENT')
        for row in result['attempts']:
            self.assertEqual(row['status'],'failed')
            self.assertIsNone(row['latency_seconds']); self.assertIsNone(row['prediction'])
        with self.assertRaises(FileExistsError): self.run_batch()

    def test_failure_after_output_before_terminal_is_not_success(self):
        real=r.write_once
        def fail(fd,name,data):
            if name=='terminal.json': raise OSError('synthetic full disk')
            return real(fd,name,data)
        with patch.object(r,'write_once',side_effect=fail):
            with self.assertRaises(OSError): self.run_batch()
        self.assertTrue((self.batch/'output.bin').exists())
        imported = self.export()
        self.assertEqual(imported['attempts'][0]['status'], 'failed')
        self.assertIsNone(imported['attempts'][0]['output_sha256'])
        self.assertFalse(imported['stored_artifact_bytes_verified'])
        self.assertEqual(imported['batches'][0]['unverified_artifacts'], ['output.bin'])

    def test_schema_rejection_records_original_response(self):
        self.run_batch(response=b'{"findings":[],"approved":true}')
        row=self.export()['attempts'][0]
        self.assertEqual(row['status'],'rejected')
        self.assertIsNone(row['prediction'])
        self.assertEqual(row['output_sha256'],r.digest((self.batch/'output.bin').read_bytes()))

    def test_rejection_code_preserves_whole_batch_failure(self):
        response = json.loads(self.response)
        response['findings'][0]['evidence_refs'] = ['A99']
        self.run_batch(response=r.json_bytes(response))
        terminal = json.loads((self.batch/'terminal.json').read_bytes())
        self.assertEqual(terminal['schema_version'], 2)
        self.assertEqual(terminal['reason'], 'OK')  # process success is not schema success
        self.assertEqual(terminal['validation_code'], 'UNKNOWN_EVIDENCE_REFERENCE')
        imported = self.export()
        self.assertEqual(imported['batches'][0]['validation_code'], 'UNKNOWN_EVIDENCE_REFERENCE')
        self.assertTrue(all(row['status'] == 'rejected' and row['prediction'] is None for row in imported['attempts']))

    def test_rejection_code_tampering_is_detected_by_revalidation(self):
        self.run_batch(response=b'{broken')
        self.alter(self.batch/'terminal.json', lambda value: value.update(validation_code='UNCOVERED_ALERTS'))
        with self.assertRaisesRegex(ValueError, 'TERMINAL_VALIDATION_CODE_MISMATCH'): self.export()

    def test_diagnostic_whitelist_never_copies_exception_text(self):
        for exc in (ValueError('PRIVATE-MODEL-TEXT'), ValueError({'private': 'data'}),
                    ValueError('INVALID_JSON', 'PRIVATE-MODEL-TEXT')):
            with self.subTest(error_type=type(exc).__name__), patch.object(r.a, 'validate_response', side_effect=exc):
                status, findings, code = r.classify_output(b'{}', 'OK', {})
            self.assertEqual((status, findings, code), ('rejected', [], 'INVALID_MODEL_RESPONSE'))

    def test_invalid_utf8_has_bounded_diagnostic(self):
        self.run_batch(response=b'\xff')
        self.assertEqual(self.export()['batches'][0]['validation_code'], 'INVALID_UTF8')

    def test_completed_failed_and_interrupted_have_no_validation_code(self):
        context = r.build_bundle(self.inputs, '2026-09-18T01:00:00Z')[1]
        self.assertIsNone(r.classify_output(self.response, 'OK', context)[2])
        self.assertIsNone(r.classify_output(b'bad', 'DEADLINE_EXCEEDED', context)[2])
        with patch.object(r, 'bounded_process', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                r.run_batch(self.base, self.manifest_bytes, 'batch-1', self.inputs, infer=True)
        self.assertIsNone(self.export()['batches'][0]['validation_code'])

    def test_insufficient_evidence_is_completed_not_operational_abstention(self):
        response = json.loads(self.response)
        response['findings'][0]['classification'] = 'insufficient_evidence'
        self.run_batch(response=r.json_bytes(response))
        report = r.e.evaluate(self.manifest, self.export()['attempts'], [])
        self.assertEqual(report['counts']['completed'], 2)
        self.assertEqual(report['counts']['abstained'], 0)

    def test_offline_analyst_output_cannot_be_imported_as_completed(self):
        self.run_batch(response=r.json_bytes({'status':'offline_context_only','findings':[]}))
        self.assertEqual(self.export()['attempts'][0]['status'],'rejected')

    def test_cleanup_failure_remains_failed_even_with_valid_output(self):
        self.run_batch(reason='WORKER_CLEANUP_FAILED', code=0)
        result = self.export()
        self.assertEqual(result['batches'][0]['reason'], 'WORKER_CLEANUP_FAILED')
        self.assertEqual(result['attempts'][0]['status'], 'failed')
        self.assertIsNone(result['attempts'][0]['prediction'])

    def test_timeouts_and_partial_output_remain_failures(self):
        self.run_batch(reason='DEADLINE_EXCEEDED', response=b'{partial', code=None)
        rows=self.export()['attempts']
        self.assertEqual(rows[0]['status'],'failed')
        self.assertIsNone(rows[0]['prediction'])
        self.assertEqual(rows[0]['latency_seconds'],.25)

    def test_export_requires_expected_manifest_hash(self):
        self.run_batch()
        with self.assertRaisesRegex(ValueError,'MANIFEST_HASH_MISMATCH'):
            r.export_attempts(self.base,'b'*64)

    def test_changed_input_context_or_output_bytes_refuse_export(self):
        self.run_batch()
        for name in ('alerts.jsonl','context.json','code.json','output.bin'):
            path=self.batch/name; before=path.read_bytes(); path.write_bytes(before+b' ')
            with self.subTest(name=name), self.assertRaises(ValueError): self.export()
            path.write_bytes(before)

    def test_changed_source_code_requires_original_revision_for_import(self):
        self.run_batch()
        with patch.object(r,'code_snapshot',return_value=b'changed'):
            with self.assertRaisesRegex(ValueError,'CONTEXT_OR_CODE_SNAPSHOT_MISMATCH'): self.export()

    def test_rehashed_forged_context_still_fails_reconstruction(self):
        self.run_batch()
        path=self.batch/'context.json'
        self.alter(path,lambda value:value['alerts'][0].update(rule_id='999999'))
        self.alter(self.batch/'intent.json',lambda value:value['artifact_sha256'].update(
            {'context.json':r.digest(path.read_bytes())}))
        with self.assertRaisesRegex(ValueError,'CONTEXT_OR_CODE_SNAPSHOT_MISMATCH'): self.export()

    def test_partial_terminal_is_corruption_not_interrupted_success(self):
        self.run_batch(); (self.batch/'terminal.json').write_bytes(b'{partial')
        with self.assertRaises(ValueError): self.export()

    def test_terminal_status_cannot_disagree_with_model_validation(self):
        self.run_batch()
        self.alter(self.batch/'terminal.json',lambda value:value.update(status='failed'))
        with self.assertRaisesRegex(ValueError,'TERMINAL_STATUS_MISMATCH'): self.export()

    def test_manifest_bytes_are_frozen_across_batches(self):
        self.run_batch()
        with self.assertRaisesRegex(ValueError,'STORE_MANIFEST_MISMATCH'):
            r.run_batch(self.base,self.manifest_bytes+b' ','batch-1',self.inputs,infer=True)

    def test_unexecuted_batch_remains_missing_in_full_denominator(self):
        manifest=copy.deepcopy(self.manifest)
        extra=copy.deepcopy(manifest['cases'][0])
        extra.update(case_id='not-run',batch_id='other',input_sha256='b'*64)
        manifest['cases'].append(extra)
        self.manifest=manifest; self.manifest_bytes=r.json_bytes(manifest)
        self.run_batch()
        imported=self.export()
        report=r.e.evaluate(manifest,imported['attempts'],[])
        self.assertEqual(report['counts']['completed'],2)
        self.assertEqual(report['counts']['missing'],1)

    def test_extra_store_entry_cannot_be_silently_ignored(self):
        self.run_batch(); (self.base/'unexpected').mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'UNEXPECTED_STORE_ENTRY'): self.export()

    def test_unexpected_batch_entry_refuses_export(self):
        self.run_batch()
        (self.batch/'unexpected').write_bytes(b'synthetic')
        with self.assertRaisesRegex(ValueError, 'UNEXPECTED_BATCH_ENTRY'): self.export()

    def test_orphan_output_must_still_be_private_regular_file(self):
        self.run_batch()
        (self.batch/'terminal.json').unlink()
        (self.batch/'output.bin').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'PRIVATE_REGULAR_ARTIFACT_REQUIRED'): self.export()

    def test_inventory_snapshot_reconstructs_at_preparation_time(self):
        at = r.datetime.now(r.timezone.utc).isoformat()
        inventory = {'schema_version': 1, 'as_of': at, 'assets': [
            {'manager': 'private-manager', 'agent_id': '001', 'os_family': 'linux',
             'os_version': '24.04', 'deployment': 'container', 'role': 'endpoint',
             'source_ref': 'NEVER-SEND-INVENTORY-SOURCE'}]}
        self.inputs['inventory.json'] = r.json_bytes(inventory)
        cfg = json.loads(self.inputs['configuration.json'])
        cfg['inventory_sha256'] = r.digest(self.inputs['inventory.json'])
        self.inputs['configuration.json'] = r.json_bytes(cfg)
        _, _, _, provenance = r.build_bundle(self.inputs, at)
        self.manifest['provenance'] = provenance
        self.manifest_bytes = r.json_bytes(self.manifest)
        self.run_batch()
        context = (self.batch/'context.json').read_text()
        self.assertNotIn('NEVER-SEND', context)
        self.assertNotIn('private-manager', context)
        self.assertEqual(json.loads(context)['inventory']['assets'][0]['os_family'], 'linux')
        # Export freshness is relative to recorded preparation, not today's date.
        with patch.object(r.k, 'datetime', wraps=r.datetime) as clock:
            clock.now.side_effect = AssertionError('must use stored preparation time')
            self.assertEqual(self.export()['attempts'][0]['status'], 'completed')
        path = self.batch/'inventory.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'ARTIFACT_HASH_MISMATCH'): self.export()

    def test_export_cli_attempts_only_feeds_evaluator(self):
        self.run_batch()
        command = [sys.executable, '-I', '-B', str(ROOT/'ai_agent/runner.py'), 'export',
                   '--store', str(self.base), '--manifest-sha256', r.digest(self.manifest_bytes)]
        full = subprocess.run(command, capture_output=True, timeout=5)
        array = subprocess.run(command + ['--attempts-only'], capture_output=True, timeout=5)
        self.assertEqual(full.returncode, 0, full.stderr)
        self.assertEqual(array.returncode, 0, array.stderr)
        self.assertEqual(json.loads(full.stdout)['attempts'], json.loads(array.stdout))
        self.assertEqual(r.e.evaluate(self.manifest, json.loads(array.stdout), [])['counts']['completed'], 2)

    def test_worker_transport_failure_has_no_provider_text(self):
        self.run_batch()
        out = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        err = io.StringIO()
        with patch.object(r.a.Ollama, '__call__', side_effect=ValueError('PRIVATE-PROVIDER')):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = r.worker(self.batch/'configuration.json', self.batch/'context.json')
        self.assertEqual(code, 2)
        self.assertEqual(out.buffer.getvalue(), b'')
        self.assertEqual(err.getvalue(), '')

    def test_import_never_calls_provider(self):
        self.run_batch()
        with patch.object(r.a.Ollama,'__call__',side_effect=AssertionError('network forbidden')):
            self.export()

    def test_config_and_model_descriptor_are_strict(self):
        for field,value in (('model',';shell'),('endpoint','http://10.0.0.1:11434'),
                            ('deadline_seconds',True),('language','other')):
            inputs=copy.deepcopy(self.inputs); cfg=json.loads(inputs['configuration.json']); cfg[field]=value
            inputs['configuration.json']=r.json_bytes(cfg)
            with self.subTest(field=field), self.assertRaises(ValueError):
                r.build_bundle(inputs,'2026-09-18T01:00:00Z')
        inputs=copy.deepcopy(self.inputs)
        inputs['model.json']=r.json_bytes({'schema_version':1,'name':'wrong','sha256':'a'*64})
        with self.assertRaisesRegex(ValueError,'MODEL_DESCRIPTOR_MISMATCH'):
            r.build_bundle(inputs,'2026-09-18T01:00:00Z')


class CLI(unittest.TestCase):
    def test_real_cli_signals_kill_worker_group_and_keep_failed_intent(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory(
                    dir=ROOT/'.git', prefix='runner-signal-') as directory:
                base = Path(directory)
                store = base/'store'; store.mkdir(mode=0o700)
                ready = base/'ready.json'
                manifest, inputs, _ = fixture(1)
                cfg = json.loads(inputs['configuration.json']); cfg['deadline_seconds'] = 10
                inputs['configuration.json'] = r.json_bytes(cfg)
                manifest['provenance'] = r.build_bundle(inputs, '2026-09-18T01:00:00Z')[3]
                manifest_bytes = r.json_bytes(manifest)
                (base/'manifest.json').write_bytes(manifest_bytes)
                args = ['run', '--store', str(store), '--manifest', str(base/'manifest.json'),
                        '--batch-id', 'batch-1', '--infer']
                mapping = {'alerts.jsonl':'alerts', 'rules.xml':'rules',
                           'configuration.json':'configuration', 'model.json':'model-record', 'rubric.txt':'rubric'}
                for name, value in inputs.items():
                    (base/name).write_bytes(value)
                    args += ['--'+mapping[name], str(base/name)]
                child_code = 'import time; time.sleep(30)'
                worker_code = (
                    'import os,sys,subprocess,time,json,pathlib\n'
                    f'p=subprocess.Popen([sys.executable,"-I","-B","-c",{child_code!r}])\n'
                    f'pathlib.Path({str(ready)!r}).write_text(json.dumps([os.getpid(),p.pid]))\n'
                    'time.sleep(30)\n')
                # Replace only the trusted worker command; execute real CLI signal handling.
                harness = (
                    'import subprocess,runpy,sys\nreal=subprocess.Popen\n'
                    'def launch(command,**kwargs):\n'
                    f' if "_worker" in command: command=[sys.executable,"-I","-B","-c",{worker_code!r}]\n'
                    ' return real(command,**kwargs)\n'
                    'subprocess.Popen=launch\n'
                    f'sys.argv={[str(ROOT/"ai_agent/runner.py"), *args]!r}\n'
                    f'runpy.run_path({str(ROOT/"ai_agent/runner.py")!r},run_name="__main__")\n')
                proc = subprocess.Popen([sys.executable, '-I', '-B', '-c', harness],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
                pids = []
                try:
                    end = time.monotonic() + 5
                    while time.monotonic() < end:
                        try:
                            pids = json.loads(ready.read_text())
                            break
                        except (FileNotFoundError, json.JSONDecodeError):
                            time.sleep(.01)
                    self.assertEqual(len(pids), 2, 'synthetic worker did not start')
                    proc.send_signal(sig)
                    out, err = proc.communicate(timeout=5)
                    self.assertEqual(proc.returncode, 130, err)
                    self.assertEqual(out, b'')
                    self.assertEqual(err, b'')
                    end = time.monotonic() + 2
                    for pid in pids:
                        while True:
                            try:
                                state = Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1].split()[0]
                            except FileNotFoundError:
                                break
                            if state == 'Z': break  # grandchild reaping belongs to its reaper
                            self.assertLess(time.monotonic(), end, 'worker descendant still running')
                            time.sleep(.01)
                    imported = r.export_attempts(store, r.digest(manifest_bytes))
                    self.assertEqual(imported['batches'][0]['reason'], 'INTERRUPTED_AFTER_INTENT')
                    self.assertEqual(imported['attempts'][0]['status'], 'failed')
                    self.assertIsNone(imported['attempts'][0]['latency_seconds'])
                finally:
                    if pids:
                        try: os.killpg(pids[0], signal.SIGKILL)
                        except ProcessLookupError: pass
                    if proc.poll() is None: proc.kill()
                    proc.communicate(timeout=5)

    def test_invalid_cli_files_do_not_leak_private_paths(self):
        out,err=io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            code=r.main(['export','--store',str(ROOT/'PRIVATE-NONEXISTENT'), '--manifest-sha256','a'*64])
        self.assertEqual(code,1); self.assertEqual(out.getvalue(),'')
        self.assertNotIn('PRIVATE',err.getvalue())

    def test_prepare_is_offline_with_matching_provenance(self):
        manifest,inputs,_=fixture(1)
        with tempfile.TemporaryDirectory(dir=ROOT/'.git',prefix='runner-cli-') as directory:
            command=[sys.executable,'-I','-B',str(ROOT/'ai_agent/runner.py'),'prepare']
            mapping={'alerts.jsonl':'alerts','rules.xml':'rules','configuration.json':'configuration',
                     'model.json':'model-record','rubric.txt':'rubric'}
            for name,value in inputs.items():
                path=Path(directory)/name; path.write_bytes(value)
                command+=['--'+mapping[name],str(path)]
            run=subprocess.run(command,capture_output=True,timeout=5)
        self.assertEqual(run.returncode,0,run.stderr)
        result=json.loads(run.stdout)
        self.assertFalse(result['inference_performed'])
        self.assertEqual(result['provenance'],manifest['provenance'])
        self.assertNotIn(b'NEVER-SEND',run.stdout)


if __name__ == '__main__':
    unittest.main()
