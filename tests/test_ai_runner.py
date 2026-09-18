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

    def test_offline_analyst_output_cannot_be_imported_as_completed(self):
        self.run_batch(response=r.json_bytes({'status':'offline_context_only','findings':[]}))
        self.assertEqual(self.export()['attempts'][0]['status'],'rejected')

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
