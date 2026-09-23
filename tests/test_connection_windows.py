"""Synthetic Windows evidence; native CIM/NTFS acceptance is deliberately absent."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_connection_collect as f
from test_connection_measure import BASE, plan, alert

cc, w = f.cc, f.cc.w
IMAGE = {'path': r'C:\Program Files (x86)\ossec-agent\wazuh-agent.exe', 'sha256': 'b'*64}
PWSH = shutil.which('pwsh') or str(f.ROOT/'build/pwsh-7.4.13/pwsh')


def windows_plan():
    obj = plan(); obj['identity']['os'] = 'windows'; obj['clocks']['endpoint']['precision_ms'] = 1100
    for i, cycle in enumerate(obj['cycles']): cycle['target_path'] = rf'C:\SOC\cycle-{i}.txt'
    return obj


def native(p=None, at=BASE-5000, born=BASE-60000, pid=100):
    p = windows_plan() if p is None else p
    sample = {'service_name': 'WazuhSvc', 'service_state': 'Running', 'process_id': pid,
              'process_created_ticks': str(w.EPOCH_TICKS+born*10000), 'executable_path': IMAGE['path'],
              'image_sha256': IMAGE['sha256'], 'configured_image_matches': True}
    return {'schema_version': 1, 'producer': 'soc-windows-service-v1', 'capture_id': 'a'*32,
            'producer_sha256': cc.r.digest(cc.WINDOWS_PRODUCER.read_bytes()), 'plan_sha256': cc.r.digest(cc.r.json_bytes(p)),
            'run_id': p['run_id'], 'cycle_id': p['cycles'][0]['cycle_id'], 'clock_ref': p['clocks']['endpoint']['ref'],
            'hostname': p['identity']['agent_name'], 'expected_image_path': IMAGE['path'],
            'expected_image_sha256': IMAGE['sha256'], 'status': 'complete', 'samples': [sample, copy.deepcopy(sample)],
            'boot_before_ticks': str(w.EPOCH_TICKS+(BASE-3600000)*10000),
            'boot_after_ticks': str(w.EPOCH_TICKS+(BASE-3600000)*10000),
            'start_ms': at, 'end_ms': at+100, 'start_ticks': 100000000, 'end_ticks': 101000000,
            'tick_frequency': 10000000, 'acceptance_approved': False, 'authenticity_verified': False,
            'loaded_image_hash_verified': False}


def validate(obj, p=None, image=None):
    p = windows_plan() if p is None else p
    return w.validate(obj, p, 'cycle-0', cc.r.digest(cc.r.json_bytes(p)),
                      cc.r.digest(cc.WINDOWS_PRODUCER.read_bytes()), IMAGE if image is None else image)


class WindowsSchema(unittest.TestCase):
    def test_birth_identity_precision_and_nonverification(self):
        value, query = validate(native())
        self.assertEqual(value['started_ms'], BASE-60000); self.assertEqual(value['precision_ms'], 1000)
        self.assertTrue(value['running']); self.assertFalse(value['loaded_image_hash_verified'])
        self.assertEqual(query['end_monotonic_ms']-query['start_monotonic_ms'], 100)
        self.assertIn('not_service_readiness', value['start_semantics'])

    def test_pid_reuse_requires_birth_identity(self):
        a, _ = validate(native()); b, _ = validate(native(born=BASE-59000))
        self.assertNotEqual(a['instance'], b['instance'])

    def test_all_identity_bindings_are_strict(self):
        changes = {'producer': 'other', 'producer_sha256': 'c'*64, 'plan_sha256': 'c'*64,
                   'run_id': 'other', 'cycle_id': 'other', 'clock_ref': 'other', 'hostname': 'other',
                   'capture_id': 'bad', 'expected_image_sha256': 'c'*64}
        for key, value in changes.items():
            obj = native(); obj[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate(obj)

    def test_schema_types_and_nonverification_flags(self):
        for key, value in [('schema_version', True), ('tick_frequency', True), ('tick_frequency', 0),
                           ('start_ms', True), ('acceptance_approved', 0), ('authenticity_verified', True),
                           ('loaded_image_hash_verified', True), ('extra', None)]:
            obj = native(); obj[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate(obj)

    def test_service_stopped_wrong_name_pid_or_config_rejected(self):
        for key, value in [('service_name', 'other'), ('service_state', 'Stopped'), ('process_id', 0),
                           ('process_id', True), ('configured_image_matches', 1), ('image_sha256', 'd'*64)]:
            obj = native(); obj['samples'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): validate(obj)

    def test_missing_or_changed_process_sample_rejected(self):
        for count in (0, 1, 3):
            obj = native(); obj['samples'] = obj['samples'][:count] if count < 2 else obj['samples']+[obj['samples'][0]]
            with self.assertRaises(ValueError): validate(obj)
        obj = native(); obj['samples'][1]['process_id'] += 1
        with self.assertRaisesRegex(ValueError, 'PROCESS_CHANGED'): validate(obj)

    def test_boot_change_or_process_birth_before_boot_rejected(self):
        obj = native(); obj['boot_after_ticks'] = str(int(obj['boot_before_ticks'])+10000)
        with self.assertRaisesRegex(ValueError, 'BOOT_CHANGED'): validate(obj)
        obj = native(born=BASE-7200000)
        with self.assertRaisesRegex(ValueError, 'PROCESS_BINDING'): validate(obj)

    def test_future_birth_and_query_overrun_rejected(self):
        with self.assertRaisesRegex(ValueError, 'START_AFTER_SNAPSHOT'): validate(native(born=BASE+30000))
        obj = native(); obj['end_ticks'] = obj['start_ticks'] + 2001*10000
        with self.assertRaisesRegex(ValueError, 'QUERY_OVERRUN'): validate(obj)

    def test_wall_monotonic_clock_jump_rejected(self):
        obj = native(); obj['end_ms'] += 10000
        with self.assertRaisesRegex(ValueError, 'CLOCK_JUMP'): validate(obj)

    def test_tick_precision_is_exact_before_millisecond_conversion(self):
        obj = native(); obj['samples'][0]['process_created_ticks'] = str(int(obj['samples'][0]['process_created_ticks'])+1)
        with self.assertRaisesRegex(ValueError, 'PROCESS_CHANGED'): validate(obj)

    def test_windows_paths_reject_aliases_traversal_and_alternate_streams(self):
        for path in [r'\\server\share\wazuh-agent.exe', r'C:\x\..\wazuh-agent.exe', r'C:\x.\wazuh-agent.exe',
                     r'C:\x \wazuh-agent.exe', r'C:\x\wazuh-agent.exe:stream', r'C:\x\other.exe', r'C:\\wazuh-agent.exe']:
            with self.subTest(path=path), self.assertRaises(ValueError): w.image_path(path)

    def test_path_case_insensitivity_without_relaxing_host_binding(self):
        obj = native(); obj['samples'][1]['executable_path'] = IMAGE['path'].upper()
        self.assertTrue(validate(obj)[0]['running'])

    def test_failed_or_linux_evidence_rejected(self):
        obj = native(); obj['status'] = 'failed'
        with self.assertRaisesRegex(ValueError, 'INCOMPLETE'): validate(obj)
        p = windows_plan(); p['identity']['os'] = 'linux'
        with self.assertRaisesRegex(ValueError, 'BINDING'): validate(native(p), p)


class WindowsStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=f.ROOT, prefix='.windows-tests-'); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.store = self.base/'store'; self.store.mkdir(mode=0o700)
        self.p = windows_plan(); self.plan_raw = cc.r.json_bytes(self.p); self.image_raw = cc.r.json_bytes(IMAGE)
        self.raw = cc.r.json_bytes(native(self.p)); self.cid = 'cycle-0'

    def imported(self, raw=None, store=None):
        raw = self.raw if raw is None else raw
        return cc.import_windows(self.plan_raw, self.cid, raw, cc.r.digest(raw), self.image_raw, self.store if store is None else store)

    def export(self, result):
        return cc.export(self.store, result['intent_sha256'], self.plan_raw, self.cid, 'windowsservice')

    def test_private_store_replays_native_bytes(self):
        result = self.imported(); out = self.export(result)
        self.assertTrue(out['import_not_native_capture']); self.assertTrue(out['stored_bytes_verified'])
        self.assertFalse(out['authenticity_verified']); self.assertFalse(out['acceptance_approved'])
        self.assertEqual(out['native_payload_sha256'], cc.r.digest(self.raw))
        for path in self.store.iterdir(): self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_wrong_expected_hash_rejected_before_store_writes(self):
        with self.assertRaisesRegex(ValueError, 'RAW_HASH'):
            cc.import_windows(self.plan_raw, self.cid, self.raw, 'f'*64, self.image_raw, self.store)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_duplicate_keys_invalid_utf8_and_oversize_rejected(self):
        for raw in [b'{"schema_version":1,"schema_version":1}', b'\xff', b' '*(w.LIMIT+1)]:
            with self.assertRaises((ValueError, UnicodeError)): self.imported(raw)
            self.assertFalse((self.store/'intent.json').exists())

    def test_no_overwrite(self):
        self.imported()
        with self.assertRaisesRegex(ValueError, 'EMPTY_STORE'): self.imported()

    def test_partial_import_cannot_export(self):
        original = cc.r.write_once
        def write(fd, name, data):
            if name == 'windows.json': raise OSError('synthetic')
            return original(fd, name, data)
        with patch.object(cc.r, 'write_once', side_effect=write), self.assertRaises(OSError): self.imported()
        digest = cc.r.digest((self.store/'intent.json').read_bytes())
        with self.assertRaises((ValueError, OSError)):
            cc.export(self.store, digest, self.plan_raw, self.cid, 'windowsservice')

    def test_mutated_native_bytes_rejected(self):
        result = self.imported(); (self.store/'windows.json').write_bytes(self.raw+b' ')
        with self.assertRaisesRegex(ValueError, 'STORED_BYTES'): self.export(result)

    def test_mutated_image_spec_rejected(self):
        result = self.imported(); (self.store/'image.json').write_bytes(self.image_raw+b' ')
        with self.assertRaisesRegex(ValueError, 'STORED_BYTES'): self.export(result)

    def test_extra_entry_and_public_file_rejected(self):
        result = self.imported(); extra = self.store/'extra'; extra.write_bytes(b'x')
        with self.assertRaises(ValueError): self.export(result)
        extra.unlink(); (self.store/'windows.json').chmod(0o644)
        with self.assertRaises(ValueError): self.export(result)

    def test_changed_producer_or_validator_code_rejected(self):
        result = self.imported()
        with patch.object(cc, 'source_hashes', return_value={}), self.assertRaisesRegex(ValueError, 'PLAN_OR_CODE'): self.export(result)

    def test_boolean_terminal_count_rejected(self):
        result = self.imported(); path = self.store/'terminal.json'; obj = json.loads(path.read_bytes()); obj['count'] = True
        path.write_bytes(cc.r.json_bytes(obj))
        with self.assertRaisesRegex(ValueError, 'INCOMPLETE_CAPTURE'): self.export(result)

    def test_invalid_image_spec_or_wrong_platform_rejected(self):
        with self.assertRaises(ValueError):
            cc.import_windows(self.plan_raw, self.cid, self.raw, cc.r.digest(self.raw), b'{}', self.store)
        with self.assertRaises(ValueError):
            cc.import_windows(cc.r.json_bytes(plan()), self.cid, self.raw, cc.r.digest(self.raw), self.image_raw, self.store)

    def test_cli_import_and_export_private_inputs(self):
        def private(name, raw):
            path = self.base/name; path.write_bytes(raw); path.chmod(0o600); return str(path)
        args = ['import-windows', '--plan', private('plan.json', self.plan_raw), '--cycle', self.cid,
                '--input', private('native.json', self.raw), '--sha256', cc.r.digest(self.raw),
                '--image', private('image.json', self.image_raw), '--store', str(self.store)]
        with contextlib.redirect_stdout(io.StringIO()) as out: code = cc.main(args)
        self.assertEqual(code, 0); self.assertTrue(json.loads(out.getvalue())['import_not_native_capture'])

    def test_binding_service_stores_with_mocked_source_boundary(self):
        # Windows source capture is NOT implemented; only its export boundary is mocked.
        old = self.imported(); after = self.base/'after'; after.mkdir(mode=0o700)
        new_raw = cc.r.json_bytes(native(self.p, at=BASE+8000, born=BASE+3000, pid=200))
        new = self.imported(new_raw, after)
        polls = f.load('win_measure_fixture', f.ROOT/'tests/test_connection_measure.py').record()['polls']
        original = cc.export
        manager = {'path': str(self.base/'manager'), 'sha256': 'd'*64}
        def export(store, digest, raw, cid, kind):
            if kind == 'manager': return {'samples': polls}
            return original(store, digest, raw, cid, kind)
        event = {'run_id': self.p['run_id'], 'trial_id': self.cid, 'device': 'endpoint',
                 'clock_ref': self.p['clocks']['endpoint']['ref'], 'target_key': {'syscheck.path': self.p['cycles'][0]['target_path']},
                 'precision_ms': 1051, 'last_negative_start_ms': BASE+12000, 'timestamp_ms': BASE+13050}
        request = {'schema_version': 1, 'run_id': self.p['run_id'], 'cycle_id': self.cid,
                   'request_ms': BASE, 'command_end_ms': BASE+5000, 'controller_ref': 'synthetic'}
        before_desc = {'path': str(self.store), 'sha256': old['intent_sha256'], 'kind': 'windowsservice'}
        after_desc = {'path': str(after), 'sha256': new['intent_sha256'], 'kind': 'windowsservice'}
        with patch.object(cc, 'export', side_effect=export), patch.object(cc.s, 'export', return_value=event):
            row = cc.bind(self.plan_raw, cc.r.json_bytes(request), manager, before_desc, after_desc,
                          {'path': str(self.base/'source'), 'sha256': 'e'*64})
        raw_alert = alert(at=BASE+17000); raw_alert['syscheck']['path'] = self.p['cycles'][0]['target_path']
        result = cc.c.evaluate(self.p, [row], [(raw_alert, 'synthetic')])
        self.assertEqual(result['cycles'][0]['state'], 'FUNCTIONAL_EVIDENCE_WITHIN_WINDOW')
        self.assertFalse(result['acceptance_approved'])


@unittest.skipUnless(Path(PWSH).is_file(), 'PowerShell parser unavailable; native Windows acceptance still required')
class PowerShellProducer(unittest.TestCase):
    def run_ps(self, command):
        with tempfile.TemporaryDirectory(dir=f.ROOT, prefix='.pwsh-tests-') as temp:
            env = dict(os.environ, HOME=temp, DOTNET_CLI_HOME=temp, XDG_CACHE_HOME=temp, POWERSHELL_TELEMETRY_OPTOUT='1')
            return subprocess.run([PWSH, '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', command],
                                  cwd=f.ROOT, env=env, capture_output=True, text=True, timeout=20)

    def test_real_parser_and_read_only_command_structure(self):
        path = str(cc.WINDOWS_PRODUCER)
        command = "$tokens=$null;$errors=$null;$ast=[System.Management.Automation.Language.Parser]::ParseFile('"+path+"',[ref]$tokens,[ref]$errors); if($errors.Count){$errors;exit 1}; $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandAst]},$true) | ForEach-Object {$_.GetCommandName()} | ConvertTo-Json -Compress"
        out = self.run_ps(command); self.assertEqual(out.returncode, 0, out.stderr+out.stdout)
        names = json.loads(out.stdout)
        self.assertIn('Get-CimInstance', names)
        self.assertFalse(set(names) & {'Start-Service','Stop-Service','Restart-Service','Invoke-Expression','Invoke-Command','Set-Service'})

    def test_mocked_service_sample_executes_actual_function_bodies(self):
        path = str(cc.WINDOWS_PRODUCER)
        command = "$t=$null;$e=$null;$a=[System.Management.Automation.Language.Parser]::ParseFile('"+path+"',[ref]$t,[ref]$e); $a.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true) | ForEach-Object { . ([scriptblock]::Create($_.Extent.Text)) }; "
        command += "$ImagePath='C:\\SOC\\wazuh-agent.exe';$ImageSha256='"+'b'*64+"'; function Protected-ImageHash {return $ImageSha256}; function Get-CimInstance {param($ClassName,$Filter,$OperationTimeoutSec); if($ClassName -eq 'Win32_Service'){[pscustomobject]@{Name='WazuhSvc';State='Running';ProcessId=100;PathName=('\"'+$ImagePath+'\"')}}else{[pscustomobject]@{ExecutablePath=$ImagePath;CreationDate=[DateTime]'2026-09-23T01:00:03Z'}}}; Service-Sample | ConvertTo-Json -Compress"
        out = self.run_ps(command); self.assertEqual(out.returncode, 0, out.stderr+out.stdout)
        sample = json.loads(out.stdout); self.assertEqual(sample['process_id'], 100)
        self.assertEqual(sample['process_created_ticks'], str(w.EPOCH_TICKS+(BASE+3000)*10000))


if __name__ == '__main__':
    unittest.main()
