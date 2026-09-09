"""Purpose: safe T-15 regression tests; owner [ASTRA]; updated 2026-09-09.
Status: synthetic/local only. Sources: ISSUE-036, Wazuh 4.14 AR protocol.
Run: python3 -B -m unittest discover -s tests -p 'test_security.py' -v
No /var writes, live malware, networking, or destructive host operations.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


linux = load('linux_ar', 'wazuh/agents/linux/active-response/soc_ar.py')
windows = load('windows_ar', 'wazuh/agents/windows/active-response/soc_windows_ar.py')


class LinuxFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.git')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.allowed = self.root / 'monitored'
        self.allowed.mkdir()
        self.roots = (str(self.allowed),)
        self.file = self.allowed / 'file with spaces.txt'
        self.file.write_bytes(b'benign fixture')
        self.md5 = hashlib.md5(self.file.read_bytes()).hexdigest()

    def test_deletes_only_matching_regular_file(self):
        linux.remove_file(str(self.file), self.md5, self.roots)
        self.assertFalse(self.file.exists())

    def test_wrong_or_missing_hash_preserves_file(self):
        for digest in ('0' * 32, '', None, 'bad'):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                linux.remove_file(str(self.file), digest, self.roots)
            self.assertTrue(self.file.exists())

    def test_outside_prefix_and_traversal(self):
        for p in (str(self.root / 'outside'), str(self.allowed) + '-evil/file',
                  str(self.allowed) + '/../file', str(self.allowed) + '/./file',
                  str(self.allowed) + '//file', str(self.file) + '\nforged', '/etc/passwd'):
            with self.subTest(path=p), self.assertRaises(ValueError):
                linux.remove_file(p, self.md5, self.roots)
        self.assertTrue(self.file.exists())

    def test_symlink_leaf_and_parent_are_rejected(self):
        link = self.allowed / 'link'
        link.symlink_to(self.file)
        with self.assertRaises(OSError):
            linux.remove_file(str(link), self.md5, self.roots)
        parent = self.allowed / 'parent'
        parent.symlink_to(self.allowed, target_is_directory=True)
        with self.assertRaises(OSError):
            linux.remove_file(str(parent / self.file.name), self.md5, self.roots)
        self.assertTrue(self.file.exists())

    def test_hardlink_directory_fifo_and_missing(self):
        hard = self.allowed / 'hard'
        os.link(self.file, hard)
        with self.assertRaises(ValueError):
            linux.remove_file(str(hard), self.md5, self.roots)
        hard.unlink()
        directory = self.allowed / 'folder'
        directory.mkdir()
        fifo = self.allowed / 'fifo'
        os.mkfifo(fifo)
        for target in (directory, fifo):
            with self.assertRaises(ValueError):
                linux.remove_file(str(target), self.md5, self.roots)
        with self.assertRaises(FileNotFoundError):
            linux.remove_file(str(self.allowed / 'absent'), self.md5, self.roots)

    def test_file_size_bound(self):
        with patch.object(linux, 'MAX_FILE', 1), self.assertRaises(ValueError):
            linux.remove_file(str(self.file), self.md5, self.roots)

    def test_log_rejects_symlink(self):
        log = self.root / 'log'
        log.symlink_to(self.file)
        with patch.object(linux, 'LOG_FILE', log), self.assertRaises(OSError):
            linux.write_log('forged')
        self.assertEqual(self.file.read_bytes(), b'benign fixture')


class Protocol(unittest.TestCase):
    def event(self, command='add'):
        return {'command': command, 'parameters': {'alert': {
            'rule': {'id': '87105'}, 'agent': {'id': '002'},
            'data': {'virustotal': {'source': {
                'file': '/home/kali/SOCfile/test', 'md5': 'a' * 32}}}}}}

    def run_ar(self, text, mode='remove'):
        with patch.object(linux.sys, 'stdin', io.StringIO(text)), \
             contextlib.redirect_stdout(io.StringIO()) as out, \
             patch.object(linux, 'remove_file') as delete, \
             patch.object(linux, 'scan_file') as scan, \
             patch.object(linux, 'write_log'):
            result = linux.main(mode)
            return result, delete.call_count, scan.call_count, out.getvalue()

    def test_add_continue_only(self):
        result, deleted, _, out = self.run_ar(json.dumps(self.event()) + '\n{"command":"continue"}\n')
        self.assertEqual((result, deleted), (0, 1))
        self.assertEqual(json.loads(out)['parameters']['keys'][0], '002')

    def test_delete_abort_unknown_eof_never_delete(self):
        cases = [json.dumps(self.event('delete')) + '\n',
                 json.dumps(self.event()) + '\n{"command":"abort"}\n',
                 json.dumps(self.event('unexpected')) + '\n',
                 json.dumps(self.event()) + '\n', '', '[]\n', '{bad}\n',
                 'x' * 65537 + '\n']
        for case in cases:
            with self.subTest(case=case[:40]):
                _, delete, scan, _ = self.run_ar(case)
                self.assertEqual((delete, scan), (0, 0))

    def test_outside_root_rejected_before_handshake(self):
        event = self.event()
        event['parameters']['alert']['data']['virustotal']['source']['file'] = '/etc/passwd'
        code, count, _, out = self.run_ar(json.dumps(event) + '\n')
        self.assertEqual((code, count, out), (1, 0, ''))

    def test_yara_delete_and_arbitrary_arguments_rejected(self):
        code, _, scan, _ = self.run_ar('{"command":"delete"}\n', 'yara')
        self.assertEqual((code, scan), (0, 0))
        event = {'command': 'add', 'parameters': {'extra_args': ['-yara_path', '/tmp/evil'],
                 'alert': {'rule': {'id': '100301'}, 'syscheck': {'path': '/tmp/yara/malware/a'}}}}
        code, _, scan, _ = self.run_ar(json.dumps(event) + '\n', 'yara')
        self.assertEqual((code, scan), (1, 0))


class WindowsAndRouting(unittest.TestCase):
    def test_windows_path_guards(self):
        roots = (r'C:\Users\Lab\Downloads',)
        accepted = r'C:\Users\Lab\Downloads\a & b.txt'
        self.assertEqual(windows.validate_path(accepted, roots), accepted)
        for value in (r'C:\Users\Lab\DownloadsBad\a', r'C:\Users\Lab\Downloads\a:stream',
                      r'C:\Users\Lab\Downloads\..\a', r'\\server\share\a',
                      r'\\?\C:\Users\Lab\Downloads\a', r'C:\Users\Lab\Downloads\a.',
                      'C:\\Users\\Lab\\Downloads\\x\nline'):
            with self.subTest(path=value), self.assertRaises(ValueError):
                windows.validate_path(value, roots)
        with self.assertRaises(ValueError):
            windows.validate_path(accepted, ())

    def test_windows_eof_and_timeout(self):
        with self.assertRaises(ValueError):
            windows.read_message(io.StringIO(''))
        class SlowStream:
            def readline(self, _):
                import time
                time.sleep(0.05)
                return '{}\n'
        with self.assertRaises(queue.Empty):
            windows.read_message(SlowStream(), seconds=0.001)

    def test_one_local_dispatch_no_cross_agent_target(self):
        tree = ET.parse(ROOT / 'wazuh/manager/ossec.conf.d/30-active-response-remove-threat.xml')
        responses = tree.findall('active-response')
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0].findtext('location'), 'local')
        self.assertEqual(responses[0].findtext('rules_id'), '87105')
        self.assertIsNone(responses[0].find('agent_id'))
        self.assertEqual(tree.findtext('command/executable'), 'remove-threat.exe')

    def test_batch_does_not_parse_untrusted_stdin(self):
        text = (ROOT / 'wazuh/agents/windows/active-response/yara.bat').read_text()
        self.assertNotIn('%input%', text)
        self.assertNotIn('stdin.txt', text)
        self.assertNotIn('PowerShell -command', text)
        self.assertIn('DisableDelayedExpansion', text)


class LabScriptGuards(unittest.TestCase):
    def test_lab_scripts_reject_missing_opt_in_without_side_effects(self):
        for path in sorted((ROOT / 'scripts/attack-emulation').glob('*.sh')):
            result = subprocess.run(['bash', str(path)], cwd=ROOT, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2, path)
        for path in sorted((ROOT / 'scripts/lab').glob('*.sh')):
            result = subprocess.run(['bash', str(path)], cwd=ROOT, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 2, path)

    def test_invalid_network_targets_fail_before_network_command(self):
        for name in ('nmap_scan.sh', 'shellshock_test.sh'):
            for target in ('8.8.8.8', '--script=evil', '127.0.0.1', '10.0.0.1/24', '::1'):
                result = subprocess.run(['bash', str(ROOT / 'scripts/attack-emulation' / name),
                                         '--lab', target], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, (name, target))

    def test_embedded_python_compiles(self):
        import ast
        import re
        for path in (ROOT / 'scripts').rglob('*.sh'):
            for block in re.findall(r"<<'PY'\n(.*?)\nPY", path.read_text(), re.S):
                ast.parse(block, filename=str(path))

    def test_yara_decoder_preserves_spaces(self):
        import re
        text = (ROOT / 'wazuh/manager/decoders/local_decoder.xml').read_text()
        tree = ET.fromstring('<root>' + text + '</root>')
        regex = tree.find("decoder[@name='yara_decoder1']/regex").text
        match = re.search(regex, 'wazuh-yara: INFO - Scan result: Fixture C:\\Users\\Lab User\\x.txt')
        self.assertEqual(match.group(3), 'C:\\Users\\Lab User\\x.txt')


if __name__ == '__main__':
    unittest.main()
