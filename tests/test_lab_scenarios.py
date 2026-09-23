"""UC-09/11 synthetic clients: never contact an endpoint or change firewall rules."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lab_scenarios_test', ROOT/'scripts/attack-emulation/lab_scenarios.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)


class Scenarios(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT/'.git', prefix='scenarios-')
        self.addCleanup(self.tmp.cleanup)
        self.known = Path(self.tmp.name)/'known_hosts'
        self.known.write_text('synthetic host pin, never used for network\n')

    def plan(self, kind='sqli'):
        value = s.plan(kind, '192.168.50.2', 80 if kind == 'sqli' else 22, 'TRIAL0001', self.known)
        if kind == 'ssh': value['known_hosts'] = str(self.known)
        return value

    def test_default_preview_is_offline(self):
        out = io.StringIO()
        with patch.object(s.subprocess, 'run') as run, contextlib.redirect_stdout(out):
            code = s.main(['sqli', '--target', '192.168.50.2', '--trial', 'TRIAL0001'])
        self.assertEqual(code, 0); run.assert_not_called()
        self.assertFalse(json.loads(out.getvalue())['network_performed'])

    def test_targets_are_literal_rfc1918_not_urls_or_hostnames(self):
        for ip in ('8.8.8.8', '127.0.0.1', '169.254.1.1', '::1', 'localhost', '192.168.1.1;id', 'http://10.0.0.1'):
            with self.subTest(ip=ip), self.assertRaises(ValueError): s.plan('sqli', ip, 80, 'TRIAL0001')

    def test_trial_and_port_bounds(self):
        for trial in ('bad', 'TRIAL/../', 'x'*25, 'TRIAL\n0001'):
            with self.assertRaises(ValueError): s.plan('sqli', '10.0.0.2', 80, trial)
        for port in (True, 0, 65536, '80'):
            with self.assertRaises(ValueError): s.plan('sqli', '10.0.0.2', port, 'TRIAL0001')

    def test_sqli_uses_fixed_non_destructive_signature_no_redirects(self):
        p = self.plan(); cmd = p['command']
        self.assertEqual(cmd[:2], ['/usr/bin/curl', '-q'])
        self.assertIn('union%20select%20null,null', cmd[-1])
        self.assertNotIn('--location', cmd); self.assertNotIn('--insecure', cmd)
        self.assertIn('--proxy', cmd); self.assertEqual(p['planned_attempts'], 1)
        self.assertNotIn('31104', p['expected_rule_candidates'])

    def test_ssh_disables_credentials_config_and_remote_commands(self):
        p = self.plan('ssh'); cmd = p['command']
        for option in ('StrictHostKeyChecking=yes', 'IdentityAgent=none', 'IdentityFile=none',
                       'PreferredAuthentications=none', 'PasswordAuthentication=no',
                       'ControlPath=none', 'GlobalKnownHostsFile=/dev/null'):
            self.assertIn(option, cmd)
        self.assertEqual(cmd[-1], '192.168.50.2')
        self.assertEqual(cmd[:4], ['/usr/bin/ssh', '-F', '/dev/null', '-N'])
        self.assertEqual(p['planned_attempts'], 12)

    def test_host_pin_is_required_and_symlink_or_writable_rejected(self):
        with self.assertRaises(ValueError): s.plan('ssh', '10.0.0.2', 22, 'TRIAL0001')
        alias = self.known.with_name('alias'); alias.symlink_to(self.known)
        with self.assertRaises(OSError): s.regular(alias)
        self.known.chmod(0o666)
        with self.assertRaises(ValueError): s.regular(self.known)

    def test_ssh_host_file_path_does_not_expand_tokens_or_multiple_files(self):
        for name in ('host file', 'hosts%h', 'hosts~', 'hosts"quoted'):
            p = self.known.with_name(name); p.write_text('synthetic')
            with self.subTest(name=name), self.assertRaises(ValueError): s.regular(p)

    def test_no_network_without_lab_optin(self):
        with patch.object(s.subprocess, 'run') as run:
            with self.assertRaises(ValueError): s.execute(self.plan())
            run.assert_not_called()

    def test_http_404_is_not_exploit_or_detection_proof(self):
        with patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'404')) as run:
            result = s.execute(self.plan(), lab=True)
        self.assertEqual(result['attempts'][0]['http_status'], 404)
        self.assertFalse(result['detection_verified']); self.assertFalse(result['response_verified'])
        self.assertNotIn('shell', run.call_args.kwargs)
        self.assertNotIn('HOME', run.call_args.kwargs['env'])

    def test_execute_reconstructs_argv_instead_of_trusting_plan(self):
        p = self.plan(); p['command'] = ['/bin/sh', '-c', 'untrusted']
        with patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'404')) as run:
            s.execute(p, lab=True)
        self.assertEqual(run.call_args.args[0][0], '/usr/bin/curl')

    def test_ssh_nonzero_exit_does_not_claim_authenticated_failure(self):
        with patch.object(s.subprocess, 'run', return_value=subprocess.CompletedProcess([], 255)), patch.object(s.time, 'sleep'):
            result = s.execute(self.plan('ssh'), lab=True)
        self.assertEqual(len(result['attempts']), 12)
        self.assertTrue(all(v['status'] == 'client_error' for v in result['attempts']))
        self.assertFalse(result['detection_verified'])

    def test_timeout_and_start_failure_are_reported(self):
        for error, status in ((subprocess.TimeoutExpired('synthetic', 6), 'client_timeout'),
                              (FileNotFoundError('private'), 'client_start_failed')):
            with patch.object(s.subprocess, 'run', side_effect=error):
                result = s.execute(self.plan(), lab=True)
            self.assertEqual(result['attempts'][0]['status'], status)
            self.assertNotIn('private', json.dumps(result))

    def test_deadline_retains_all_unlaunched_attempts(self):
        p = self.plan('ssh')
        with patch.object(s.time, 'monotonic', side_effect=[0]+[30]*20), patch.object(s.subprocess, 'run') as run:
            result = s.execute(p, lab=True)
        self.assertEqual(len(result['attempts']), 12); run.assert_not_called()
        self.assertTrue(all(v['status'] == 'not_launched_deadline' for v in result['attempts']))

    def test_ssh_response_requires_explicit_enable_and_separate_management(self):
        with self.assertRaises(ValueError): s.ssh_response(['10.0.0.1'], '10.0.0.2')
        with self.assertRaises(ValueError): s.ssh_response([], '10.0.0.2', enable=True)
        with self.assertRaises(ValueError): s.ssh_response(['10.0.0.2'], '10.0.0.2', enable=True)

    def test_ar_filters_are_not_or_broadened_and_native_command_not_duplicated(self):
        xml = s.ssh_response(['10.0.0.1'], '10.0.0.2', enable=True)
        root = ET.fromstring(xml); ar = root.find('active-response')
        self.assertEqual(ar.findtext('rules_id'), '5712,5763')
        self.assertEqual(ar.findtext('location'), 'local')
        self.assertEqual(ar.findtext('disabled'), 'no')
        self.assertEqual(ar.findtext('timeout'), '60')
        self.assertIsNone(ar.find('level')); self.assertIsNone(ar.find('rules_group'))
        self.assertIsNone(root.find('command'))
        self.assertIn('10.0.0.1', [v.text for v in root.findall('global/white_list')])

    def test_optional_ssh_collector_is_file_based_and_separate_from_apache(self):
        base = ROOT/'wazuh/agents/linux/ossec.conf.d'
        ssh = ET.parse(base/'60-localfile-sshd.xml').getroot().find('localfile')
        web = ET.parse(base/'30-localfile-apache.xml').getroot().find('localfile')
        self.assertEqual(ssh.findtext('location'), '/var/log/auth.log')
        self.assertEqual(ssh.findtext('log_format'), 'syslog')
        self.assertEqual(web.findtext('location'), '/var/log/apache2/access.log')

    def test_cli_errors_are_generic(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err): code = s.main(['sqli', '--target', 'PRIVATE_HOST', '--trial', 'TRIAL0001'])
        self.assertEqual(code, 1); self.assertNotIn('PRIVATE_HOST', err.getvalue())


if __name__ == '__main__':
    unittest.main()
