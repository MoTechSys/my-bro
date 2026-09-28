"""Rule tests executed by the REAL Wazuh analysis engine (wazuh-logtest socket).

Why: XML well-formedness (validate_all.sh) cannot prove that a rule fires.
On 2026-09-28 these tests found four defects that syntax checks missed
(see CHANGELOG / ISSUE-063..066).

Run on a host with wazuh-manager 4.14.x and the repo rules deployed:
    sudo bash scripts/lab/deploy_manager_local.sh      # copies rules/decoders/lists
    sudo python3 -m pytest tests/test_wazuh_engine.py -v
Without the logtest socket every test is skipped (not failed), so the pure
unit suite still runs anywhere.
"""
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import wazuh_logtest_client as lt  # noqa: E402

APACHE = '/var/log/apache2/access.log'
AR_LOG = '/var/ossec/logs/active-responses.log'


def apache_line(request, status=200, agent='curl/8.0'):
    return (f'192.168.100.20 - - [28/Sep/2026:10:00:00 +0000] "{request} HTTP/1.1" '
            f'{status} 512 "-" "{agent}"')


def ps_output(*commands):
    lines = ["ossec: output: 'process list':", '    PID USER     COMMAND',
             '      1 root     /sbin/init']
    lines += [f'   {2000 + i} kali     {cmd}' for i, cmd in enumerate(commands)]
    return '\n'.join(lines)


def audit_exec(argv, exe):
    args = ' '.join(f'a{i}="{a}"' for i, a in enumerate(argv))
    stamp = 'audit(1790600000.123:456)'
    return (f'type=SYSCALL msg={stamp}: arch=c000003e syscall=59 success=yes exit=0 '
            f'a0=55d a1=55d a2=55d a3=0 items=2 ppid=1000 pid=2001 auid=1000 uid=1000 '
            f'gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 '
            f'tty=pts0 ses=1 comm="{argv[0]}" exe="{exe}" subj=unconfined key="audit-wazuh-c" '
            f'type=EXECVE msg={stamp}: argc={len(argv)} {args} '
            f'type=CWD msg={stamp}: cwd="/home/kali" '
            f'type=PATH msg={stamp}: item=0 name="{exe}" inode=1 dev=08:01 mode=0100755 '
            f'ouid=0 ogid=0 rdev=00:00 nametype=NORMAL')


def ar_log(result, path='/home/kali/SOCfile/eicar_1.com', prefix='active-response/bin/remove-threat.exe'):
    message = {'version': 1, 'origin': {'name': 'node01', 'module': 'wazuh-execd'},
               'command': 'add', 'parameters': {'extra_args': [], 'program': prefix,
               'alert': {'rule': {'id': '87105'}, 'data': {'virustotal': {'source': {
                   'file': path, 'md5': '44d88612fea8a8f36de82e1278abb02f'}}}}}}
    return f'2026/09/28 10:00:00 {prefix}: {json.dumps(message)} {result}'


@unittest.skipUnless(lt.available(), 'Wazuh logtest socket not available (needs wazuh-manager + root)')
class EngineRules(unittest.TestCase):
    def assertRule(self, expected, event, fmt='syslog', location='/var/log/test'):
        rid, out, _ = lt.rule_id(event, fmt, location)
        self.assertEqual(rid, expected, f'got {rid} ({out.get("rule", {}).get("description")})')
        return out

    def assertNotRule(self, forbidden, event, fmt='syslog', location='/var/log/test'):
        rid, out, _ = lt.rule_id(event, fmt, location)
        self.assertNotEqual(rid, forbidden, f'false positive: {out.get("rule", {}).get("description")}')

    # ---------- UC-03 AR result must be decoded by built-in ar_log_json ----------
    def test_uc03_ar_success_100092(self):
        out = self.assertRule('100092', ar_log('Successfully removed threat'), location=AR_LOG)
        self.assertEqual(out['rule']['level'], 12)
        self.assertIn('/home/kali/SOCfile/eicar_1.com', out['rule']['description'])

    def test_uc03_ar_error_100093(self):
        self.assertRule('100093', ar_log('Error removing threat: current file does not match alerted hash'),
                        location=AR_LOG)

    def test_uc03_old_prefix_is_not_decoded_regression(self):
        # Pre-2026-09-28 soc_ar.py wrote "remove-threat:" -> no decoder -> no alert.
        rid, _, _ = lt.rule_id(ar_log('Successfully removed threat', prefix='remove-threat'),
                               'syslog', AR_LOG)
        self.assertIsNone(rid)

    def test_uc03_soc_ar_writes_decodable_prefix(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        sys.path.insert(0, str(root / 'wazuh/agents/linux/active-response'))
        import soc_ar
        self.assertTrue(soc_ar.AR_LOG_PREFIX.startswith('active-response/bin/'))
        self.assertRule('100092', ar_log('Successfully removed threat', prefix=soc_ar.AR_LOG_PREFIX),
                        location=AR_LOG)

    # ---------- UC-04 Suricata ----------
    def test_uc04_suricata_86601(self):
        eve = {'timestamp': '2026-09-28T10:00:00.000000+0000', 'event_type': 'alert',
               'src_ip': '192.168.100.30', 'src_port': 50000, 'dest_ip': '192.168.100.20',
               'dest_port': 22, 'proto': 'TCP', 'alert': {'action': 'allowed', 'gid': 1,
               'signature_id': 2001219, 'rev': 20, 'signature': 'ET SCAN Potential SSH Scan',
               'category': 'Attempted Information Leak', 'severity': 2}}
        self.assertRule('86601', json.dumps(eve), 'json', '/var/log/suricata/eve.json')

    # ---------- UC-05 auditd + CDB ----------
    def test_uc05_red_command_100210(self):
        out = self.assertRule('100210', audit_exec(['nc', '-lvp', '4444'], '/usr/bin/nc'),
                              'audit', '/var/log/audit/audit.log')
        self.assertEqual(out['rule']['level'], 12)

    def test_uc05_yellow_command_not_red(self):
        self.assertNotRule('100210', audit_exec(['whoami'], '/usr/bin/whoami'),
                           'audit', '/var/log/audit/audit.log')

    def test_uc05_benign_command_not_red(self):
        self.assertNotRule('100210', audit_exec(['ls', '-la'], '/usr/bin/ls'),
                           'audit', '/var/log/audit/audit.log')

    # ---------- UC-06 Shellshock ----------
    def test_uc06_shellshock_31168(self):
        out = self.assertRule('31168', apache_line('GET /cgi-bin/status', agent='() { :; }; /bin/cat /etc/passwd'),
                              'apache', APACHE)
        self.assertEqual(out['rule']['level'], 15)

    def test_uc06_normal_request_quiet(self):
        rid, _, _ = lt.rule_id(apache_line('GET /index.html'), 'apache', APACHE)
        self.assertIn(rid, (None, '31100', '31108'))

    # ---------- UC-07 YARA ----------
    def test_uc07_yara_108001(self):
        out = self.assertRule('108001', 'wazuh-yara: INFO - Scan result: EICAR_test_file /tmp/yara/malware/e.com',
                              location=AR_LOG)
        self.assertEqual(out['data']['yara_rule'], 'EICAR_test_file')
        self.assertEqual(out['data']['yara_scanned_file'], '/tmp/yara/malware/e.com')

    def test_uc07_yara_audit_line_not_positive(self):
        self.assertNotRule('108001', 'wazuh-yara: AUDIT - {"event": "scan_complete", "matches": 0}',
                           location=AR_LOG)

    # ---------- UC-08 Netcat listener (variants found missing on 2026-09-28) ----------
    def test_uc08_listener_variants(self):
        for cmd in ('nc -l -p 8000', 'nc -lvp 4444', 'nc -nlvp 4444', 'ncat -l 4444',
                    'ncat --listen 4444', '/usr/bin/nc -l 9001', 'nc.traditional -l -p 5555',
                    'netcat -lp 31337', 'nc -k -l 7000'):
            with self.subTest(cmd=cmd):
                out = self.assertRule('100051', ps_output(cmd), 'full_command', 'process list')
                self.assertEqual(out['rule']['level'], 7)

    def test_uc08_non_listener_not_flagged(self):
        for cmd in ('nc 192.168.100.5 4444', 'rsync -l a b', 'vncserver -localhost',
                    'tail -f /var/log/syslog', 'sync -l', 'ncdu /home'):
            with self.subTest(cmd=cmd):
                self.assertNotRule('100051', ps_output(cmd), 'full_command', 'process list')

    # ---------- UC-09 SQL injection (needs log_format apache, ISSUE-059) ----------
    def test_uc09_sqli_attempt_31103(self):
        for status in (404, 500):
            with self.subTest(status=status):
                self.assertRule('31103', apache_line('GET /item.php?id=1%20union%20select%201,2', status),
                                'apache', APACHE)

    def test_uc09_sqli_success_31106(self):
        self.assertRule('31106', apache_line('GET /item.php?id=1%20union%20select%201,2', 200),
                        'apache', APACHE)

    # ---------- UC-11 SSH brute force -> 5712 / 5763 (AR triggers) ----------
    # Verified 2026-09-28: 8 failures for an INVALID user -> 5710 x7 then 5712;
    # for a VALID user -> 5760 x7 then 5763. Binding AR to 5763 only (old plan)
    # would never block a dictionary attack on non-existent users (ISSUE-067).
    def _burst(self, user_phrase, ip, base_port):
        token, fired = None, []
        for i in range(8):
            event = (f'Sep 28 10:00:{10 + i:02d} kali1 sshd[{3000 + i}]: Failed password for '
                     f'{user_phrase} from {ip} port {base_port + i} ssh2')
            rid, _, token = lt.rule_id(event, 'syslog', '/var/log/auth.log', token)
            fired.append(rid)
        return fired

    def test_uc11_invalid_user_burst_fires_5712(self):
        fired = self._burst('invalid user admin', '192.168.100.66', 40000)
        self.assertEqual(fired[-1], '5712', fired)

    def test_uc11_valid_user_burst_fires_5763(self):
        fired = self._burst('root', '192.168.100.67', 41000)
        self.assertEqual(fired[-1], '5763', fired)

    def test_uc11_ar_config_covers_both_triggers(self):
        import xml.etree.ElementTree as ET
        root = pathlib.Path(__file__).resolve().parents[1]
        tree = ET.parse(root / 'wazuh/manager/ossec.conf.d/50-active-response-firewall-drop.xml')
        ids = {x.strip() for x in tree.findtext('active-response/rules_id').split(',')}
        self.assertTrue({'5712', '5763'} <= ids, ids)

if __name__ == '__main__':
    unittest.main()
