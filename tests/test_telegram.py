"""UC-10 custom-telegram integration tests (no network; mocked Telegram API)."""
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
import urllib.error

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'custom_telegram', ROOT / 'wazuh/manager/integrations/custom-telegram.py')
tg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tg)

TOKEN = '123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsawQ'   # format-valid fake
CHAT = '-1001234567890'
ALERT = {
    'timestamp': '2026-09-28T16:34:34.279+0000',
    'rule': {'id': '87105', 'level': 12, 'description': 'VirusTotal: Alert - /home/kali/SOCfile/x - 60 engines',
             'mitre': {'id': ['T1204.002']}},
    'agent': {'id': '001', 'name': 'kali1'},
    'data': {'virustotal': {'source': {'file': '/home/kali/SOCfile/x'}}},
    'full_log': 'user=kali password=hunter2 api_key=abcdef1234 <script>',
}


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Opener:
    def __init__(self, script):
        self.script, self.calls = list(script), []

    def __call__(self, req, timeout):
        self.calls.append((req.full_url, req.data.decode(), timeout))
        action = self.script.pop(0)
        if isinstance(action, Exception):
            raise action
        return FakeResp(json.dumps(action).encode())


def http_error(code, body=b'{}'):
    return urllib.error.HTTPError('u', code, 'x', {}, io.BytesIO(body))


class Telegram(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.alert = self.dir / 'alert.json'
        self.alert.write_text(json.dumps(ALERT))
        self.state = str(self.dir / 'state.json')
        self.logs = []
        self._log, tg.log = tg.log, self.logs.append

    def tearDown(self):
        tg.log = self._log
        self.tmp.cleanup()

    def run_main(self, opener, alert=None):
        path = alert or str(self.alert)
        return tg.main(['x', path, TOKEN, CHAT], opener=opener, sleep=lambda s: None, state_file=self.state)

    def test_success_payload(self):
        op = Opener([{'ok': True}])
        self.assertEqual(self.run_main(op), 0)
        url, body, timeout = op.calls[0]
        self.assertIn('/bot' + TOKEN + '/sendMessage', url)
        self.assertEqual(timeout, tg.TIMEOUT)
        self.assertIn('parse_mode=HTML', body)
        self.assertIn('87105', body)

    def test_redaction_and_html_escape(self):
        text = tg.build_message(ALERT)
        self.assertNotIn('hunter2', text)
        self.assertNotIn('abcdef1234', text)
        self.assertIn('[REDACTED]', text)
        self.assertNotIn('<script>', text)
        self.assertIn('&lt;script&gt;', text)
        self.assertLessEqual(len(tg.build_message(dict(ALERT, full_log='A' * 20000))), tg.MAX_TEXT)

    def test_token_never_logged_on_failure(self):
        op = Opener([http_error(401)])
        self.assertEqual(self.run_main(op), 8)
        self.assertEqual(len(op.calls), 1)          # 4xx: no pointless retries
        self.assertFalse(any(TOKEN in line for line in self.logs))

    def test_retry_then_success(self):
        op = Opener([urllib.error.URLError('down'), TimeoutError(), {'ok': True}])
        self.assertEqual(self.run_main(op), 0)
        self.assertEqual(len(op.calls), 3)

    def test_rate_limit_429_honoured(self):
        waits = []
        op = Opener([http_error(429, b'{"parameters":{"retry_after":3}}'), {'ok': True}])
        rc = tg.main(['x', str(self.alert), TOKEN, CHAT], opener=op, sleep=waits.append, state_file=self.state)
        self.assertEqual(rc, 0)
        self.assertIn(3, waits)

    def test_bounded_attempts(self):
        op = Opener([urllib.error.URLError('x')] * 5)
        self.assertEqual(self.run_main(op), 8)
        self.assertEqual(len(op.calls), tg.ATTEMPTS)

    def test_dedup_within_window(self):
        op = Opener([{'ok': True}, {'ok': True}])
        self.assertEqual(self.run_main(op), 0)
        self.assertEqual(self.run_main(op), 0)
        self.assertEqual(len(op.calls), 1)

    def test_dedup_distinguishes_objects(self):
        other = self.dir / 'b.json'
        a2 = json.loads(json.dumps(ALERT))
        a2['data']['virustotal']['source']['file'] = '/home/kali/SOCfile/y'
        other.write_text(json.dumps(a2))
        op = Opener([{'ok': True}, {'ok': True}])
        self.run_main(op)
        self.run_main(op, str(other))
        self.assertEqual(len(op.calls), 2)

    def test_bad_arguments(self):
        op = Opener([])
        self.assertEqual(tg.main(['x'], opener=op), 2)
        self.assertEqual(tg.main(['x', str(self.alert), 'YOUR_TELEGRAM_BOT_TOKEN', CHAT], opener=op), 2)
        self.assertEqual(tg.main(['x', str(self.alert), TOKEN, 'not a chat'], opener=op), 2)
        self.assertEqual(op.calls, [])

    def test_missing_and_invalid_alert(self):
        op = Opener([])
        self.assertEqual(self.run_main(op, str(self.dir / 'nope.json')), 6)
        bad = self.dir / 'bad.json'
        bad.write_text('{not json')
        self.assertEqual(self.run_main(op, str(bad)), 7)

    def test_config_has_no_real_secret(self):
        text = (ROOT / 'wazuh/manager/ossec.conf.d/60-integration-telegram.xml').read_text()
        self.assertIsNone(tg.TOKEN_RE.search(text.replace('<', ' ').replace('>', ' ')))
        self.assertIn('<level>12</level>', text)


if __name__ == '__main__':
    unittest.main()
