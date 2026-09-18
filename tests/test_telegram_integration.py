"""Private notification regressions. Synthetic credentials; never contact Telegram."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('telegram_tests', ROOT/'wazuh/manager/integrations/custom-telegram.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)


def config():
    return {'schema_version': 1, 'enabled': True, 'bot_token': '123456:synthetic_not_a_real_bot_token',
            'chat_id': '-123456789', 'hmac_key': 'a'*64, 'min_level': 12,
            'max_per_hour': 3, 'max_total_attempts': 10}


def alert():
    return {'id': 'private-event', 'manager': {'name': 'private-manager'},
            'agent': {'id': '001', 'name': 'private-host'}, 'timestamp': '2026-09-18T07:00:00Z',
            'rule': {'id': '100210', 'level': 12, 'description': 'PRIVATE DESCRIPTION'},
            'full_log': 'PRIVATE LOG https://private.invalid', 'data': {'srcip': '10.0.0.5'},
            'syscheck': {'path': '/private/filename'}}


class Notification(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT/'.git', prefix='telegram-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.store = self.base/'store'; self.store.mkdir(mode=0o700)
        self.cfg = config(); self.row = alert()
        self.config_file = self.base/'config.json'
        self.config_file.write_bytes(t.encoded(self.cfg)); self.config_file.chmod(0o600)

    def send(self, status='sent'):
        with patch.object(t, 'bounded_send', return_value=status):
            return t.deliver(self.row, self.cfg, self.store, send=True)

    def test_config_private_roundtrip(self):
        self.assertEqual(t.load_config(self.config_file), self.cfg)

    def test_config_rejects_unknown_fields_and_invalid_values(self):
        for key, value in [('extra', True), ('enabled', 1), ('min_level', 11), ('max_per_hour', 61),
                           ('max_total_attempts', 1001), ('bot_token', 'token/redirect'),
                           ('chat_id', '@publicname'), ('hmac_key', 'weak')]:
            cfg = config(); cfg[key] = value
            self.config_file.write_bytes(t.encoded(cfg))
            with self.subTest(key=key), self.assertRaises(ValueError): t.load_config(self.config_file)

    def test_strict_json_rejects_duplicate_nonfinite_and_overflow(self):
        for value in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'):
            with self.assertRaises(ValueError): t.strict_json(value)

    def test_private_config_rejects_public_mode_symlink_and_hardlink(self):
        self.config_file.chmod(0o644)
        with self.assertRaises(ValueError): t.load_config(self.config_file)
        self.config_file.chmod(0o600)
        alias = self.base/'alias'; alias.symlink_to(self.config_file)
        with self.assertRaises(OSError): t.load_config(alias)
        hard = self.base/'hard'; os.link(self.config_file, hard)
        with self.assertRaises(ValueError): t.load_config(self.config_file)

    def test_private_store_rejects_writable_ancestor(self):
        self.base.chmod(0o770)
        with self.assertRaises(ValueError): t.private_dir(self.store)
        self.base.chmod(0o700)

    def test_projection_never_sends_raw_free_text_identity_or_ips(self):
        item = t.project(self.row, self.cfg)
        for marker in ('PRIVATE', 'private-', '10.0.0.5', '/private/', '001', 'synthetic_not'):
            self.assertNotIn(marker, item['message'])
        self.assertIn('100210', item['message']); self.assertIn('Level: 12', item['message'])
        self.assertLess(len(item['message']), 4096)
        self.assertEqual(t.project(self.row, self.cfg), item)

    def test_hmac_aliases_change_with_key_and_manager(self):
        first = t.project(self.row, self.cfg)
        cfg = config(); cfg['hmac_key'] = 'b'*64
        self.assertNotEqual(first['event'], t.project(self.row, cfg)['event'])
        self.row['manager']['name'] = 'another-manager'
        self.assertNotEqual(first['event'], t.project(self.row, self.cfg)['event'])

    def test_below_threshold_has_no_network_or_store_writes(self):
        self.row['rule']['level'] = 11
        with patch.object(t, 'bounded_send') as send:
            result = t.deliver(self.row, self.cfg, self.store, send=True)
        send.assert_not_called(); self.assertEqual(result['status'], 'filtered')
        self.assertEqual(list(self.store.iterdir()), [])

    def test_invalid_level_timestamp_or_required_identity_rejected(self):
        for field, value in [('level', True), ('level', 17), ('id', 'x;id')]:
            row = alert(); row['rule'][field] = value
            with self.assertRaises(ValueError): t.project(row, self.cfg)
        self.row['timestamp'] = '2026-09-18T07:00:00'
        with self.assertRaises(ValueError): t.project(self.row, self.cfg)

    def test_preview_and_disabled_never_launch_or_write(self):
        with patch.object(t, 'bounded_send') as send:
            self.assertEqual(t.deliver(self.row, self.cfg, self.store)['status'], 'preview')
            self.cfg['enabled'] = False
            self.assertEqual(t.deliver(self.row, self.cfg, self.store, send=True)['status'], 'preview')
        send.assert_not_called(); self.assertEqual(list(self.store.iterdir()), [])

    def test_durable_intent_precedes_network_and_is_private(self):
        def send(cfg, message, store_fd):
            self.assertEqual(os.fstat(store_fd).st_ino, self.store.stat().st_ino)
            files = list(self.store.glob('*.intent.json'))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
            self.assertNotIn('private', files[0].read_text())
            return 'sent'
        with patch.object(t, 'bounded_send', side_effect=send):
            result = t.deliver(self.row, self.cfg, self.store, send=True)
        self.assertTrue(result['delivery_confirmed'])
        self.assertEqual(len(list(self.store.iterdir())), 2)

    def test_duplicate_never_resends(self):
        self.send()
        with patch.object(t, 'bounded_send') as send:
            result = t.deliver(self.row, self.cfg, self.store, send=True)
        self.assertEqual(result['status'], 'duplicate_suppressed'); send.assert_not_called()
        self.assertFalse(result['delivery_confirmed'])

    def test_changed_content_same_event_identity_fails_closed(self):
        self.send(); self.row['full_log'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'EVENT_ID_CONFLICT'): self.send()

    def test_unknown_delivery_never_automatically_retries(self):
        self.assertEqual(self.send('unknown')['status'], 'unknown')
        self.assertEqual(self.send()['status'], 'duplicate_suppressed')

    def test_interrupted_intent_suppresses_uncertain_resend(self):
        with patch.object(t, 'bounded_send', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): t.deliver(self.row, self.cfg, self.store, send=True)
        self.assertEqual(self.send()['status'], 'duplicate_suppressed')

    def test_partial_record_refuses_network(self):
        self.send(); path = next(self.store.glob('*.intent.json')); path.write_bytes(b'{partial')
        with patch.object(t, 'bounded_send') as send:
            with self.assertRaises(ValueError): t.deliver(self.row, self.cfg, self.store, send=True)
            send.assert_not_called()

    def test_hourly_quota_counts_failed_attempts(self):
        self.cfg['max_per_hour'] = 1
        self.send('unknown'); self.row['id'] = 'different'
        self.assertEqual(self.send()['status'], 'rate_limited')
        self.assertEqual(len(list(self.store.glob('*.intent.json'))), 1)

    def test_total_cap_does_not_expire_or_silently_drop_old_records(self):
        self.cfg['max_total_attempts'] = 1
        with patch.object(t.time, 'time', return_value=1): self.send()
        self.row['id'] = 'different'
        with patch.object(t.time, 'time', return_value=10000): self.assertEqual(self.send()['status'], 'rate_limited')

    def test_backward_clock_refuses_new_send(self):
        with patch.object(t.time, 'time', return_value=100): self.send()
        self.row['id'] = 'different'
        with patch.object(t.time, 'time', return_value=99), self.assertRaisesRegex(ValueError, 'CLOCK_MOVED_BACKWARD'):
            self.send()

    def test_lock_refuses_concurrent_invocation(self):
        fd = t.private_dir(self.store)
        try:
            t.fcntl.flock(fd, t.fcntl.LOCK_EX | t.fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): self.send()
        finally: os.close(fd)

    def test_unexpected_entry_and_orphan_terminal_fail_closed(self):
        p = self.store/'unexpected'; p.write_bytes(b'bad')
        with self.assertRaises(ValueError): self.send()
        p.unlink()
        p = self.store/('a'*64+'.terminal.json'); p.write_bytes(t.encoded({'status':'sent'})); p.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'ORPHAN_TERMINAL'): self.send()

    def test_fsync_failure_never_calls_network(self):
        with patch.object(t.os, 'fsync', side_effect=OSError('private')), patch.object(t, 'bounded_send') as send:
            with self.assertRaises(OSError): t.deliver(self.row, self.cfg, self.store, send=True)
            send.assert_not_called()

    def test_native_abi_rejects_secrets_and_hook_urls(self):
        err = io.StringIO()
        with patch.object(t, 'run') as run, contextlib.redirect_stderr(err):
            self.assertEqual(t.main(['alert.json', 'PRIVATE_TOKEN', 'https://other.invalid']), 1)
        run.assert_not_called(); self.assertNotIn('PRIVATE_TOKEN', err.getvalue())

    def test_native_abi_uses_fixed_private_config(self):
        with patch.object(t, 'run', return_value={'status':'filtered'}) as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(t.main(['alert.json', '', '']), 0)
        run.assert_called_once_with('alert.json', t.CONFIG, t.STORE, True)

    def test_native_full_4141_abi_and_literal_redirection(self):
        for tail in ([], ['>', '/dev/null 2>&1'], ['>', '/dev/null', '2>&1']):
            args = ['alert.json', '', '', '', '', '10', '3'] + tail
            with patch.object(t, 'run', return_value={'status':'filtered'}) as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(t.main(args), 0)
            run.assert_called_once_with('alert.json', t.CONFIG, t.STORE, True)
        t.native_args(['alert.json', '', '', 'debug', '', '10', '3'])

    def test_native_options_or_extra_commands_rejected(self):
        for args in (['a', '', '', '', '/tmp/options', '10', '3'],
                     ['a', '', '', '', '', '10', '3', ';id'],
                     ['a', '', '', '', '', '-1', '3'],
                     ['a', '', '', 'private', '', '10', '3']):
            with self.assertRaises(ValueError): t.native_args(args)

    def test_alert_fifo_and_symlink_rejected(self):
        fifo = self.base/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): t.alert_file(fifo)
        link = self.base/'link'; link.symlink_to(self.config_file)
        with self.assertRaises(OSError): t.alert_file(link)

    def test_integration_xml_has_only_level_filter_and_no_credentials(self):
        import xml.etree.ElementTree as ET
        value = ET.parse(ROOT/'wazuh/manager/ossec.conf.d/60-integration-telegram.xml').getroot().find('integration')
        self.assertEqual(value.findtext('name'), 'custom-telegram.py')
        self.assertEqual(value.findtext('level'), '12')
        self.assertEqual(value.findtext('alert_format'), 'json')
        self.assertIsNone(value.find('api_key')); self.assertIsNone(value.find('hook_url'))
        self.assertIsNone(value.find('options'))

    def test_cli_preview_subprocess_is_offline(self):
        path = self.base/'alert.json'; path.write_bytes(t.encoded(self.row))
        result = subprocess.run([os.sys.executable, '-I', '-B', str(ROOT/'wazuh/manager/integrations/custom-telegram.py'),
                                 '--alert', str(path), '--config', str(self.config_file)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'preview')
        self.assertEqual(list(self.store.iterdir()), [])


class Transport(unittest.TestCase):
    def response(self, raw, status=200):
        class Response(io.BytesIO): pass
        value = Response(raw); value.status = status
        return value

    def test_tls_fixed_endpoint_no_proxy_redirect_or_parse_mode(self):
        cfg = config()
        response = self.response(t.encoded({'ok':True, 'result':{'message_id':1, 'chat':{'id':int(cfg['chat_id'])}}}))
        with patch.object(t.urllib.request, 'build_opener') as build:
            build.return_value.open.return_value = response
            self.assertEqual(t.send_http(cfg, 'synthetic'), 'sent')
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], t.NoRedirect)
        request = build.return_value.open.call_args.args[0]
        self.assertTrue(request.full_url.startswith('https://api.telegram.org/bot'))
        payload = json.loads(request.data)
        self.assertNotIn('parse_mode', payload)
        self.assertTrue(payload['protect_content'])
        self.assertTrue(payload['link_preview_options']['is_disabled'])

    def test_errors_truncated_response_false_ok_and_wrong_chat_are_unknown(self):
        values = [b'private error', b'x'*16385, b'[]', t.encoded({'ok':False}),
                  t.encoded({'ok':True, 'result':{'message_id':1,'chat':{'id':123}}})]
        for raw in values:
            with self.subTest(size=len(raw)), patch.object(t.urllib.request, 'build_opener') as build:
                build.return_value.open.return_value = self.response(raw)
                self.assertEqual(t.send_http(config(), 'synthetic'), 'unknown')
        with patch.object(t.urllib.request, 'build_opener') as build:
            build.return_value.open.side_effect = t.http.client.BadStatusLine('PRIVATE')
            self.assertEqual(t.send_http(config(), 'synthetic'), 'unknown')

    def test_real_worker_is_bounded_for_stalled_transport(self):
        with patch.object(t, 'send_http', side_effect=lambda *_: time.sleep(20)), patch.object(t, 'WORKER_SECONDS', .15):
            started = time.monotonic()
            self.assertEqual(t.bounded_send(config(), 'synthetic'), 'unknown')
        self.assertLess(time.monotonic() - started, 3)

    def test_worker_closes_inherited_store_fd_without_unlocking_parent(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.git', prefix='telegram-fork-') as directory:
            fd = t.private_dir(directory)
            t.fcntl.flock(fd, t.fcntl.LOCK_EX | t.fcntl.LOCK_NB)
            ctx = t.multiprocessing.get_context('fork')
            ready, finish = ctx.Event(), ctx.Event()
            receiver, sender = ctx.Pipe(duplex=False)
            def transport(*_):
                ready.set()
                finish.wait(5)
                return 'unknown'
            with patch.object(t, 'send_http', side_effect=transport):
                proc = ctx.Process(target=t.child_send, args=(sender, config(), 'synthetic', fd))
                proc.start()
            try:
                self.assertTrue(ready.wait(3))
                other = t.private_dir(directory)
                try:
                    # Child must close, not LOCK_UN the shared open description.
                    with self.assertRaises(BlockingIOError):
                        t.fcntl.flock(other, t.fcntl.LOCK_EX | t.fcntl.LOCK_NB)
                    os.close(fd); fd = None
                    # Same descriptor-release effect as parent exit, without orphaning a child.
                    self.assertTrue(proc.is_alive())
                    t.fcntl.flock(other, t.fcntl.LOCK_EX | t.fcntl.LOCK_NB)
                finally:
                    os.close(other)
            finally:
                finish.set(); proc.join(3)
                if proc.is_alive(): proc.kill(); proc.join(2)
                proc.close(); receiver.close(); sender.close()
                if fd is not None: os.close(fd)

    def test_bounded_send_passes_store_fd_to_worker(self):
        with tempfile.TemporaryDirectory(dir=ROOT/'.git', prefix='telegram-fd-') as directory:
            fd = t.private_dir(directory)
            def transport(*_):
                try: os.fstat(fd)
                except OSError: return 'sent'
                return 'unknown'
            try:
                with patch.object(t, 'send_http', side_effect=transport):
                    self.assertEqual(t.bounded_send(config(), 'synthetic', fd), 'sent')
                self.assertTrue(os.fstat(fd))  # parent's descriptor remains valid
            finally: os.close(fd)

    def test_real_worker_accepts_only_confirmation(self):
        with patch.object(t, 'send_http', return_value='sent'):
            self.assertEqual(t.bounded_send(config(), 'synthetic'), 'sent')
        with patch.object(t, 'send_http', side_effect=RuntimeError('PRIVATE_TEXT')):
            self.assertEqual(t.bounded_send(config(), 'synthetic'), 'unknown')


if __name__ == '__main__':
    unittest.main()
