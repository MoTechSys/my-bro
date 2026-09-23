"""T-70 real loopback HTTP/CLI integration; synthetic only, no Ollama model.

The HTTP server binds loopback only. It stores requests in memory and never logs
bodies. Test artifacts are private and temporary; no genuine lab data is used.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from test_ai_runner import ROOT, fixture, r


class SyntheticHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *args):
        pass  # Deliberately no HTTP access log: test requests may contain sentinels.

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if self.path != '/api/chat' or not 0 < length <= 262144:
                self.send_error(400)
                return
            payload = json.loads(self.rfile.read(length))
            with self.server.lock:
                self.server.requests.append(payload)
            mode = payload['model'].removeprefix('synthetic-')
            self.server.received.set()
            if mode == 'bad-status':
                self.connection.sendall(b'PRIVATE-PROVIDER-BAD-STATUS\r\n\r\n')
                self.close_connection = True
                return
            if mode == 'slow-headers':
                self.connection.sendall(b'HTTP/1.1 200 OK\r\nX-Synthetic: ')
                while not self.server.stopping.wait(.03):
                    self.connection.sendall(b'x')
                return
            if mode == 'http-error':
                self.send_response(503)
                raw = b'PRIVATE-PROVIDER-ERROR'
            else:
                self.send_response(200)
                finding = {'evidence_refs': ['A99' if mode == 'rejected' else 'A1'],
                    'classification': 'suspicious', 'assessment': 'Synthetic advice only.',
                    'mitre_ids': ['T1059'], 'recommendation': 'investigate'}
                envelope = {'model': payload['model'], 'done': mode != 'not-done',
                    'message': {'role': 'assistant', 'content': json.dumps({'findings': [finding]})}}
                if mode == 'tool-call':
                    envelope['message']['tool_calls'] = [{'function': {'name': 'forbidden'}}]
                raw = b'x' * (r.a.MAX_RESPONSE + 1) if mode == 'oversized' else r.json_bytes(envelope)
            self.send_header('Content-Type', 'application/json')
            chunked = mode in ('chunked', 'incomplete-chunked', 'ambiguous-framing')
            if chunked:
                self.send_header('Transfer-Encoding', 'chunked')
            if not chunked or mode == 'ambiguous-framing':
                self.send_header('Content-Length', 'invalid' if mode == 'invalid-length' else
                                 str(len(raw) + (100 if mode == 'truncated-valid' else 0)))
            if mode == 'duplicate-length':
                self.send_header('Content-Length', str(len(raw)))
            if mode == 'encoded':
                self.send_header('Content-Encoding', 'gzip')
            self.send_header('Connection', 'close')
            self.end_headers()
            if chunked:
                tail = b'' if mode == 'incomplete-chunked' else b'0\r\n\r\n'
                self.wfile.write(f'{len(raw):x}\r\n'.encode() + raw + b'\r\n' + tail)
                self.wfile.flush()
            elif mode == 'slow-body':
                for byte in raw:
                    self.wfile.write(bytes([byte])); self.wfile.flush()
                    if self.server.stopping.wait(.03): break
            else:
                self.wfile.write(raw[:12] if mode == 'truncated-json' else raw)
                self.wfile.flush()
            self.close_connection = True
        except (BrokenPipeError, ConnectionResetError):
            # Expected: the runner kills its client on deadlines/oversize output.
            self.close_connection = True


class Transport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        port = int(os.environ.get('SOC_TRANSPORT_TEST_PORT', '0'))
        cls.server = ThreadingHTTPServer(('127.0.0.1', port), SyntheticHandler)
        cls.server.requests = []
        cls.server.lock = threading.Lock()
        cls.server.received = threading.Event()
        cls.server.stopping = threading.Event()
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': .02})
        cls.thread.start()
        if port:
            print('Synthetic loopback HTTP test listener ready on port', port, flush=True)

    @classmethod
    def tearDownClass(cls):
        cls.server.stopping.set()
        cls.server.shutdown()
        cls.thread.join(timeout=2)
        cls.server.server_close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT/'.git', prefix='transport-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.store = self.base/'store'; self.store.mkdir(mode=0o700)
        with self.server.lock: self.server.requests.clear()
        self.server.received.clear()

    def run_cli(self, mode='ok', deadline=2):
        manifest, inputs, _ = fixture(1)
        cfg = json.loads(inputs['configuration.json'])
        cfg.update(model='synthetic-' + mode, deadline_seconds=deadline,
                   endpoint='http://127.0.0.1:' + str(self.server.server_port))
        inputs['configuration.json'] = r.json_bytes(cfg)
        inputs['model.json'] = r.json_bytes({'schema_version': 1, 'name': cfg['model'], 'sha256': 'a'*64})
        manifest['provenance'] = r.build_bundle(inputs, '2026-09-22T00:00:00Z')[3]
        self.manifest = manifest
        self.manifest_bytes = r.json_bytes(manifest)
        self.command = [sys.executable, '-I', '-B', str(ROOT/'ai_agent/runner.py'), 'run',
                        '--store', str(self.store), '--manifest', str(self.base/'manifest.json'),
                        '--batch-id', 'batch-1', '--infer']
        mapping = {'alerts.jsonl': 'alerts', 'rules.xml': 'rules', 'configuration.json': 'configuration',
                   'model.json': 'model-record', 'rubric.txt': 'rubric'}
        with r.store_lock(self.base) as fd:
            r.write_once(fd, 'manifest.json', self.manifest_bytes)
            for name, data in inputs.items():
                r.write_once(fd, name, data)
                self.command += ['--' + mapping[name], str(self.base/name)]
        start = time.monotonic()
        result = subprocess.run(self.command, capture_output=True, timeout=8)
        elapsed = time.monotonic() - start
        self.assertTrue(self.server.received.wait(.2), 'worker did not reach the HTTP fixture')
        self.assertNotIn(b'PRIVATE', result.stdout + result.stderr)
        self.assertNotIn(b'NEVER-SEND', result.stdout + result.stderr)
        imported = r.export_attempts(self.store, r.digest(self.manifest_bytes))
        return result, imported, elapsed

    def test_complete_http_worker_to_c4_and_request_privacy(self):
        result, imported, _ = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(imported['attempts'][0]['status'], 'completed')
        self.assertEqual(json.loads(result.stdout)['execution_authority'], 'none')
        request = self.server.requests[0]
        sent = json.dumps(request)
        for marker in ('NEVER-SEND', 'private-manager', 'full_log', 'gold', 'labeler_ref', 'reviewer_ref'):
            self.assertNotIn(marker, sent)
        self.assertFalse(request['stream'])
        self.assertEqual([m['role'] for m in request['messages']], ['system', 'user'])
        self.assertEqual(request['format'], r.a.OUTPUT_SCHEMA)
        self.assertFalse(imported['model_runtime_identity_verified'])
        self.assertFalse(imported['acceptance_approved'])
        self.assertEqual(r.e.evaluate(self.manifest, imported['attempts'], [])['planned_cases'], 1)

    def test_schema_rejection_is_distinct_from_transport_failure(self):
        result, imported, _ = self.run_cli('rejected')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(imported['batches'][0]['validation_code'], 'UNKNOWN_EVIDENCE_REFERENCE')
        self.assertEqual(imported['attempts'][0]['status'], 'rejected')

    def assert_failed(self, mode):
        result, imported, _ = self.run_cli(mode)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(imported['attempts'][0]['status'], 'failed')
        self.assertIsNone(imported['attempts'][0]['prediction'])
        self.assertEqual(imported['batches'][0]['reason'], 'WORKER_FAILED')
        self.assertEqual(r.e.evaluate(self.manifest, imported['attempts'], [])['counts']['failed'], 1)

    def test_http_error_body_is_not_public_diagnostic(self): self.assert_failed('http-error')
    def test_invalid_http_status_is_sanitized(self): self.assert_failed('bad-status')
    def test_cut_json_is_failure(self): self.assert_failed('truncated-json')
    def test_valid_json_with_truncated_http_body_is_failure(self): self.assert_failed('truncated-valid')
    def test_oversized_envelope_is_failure(self): self.assert_failed('oversized')
    def test_incomplete_generation_is_failure(self): self.assert_failed('not-done')
    def test_tool_call_is_failure(self): self.assert_failed('tool-call')
    def test_incomplete_chunked_body_is_failure(self): self.assert_failed('incomplete-chunked')
    def test_duplicate_length_is_failure(self): self.assert_failed('duplicate-length')
    def test_invalid_length_is_failure(self): self.assert_failed('invalid-length')
    def test_ambiguous_framing_is_failure(self): self.assert_failed('ambiguous-framing')
    def test_unsupported_encoding_is_failure(self): self.assert_failed('encoded')

    def test_chunked_envelope_is_supported(self):
        result, imported, _ = self.run_cli('chunked')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(imported['attempts'][0]['status'], 'completed')

    def assert_deadline(self, mode):
        result, imported, elapsed = self.run_cli(mode, .6)
        self.assertEqual(result.returncode, 2)
        self.assertLess(elapsed, 4)
        self.assertEqual(imported['batches'][0]['reason'], 'DEADLINE_EXCEEDED')
        self.assertEqual(imported['attempts'][0]['status'], 'failed')
        again = subprocess.run(self.command, capture_output=True, timeout=5)
        self.assertEqual(again.returncode, 1)
        self.assertEqual(len(self.server.requests), 1, 'failed batch must not be retried')
        self.assertEqual(imported, r.export_attempts(self.store, r.digest(self.manifest_bytes)))

    def test_dripping_headers_cannot_reset_global_deadline(self): self.assert_deadline('slow-headers')
    def test_dripping_body_cannot_reset_global_deadline(self): self.assert_deadline('slow-body')
