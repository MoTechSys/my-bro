#!/usr/bin/env python3
"""T-70 durable evidence runner and offline importer; AI, 2026-09-18; UC-14/ADR-014.

Linux only. Trusted local code, not a plugin sandbox or signed evidence store.
No model download, shell commands, response execution or external LLM service.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent

def load_module(name):
    spec = importlib.util.spec_from_file_location('_runner_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


e = load_module('evaluate')
a = e.a
k = load_module('knowledge')
MAX_ARTIFACT = a.MAX_INPUT
MAX_WORKER_OUTPUT = a.MAX_RESPONSE
CONFIG_KEYS = {'schema_version', 'model', 'endpoint', 'language', 'window_seconds',
               'deadline_seconds', 'inventory_sha256'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return a.encoded(value) + b'\n'


def read_bytes(path, limit=MAX_ARTIFACT):
    # a.read_file decodes UTF-8 without newline translation; reencoding preserves bytes.
    return a.read_file(path, limit).encode('utf-8')


def check_config(value):
    e.exact(value, CONFIG_KEYS)
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('INVALID_CONFIG_VERSION')
    a.Ollama(value['model'], value['endpoint'])  # validates only; no inference
    if value['language'] not in ('ar', 'en'):
        raise ValueError('INVALID_LANGUAGE')
    if type(value['window_seconds']) is not int or not 1 <= value['window_seconds'] <= 3600:
        raise ValueError('INVALID_WINDOW')
    seconds = value['deadline_seconds']
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 120:
        raise ValueError('INVALID_DEADLINE')
    if value['inventory_sha256'] is not None:
        e.sha256(value['inventory_sha256'])


def directory(path):
    """Pin a private directory fd, walking absolute ancestors without symlinks.

    Ancestors must belong to root/current uid and forbid group/other writes.
    Leaf additionally forbids group/other reads. ACLs and a same-uid writer remain
    operator responsibilities; chmod alone does not authenticate artifacts.
    """
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                raise ValueError('UNTRUSTED_DIRECTORY')
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('PRIVATE_DIRECTORY_REQUIRED')
        return fd
    except BaseException:
        os.close(fd)
        raise


def filename(name):
    if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}', name):
        raise ValueError('INVALID_ARTIFACT_NAME')
    return name


def read_at(fd, name, limit=MAX_ARTIFACT):
    file_fd = os.open(filename(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                      dir_fd=fd)
    with os.fdopen(file_fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise ValueError('PRIVATE_REGULAR_ARTIFACT_REQUIRED')
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('ARTIFACT_TOO_LARGE')
    return data


def write_once(fd, name, data):
    """Exclusive immutable-by-convention publication; fsync file AND directory.

    A partial write is intentionally left in place. Readers reject corruption;
    retries may not overwrite it. This is crash detection, not atomic replacement.
    """
    if not isinstance(data, bytes) or len(data) > MAX_ARTIFACT:
        raise ValueError('ARTIFACT_TOO_LARGE')
    file_fd = os.open(filename(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                      0o600, dir_fd=fd)
    with os.fdopen(file_fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(fd)


@contextmanager
def store_lock(path):
    fd = directory(path)
    try:
        # Directory inode locking avoids lock-file replacement and creates no files.
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield fd
    finally:
        os.close(fd)


def bounded_process(command, seconds):
    """Fixed trusted argv supplied by run_batch; bounded stdout and monotonic wall time.

    Signal the worker group before reaping its leader; never kill Ollama. This
    caller must exclusively own child reaping (no SIGCHLD handler/other waiter).
    Cleanup failure is recorded, not a claim that every process terminated.
    Startup and OS scheduling/kill latency are not hard real-time guarantees.
    """
    if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 < seconds <= 120:
        raise ValueError('INVALID_DEADLINE')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise ValueError('DEFAULT_SIGCHLD_REQUIRED')
    start = time.monotonic()
    deadline = start + seconds
    output = bytearray()
    proc = None
    reason = 'WORKER_FAILED'
    returncode = None
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True,
                                env={'PATH': os.defpath, 'LANG': 'C.UTF-8', 'TZ': 'UTC'}, cwd=HERE.parent)
        os.set_blocking(proc.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = 'DEADLINE_EXCEEDED'
                    break
                events = selector.select(min(remaining, .1))
                if not events:
                    continue
                chunk = os.read(proc.stdout.fileno(), min(65536, MAX_WORKER_OUTPUT + 1 - len(output)))
                if chunk:
                    output.extend(chunk)
                    if len(output) > MAX_WORKER_OUTPUT:
                        reason = 'OUTPUT_LIMIT'
                        break
                else:
                    # Observe exit without reaping: reserve the leader PID/PGID
                    # until group cleanup, even when descendants closed stdout.
                    reason = 'DEADLINE_EXCEEDED'
                    while time.monotonic() < deadline:
                        ended = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        if ended is not None:
                            returncode = ended.si_status if ended.si_code == os.CLD_EXITED else -ended.si_status
                            reason = 'OK' if returncode == 0 else 'WORKER_FAILED'
                            break
                        time.sleep(min(.01, max(0, deadline - time.monotonic())))
                    break
    except OSError:
        reason = 'WORKER_START_OR_IO_FAILED'
    finally:
        if proc is not None:
            # Defer cancellation arriving for the first time DURING cleanup too.
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            try:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError:
                    reason = 'WORKER_CLEANUP_FAILED'
                try:
                    proc.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    reason = 'WORKER_CLEANUP_FAILED'
            finally:
                try:
                    proc.stdout.close()
                finally:
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return {'reason': reason, 'returncode': returncode,
            'latency_seconds': time.monotonic() - start, 'output': bytes(output)}


SOURCE_NAMES = ('analyst.py', 'knowledge.py', 'evaluate.py', 'runner.py')
INPUT_NAMES = {'alerts.jsonl', 'rules.xml', 'configuration.json', 'model.json', 'rubric.txt'}
GENERATED_NAMES = {'knowledge.json', 'code.json', 'prompt.json', 'context.json'}
REASONS = {'OK', 'WORKER_FAILED', 'WORKER_START_OR_IO_FAILED', 'DEADLINE_EXCEEDED',
           'OUTPUT_LIMIT', 'WORKER_CLEANUP_FAILED'}
# Only reviewed public codes may enter metadata, never arbitrary exception text.
VALIDATION_CODES = frozenset({
    'INVALID_JSON', 'DUPLICATE_JSON_KEY', 'NONFINITE_JSON', 'INTEGER_TOO_LARGE',
    'MODEL_RESPONSE_TOO_LARGE_OR_INVALID', 'INVALID_MODEL_SCHEMA', 'INVALID_FINDING_COUNT',
    'INVALID_FINDING_SCHEMA', 'INVALID_REFERENCE_LIST', 'UNKNOWN_EVIDENCE_REFERENCE',
    'REPEATED_ALERT_FINDING', 'UNSUPPORTED_CROSS_ALERT_LINK',
    'UNAPPROVED_CLASSIFICATION_OR_RECOMMENDATION', 'INVALID_TEXT',
    'UNSUPPORTED_MITRE_MAPPING', 'UNCOVERED_ALERTS',
})


def code_snapshot():
    return json_bytes({name: digest(read_bytes(HERE / name)) for name in SOURCE_NAMES})


def build_bundle(inputs, at):
    """Freeze exact bytes; no manifest, labels or rubric enter the model context."""
    if set(inputs) not in (INPUT_NAMES, INPUT_NAMES | {'inventory.json'}):
        raise ValueError('INVALID_INPUT_ARTIFACTS')
    if any(not isinstance(v, bytes) or not v or len(v) > MAX_ARTIFACT for v in inputs.values()):
        raise ValueError('INVALID_INPUT_BYTES')
    cfg = a.strict_json(inputs['configuration.json'])
    check_config(cfg)
    model = a.strict_json(inputs['model.json'])
    e.exact(model, {'schema_version', 'name', 'sha256'})
    if type(model['schema_version']) is not int or model['schema_version'] != 1 or model['name'] != cfg['model']:
        raise ValueError('MODEL_DESCRIPTOR_MISMATCH')
    e.sha256(model['sha256'])  # operator declaration of weights; not a runtime attestation
    records = a.read_alerts(inputs['alerts.jsonl'].decode('utf-8'))
    rules = inputs['rules.xml'].decode('utf-8')
    context = a.prepare(records, a.load_rules(rules), cfg['language'], cfg['window_seconds'])
    context = k.enrich(context, rules, records,
                       inputs['inventory.json'].decode('utf-8') if 'inventory.json' in inputs else None,
                       cfg['inventory_sha256'], now=datetime.fromisoformat(a.timestamp(at)))
    prompt = {'system': a.SYSTEM, 'format': a.OUTPUT_SCHEMA, 'stream': False,
              'options': {'temperature': 0, 'num_predict': 2048}, 'roles': ['system', 'user']}
    bundle = dict(inputs, **{'knowledge.json': read_bytes(HERE/'mitre_subset.json'),
                            'code.json': code_snapshot(), 'prompt.json': json_bytes(prompt),
                            'context.json': json_bytes(context)})
    mapping = {'code_sha256': 'code.json', 'model_sha256': 'model.json',
               'prompt_sha256': 'prompt.json', 'knowledge_sha256': 'knowledge.json',
               'rules_sha256': 'rules.xml', 'configuration_sha256': 'configuration.json',
               'rubric_sha256': 'rubric.txt'}
    provenance = {field: digest(bundle[name]) for field, name in mapping.items()}
    return bundle, context, cfg, provenance


def batch_directory(evaluation_id, batch_id):
    e.identifier(evaluation_id)
    e.identifier(batch_id)
    return 'batch-' + digest(a.encoded([evaluation_id, batch_id]))


def batch_cases(manifest, batch_id, context, input_hash, provenance):
    e.evaluate(manifest, [], [])  # validate the entire predeclared denominator
    e.identifier(batch_id)
    cases = [case for case in manifest['cases'] if case['batch_id'] == batch_id]
    if not cases or {c['alert_ref'] for c in cases} != {v['ref'] for v in context['alerts']}:
        raise ValueError('BATCH_COVERAGE_MISMATCH')
    if any(c['input_sha256'] != input_hash for c in cases) or manifest['provenance'] != provenance:
        raise ValueError('FROZEN_PROVENANCE_MISMATCH')
    return cases


def classify_output(output, reason, context):
    if reason != 'OK':
        return 'failed', [], None
    try:
        findings = a.validate_response(output.decode('utf-8'), context)
    except UnicodeError:
        return 'rejected', [], 'INVALID_UTF8'
    except ValueError as exc:
        code = exc.args[0] if len(exc.args) == 1 and isinstance(exc.args[0], str) else None
        return 'rejected', [], code if code in VALIDATION_CODES else 'INVALID_MODEL_RESPONSE'
    return 'completed', findings, None


def run_batch(store, manifest_bytes, batch_id, inputs, *, infer=False):
    """One locked attempt per batch. Preflight failure never launches a provider.

    SIGKILL/disk failures leave immutable intent or partial evidence. Export
    refuses corrupt records; an intact intent without terminal means interrupted,
    not permission to re-run. Use a new evaluation for an explicit retry.
    """
    if infer is not True:
        raise ValueError('EXPLICIT_INFERENCE_REQUIRED')
    if len(manifest_bytes) > MAX_ARTIFACT:
        raise ValueError('MANIFEST_TOO_LARGE')
    at = datetime.now(timezone.utc).isoformat()
    manifest = a.strict_json(manifest_bytes)
    bundle, context, cfg, provenance = build_bundle(inputs, at)
    cases = batch_cases(manifest, batch_id, context, digest(bundle['alerts.jsonl']), provenance)
    name = batch_directory(manifest['evaluation_id'], batch_id)
    with store_lock(store) as root_fd:
        try:
            frozen = read_at(root_fd, 'manifest.json')
        except FileNotFoundError:
            write_once(root_fd, 'manifest.json', manifest_bytes)
        else:
            if frozen != manifest_bytes:
                raise ValueError('STORE_MANIFEST_MISMATCH')
        os.mkdir(name, mode=0o700, dir_fd=root_fd)  # fails on replay, including interrupted preparation
        os.fsync(root_fd)
        batch_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
        try:
            for artifact, data in bundle.items():
                write_once(batch_fd, artifact, data)
            intent = {'schema_version': 1, 'evaluation_id': manifest['evaluation_id'], 'batch_id': batch_id,
                      'prepared_at': at, 'manifest_sha256': digest(manifest_bytes),
                      'artifact_sha256': {key: digest(value) for key, value in bundle.items()}}
            intent_bytes = json_bytes(intent)
            write_once(batch_fd, 'intent.json', intent_bytes)  # file + directory fsync BEFORE Popen
            base = Path(os.path.abspath(store)) / name
            command = [sys.executable, '-I', '-B', str(HERE/'runner.py'), '_worker',
                       str(base/'configuration.json'), str(base/'context.json')]
            result = bounded_process(command, cfg['deadline_seconds'])
            output = result['output']
            status, _, validation_code = classify_output(output, result['reason'], context)
            write_once(batch_fd, 'output.bin', output)
            terminal = {'schema_version': 2, 'intent_sha256': digest(intent_bytes), 'status': status,
                        'validation_code': validation_code,
                        'reason': result['reason'], 'returncode': result['returncode'],
                        'latency_seconds': result['latency_seconds'], 'output_sha256': digest(output)}
            write_once(batch_fd, 'terminal.json', json_bytes(terminal))
            return {'batch_id': batch_id, 'status': status, 'case_count': len(cases),
                    'validation_code': validation_code,
                    'execution_authority': 'none', 'acceptance_approved': False}
        finally:
            os.close(batch_fd)


def import_batch(batch_fd, manifest, manifest_hash, batch_id):
    intent_bytes = read_at(batch_fd, 'intent.json')
    intent = a.strict_json(intent_bytes)
    e.exact(intent, {'schema_version', 'evaluation_id', 'batch_id', 'prepared_at',
                     'manifest_sha256', 'artifact_sha256'})
    if (type(intent['schema_version']) is not int or intent['schema_version'] != 1
            or intent['evaluation_id'] != manifest['evaluation_id'] or intent['batch_id'] != batch_id
            or intent['manifest_sha256'] != manifest_hash):
        raise ValueError('INTENT_BINDING_MISMATCH')
    hashes = intent['artifact_sha256']
    if not isinstance(hashes, dict) or set(hashes) not in (INPUT_NAMES | GENERATED_NAMES,
                                                         INPUT_NAMES | GENERATED_NAMES | {'inventory.json'}):
        raise ValueError('INVALID_ARTIFACT_SET')
    entries = set(os.listdir(batch_fd))
    if not entries <= hashes.keys() | {'intent.json', 'terminal.json', 'output.bin'}:
        raise ValueError('UNEXPECTED_BATCH_ENTRY')
    unverified = []
    bundle = {}
    for name, expected in hashes.items():
        e.sha256(expected)
        data = read_at(batch_fd, name)
        if digest(data) != expected:
            raise ValueError('ARTIFACT_HASH_MISMATCH')
        bundle[name] = data
    rebuilt, context, cfg, provenance = build_bundle(
        {key: value for key, value in bundle.items() if key in INPUT_NAMES or key == 'inventory.json'},
        intent['prepared_at'])
    if bundle != rebuilt:
        raise ValueError('CONTEXT_OR_CODE_SNAPSHOT_MISMATCH')
    cases = batch_cases(manifest, batch_id, context, digest(bundle['alerts.jsonl']), provenance)
    try:
        terminal_bytes = read_at(batch_fd, 'terminal.json')
    except FileNotFoundError:
        status, findings, seconds, output_hash = 'failed', [], None, None
        validation_code = None
        reason = 'INTERRUPTED_AFTER_INTENT'
        if 'output.bin' in entries:
            # Check type/permissions/size, but no terminal exists to bind these bytes.
            read_at(batch_fd, 'output.bin', MAX_WORKER_OUTPUT + 1)
            unverified.append('output.bin')
    else:
        terminal = a.strict_json(terminal_bytes)
        e.exact(terminal, {'schema_version', 'intent_sha256', 'status', 'reason',
                          'returncode', 'latency_seconds', 'output_sha256', 'validation_code'})
        if (type(terminal['schema_version']) is not int or terminal['schema_version'] != 2
                or terminal['intent_sha256'] != digest(intent_bytes)):
            raise ValueError('TERMINAL_BINDING_MISMATCH')
        reason = terminal['reason']
        if not isinstance(reason, str) or reason not in REASONS:
            raise ValueError('INVALID_TERMINAL_REASON')
        code = terminal['returncode']
        if code is not None and type(code) is not int:
            raise ValueError('INVALID_RETURN_CODE')
        if (reason == 'OK' and code != 0) or (reason == 'WORKER_FAILED' and code in (None, 0)):
            raise ValueError('CONFLICTING_RETURN_CODE')
        seconds = terminal['latency_seconds']
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or not 0 <= seconds <= 86400:
            raise ValueError('INVALID_DURATION')
        output_hash = e.sha256(terminal['output_sha256'])
        output = read_at(batch_fd, 'output.bin', MAX_WORKER_OUTPUT + 1)
        if digest(output) != output_hash:
            raise ValueError('OUTPUT_HASH_MISMATCH')
        if reason == 'OK' and len(output) > MAX_WORKER_OUTPUT:
            raise ValueError('SUCCESS_OUTPUT_TOO_LARGE')
        status, findings, validation_code = classify_output(output, reason, context)
        if validation_code != terminal['validation_code']:
            raise ValueError('TERMINAL_VALIDATION_CODE_MISMATCH')
        if status != terminal['status']:
            raise ValueError('TERMINAL_STATUS_MISMATCH')
    by_ref = {ref: {'classification': finding['classification'], 'mitre_ids': finding['mitre_ids']}
              for finding in findings for ref in finding['evidence_refs']}
    attempts = [{'case_id': case['case_id'], 'input_sha256': case['input_sha256'],
                 'provenance': provenance, 'status': status, 'prediction': by_ref.get(case['alert_ref']),
                 'output_sha256': output_hash, 'latency_seconds': seconds} for case in cases]
    return attempts, {'batch_id': batch_id, 'reason': reason, 'status': status,
                      'validation_code': validation_code,
                      'intent_sha256': digest(intent_bytes), 'unverified_artifacts': unverified}


def export_attempts(store, expected_manifest_sha256):
    """Read-only import under the same lock; incomplete preparations/corrupt files refuse export."""
    e.sha256(expected_manifest_sha256)
    attempts, states = [], []
    with store_lock(store) as root_fd:
        manifest_bytes = read_at(root_fd, 'manifest.json')
        if digest(manifest_bytes) != expected_manifest_sha256:
            raise ValueError('MANIFEST_HASH_MISMATCH')
        manifest = a.strict_json(manifest_bytes)
        e.evaluate(manifest, [], [])
        expected = {batch_directory(manifest['evaluation_id'], c['batch_id']): c['batch_id']
                    for c in manifest['cases']}
        entries = set(os.listdir(root_fd))
        if not entries <= expected.keys() | {'manifest.json'}:
            raise ValueError('UNEXPECTED_STORE_ENTRY')
        for name in sorted(entries - {'manifest.json'}):
            batch_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
            try:
                info = os.fstat(batch_fd)
                if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise ValueError('PRIVATE_BATCH_REQUIRED')
                rows, state = import_batch(batch_fd, manifest, expected_manifest_sha256, expected[name])
                attempts.extend(rows)
                states.append(state)
            finally:
                os.close(batch_fd)
    e.evaluate(manifest, attempts, [])  # final contract check, retaining all planned/missing cases
    return {'schema_version': 1, 'evaluation_id': manifest['evaluation_id'],
            'manifest_sha256': expected_manifest_sha256, 'attempts': attempts, 'batches': states,
            'stored_artifact_bytes_verified': not any(s['unverified_artifacts'] for s in states),
            'model_runtime_identity_verified': False,
            'human_independence_verified': False, 'acceptance_approved': False,
            'notice': 'Local integrity/reconstruction only, not signed authenticity, trusted timing or native acceptance.'}


def worker(config_path, context_path):
    """Internal trusted worker. It reads only config/context; no gold/manifest/rubric argument."""
    try:
        cfg = a.strict_json(read_bytes(config_path))
        check_config(cfg)
        context = a.strict_json(read_bytes(context_path, a.MAX_CONTEXT + 1))
        value = a.Ollama(cfg['model'], cfg['endpoint'])(context)
        sys.stdout.buffer.write(value.encode('utf-8'))
        sys.stdout.buffer.flush()
        return 0
    except (ValueError, OSError, UnicodeError):
        return 2  # no provider text in stderr


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('prepare', 'run'):
        child = sub.add_parser(action)
        for flag in ('alerts', 'rules', 'configuration', 'model-record', 'rubric'):
            child.add_argument('--' + flag, required=True)
        child.add_argument('--inventory')
        if action == 'run':
            child.add_argument('--store', required=True)
            child.add_argument('--manifest', required=True)
            child.add_argument('--batch-id', required=True)
            child.add_argument('--infer', action='store_true')
    child = sub.add_parser('export')
    child.add_argument('--store', required=True)
    child.add_argument('--manifest-sha256', required=True)
    child.add_argument('--attempts-only', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'export':
            result = export_attempts(args.store, args.manifest_sha256)
            if args.attempts_only:
                result = result['attempts']
        else:
            mapping = {'alerts.jsonl': args.alerts, 'rules.xml': args.rules,
                       'configuration.json': args.configuration, 'model.json': args.model_record,
                       'rubric.txt': args.rubric}
            if args.inventory:
                mapping['inventory.json'] = args.inventory
            inputs = {name: read_bytes(path) for name, path in mapping.items()}
            if args.action == 'prepare':
                _, context, _, provenance = build_bundle(inputs, datetime.now(timezone.utc).isoformat())
                result = {'input_sha256': digest(inputs['alerts.jsonl']), 'provenance': provenance,
                          'eligible_alerts': [{'ref': item['ref'], 'source_record': item['source_record']}
                                             for item in context['alerts']], 'inference_performed': False}
            else:
                result = run_batch(args.store, read_bytes(args.manifest), args.batch_id, inputs, infer=args.infer)
        print(a.encoded(result).decode('ascii'))
        return 0 if args.action != 'run' or result['status'] == 'completed' else 2
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, subprocess.SubprocessError):
        print('{"status":"rejected","execution_authority":"none","acceptance_approved":false}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '_worker':
        raise SystemExit(worker(sys.argv[2], sys.argv[3]))
    # SIGTERM/SIGINT clean up our child group; a durable intent remains, never a retry.
    def interrupted(*_):
        # A second cancellation must not interrupt the bounded child cleanup.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
