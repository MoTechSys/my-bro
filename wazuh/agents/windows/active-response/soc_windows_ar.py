# Purpose: bounded Windows AR; owner [ASTRA]; updated 2026-09-09.
# Status: native Windows validation pending; sources: Wazuh 4.14 AR, ISSUE-036.
# Configure exact roots BEFORE PyInstaller packaging, never from alert data.
import datetime
import hashlib
import json
import ntpath
import os
from pathlib import Path
import queue
import re
import stat
import subprocess
import sys
import threading

VT_ROOTS = ()  # Example ONLY after lab verification: (r'C:\Users\Lenovo\Downloads',)
YARA_ROOTS = ()  # Explicit approved monitored directories; empty = fail closed.
AGENT_HOME = Path(r'C:\Program Files (x86)\ossec-agent')
LOG_FILE = AGENT_HOME / 'active-response/active-responses.log'
YARA_EXE = AGENT_HOME / 'active-response/bin/yara/yara64.exe'
YARA_RULES = AGENT_HOME / 'active-response/bin/yara/rules/yara_rules.yar'
MAX_FILE = 100 * 1024 * 1024


def read_message(stream, seconds=5):
    result = queue.Queue(maxsize=1)
    def reader():
        try:
            result.put(stream.readline(65537))
        except Exception as exc:
            result.put(exc)
    threading.Thread(target=reader, daemon=True).start()
    line = result.get(timeout=seconds)
    if isinstance(line, Exception):
        raise line
    if not line or len(line) > 65536 or not line.endswith('\n'):
        raise ValueError('missing or oversized JSON line')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError('JSON object required')
    return value


def validate_path(value, roots):
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        raise ValueError('invalid path')
    if not re.match(r'^[A-Za-z]:\\', value) or ':' in value[2:] or '/' in value:
        raise ValueError('local absolute DOS path required; no ADS, UNC or device paths')
    parts = value[3:].split('\\')
    if any(not p or p in ('.', '..') or p.endswith((' ', '.')) for p in parts):
        raise ValueError('ambiguous path component')
    clean = ntpath.normcase(value)
    if not any(clean.startswith(ntpath.normcase(r).rstrip('\\') + '\\') for r in roots):
        raise ValueError('path outside configured allowlist')
    return value


def snapshot(path):
    # Reject junctions/reparse points at EVERY level, not just the leaf.
    p = Path(path)
    for component in reversed((p, *p.parents)):
        info = os.lstat(component)
        if getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError('reparse point refused')
    info = os.stat(p, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise ValueError('single-link bounded regular file required')
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def log_line(text):
    with LOG_FILE.open('a', encoding='utf-8') as log:
        log.write(text + '\n')


def main(mode):
    message = {}
    try:
        if os.name != 'nt':
            raise ValueError('Windows-only response')
        message = read_message(sys.stdin)
        if message.get('command') == 'delete':
            return 0
        if message.get('command') != 'add':
            raise ValueError('unsupported command')
        alert = message['parameters']['alert']
        if mode == 'remove':
            if str(alert['rule']['id']) != '87105':
                raise ValueError('unexpected rule')
            source = alert['data']['virustotal']['source']
            path = validate_path(source['file'], VT_ROOTS)
            digest = source['md5']
            if not isinstance(digest, str) or not re.fullmatch('[0-9a-fA-F]{32}', digest):
                raise ValueError('source.md5 required')
            print(json.dumps({'version': 1, 'origin': {'name': 'remove-threat',
                  'module': 'active-response'}, 'command': 'check_keys',
                  'parameters': {'keys': [str(alert.get('agent', {}).get('id', '')), path, digest]}}), flush=True)
            decision = read_message(sys.stdin).get('command')
            if decision == 'abort':
                return 0
            if decision != 'continue':
                raise ValueError('invalid execd reply')
            before = snapshot(path)
            md5 = hashlib.md5(usedforsecurity=False)
            count = 0
            with open(path, 'rb') as stream:
                for chunk in iter(lambda: stream.read(65536), b''):
                    count += len(chunk)
                    if count > MAX_FILE:
                        raise ValueError('file grew beyond bound')
                    md5.update(chunk)
            if md5.hexdigest() != digest.lower() or before != snapshot(path):
                raise ValueError('file changed or hash mismatch')
            # Name-based deletion still has a final race on Windows. Deployment
            # requires controlled-directory ACLs and native review, see report.
            os.remove(path)
            stamp = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
            log_line(f'{stamp} remove-threat: {json.dumps(message)} Successfully removed threat')
        elif mode == 'yara':
            if str(alert['rule']['id']) not in ('100303', '100304'):
                raise ValueError('unexpected YARA rule')
            path = validate_path(alert['syscheck']['path'], YARA_ROOTS)
            before = snapshot(path)
            result = subprocess.run([str(YARA_EXE), '-w', '-a', '10', '-l', '100',
                                     str(YARA_RULES), path], shell=False,
                                    capture_output=True, timeout=20, check=False)
            if result.returncode != 0 or snapshot(path) != before:
                raise ValueError('YARA failed or target changed')
            lines = result.stdout.decode('utf-8', errors='strict').splitlines()
            for line in lines:
                rule, _, target = line.partition(' ')
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', rule) or target != path:
                    raise ValueError('unexpected YARA output')
                log_line(f'wazuh-yara: INFO - Scan result: {rule} {path}')
            log_line('wazuh-yara: AUDIT - ' + json.dumps({'event': 'scan_complete', 'path': path,
                     'time': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'matches': len(lines)}))
        else:
            raise ValueError('unknown response mode')
        return 0
    except Exception as exc:
        # Do not return success after a deletion/scan error or an EOF handshake.
        prefix = 'Error removing threat' if mode == 'remove' else 'wazuh-yara: ERROR -'
        try:
            if mode == 'remove':
                stamp = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
                log_line(f'{stamp} remove-threat: {json.dumps(message)} Error removing threat: {json.dumps(str(exc))}')
            else:
                log_line(prefix + ' ' + json.dumps({'error': str(exc), 'alert': message}))
        except OSError:
            pass
        print(prefix + ': ' + str(exc), file=sys.stderr)
        return 1
