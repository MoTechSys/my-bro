#!/usr/bin/env python3
"""Purpose: bounded Linux AR; owner [ASTRA]; status: lab validation pending.
Updated: 2026-09-09. Sources: Wazuh 4.14 custom-active-response-scripts,
ISSUE-036 and tests/SECURITY_REVIEW.md. Deploy root:wazuh 0750 beside wrappers.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

VT_ROOTS = ('/home/kali/SOCfile',)
YARA_ROOTS = ('/tmp/yara/malware', '/home/kali/abdul')
YARA_BIN = '/usr/local/bin/yara'
YARA_RULES = '/var/ossec/etc/yara/rules/yara_rules.yar'
MAX_FILE = 100 * 1024 * 1024
MAX_INPUT = 65536
LOG_FILE = Path(__file__).resolve().parents[2] / 'logs/active-responses.log'


def read_message(stream):
    line = stream.readline(MAX_INPUT + 1)
    if not line or len(line) > MAX_INPUT or not line.endswith('\n'):
        raise ValueError('missing, oversized or incomplete JSON line')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError('JSON object required')
    return value


def valid_path(path, roots):
    if not isinstance(path, str) or not path.startswith('/'):
        raise ValueError('absolute path required')
    if any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise ValueError('control character in path')
    parts = path.split('/')[1:]
    if any(p in ('', '.', '..') for p in parts):
        raise ValueError('non-canonical path')
    if not any(path.startswith(root.rstrip('/') + '/') for root in roots):
        raise ValueError('path outside approved monitored roots')
    return parts


@contextlib.contextmanager
def open_target(path, roots):
    """Walk each component without following links; pin parent and file FDs."""
    parts = valid_path(path, roots)
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    fd = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('single-link regular file required')
        if info.st_size > MAX_FILE:
            raise ValueError('file exceeds safety size limit')
        yield directory, parts[-1], fd
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_nlink)


def remove_file(path, digest, roots=VT_ROOTS):
    if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-fA-F]{32}', digest):
        raise ValueError('VirusTotal source.md5 required')
    with open_target(path, roots) as (parent, name, fd):
        before = os.fstat(fd)
        md5 = hashlib.md5(usedforsecurity=False)
        count = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            count += len(chunk)
            if count > MAX_FILE:
                raise ValueError('file grew beyond limit')
            md5.update(chunk)
        if md5.hexdigest().lower() != digest.lower():
            raise ValueError('current file does not match alerted hash')
        if identity(before) != identity(os.fstat(fd)):
            raise ValueError('file changed while hashing')
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if identity(before) != identity(current):
            raise ValueError('file replaced before deletion')
        # unlink is restricted to a basename under the pinned parent descriptor.
        # Linux has no portable unlink-by-open-file-handle: final name-swap risk
        # remains inside the allowed directory; see SECURITY_REVIEW limitations.
        os.unlink(name, dir_fd=parent)


def write_log(text):
    # Only the root-owned installation log path; no event-controlled location.
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(LOG_FILE, flags, 0o640)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('log must be regular')
        os.write(fd, (text + '\n').encode('utf-8'))
    finally:
        os.close(fd)


def log_remove(message, result):
    stamp = time.strftime('%Y/%m/%d %H:%M:%S')
    # JSON escaping prevents event data from injecting extra log records.
    write_log(f'{stamp} remove-threat: {json.dumps(message, ensure_ascii=True)} {result}')


def scan_file(path):
    with open_target(path, YARA_ROOTS) as (_, _, fd):
        stable = False
        for _ in range(10):
            before = identity(os.fstat(fd))
            time.sleep(1)
            if before == identity(os.fstat(fd)):
                stable = True
                break
        if not stable:
            raise ValueError('file did not stabilize within 10 seconds')
        for trusted in (YARA_BIN, YARA_RULES):
            info = os.stat(trusted, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('YARA executable/rules must be root-owned, non-writable regular files')
        # Bound process output and CPU/address space without a shell or recursion.
        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
        process = subprocess.run(
            [YARA_BIN, '-w', '-a', '10', '-l', '100', YARA_RULES, f'/proc/self/fd/{fd}'],
            pass_fds=(fd,), capture_output=True, timeout=25, check=False,
            preexec_fn=limits, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
        if process.returncode != 0:
            raise ValueError('YARA failed (exit %s)' % process.returncode)
        if before != identity(os.fstat(fd)):
            raise ValueError('file changed during scan')
        for line in process.stdout.decode('utf-8', errors='strict').splitlines():
            rule, _, scanned = line.partition(' ')
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', rule) or scanned != f'/proc/self/fd/{fd}':
                raise ValueError('unexpected YARA output')
            write_log(f'wazuh-yara: INFO - Scan result: {rule} {path}')
        write_log('wazuh-yara: AUDIT - ' + json.dumps(
            {'event': 'scan_complete', 'path': path, 'time': time.time(),
             'matches': len(process.stdout.splitlines())}))


def main(mode):
    message = {}
    try:
        message = read_message(sys.stdin)
        command = message.get('command')
        if command == 'delete':
            return 0  # Stateless responses must never delete/scan on rollback.
        if command != 'add':
            raise ValueError('unsupported AR command')
        alert = message['parameters']['alert']
        if mode == 'remove':
            if str(alert['rule']['id']) != '87105':
                raise ValueError('expected VirusTotal positive rule 87105')
            source = alert['data']['virustotal']['source']
            valid_path(source['file'], VT_ROOTS)
            keys = [str(alert.get('agent', {}).get('id', '')), source['file'], source['md5']]
            print(json.dumps({'version': 1, 'origin': {'name': 'remove-threat',
                  'module': 'active-response'}, 'command': 'check_keys',
                  'parameters': {'keys': keys}}), flush=True)
            decision = read_message(sys.stdin).get('command')
            if decision == 'abort':
                return 0
            if decision != 'continue':
                raise ValueError('invalid execd decision')
            remove_file(source['file'], source['md5'])
            log_remove(message, 'Successfully removed threat')
        elif mode == 'yara':
            if str(alert['rule']['id']) not in ('100300', '100301'):
                raise ValueError('unexpected YARA trigger')
            expected = ['-yara_path', '/usr/local/bin', '-yara_rules', YARA_RULES]
            if message['parameters'].get('extra_args') != expected:
                raise ValueError('unapproved YARA arguments')
            scan_file(alert['syscheck']['path'])
        else:
            raise ValueError('unknown mode')
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        if mode == 'remove':
            log_remove(message, 'Error removing threat: ' + str(error))
        else:
            write_log('wazuh-yara: ERROR - ' + json.dumps(str(error)))
        return 1


if __name__ == '__main__':
    if sys.platform != 'linux' or len(sys.argv) != 2:
        sys.exit(1)
    # Whole response deadline also bounds pipe reads/handshake and hashing.
    signal.alarm(45)
    sys.exit(main(sys.argv[1]))
