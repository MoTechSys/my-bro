#!/usr/bin/env python3
"""Bounded UC-09/11 lab clients and explicit SSH AR configuration; AI 2026-09-18.

Preview by default. Not an exploit-success detector, credential guesser or T-11
measurement journal. Use only a dedicated, authorized non-production endpoint.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

PRIVATE = tuple(ipaddress.ip_network(v) for v in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))


def lab_ip(value):
    ip = ipaddress.IPv4Address(value)
    if not any(ip in network for network in PRIVATE):
        raise ValueError('RFC1918_TARGET_REQUIRED')
    return str(ip)


def trial_key(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9]{8,24}', value):
        raise ValueError('INVALID_TRIAL_KEY')
    return value


def regular(path):
    path = Path(path).absolute()
    if any(c.isspace() or c in '\"\'~%' for c in str(path)):
        raise ValueError('HOST_FILE_PATH_MUST_BE_LITERAL')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size == 0 or info.st_size > 65536:
            raise ValueError('PINNED_HOST_FILE_REQUIRED')
        if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
            raise ValueError('UNTRUSTED_HOST_FILE')
    finally:
        os.close(fd)
    # Parent directory integrity remains an operator prerequisite.
    return str(path)


def plan(kind, target, port, trial, known_hosts=None):
    target, trial = lab_ip(target), trial_key(trial)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('INVALID_PORT')
    if kind == 'sqli':
        # Fixed, non-destructive signature sent only to an approved static/non-DB URL.
        path = '/soc-probe-' + trial + '?q=union%20select%20null,null'
        command = ['/usr/bin/curl', '-q', '--silent', '--globoff', '--noproxy', '*',
                   '--proxy', '', '--proto', '=http', '--connect-timeout', '3', '--max-time', '6',
                   '--max-redirs', '0', '--output', '/dev/null', '--write-out', '%{http_code}',
                   'http://' + target + ':' + str(port) + path]
        count, expected = 1, ['31103', '31106_if_HTTP_200']
    elif kind == 'ssh':
        if known_hosts is None:
            raise ValueError('PINNED_HOST_FILE_REQUIRED')
        known_hosts = regular(known_hosts)
        options = ['BatchMode=yes', 'ConnectTimeout=3', 'ConnectionAttempts=1',
                   'StrictHostKeyChecking=yes', 'UpdateHostKeys=no',
                   'UserKnownHostsFile=' + known_hosts, 'GlobalKnownHostsFile=/dev/null',
                   'IdentityAgent=none', 'IdentityFile=none', 'IdentitiesOnly=yes',
                   'PreferredAuthentications=none', 'PasswordAuthentication=no',
                   'PubkeyAuthentication=no', 'KbdInteractiveAuthentication=no',
                   'GSSAPIAuthentication=no', 'HostbasedAuthentication=no',
                   'ForwardAgent=no', 'ClearAllForwardings=yes', 'ControlMaster=no',
                   'ControlPath=none', 'RequestTTY=no', 'LogLevel=ERROR']
        command = ['/usr/bin/ssh', '-F', '/dev/null', '-N']
        for option in options:
            command += ['-o', option]
        command += ['-p', str(port), '-l', 'socprobe_' + trial.lower(), target]
        count, expected = 12, ['5710', '5712_if_native_correlation_matches']
    else:
        raise ValueError('INVALID_SCENARIO')
    return {'schema_version': 1, 'scenario': kind, 'trial': trial, 'target': target,
            'port': port, 'planned_attempts': count, 'deadline_seconds': 25,
            'command': command, 'expected_rule_candidates': expected,
            'network_performed': False, 'detection_verified': False, 'response_verified': False}


def execute(value, *, lab=False):
    if lab is not True:
        raise ValueError('EXPLICIT_LAB_REQUIRED')
    # Rebuild all argv: caller-supplied command is never executed.
    kind = value['scenario']
    known = None
    if kind == 'ssh':
        known = value['known_hosts']
    approved = plan(kind, value['target'], value['port'], value['trial'], known)
    started = time.monotonic()
    end = started + approved['deadline_seconds']
    rows = []
    for number in range(1, approved['planned_attempts'] + 1):
        left = end - time.monotonic()
        row = {'number': number, 'exit_code': None, 'http_status': None}
        if left <= 0:
            row['status'] = 'not_launched_deadline'
        else:
            try:
                result = subprocess.run(approved['command'], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE if kind == 'sqli' else subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, timeout=min(6, left),
                                        env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
                row['exit_code'] = result.returncode
                row['status'] = 'client_returned' if result.returncode == 0 else 'client_error'
                if kind == 'sqli' and result.returncode == 0 and re.fullmatch(rb'[1-5][0-9]{2}', result.stdout):
                    row['http_status'] = int(result.stdout)
            except subprocess.TimeoutExpired:
                row['status'] = 'client_timeout'
            except OSError:
                row['status'] = 'client_start_failed'
            if number < approved['planned_attempts']:
                time.sleep(min(.25, max(0, end - time.monotonic())))
        rows.append(row)
    return {**{k: v for k, v in approved.items() if k != 'command'},
            'network_performed': any(v['status'] != 'not_launched_deadline' and
                                     v['status'] != 'client_start_failed' for v in rows),
            'attempts': rows, 'elapsed_seconds': time.monotonic() - started,
            'notice': 'Client outcomes only. SSH exit255 includes transport/host-key/auth errors; '
                      'no credential guesses or remote commands. Verify source, native rule, block and unblock separately.'}


def ssh_response(management_ips, probe_source, *, enable=False):
    if enable is not True or not 1 <= len(management_ips) <= 16:
        raise ValueError('EXPLICIT_RESPONSE_AND_MANAGEMENT_IPS_REQUIRED')
    source = lab_ip(probe_source)
    safe = set()
    for item in management_ips:
        ip = ipaddress.ip_address(item)
        if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            raise ValueError('INVALID_MANAGEMENT_IP')
        safe.add(str(ip))
    safe.update(('127.0.0.1', '::1'))
    if source in safe:
        raise ValueError('PROBE_SOURCE_IS_MANAGEMENT')
    root = ET.Element('ossec_config')
    global_config = ET.SubElement(root, 'global')
    for ip in sorted(safe):
        ET.SubElement(global_config, 'white_list').text = ip
    response = ET.SubElement(root, 'active-response')
    # Do not add level/group (these are OR, not AND), or duplicate native command.
    for tag, value in [('disabled', 'no'), ('command', 'firewall-drop'), ('location', 'local'),
                       ('rules_id', '5712,5763'), ('timeout', '60')]:
        ET.SubElement(response, tag).text = value
    ET.indent(root)
    return ET.tostring(root, encoding='unicode')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for kind, port in [('ssh', 22), ('sqli', 80)]:
        child = sub.add_parser(kind)
        child.add_argument('--target', required=True)
        child.add_argument('--trial', required=True)
        child.add_argument('--port', type=int, default=port)
        child.add_argument('--lab', action='store_true')
        if kind == 'ssh': child.add_argument('--known-hosts', required=True)
    child = sub.add_parser('ssh-response')
    child.add_argument('--management-ip', action='append', required=True)
    child.add_argument('--probe-source', required=True)
    child.add_argument('--enable-response', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'ssh-response':
            print(ssh_response(args.management_ip, args.probe_source, enable=args.enable_response))
        else:
            value = plan(args.action, args.target, args.port, args.trial, getattr(args, 'known_hosts', None))
            if args.action == 'ssh': value['known_hosts'] = str(Path(args.known_hosts).absolute())
            print(json.dumps(execute(value, lab=True) if args.lab else value, sort_keys=True))
        return 0  # successful report generation is not successful detection/AR
    except (OSError, ValueError, KeyError, TypeError):
        print('{"status":"rejected","detection_verified":false}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
