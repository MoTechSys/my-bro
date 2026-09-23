#!/usr/bin/env python3
"""Read-only procfs evidence for the five required Linux Wazuh daemons.

Two bounded scans, no command execution. Birth times are derived from kernel
btime + start_ticks/CLK_TCK, not service readiness or authenticated wall time.
The caller persists raw observations and supplies protected-binary validation.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

DAEMONS = ('wazuh-execd', 'wazuh-agentd', 'wazuh-syscheckd',
           'wazuh-logcollector', 'wazuh-modulesd')
MAX_PROCESSES = 4096
MAX_TEXT = 65536
UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def require(ok, code):
    if not ok:
        raise ValueError(code)


def keys(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), 'PROC_SCHEMA')


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'PROC_INTEGER')


def process_stat(text):
    require(isinstance(text, str) and len(text) <= MAX_TEXT, 'PROC_STAT')
    match = re.fullmatch(r'([0-9]+) \((.*)\) (.+)\s*', text.strip())
    require(match is not None, 'PROC_STAT')
    fields = match[3].split()
    require(len(fields) >= 20 and len(fields[0]) == 1 and
            re.fullmatch(r'[0-9]+', fields[19]), 'PROC_STAT')
    pid, ticks = int(match[1]), int(fields[19])
    integer(pid, 1, 2**31-1); integer(ticks, 1, 2**63-1)
    return {'pid': pid, 'name': match[2], 'state': fields[0], 'ticks': ticks}


def boot_seconds(text):
    require(isinstance(text, str) and re.fullmatch(r'btime [0-9]+\n?', text), 'PROC_BTIME')
    value = int(text.split()[1]); integer(value, 0, 253402300799)
    return value


def metadata(info):
    return [info.st_dev, info.st_ino, info.st_uid, info.st_mode]


def check_metadata(value):
    require(isinstance(value, list) and len(value) == 4, 'PROC_EXECUTABLE_METADATA')
    for x in value: integer(x, 0, 2**64-1)
    require(value[1] > 0 and value[2] == 0 and stat.S_ISREG(value[3]) and
            not value[3] & 0o022 and value[3] & 0o111, 'PROC_EXECUTABLE_PROTECTION')


def normalize(obj, boot):
    keys(obj, 'schema_version boot_id clk_tck namespaces_before namespaces_after btime_before btime_after first second')
    require(type(obj['schema_version']) is int and obj['schema_version'] == 1, 'PROC_VERSION')
    require(isinstance(boot, str) and re.fullmatch(UUID, boot) and obj['boot_id'] == boot, 'PROC_BOOT_ID')
    integer(obj['clk_tck'], 1, 1000000)
    for namespaces in (obj['namespaces_before'], obj['namespaces_after']):
        keys(namespaces, 'pid time')
        for name in ('pid', 'time'):
            require(isinstance(namespaces[name], str) and
                    re.fullmatch(name+r':\[[0-9]+\]', namespaces[name]), 'PROC_NAMESPACE')
    require(obj['namespaces_before'] == obj['namespaces_after'], 'PROC_NAMESPACE_CHANGED')
    btime = boot_seconds(obj['btime_before'])
    require(boot_seconds(obj['btime_after']) == btime, 'PROC_BTIME_CHANGED')
    passes = []
    for rows in (obj['first'], obj['second']):
        require(isinstance(rows, list) and len(rows) == len(DAEMONS), 'PROC_REQUIRED_DAEMONS')
        found, pids = {}, set()
        for row in rows:
            keys(row, 'name stat exe_link exe_stat binary_stat')
            name = row['name']
            require(isinstance(name, str) and name in DAEMONS and name not in found, 'PROC_DAEMON_DUPLICATE')
            value = process_stat(row['stat'])
            require(value['name'] == name[:15] and value['pid'] not in pids, 'PROC_DAEMON_IDENTITY')
            require(value['state'] in {'R', 'S'}, 'PROC_DAEMON_NOT_LIVE')
            require(row['exe_link'] == '/var/ossec/bin/'+name, 'PROC_EXE_PATH')
            check_metadata(row['exe_stat']); check_metadata(row['binary_stat'])
            require(row['exe_stat'] == row['binary_stat'], 'PROC_EXE_INODE')
            found[name] = (value['pid'], value['ticks'], row['exe_stat'])
            pids.add(value['pid'])
        passes.append(found)
    require(passes[0] == passes[1], 'PROC_CHANGED_DURING_SCAN')
    ids = {name: f'{boot}:{value[0]}:{value[1]}' for name, value in sorted(passes[0].items())}
    # Identity does not depend on the current wall-clock estimate of boot time.
    identity = {'namespaces': obj['namespaces_before'], 'daemons': ids}
    encoded = json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()
    started = [btime*1000 + value[1]*1000//obj['clk_tck'] for value in passes[0].values()]
    require(max(started) <= 253402300799999, 'PROC_BIRTH_RANGE')
    return {'instance': 'linux-proc:' + hashlib.sha256(encoded).hexdigest(),
            'daemon_instances': ids, 'namespaces': obj['namespaces_before'],
            'earliest_started_ms': min(started), 'started_ms': max(started),
            'running': True, 'precision_ms': 1000 + (1000+obj['clk_tck']-1)//obj['clk_tck'],
            'start_semantics': 'latest_required_daemon_birth_not_service_readiness'}


def read_text(path, deadline):
    require(time.monotonic() <= deadline, 'PROC_DEADLINE')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode), 'PROC_REGULAR_REQUIRED')
        data = os.read(fd, MAX_TEXT+1)
        require(len(data) <= MAX_TEXT, 'PROC_TEXT_LIMIT')
    finally:
        os.close(fd)
    require(time.monotonic() <= deadline, 'PROC_DEADLINE')
    return data.decode('utf-8')


def namespaces(proc):
    return {name: os.readlink(proc/'self/ns'/name) for name in ('pid', 'time')}


def btime_line(proc, deadline):
    lines = [x for x in read_text(proc/'stat', deadline).splitlines() if x.startswith('btime ')]
    require(len(lines) == 1, 'PROC_BTIME'); boot_seconds(lines[0])
    return lines[0]+'\n'


def scan(proc, deadline, protected):
    paths = []
    with os.scandir(proc) as entries:
        for item in entries:
            require(time.monotonic() <= deadline, 'PROC_DEADLINE')
            if re.fullmatch(r'[0-9]+', item.name):
                paths.append(Path(item.path))
                require(len(paths) <= MAX_PROCESSES, 'PROC_PROCESS_LIMIT')
    rows = []
    for path in sorted(paths, key=lambda x: int(x.name)):
        try:
            raw = read_text(path/'stat', deadline)
        except (FileNotFoundError, ProcessLookupError):
            continue
        value = process_stat(raw)
        require(value['pid'] == int(path.name), 'PROC_PID_PATH')
        names = [name for name in DAEMONS if name[:15] == value['name']]
        if not names:
            continue
        name = names[0]; binary = '/var/ossec/bin/'+name
        protected(binary)
        # procfs exe is intentionally followed; its inode must equal the protected binary.
        row = {'name': name, 'stat': raw, 'exe_link': os.readlink(path/'exe'),
               'exe_stat': metadata(os.stat(path/'exe')), 'binary_stat': metadata(os.stat(binary))}
        rows.append(row)
        require(len(rows) <= len(DAEMONS), 'PROC_REQUIRED_DAEMONS')
    require(time.monotonic() <= deadline, 'PROC_DEADLINE')
    return rows


def collect(protected, proc=Path('/proc')):
    """Production caller uses /proc only. proc injection is for offline tests.

    Deadline checks do not interrupt a stalled kernel syscall. No scanning of
    command lines, environments, user files or native service control commands.
    """
    deadline = time.monotonic()+1.5
    own = process_stat(read_text(proc/'self/stat', deadline))
    require(own['pid'] == os.getpid(), 'PROC_PID_NAMESPACE_MISMATCH')
    boot = read_text(proc/'sys/kernel/random/boot_id', deadline).strip()
    obj = {'schema_version': 1, 'boot_id': boot, 'clk_tck': os.sysconf('SC_CLK_TCK'),
           'namespaces_before': namespaces(proc), 'btime_before': btime_line(proc, deadline)}
    obj['first'] = scan(proc, deadline, protected)
    obj['second'] = scan(proc, deadline, protected)
    obj.update(namespaces_after=namespaces(proc), btime_after=btime_line(proc, deadline))
    require(read_text(proc/'sys/kernel/random/boot_id', deadline).strip() == boot, 'PROC_BOOT_CHANGED')
    normalize(obj, boot)
    raw = json.dumps(obj, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    require(len(raw) <= MAX_TEXT, 'PROC_TEXT_LIMIT')
    return raw, boot
