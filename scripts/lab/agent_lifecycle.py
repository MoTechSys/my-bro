#!/usr/bin/env python3
"""Opt-in container lifecycle wrapper for an ALREADY configured Wazuh agent.

AI, 2026-09-11; ISSUE-064/065. Requires Docker --init and a protected install.
Does not enroll, edit config, delete PID files, mount storage or recreate Docker.
On sustained unhealthy state exits nonzero after bounded service cleanup, so an
operator-configured restart policy can act. Native recovery acceptance pending.
"""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

_spec = importlib.util.spec_from_file_location('agent_health', Path(__file__).with_name('agent_health.py'))
health = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(health)

CONTROL = '/var/ossec/bin/wazuh-control'
APACHE = '/usr/sbin/apache2ctl'
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'TZ': 'UTC', 'LANG': 'C'}


def emit(event, **fields):
    print(json.dumps(dict(event=event, **fields), ensure_ascii=True, allow_nan=False), flush=True)


def protected(path):
    """Validate root-owned, non-group/world-writable resolution and ancestors.

    Installation directory ACLs remain a deployment requirement. This is not
    a substitute for package provenance or protection against a privileged writer.
    """
    source = Path(path)
    resolved = source.resolve(strict=True)
    for item in {source, *source.parents, resolved, *resolved.parents}:
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('UNPROTECTED_INSTALLATION')
    if not resolved.is_file():
        raise ValueError('REGULAR_INSTALLATION_FILE_REQUIRED')


def guard():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('ROOT_LINUX_CONTAINER_REQUIRED')
    pid1 = health.parse_stat(health.bounded_text('/proc/1/stat'))
    if pid1['name'] not in health.INIT_NAMES or os.getppid() != 1:
        raise ValueError('DIRECT_CHILD_OF_CONTAINER_INIT_REQUIRED')
    for path in (CONTROL, APACHE, '/var/ossec/etc/ossec.conf',
                 str(Path(__file__).resolve()), str(Path(__file__).with_name('agent_health.py').resolve())):
        protected(path)
    snapshot = health.collect()
    # Never start a second agent or clear stale state on the operator's behalf.
    if snapshot['processes'] or snapshot['zombies'] or snapshot['pid1'] is None:
        raise ValueError('EXISTING_OR_UNREADABLE_PROCESS_STATE')
    # Inspect the process table independently: absent state files before the first
    # start are expected, but proc permission/parse errors must still fail closed.
    entries = [p for p in Path('/proc').iterdir() if p.name.isdecimal()]
    if len(entries) > health.MAX_PROCESSES:
        raise ValueError('PROCESS_LIMIT')
    for path in entries:
        try:
            record = health.parse_stat(health.bounded_text(path / 'stat'))
        except FileNotFoundError:
            continue
        if record['name'] in {n[:15] for n in health.DAEMONS}:
            raise ValueError('EXISTING_AGENT_PROCESS')


def service(program, action, timeout):
    """Fixed argv, clean environment, no untrusted config or shell interpolation."""
    if program not in {CONTROL, APACHE} or action not in {'start', 'stop'}:
        raise ValueError('UNAPPROVED_SERVICE_ACTION')
    command = [program, action] if program == CONTROL else [program, '-k', action]
    result = subprocess.run(command, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=ENV, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError('SERVICE_ACTION_FAILED')


def watch(stopped, sample=health.collect, wait=time.sleep, now=time.monotonic,
          startup_seconds=120, poll_seconds=5, failure_limit=3, log=emit):
    for value in (startup_seconds, poll_seconds):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError('INVALID_SUPERVISION_INTERVAL')
    if type(failure_limit) is not int or failure_limit < 1:
        raise ValueError('INVALID_FAILURE_LIMIT')
    deadline = now() + startup_seconds
    ready, failures, baseline, progress_errors = False, 0, None, []
    while not stopped():
        current = sample()
        reasons = health.assess(current)
        if not reasons and baseline is None:
            baseline = current
        elif baseline is not None and current['monotonic'] - baseline['monotonic'] >= 65:
            progress_errors = health.assess_progress(baseline, current)
            baseline = current
        reasons += progress_errors
        if reasons:
            failures += 1
            log('health_failed', reasons=reasons, consecutive=failures)
            if (ready and failures >= failure_limit) or (not ready and now() >= deadline):
                log('lifecycle_exit', reason='HEALTH_GATE_FAILED')
                return 1
        else:
            failures = 0
            if not ready:
                ready = True
                log('services_live', notice='Not canary/PILOT acceptance; progress window still required.')
        wait(poll_seconds)
    log('shutdown_requested')
    return 0


def run(stopped, start_stop=service, monitor=watch, log=emit):
    """Track attempted starts so partially started services are always stopped."""
    attempted = []
    result = 1
    try:
        for program in (APACHE, CONTROL):
            if stopped():
                result = 0
                break
            attempted.append(program)
            start_stop(program, 'start', 45)
        else:
            result = monitor(stopped)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        log('lifecycle_error', reason='START_OR_MONITOR_FAILED')
    finally:
        for program in reversed(attempted):
            try:
                start_stop(program, 'stop', 30)
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                result = 1
                log('shutdown_error', service=Path(program).name)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', action='store_true', help='explicitly enable service mutations in a prepared container')
    args = parser.parse_args(argv)
    if not args.lab:
        parser.error('--lab is required; this entrypoint changes service state')
    try:
        guard()
    except (OSError, ValueError, KeyError, TypeError):
        emit('refused', reason='CONTAINER_OR_INSTALLATION_PREFLIGHT_FAILED')
        return 2
    # All child state timestamps must use the same documented convention.
    os.environ['TZ'] = 'UTC'
    time.tzset()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    return run(stopped.is_set)


if __name__ == '__main__':
    raise SystemExit(main())
