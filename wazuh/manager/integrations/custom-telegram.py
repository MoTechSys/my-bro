#!/usr/bin/python3
"""UC-10 bounded, opt-in Telegram notification; AI 2026-09-18.

No commands/AR, raw logs, credentials in argv, automatic retries or unsigned
claims of exactly-once delivery. Linux private store; trusted local operator.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import hmac
import http.client
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import urllib.error
import urllib.request

CONFIG = Path('/etc/soc-telegram/config.json')
STORE = Path('/var/lib/soc-telegram')
MAX_INPUT = 4 * 1024 * 1024
MAX_RECORDS = 1000
WORKER_SECONDS = 10
CONFIG_KEYS = {'schema_version', 'enabled', 'bot_token', 'chat_id', 'hmac_key',
               'min_level', 'max_per_hour', 'max_total_attempts'}


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False).encode('utf-8')


def strict_json(data):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out: raise ValueError('DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    def constant(_): raise ValueError('NONFINITE_JSON')
    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
        encoded(value)  # reject overflowing float representations
        return value
    except (RecursionError, UnicodeError, TypeError):
        raise ValueError('INVALID_JSON') from None


def private_dir(path):
    path = Path(os.path.abspath(path))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd); fd = next_fd
            info = os.fstat(fd)
            if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
                raise ValueError('UNTRUSTED_PARENT')
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('PRIVATE_DIRECTORY_REQUIRED')
        return fd
    except BaseException:
        os.close(fd); raise


def read_at(fd, name, limit=65536):
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
    with os.fdopen(handle, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('PRIVATE_FILE_REQUIRED')
        data = f.read(limit + 1)
    if len(data) > limit: raise ValueError('FILE_TOO_LARGE')
    return data


def write_once(fd, name, value):
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
    with os.fdopen(handle, 'wb') as f:
        f.write(encoded(value)); f.flush(); os.fsync(f.fileno())
    os.fsync(fd)


def load_config(path):
    path = Path(os.path.abspath(path)); fd = private_dir(path.parent)
    try: cfg = strict_json(read_at(fd, path.name))
    finally: os.close(fd)
    if not isinstance(cfg, dict) or set(cfg) != CONFIG_KEYS:
        raise ValueError('INVALID_CONFIG')
    if type(cfg['schema_version']) is not int or cfg['schema_version'] != 1 or type(cfg['enabled']) is not bool:
        raise ValueError('INVALID_CONFIG')
    if not isinstance(cfg['bot_token'], str) or not re.fullmatch(r'[0-9]{5,20}:[A-Za-z0-9_-]{20,100}', cfg['bot_token']):
        raise ValueError('INVALID_TOKEN')
    if not isinstance(cfg['chat_id'], str) or not re.fullmatch(r'-?[1-9][0-9]{0,19}', cfg['chat_id']):
        raise ValueError('INVALID_CHAT')
    if not isinstance(cfg['hmac_key'], str) or not re.fullmatch(r'[0-9a-f]{64}', cfg['hmac_key']):
        raise ValueError('INVALID_HMAC_KEY')
    for key, low, high in [('min_level', 12, 16), ('max_per_hour', 1, 60), ('max_total_attempts', 1, MAX_RECORDS)]:
        if type(cfg[key]) is not int or not low <= cfg[key] <= high: raise ValueError('INVALID_LIMIT')
    return cfg


def alert_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode): raise ValueError('REGULAR_ALERT_REQUIRED')
        raw = f.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT: raise ValueError('ALERT_TOO_LARGE')
    return strict_json(raw)


def text(value, maximum=128):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or any(ord(c) < 32 for c in value):
        raise ValueError('INVALID_ALERT_FIELD')
    return value


def project(alert, cfg):
    if not isinstance(alert, dict): raise ValueError('INVALID_ALERT')
    level = alert['rule']['level']; rid = alert['rule']['id']
    if type(level) is not int or not 0 <= level <= 16 or not isinstance(rid, str) or not re.fullmatch(r'[0-9]{1,6}', rid):
        raise ValueError('INVALID_RULE')
    if level < cfg['min_level']: return None
    identity = [text(alert['manager']['name']), text(alert['agent']['id']), text(alert['id'])]
    at = datetime.fromisoformat(text(alert['timestamp'], 40).replace('Z', '+00:00'))
    if at.tzinfo is None: raise ValueError('TIMEZONE_REQUIRED')
    key = bytes.fromhex(cfg['hmac_key'])
    def tag(value): return hmac.new(key, encoded(value), hashlib.sha256).hexdigest()
    event = tag(identity)
    message = ('SOC advisory alert\nRule: ' + rid + '\nLevel: ' + str(level) +
               '\nAgent ref: ' + tag(identity[:2])[:16] + '\nEvent ref: ' + event[:16] +
               '\nTime UTC: ' + at.astimezone(timezone.utc).isoformat() +
               '\nReview in Wazuh. No automatic response.')
    return {'event': event, 'fingerprint': tag(alert), 'message': message}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def send_http(cfg, message):
    """Fixed TLS API endpoint; proxies/redirects disabled, no response text logged."""
    request = urllib.request.Request('https://api.telegram.org/bot' + cfg['bot_token'] + '/sendMessage',
        data=encoded({'chat_id': cfg['chat_id'], 'text': message,
                      'link_preview_options': {'is_disabled': True}, 'protect_content': True}),
        headers={'Content-Type': 'application/json'}, method='POST')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=5) as response:
            if response.status != 200: return 'unknown'
            raw = response.read(16385)
        if len(raw) > 16384: return 'unknown'
        value = strict_json(raw)
        result = value.get('result') if isinstance(value, dict) else None
        if (value.get('ok') is True and isinstance(result, dict)
                and type(result.get('message_id')) is int and result['message_id'] > 0
                and isinstance(result.get('chat'), dict)
                and str(result['chat'].get('id')) == cfg['chat_id']):
            return 'sent'
    except (OSError, ValueError, TypeError, AttributeError, http.client.HTTPException, urllib.error.URLError):
        pass
    return 'unknown'  # may have arrived before timeout/lost acknowledgement; never retry automatically


def child_send(conn, cfg, message, store_fd=None):
    # fork inherits the open file description and its flock despite O_CLOEXEC.
    # Close only our duplicate: LOCK_UN would also release the parent's lock.
    if store_fd is not None:
        os.close(store_fd)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGALRM, lambda *_: os._exit(124))
    signal.alarm(math.ceil(WORKER_SECONDS))  # bounds worker lifetime if parent is killed
    null = os.open(os.devnull, os.O_RDWR)
    for target in (0, 1, 2): os.dup2(null, target)
    if null > 2: os.close(null)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LANG='C.UTF-8')
    try:
        try:
            status = send_http(cfg, message)
        except Exception:
            status = 'unknown'  # no traceback or arbitrary exception text from child
        conn.send(status)
    finally:
        conn.close()


def bounded_send(cfg, message, store_fd=None):
    # Forked child receives secrets in memory, never argv. Trusted single-thread CLI only.
    context = multiprocessing.get_context('fork')
    receiver, sender = context.Pipe(duplex=False)
    proc = context.Process(target=child_send, args=(sender, cfg, message, store_fd))
    started = False
    try:
        proc.start(); started = True; sender.close()
        proc.join(timeout=WORKER_SECONDS)
        if not proc.is_alive() and proc.exitcode == 0 and receiver.poll():
            value = receiver.recv()
            if value == 'sent': return 'sent'
    except (OSError, EOFError):
        pass
    finally:
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            try:
                if started:
                    if proc.is_alive(): proc.kill()
                    proc.join(timeout=2)
                    if not proc.is_alive(): proc.close()
                else:
                    proc.close()
            finally:
                sender.close(); receiver.close()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    return 'unknown'


def deliver(alert, cfg, store, *, send=False):
    item = project(alert, cfg)
    if item is None: return {'status': 'filtered', 'delivery_confirmed': False}
    if send is not True or cfg['enabled'] is not True:
        return {'status': 'preview', 'text': item['message'], 'delivery_confirmed': False}
    fd = private_dir(store)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        entries = os.listdir(fd)
        if len(entries) > 2 * MAX_RECORDS: raise ValueError('STORE_LIMIT')
        intents, terminals = {}, set()
        for name in entries:
            if not re.fullmatch(r'[0-9a-f]{64}\.(intent|terminal)\.json', name):
                raise ValueError('UNEXPECTED_STORE_ENTRY')
            eid, kind, _ = name.split('.')
            value = strict_json(read_at(fd, name))
            if kind == 'terminal':
                if not isinstance(value, dict) or set(value) != {'status'} or value['status'] not in ('sent', 'unknown'):
                    raise ValueError('INVALID_TERMINAL')
                terminals.add(eid)
            else:
                if (not isinstance(value, dict) or set(value) != {'at', 'fingerprint'}
                        or type(value['at']) not in (int, float) or not math.isfinite(value['at']) or value['at'] < 0
                        or not isinstance(value['fingerprint'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['fingerprint'])):
                    raise ValueError('INVALID_INTENT')
                intents[eid] = value
        if not terminals <= intents.keys(): raise ValueError('ORPHAN_TERMINAL')
        if item['event'] in intents:
            if intents[item['event']]['fingerprint'] != item['fingerprint']: raise ValueError('EVENT_ID_CONFLICT')
            return {'status': 'duplicate_suppressed', 'delivery_confirmed': False}
        now = time.time()
        if any(record['at'] > now for record in intents.values()): raise ValueError('CLOCK_MOVED_BACKWARD')
        if len(intents) >= cfg['max_total_attempts'] or sum(now - r['at'] < 3600 for r in intents.values()) >= cfg['max_per_hour']:
            return {'status': 'rate_limited', 'delivery_confirmed': False}
        write_once(fd, item['event'] + '.intent.json', {'at': now, 'fingerprint': item['fingerprint']})
        status = bounded_send(cfg, item['message'], fd)
        if status not in ('sent', 'unknown'): status = 'unknown'
        write_once(fd, item['event'] + '.terminal.json', {'status': status})
        return {'status': status, 'delivery_confirmed': status == 'sent'}
    finally:
        os.close(fd)


def run(alert_path, config_path, store, send):
    return deliver(alert_file(alert_path), load_config(config_path), store, send=send)


def native_args(args):
    """Wazuh4.14.1 Integrator appends debug/options/timeout/retries, not just 3 args.

    Its C splitter can leave literal redirection fields; these are inert argv,
    never shell syntax here. Private config owns all destination/retry settings.
    """
    if not args or any(v for v in args[1:3]): raise ValueError('PRIVATE_CONFIG_ONLY')
    if len(args) <= 3: return
    if len(args) < 7 or args[3] not in ('', 'debug') or args[4] != '':
        raise ValueError('UNSUPPORTED_NATIVE_ARGUMENTS')
    if any(not re.fullmatch(r'[0-9]{1,3}', v) for v in args[5:7]):
        raise ValueError('INVALID_NATIVE_LIMITS')
    if not 1 <= int(args[5]) <= 120 or not 0 <= int(args[6]) <= 100:
        raise ValueError('INVALID_NATIVE_LIMITS')
    if args[7:] not in ([], ['>', '/dev/null 2>&1'], ['>', '/dev/null', '2>&1']):
        raise ValueError('UNSUPPORTED_NATIVE_ARGUMENTS')


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if args and not args[0].startswith('-'):
            # Secrets/URLs via argv are explicitly rejected; use the private config.
            native_args(args)
            result = run(args[0], CONFIG, STORE, True)
        else:
            parser = argparse.ArgumentParser(description=__doc__)
            parser.add_argument('--alert', required=True)
            parser.add_argument('--config', default=str(CONFIG))
            parser.add_argument('--store', default=str(STORE))
            parser.add_argument('--send', action='store_true')
            parsed = parser.parse_args(args)
            result = run(parsed.alert, parsed.config, parsed.store, parsed.send)
        print(encoded(result).decode('ascii'))
        return 2 if result['status'] in ('unknown', 'rate_limited') else 0
    except (OSError, ValueError, TypeError, KeyError, OverflowError):
        print('{"status":"rejected","delivery_confirmed":false}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    def interrupted(*_):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
