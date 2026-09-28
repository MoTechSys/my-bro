#!/var/ossec/framework/python/bin/python3
"""UC-10: Telegram notification for high-severity Wazuh alerts.

Owner [CLAUDE]; 2026-09-28. Standard library only (no `requests`).
Wazuh integratord calls:  custom-telegram <alert_file> <api_key> <hook_url> [debug]
  api_key  = "<BOT_TOKEN>"        (from @BotFather; NEVER committed to Git)
  hook_url = "<CHAT_ID>"          (numeric chat/channel id, e.g. -1001234567890)
Level filtering is done by <level> in ossec.conf, so this script never decides
whether to delete/respond; it only notifies (level>=12 is not a response permission).

Safety:
- The token is read from argv (as integratord passes it) and is never logged.
- Message content is redacted (API keys, passwords, bearer tokens) and truncated.
- De-duplication: identical (rule.id, agent.id, key field) within DEDUP_SECONDS is dropped.
- Bounded network: timeout 10 s, 3 attempts with backoff, honours HTTP 429 retry_after.
Exit codes: 0 sent/deduplicated, 2 bad args, 6 alert file missing, 7 invalid JSON, 8 delivery failed.
"""
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = 'https://api.telegram.org/bot{token}/sendMessage'
MAX_TEXT = 3500                    # Telegram hard limit is 4096
DEDUP_SECONDS = 60
TIMEOUT = 10
ATTEMPTS = 3
HERE = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = os.path.join(HERE, 'logs', 'integrations.log')
STATE_FILE = os.path.join(HERE, 'tmp', 'custom-telegram.dedup.json')

TOKEN_RE = re.compile(r'^\d{5,15}:[A-Za-z0-9_-]{30,64}$')
CHAT_RE = re.compile(r'^-?\d{3,20}$|^@[A-Za-z][A-Za-z0-9_]{4,31}$')
SECRET_PATTERNS = [
    (re.compile(r'(?i)\b(pass(word)?|pwd|secret|token|api[_-]?key)\b(\s*[=:]\s*)\S+'), r'\1\3[REDACTED]'),
    (re.compile(r'(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}'), 'Bearer [REDACTED]'),
    (re.compile(r'\b\d{5,15}:[A-Za-z0-9_-]{30,64}\b'), '[REDACTED_BOT_TOKEN]'),
    (re.compile(r'\b[a-f0-9]{64}\b'), lambda m: m.group(0)[:12] + '…'),  # shorten sha256/VT keys
]


def log(line):
    try:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(time.strftime('%Y/%m/%d %H:%M:%S') + ' custom-telegram: ' + line + '\n')
    except OSError:
        pass


def redact(text):
    text = str(text)
    for pattern, repl in SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def get(d, path, default='-'):
    for key in path.split('.'):
        if not isinstance(d, dict) or key not in d:
            return default
        d = d[key]
    return d


def key_field(alert):
    for path in ('data.srcip', 'syscheck.path', 'data.virustotal.source.file',
                 'data.url', 'data.audit.exe', 'data.yara_scanned_file'):
        value = get(alert, path, None)
        if value not in (None, '', '-'):
            return str(value)
    return ''


def build_message(alert):
    rule = alert.get('rule', {})
    mitre = ', '.join(get(alert, 'rule.mitre.id', []) or []) or '-'
    lines = [
        f"🚨 <b>Wazuh alert — level {html.escape(str(rule.get('level', '?')))}</b>",
        f"<b>Rule:</b> {html.escape(str(rule.get('id', '?')))} — {html.escape(redact(rule.get('description', '')))}",
        f"<b>Agent:</b> {html.escape(str(get(alert, 'agent.name')))} ({html.escape(str(get(alert, 'agent.id')))})",
        f"<b>MITRE:</b> {html.escape(mitre)}",
        f"<b>Time:</b> {html.escape(str(alert.get('timestamp', '-')))}",
    ]
    key = key_field(alert)
    if key:
        lines.append(f"<b>Object:</b> <code>{html.escape(redact(key))[:300]}</code>")
    src = get(alert, 'data.srcip', None)
    if src and src != key:
        lines.append(f"<b>Source IP:</b> <code>{html.escape(str(src))}</code>")
    full_log = alert.get('full_log')
    if full_log:
        lines.append(f"<pre>{html.escape(redact(full_log))[:900]}</pre>")
    text = '\n'.join(lines)
    return text[:MAX_TEXT]


def fingerprint(alert):
    raw = '|'.join((str(get(alert, 'rule.id')), str(get(alert, 'agent.id')), key_field(alert)))
    return hashlib.sha256(raw.encode()).hexdigest()


def is_duplicate(fp, now=None, state_file=STATE_FILE):
    now = now or time.time()
    try:
        with open(state_file, encoding='utf-8') as f:
            state = json.load(f)
        if not isinstance(state, dict):
            state = {}
    except (OSError, ValueError):
        state = {}
    state = {k: v for k, v in state.items() if isinstance(v, (int, float)) and now - v < DEDUP_SECONDS}
    duplicate = fp in state
    if not duplicate:
        state[fp] = now
    try:
        tmp = state_file + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(state, f)
        os.replace(tmp, state_file)
    except OSError:
        pass
    return duplicate


def send(token, chat_id, text, opener=urllib.request.urlopen, sleep=time.sleep):
    body = urllib.parse.urlencode({'chat_id': chat_id, 'text': text, 'parse_mode': 'HTML',
                                   'disable_web_page_preview': 'true'}).encode()
    url = API.format(token=token)
    last = 'unknown'
    for attempt in range(1, ATTEMPTS + 1):
        try:
            req = urllib.request.Request(url, data=body, method='POST',
                                         headers={'Content-Type': 'application/x-www-form-urlencoded'})
            with opener(req, timeout=TIMEOUT) as resp:
                payload = json.loads(resp.read().decode('utf-8') or '{}')
                if payload.get('ok'):
                    return True, attempt
                last = f"api ok=false: {payload.get('description', '')[:120]}"
        except urllib.error.HTTPError as e:
            last = f'HTTP {e.code}'
            if e.code == 429:
                try:
                    wait = int(json.loads(e.read().decode()).get('parameters', {}).get('retry_after', 2))
                except Exception:
                    wait = 2
                sleep(min(wait, 10))
                continue
            if 400 <= e.code < 500:
                break          # bad token/chat: retrying will not help
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            last = type(e).__name__
        sleep(2 ** (attempt - 1))
    log('delivery failed: ' + last)       # never includes the token
    return False, ATTEMPTS


def main(argv, opener=urllib.request.urlopen, sleep=time.sleep, state_file=STATE_FILE):
    if len(argv) < 4:
        log('bad arguments')
        return 2
    alert_file, token, chat_id = argv[1], argv[2], argv[3]
    if not TOKEN_RE.match(token or '') or not CHAT_RE.match(chat_id or ''):
        log('invalid bot token or chat id format (values not logged)')
        return 2
    try:
        with open(alert_file, encoding='utf-8') as f:
            alert = json.load(f)
    except FileNotFoundError:
        log('alert file not found')
        return 6
    except ValueError:
        log('invalid alert JSON')
        return 7
    if is_duplicate(fingerprint(alert), state_file=state_file):
        log(f"deduplicated rule {get(alert, 'rule.id')}")
        return 0
    ok, attempts = send(token, chat_id, build_message(alert), opener, sleep)
    if ok:
        log(f"sent rule {get(alert, 'rule.id')} level {get(alert, 'rule.level')} in {attempts} attempt(s)")
        return 0
    return 8


if __name__ == '__main__':
    sys.exit(main(sys.argv))
