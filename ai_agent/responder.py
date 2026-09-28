"""L3 human-in-the-loop responder (owner [CLAUDE], 2026-09-28).

The AI analyst only *proposes*. This module:
  1. validates a proposal against analyst.ACTIONS (allowlist) and strict parameter formats;
  2. refuses protected targets (management IPs, root/wazuh accounts, paths outside approved roots);
  3. requires an explicit human approval (interactive "yes" or --approve with the proposal hash);
  4. executes ONLY through the official Wazuh API  PUT /active-response  (no shell);
  5. writes an append-only JSONL audit trail (who, what, when, hash, API result).
"""
import hashlib
import ipaddress
import json
import os
import re
import ssl
import time
import urllib.request
from pathlib import Path

try:
    from .analyst import ACTIONS
except ImportError:
    from analyst import ACTIONS

AUDIT = Path(os.environ.get('SOC_AI_AUDIT', Path(__file__).resolve().parent / 'audit.jsonl'))
PROTECTED_NETS = [ipaddress.ip_network(n) for n in
                  os.environ.get('SOC_PROTECTED_NETS', '127.0.0.0/8,198.51.100.10/32').split(',') if n]
PROTECTED_USERS = {'root', 'wazuh', 'administrator', 'system'}
FILE_ROOTS = ('/home/kali/SOCfile/', '/tmp/yara/malware/', 'c:\\users\\')
USER_RE = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}$', re.I)


class Refused(ValueError):
    pass


def proposal_hash(p):
    canon = json.dumps({'action': p['action'], 'params': p.get('params', {})}, sort_keys=True)
    return hashlib.sha256(canon.encode()).hexdigest()[:16]


def validate(p):
    action = p.get('action')
    if action not in ACTIONS:
        raise Refused(f'action {action!r} is not in the allowlist')
    spec = ACTIONS[action]
    params = p.get('params') or {}
    extra = set(params) - ({spec['needs']} if spec['needs'] else set())
    if extra:
        raise Refused(f'unexpected parameters {sorted(extra)}')
    if spec['needs'] == 'srcip':
        try:
            ip = ipaddress.ip_address(params.get('srcip', ''))
        except ValueError:
            raise Refused('srcip is not a valid IP address')
        if any(ip in n for n in PROTECTED_NETS):
            raise Refused(f'{ip} is a protected management address')
    elif spec['needs'] == 'user':
        u = params.get('user', '')
        if not USER_RE.match(u) or u.lower() in PROTECTED_USERS:
            raise Refused(f'user {u!r} is invalid or protected')
    elif spec['needs'] == 'file':
        f = params.get('file', '')
        if '..' in f or not f.lower().startswith(FILE_ROOTS) or any(ord(c) < 32 for c in f):
            raise Refused('file outside approved monitored roots')
    return spec


def audit(record):
    AUDIT.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(dict(record, ts=time.strftime('%Y-%m-%dT%H:%M:%S%z')), ensure_ascii=False) + '\n')


class WazuhAPI:
    def __init__(self, url=None, user=None, password=None, verify_tls=False, opener=None):
        self.url = (url or os.environ.get('WAZUH_API_URL', 'https://127.0.0.1:55000')).rstrip('/')
        self.user = user or os.environ.get('WAZUH_API_USER', 'wazuh')
        self.password = password or os.environ.get('WAZUH_API_PASSWORD', '')
        self.ctx = ssl.create_default_context()
        if not verify_tls:           # lab uses the self-signed certificate generated at install
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.opener = opener or (lambda req, timeout: urllib.request.urlopen(req, timeout=timeout, context=self.ctx))
        self._token = None

    def _req(self, method, path, body=None, auth=None):
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = auth
        elif self._token:
            headers['Authorization'] = 'Bearer ' + self._token
        req = urllib.request.Request(self.url + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        with self.opener(req, timeout=20) as r:
            return json.loads(r.read().decode())

    def login(self):
        import base64
        basic = 'Basic ' + base64.b64encode(f'{self.user}:{self.password}'.encode()).decode()
        self._token = self._req('POST', '/security/user/authenticate', auth=basic)['data']['token']

    def active_response(self, command, agents, arguments=(), alert=None):
        if not self._token:
            self.login()
        body = {'command': command, 'arguments': list(arguments)}
        if alert:
            body['alert'] = alert
        q = ','.join(agents)
        return self._req('PUT', f'/active-response?agents_list={q}', body)


def build_ar_alert(action, params):
    """Minimal alert JSON so the stock AR scripts find their fields (data.srcip / dstuser)."""
    if action == 'block_ip':
        return {'data': {'srcip': params['srcip']}}
    if action == 'disable_account':
        return {'data': {'dstuser': params['user']}}
    return None


def execute(proposal, agent_id, approver, approved_hash, api=None, dry_run=False):
    """Execute one approved proposal. approved_hash must equal proposal_hash(proposal)."""
    h = proposal_hash(proposal)
    rec = {'proposal': proposal, 'hash': h, 'agent': agent_id, 'approver': approver}
    try:
        spec = validate(proposal)
        if not approver or not re.match(r'^[\w.@-]{2,64}$', approver):
            raise Refused('a named human approver is required')
        if approved_hash != h:
            raise Refused('approval hash mismatch (proposal changed after review)')
        if not re.fullmatch(r'\d{3,5}', str(agent_id)):
            raise Refused('agent id must be numeric, e.g. 001')
    except Refused as e:
        audit(dict(rec, result='refused', reason=str(e)))
        raise
    if spec['command'] is None:
        audit(dict(rec, result='noop'))
        return {'result': 'noop', 'hash': h}
    if proposal['action'] == 'quarantine_file':
        # Deletion needs the VirusTotal/YARA alert context that soc_ar.py re-verifies (hash).
        audit(dict(rec, result='refused', reason='file quarantine must come from a real 87105 alert (use AR)'))
        raise Refused('quarantine_file is executed by the automatic AR on rule 87105, not manually')
    if dry_run:
        audit(dict(rec, result='dry_run'))
        return {'result': 'dry_run', 'hash': h}
    api = api or WazuhAPI()
    alert = build_ar_alert(proposal['action'], proposal['params'])
    command = spec['command'] + (str(spec['timeout']) if spec.get('timeout') else '')
    # Wazuh 4.14 API: "!<script>" runs the AR executable directly; a bare name must match an
    # ossec.conf <command> block, otherwise error 1652 (verified live 2026-09-28).
    resp = api.active_response('!' + spec['command'], [str(agent_id)], alert=alert)
    data = resp.get('data', {})
    # Wazuh returns error=0 with total_affected_items=0 when nothing was sent (e.g. agent 000,
    # disconnected agent): that is NOT success.
    ok = (resp.get('error', 1) == 0 and data.get('total_failed_items', 1) == 0
          and data.get('total_affected_items', 0) >= 1)
    audit(dict(rec, result='executed' if ok else 'api_error', api=resp.get('message'), command=command))
    return {'result': 'executed' if ok else 'api_error', 'hash': h, 'api': resp}
