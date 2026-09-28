"""T-70 AI analyst tests: grounding guard, correlation, L3 allowlist, responder safety.

No network: the LLM is a fake object; the Wazuh API is a fake opener.
"""
import json
import os
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'ai_agent'))
import analyst as A  # noqa: E402
import responder as R  # noqa: E402
from knowledge import KnowledgeBase  # noqa: E402

KB = KnowledgeBase()


def alert(rid, level, ts, desc='x', data=None, agent='kali1', mitre=None, groups=None, syscheck=None):
    a = {'timestamp': ts, 'rule': {'id': rid, 'level': level, 'description': desc,
                                   'groups': groups or []}, 'agent': {'id': '001', 'name': agent}}
    if mitre:
        a['rule']['mitre'] = {'id': mitre}
    if data:
        a['data'] = data
    if syscheck:
        a['syscheck'] = syscheck
    return a


class FakeLLM:
    def __init__(self, answer=None, exc=None):
        self.answer, self.exc, self.calls, self.model = answer, exc, [], 'fake'

    enabled = True

    def chat(self, system, user):
        self.calls.append(json.loads(user))
        if self.exc:
            raise self.exc
        return self.answer(json.loads(user)) if callable(self.answer) else self.answer


class Off:
    enabled = False
    model = 'off'


BRUTE = [alert('5710', 5, f'2026-09-28T10:00:0{i}.000+0000', data={'srcip': '10.0.0.66', 'dstuser': f'u{i}'},
               mitre=['T1110.001']) for i in range(7)] + \
        [alert('5712', 10, '2026-09-28T10:00:08.000+0000', data={'srcip': '10.0.0.66'}, mitre=['T1110']),
         alert('651', 3, '2026-09-28T10:00:09.000+0000',
               data={'srcip': '10.0.0.66', 'parameters': {'alert': {'data': {'srcip': '10.0.0.66'}}}})]
MALWARE = [alert('100201', 7, '2026-09-28T11:00:00.000+0000', syscheck={'path': '/home/kali/SOCfile/m.bin'}),
           alert('87105', 12, '2026-09-28T11:00:03.000+0000', mitre=['T1203'],
                 data={'virustotal': {'source': {'file': '/home/kali/SOCfile/m.bin'}}}),
           alert('100092', 12, '2026-09-28T11:00:04.000+0000', data={'parameters': {'alert': {
               'data': {'virustotal': {'source': {'file': '/home/kali/SOCfile/m.bin'}}}}}})]
NOISE = [alert('19007', 7, '2026-09-28T10:00:05.000+0000', groups=['sca']),
         alert('510', 7, '2026-09-28T10:00:05.000+0000', groups=['rootcheck'])]


class Knowledge(unittest.TestCase):
    def test_loads_project_and_builtin_rules(self):
        self.assertEqual(KB.rule_info('100404')['level'], 12)
        self.assertIn('5712', KB.builtin)
        self.assertIsNone(KB.rule_info('999999'))

    def test_mitre_from_official_source_includes_revoked_mapping(self):
        self.assertEqual(KB.technique('T1110')['name'], 'Brute Force')
        self.assertEqual(KB.technique('T1562.004')['revoked_by'], 'T1686')

    def test_bm25_retrieves_relevant(self):
        top = KB.search('ssh brute force non existent user', k=3)
        self.assertTrue(any(d['id'] in ('rule:5712', 'mitre:T1110') for d in top), top)

    def test_every_rule_mitre_id_is_known(self):
        for rid, r in KB.rules.items():
            for t in r['mitre']:
                self.assertIsNotNone(KB.technique(t), f'{rid}->{t} missing from MITRE KB')


class L1Explain(unittest.TestCase):
    def test_offline_deterministic(self):
        out = A.Analyst(KB, Off()).explain(BRUTE[7])
        self.assertEqual(out['mode'], 'deterministic')
        self.assertEqual(out['severity'], 'high')
        self.assertIn('rule:5712', out['citations'])
        self.assertIn('T1110 Brute Force', out['mitre'])

    def test_grounded_llm_answer_accepted(self):
        good = {'summary': 's', 'severity': 'high', 'why': 'w', 'mitre': ['T1110'], 'next_steps': ['n'],
                'citations': ['rule:5712', 'mitre:T1110']}
        out = A.Analyst(KB, FakeLLM(good)).explain(BRUTE[7])
        self.assertEqual(out['mode'], 'llm')

    def test_hallucinated_citation_rejected(self):
        bad = {'summary': 's', 'severity': 'high', 'why': 'w', 'mitre': ['T1110'], 'next_steps': [],
               'citations': ['rule:424242']}
        out = A.Analyst(KB, FakeLLM(bad)).explain(BRUTE[7])
        self.assertEqual(out['mode'], 'deterministic')
        self.assertEqual(out['llm_rejected']['bad_citations'], ['rule:424242'])

    def test_invented_mitre_rejected(self):
        bad = {'summary': 'this is T9999', 'severity': 'high', 'why': 'w', 'mitre': ['T9999'],
               'next_steps': [], 'citations': ['rule:5712']}
        out = A.Analyst(KB, FakeLLM(bad)).explain(BRUTE[7])
        self.assertEqual(out['llm_rejected']['unknown_mitre'], ['T9999'])

    def test_missing_keys_or_errors_fall_back(self):
        a = A.Analyst(KB, FakeLLM({'summary': 'only'}))
        self.assertEqual(a.explain(BRUTE[7])['mode'], 'deterministic')
        a = A.Analyst(KB, FakeLLM(exc=TimeoutError()))
        out = a.explain(BRUTE[7])
        self.assertEqual((out['mode'], out['llm_error']), ('deterministic', 'TimeoutError'))

    def test_secrets_redacted_before_llm(self):
        llm = FakeLLM({'summary': 's', 'severity': 'low', 'why': 'w', 'mitre': [], 'next_steps': [],
                       'citations': ['rule:5712']})
        a = alert('5712', 10, '2026-09-28T10:00:00', data={'srcip': '1.2.3.4'})
        a['full_log'] = 'password=hunter2 token: abc123456789 Bearer eyJhbGciOiJ.x.y'
        A.Analyst(KB, llm).explain(a)
        sent = json.dumps(llm.calls[0])
        self.assertNotIn('hunter2', sent)
        self.assertNotIn('abc123456789', sent)
        self.assertNotIn('eyJhbGciOiJ', sent)


class L2Correlate(unittest.TestCase):
    def setUp(self):
        self.a = A.Analyst(KB, Off())

    def test_chains_by_entity_and_joins_response(self):
        incs = self.a.correlate(BRUTE + MALWARE + NOISE)
        self.assertEqual(len(incs), 2, [i['rules'] for i in incs])
        ssh = next(i for i in incs if 'srcip=10.0.0.66' in i['entities'])
        self.assertEqual(ssh['rules'], ['5710', '5712', '651'])
        self.assertTrue(ssh['auto_response_seen'])
        self.assertIn('credential-access', ssh['kill_chain'])
        mal = next(i for i in incs if 'file=/home/kali/SOCfile/m.bin' in i['entities'])
        self.assertEqual(mal['rules'], ['100201', '87105', '100092'])

    def test_noise_excluded(self):
        self.assertEqual(self.a.correlate(NOISE), [])

    def test_time_window_splits(self):
        late = alert('5712', 10, '2026-09-28T12:00:00.000+0000', data={'srcip': '10.0.0.66'})
        incs = self.a.correlate(BRUTE + [late], window_s=900)
        self.assertEqual(len(incs), 2)

    def test_kill_chain_order_follows_attack_tactics(self):
        mt = [alert('100411', 10, '2026-09-28T10:00:00', data={'srcip': '9.9.9.9'}, mitre=['T1046']),
              alert('100402', 10, '2026-09-28T10:01:00', data={'srcip': '9.9.9.9'}, mitre=['T1110.001']),
              alert('100404', 12, '2026-09-28T10:02:00', data={'srcip': '9.9.9.9', 'dstuser': 'admin'}, mitre=['T1078'])]
        inc = self.a.correlate(mt)[0]
        chain = inc['kill_chain']
        self.assertLess(chain.index('initial-access'), chain.index('credential-access'))
        self.assertLess(chain.index('credential-access'), chain.index('discovery'))
        self.assertGreaterEqual(inc['risk_score'], 90)


class L3Suggest(unittest.TestCase):
    def setUp(self):
        self.a = A.Analyst(KB, Off())

    def test_router_compromise_proposes_block_disable_notify(self):
        mt = [alert('100402', 10, '2026-09-28T10:01:00', data={'srcip': '9.9.9.9'}),
              alert('100404', 12, '2026-09-28T10:02:00', data={'srcip': '9.9.9.9', 'dstuser': 'admin'})]
        inc = self.a.correlate(mt)[0]
        acts = [p['action'] for p in self.a.suggest(inc, mt)['proposals']]
        self.assertEqual(acts, ['block_ip', 'disable_account', 'notify'])

    def test_already_handled_not_reblocked(self):
        inc = next(i for i in self.a.correlate(BRUTE) if i['auto_response_seen'])
        acts = [p['action'] for p in self.a.suggest(inc, BRUTE)['proposals']]
        self.assertNotIn('block_ip', acts)

    def test_params_come_only_from_incident_members(self):
        # Regression: an unrelated earlier alert with another IP must never be proposed.
        other = alert('5712', 10, '2026-09-28T09:00:00', data={'srcip': '203.0.113.77'})
        mt = [alert('100402', 10, '2026-09-28T10:01:00', data={'srcip': '9.9.9.9'}),
              alert('100403', 3, '2026-09-28T10:01:30', data={'srcip': '9.9.9.9', 'dstuser': 'admin'}),
              alert('100404', 12, '2026-09-28T10:02:00', data={'srcip': '9.9.9.9', 'dstuser': 'admin'})]
        incs = self.a.correlate([other] + mt, min_level=5)
        inc = next(i for i in incs if 'srcip=9.9.9.9' in i['entities'])
        props = {p['action']: p['params'] for p in self.a.suggest(inc)['proposals']}
        self.assertEqual(props['block_ip'], {'srcip': '9.9.9.9'})
        self.assertEqual(props['disable_account'], {'user': 'admin'})

    def test_llm_can_only_rank_never_add(self):
        mt = [alert('100402', 10, '2026-09-28T10:01:00', data={'srcip': '9.9.9.9'})]
        inc = self.a.correlate(mt)[0]
        llm = FakeLLM({'ranking': ['rm_rf_everything', 'notify', 'block_ip'], 'rationale': 'r',
                       'citations': ['rule:100402']})
        res = A.Analyst(KB, llm).suggest(inc, mt)
        self.assertEqual([p['action'] for p in res['proposals']], ['notify', 'block_ip'])
        self.assertTrue(all(p['action'] in A.ACTIONS for p in res['proposals']))


class FakeAPI:
    def __init__(self):
        self.calls = []

    def active_response(self, command, agents, arguments=(), alert=None):
        self.calls.append((command, agents, alert))
        return self.reply

    reply = {'error': 0, 'data': {'total_affected_items': 1, 'total_failed_items': 0}, 'message': 'AR command was sent'}


class Responder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        R.AUDIT = pathlib.Path(self.tmp.name) / 'audit.jsonl'

    def tearDown(self):
        self.tmp.cleanup()

    def audit(self):
        return [json.loads(x) for x in R.AUDIT.read_text().splitlines()]

    def prop(self, action='block_ip', **params):
        return {'action': action, 'params': params or {'srcip': '10.0.0.66'}}

    def test_approved_block_calls_wazuh_api(self):
        p, api = self.prop(), FakeAPI()
        out = R.execute(p, '001', 'omar', R.proposal_hash(p), api=api)
        self.assertEqual(out['result'], 'executed')
        self.assertEqual(api.calls, [('!firewall-drop', ['001'], {'data': {'srcip': '10.0.0.66'}})])
        self.assertEqual(self.audit()[-1]['result'], 'executed')

    def test_refusals(self):
        api = FakeAPI()
        cases = [
            (self.prop(), '001', 'omar', 'wronghash'),                          # tampered after review
            (self.prop(), '001', '', None),                                     # no human
            (self.prop(srcip='127.0.0.1'), '001', 'omar', None),                # protected
            (self.prop(srcip='198.51.100.10'), '001', 'omar', None),            # management IP
            (self.prop(srcip='1.2.3.4; rm -rf /'), '001', 'omar', None),        # injection
            ({'action': 'shell', 'params': {'cmd': 'id'}}, '001', 'omar', None),  # not allowlisted
            (self.prop('disable_account', user='root'), '001', 'omar', None),
            (self.prop('block_ip', srcip='10.0.0.1', extra='x'), '001', 'omar', None),
            (self.prop(), '001;x', 'omar', None),
            (self.prop('quarantine_file', file='/etc/passwd'), '001', 'omar', None),
        ]
        for p, agent, who, h in cases:
            with self.subTest(p=p, agent=agent, who=who):
                with self.assertRaises(R.Refused):
                    R.execute(p, agent, who, h or R.proposal_hash(p), api=api)
        self.assertEqual(api.calls, [])
        self.assertEqual({r['result'] for r in self.audit()}, {'refused'})

    def test_nothing_sent_is_not_success(self):
        # Real Wazuh 4.14.7 reply for agents_list=000 (manager): error 0 but 0 affected items.
        p, api = self.prop(), FakeAPI()
        api.reply = {'error': 0, 'message': 'AR command was not sent to any agent',
                     'data': {'affected_items': [], 'total_affected_items': 0, 'total_failed_items': 0}}
        self.assertEqual(R.execute(p, '001', 'omar', R.proposal_hash(p), api=api)['result'], 'api_error')

    def test_notify_is_noop_and_dry_run(self):
        p = {'action': 'notify', 'params': {}}
        self.assertEqual(R.execute(p, '001', 'omar', R.proposal_hash(p))['result'], 'noop')
        q = self.prop()
        api = FakeAPI()
        self.assertEqual(R.execute(q, '001', 'omar', R.proposal_hash(q), api=api, dry_run=True)['result'], 'dry_run')
        self.assertEqual(api.calls, [])


if __name__ == '__main__':
    unittest.main()
