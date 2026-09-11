"""Pinned knowledge/inventory regressions; AI, 2026-09-11. No network or native lab."""
from datetime import datetime, timedelta, timezone
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('knowledge_tests_module', ROOT / 'ai_agent/knowledge.py')
k = importlib.util.module_from_spec(spec); spec.loader.exec_module(k)
a = k.a
NOW = datetime(2026, 9, 11, 13, tzinfo=timezone.utc)
RULES = (ROOT / 'wazuh/manager/rules/local_rules.xml').read_text()
PACK = (ROOT / 'ai_agent/mitre_subset.json').read_text()


def records(rule='100051', manager='private-manager', agent='001'):
    return [{'id': 'private-event', 'timestamp': '2026-09-11T12:00:00Z',
             'manager': {'name': manager}, 'agent': {'id': agent},
             'rule': {'id': rule, 'level': 12}}]


def inventory():
    return {'schema_version': 1, 'as_of': NOW.isoformat(), 'assets': [
        {'manager': 'private-manager', 'agent_id': '001', 'os_family': 'linux',
         'os_version': '24.04.4', 'deployment': 'container', 'role': 'endpoint',
         'source_ref': 'private-audit-001'}]}


def enrich(rows=None, rules=RULES, inv=None):
    rows = records() if rows is None else rows
    text = None if inv is None else json.dumps(inv)
    return k.enrich(a.prepare(rows, a.load_rules(rules)), rules, rows,
                    text, None if text is None else k.digest(text), now=NOW)


class PinnedKnowledge(unittest.TestCase):
    def test_pack_hash_release_and_license(self):
        pack = k.load_pack(PACK)
        self.assertEqual(k.digest(PACK), k.PACK_SHA256)
        self.assertEqual(pack['source']['release'], 'v19.2')
        self.assertEqual(pack['source']['commit'], k.UPSTREAM_COMMIT)
        self.assertEqual(k.digest(pack['license']['text']), pack['license']['sha256'])
        self.assertIn('2026 The MITRE Corporation', pack['license']['text'])

    def test_only_current_rule_techniques_are_in_subset(self):
        self.assertEqual({v['technique_id'] for v in k.load_pack(PACK)['techniques']},
                         {'T1059', 'T1204.002', 'T1571'})

    def test_tampered_pack_rejected_even_if_json_valid(self):
        with self.assertRaisesRegex(ValueError, 'HASH_MISMATCH'):
            k.load_pack(PACK.replace('Non-Standard Port', 'arbitrary instruction'))

    def test_exact_retrieval_does_not_dump_all_documents(self):
        value = enrich()
        self.assertEqual([d['technique_id'] for d in value['mitre_documents']], ['T1571'])
        self.assertEqual(value['mitre_missing_ids'], [])
        self.assertEqual(value['inventory']['status'], 'not_supplied')

    def test_curated_notes_explain_mapping_limits(self):
        value = enrich()
        self.assertIn('does not prove', value['knowledge'][0]['explanation'])
        yara = enrich(records('108001'))
        self.assertIn('user execution', yara['knowledge'][0]['explanation'])
        self.assertTrue(yara['knowledge'][0]['annotation_is_not_behavior_proof'])

    def test_curated_notes_require_exact_ruleset_hash(self):
        value = enrich(rules=RULES + '\n')
        self.assertFalse(value['knowledge_provenance']['curated_rule_notes_applied'])
        self.assertNotIn('explanation', value['knowledge'][0])

    def test_unknown_mitre_is_missing_not_invented(self):
        rules = '<group><rule id="1"><mitre><id>T9999</id></mitre></rule></group>'
        value = enrich(records('1'), rules)
        self.assertEqual(value['mitre_documents'], [])
        self.assertEqual(value['mitre_missing_ids'], ['T9999'])
        raw = json.dumps({'findings': [{'evidence_refs': ['A1'], 'classification': 'suspicious',
                          'assessment': 'Advice', 'mitre_ids': ['T9999'], 'recommendation': 'investigate'}]})
        with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_MITRE_MAPPING'): a.validate_response(raw, value)

    def test_server_adds_validated_mitre_citation(self):
        value = enrich()
        raw = json.dumps({'findings': [{'evidence_refs': ['A1'], 'classification': 'insufficient_evidence',
                          'assessment': 'Needs protocol evidence.', 'mitre_ids': ['T1571'], 'recommendation': 'investigate'}]})
        self.assertEqual(a.validate_response(raw, value)[0]['knowledge_refs'], ['mitre:T1571', 'rule:100051'])

    def test_description_excerpts_explicitly_bounded(self):
        value = enrich(records('100210'))
        self.assertLessEqual(len(value['mitre_documents'][0]['description_excerpt']), 1600)
        self.assertIn('excerpt_truncated', value['mitre_documents'][0])

    def test_enrichment_does_not_mutate_inputs(self):
        rows = records(); ctx = a.prepare(rows, a.load_rules(RULES))
        before = copy.deepcopy(ctx)
        value = k.enrich(ctx, RULES, rows)
        self.assertEqual(ctx, before)
        value['knowledge'].clear(); self.assertEqual(ctx, before)

    def test_enriched_context_size_is_enforced(self):
        rows = records(); ctx = a.prepare(rows, a.load_rules(RULES))
        with patch.object(a, 'MAX_CONTEXT', 10), self.assertRaisesRegex(ValueError, 'ENRICHED_CONTEXT_TOO_LARGE'):
            k.enrich(ctx, RULES, rows)


class Inventory(unittest.TestCase):
    def load(self, value, digest=None):
        text = json.dumps(value)
        return k.load_inventory(text, k.digest(text) if digest is None else digest, NOW)

    def test_fresh_inventory_is_projected_without_identity_or_source_text(self):
        value = enrich(inv=inventory())
        projected = value['inventory']
        text = json.dumps(value)
        self.assertEqual(projected['status'], 'operator_declared_snapshot')
        self.assertFalse(projected['historical_event_state_verified'])
        self.assertEqual(projected['assets'][0]['os_family'], 'linux')
        for secret in ('private-manager', 'private-audit-001', 'private-event'):
            self.assertNotIn(secret, text)
        self.assertEqual(projected['unmatched_agent_refs'], [])

    def test_inventory_requires_approved_hash(self):
        for digest in ('', '0' * 64, 'not-a-hash'):
            with self.assertRaisesRegex(ValueError, 'HASH_REQUIRED_OR_MISMATCH'): self.load(inventory(), digest)

    def test_missing_file_and_missing_hash_rejected(self):
        rows = records(); ctx = a.prepare(rows, a.load_rules(RULES))
        with self.assertRaises(ValueError): k.enrich(ctx, RULES, rows, inventory_sha256='0' * 64)
        with self.assertRaises(ValueError): k.enrich(ctx, RULES, rows, json.dumps(inventory()))

    def test_stale_future_naive_timestamps_rejected(self):
        for at in (NOW - timedelta(seconds=86401), NOW + timedelta(seconds=1), NOW.replace(tzinfo=None)):
            value = inventory(); value['as_of'] = at.isoformat()
            with self.assertRaises(ValueError): self.load(value)
        value = inventory(); value['as_of'] = (NOW - timedelta(days=1)).isoformat()
        self.load(value)

    def test_unknown_fields_are_not_forwarded(self):
        for top_level in (True, False):
            value = inventory()
            target = value if top_level else value['assets'][0]
            target['password'] = 'must-not-forward'
            with self.assertRaises(ValueError): self.load(value)

    def test_duplicate_or_invalid_assets_rejected(self):
        value = inventory(); value['assets'] *= 2
        with self.assertRaises(ValueError): self.load(value)
        for field, invalid in (('os_family', 'secret'), ('role', 'admin'), ('deployment', 'invalid'),
                               ('source_ref', 'https://private.invalid'), ('os_version', 'unsafe value')):
            value = inventory(); value['assets'][0][field] = invalid
            with self.assertRaises(ValueError): self.load(value)

    def test_asset_match_includes_manager(self):
        value = enrich(records(manager='other-manager'), inv=inventory())
        self.assertEqual(value['inventory']['assets'], [])
        self.assertEqual(len(value['inventory']['unmatched_agent_refs']), 1)

    def test_empty_and_wrong_version_rejected(self):
        for assets in ([], 'bad', [{}] * 101):
            value = inventory(); value['assets'] = assets
            with self.assertRaises(ValueError): self.load(value)
        value = inventory(); value['schema_version'] = True
        with self.assertRaises(ValueError): self.load(value)


if __name__ == '__main__':
    unittest.main()
