"""Pinned, offline knowledge retrieval; AI, 2026-09-11; ADR-014.

MITRE subset provenance is checked against a code-reviewed digest. Inventory is
optional, private, exact-keyed, freshness-bounded and operator-declared, not signed.
"""
import hashlib
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
import re

_spec = importlib.util.spec_from_file_location('_knowledge_contracts', Path(__file__).with_name('analyst.py'))
a = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(a)

PACK_SHA256 = '50b6e920cceaf9a1548495f86b51621f4b324702fc026da279438fd7e4ae61e3'
RULES_SHA256 = '98154bbac8c95fddec70a5223253a46e1e8f716e40768662b420d3519d00443d'
UPSTREAM_COMMIT = '6cda5ad8462c79e14fbb872f4e09059b18e0cfc4'
RULE_NOTES = {
    '100200': 'Configured FIM path: file modification observed; cause and intent are not established.',
    '100201': 'Configured FIM path: file addition observed; content safety is not established.',
    '100092': 'Active-response log reports removal; independent file-state confirmation is still required.',
    '100093': 'Active-response log reports a removal error; do not claim successful remediation.',
    '100210': 'Audit command matched the configured red list; a command match alone does not establish malicious intent.',
    '100300': 'File modification in a configured YARA-monitored location; this is not a positive scan result.',
    '100301': 'File addition in a configured YARA-monitored location; this is not a positive scan result.',
    '100303': 'File modification in a configured Windows monitored location; native scan acceptance is separate.',
    '100304': 'File addition in a configured Windows monitored location; native scan acceptance is separate.',
    '108000': 'YARA decoder grouping rule, not a positive finding by itself.',
    '108001': 'YARA rule reports a pattern match. T1204.002 additionally requires user execution, which this match alone does not prove.',
    '100050': 'Process-list grouping rule, not a suspicious listener finding by itself.',
    '100051': 'Netcat listener pattern matched. T1571 concerns non-standard protocol/port pairings; a listener alone does not prove that behavior.',
}


def digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def load_pack(text):
    if digest(text) != PACK_SHA256:
        raise ValueError('KNOWLEDGE_PACK_HASH_MISMATCH')
    pack = a.strict_json(text)
    if type(pack.get('schema_version')) is not int or pack['schema_version'] != 1:
        raise ValueError('INVALID_KNOWLEDGE_SCHEMA')
    source = pack['source']
    if source['commit'] != UPSTREAM_COMMIT or source['release'] != 'v19.2':
        raise ValueError('UNEXPECTED_KNOWLEDGE_SOURCE')
    entries = pack['techniques']
    ids = [item['technique_id'] for item in entries]
    if len(set(ids)) != len(ids) or not entries:
        raise ValueError('INVALID_KNOWLEDGE_IDS')
    for item in entries:
        tid = item['technique_id']
        if not a.TECHNIQUE.fullmatch(tid) or item['url'] != 'https://attack.mitre.org/techniques/' + tid.replace('.', '/'):
            raise ValueError('INVALID_KNOWLEDGE_REFERENCE')
    return pack


def load_inventory(text, expected_sha256, now=None):
    if (not isinstance(expected_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', expected_sha256)
            or digest(text) != expected_sha256):
        raise ValueError('INVENTORY_HASH_REQUIRED_OR_MISMATCH')
    value = a.strict_json(text)
    if not isinstance(value, dict) or set(value) != {'schema_version', 'as_of', 'assets'}:
        raise ValueError('INVALID_INVENTORY_SCHEMA')
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('INVALID_INVENTORY_VERSION')
    at = datetime.fromisoformat(a.timestamp(value['as_of']))
    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None or not 0 <= (current - at).total_seconds() <= 86400:
        raise ValueError('INVENTORY_STALE_OR_FUTURE')
    assets = value['assets']
    if not isinstance(assets, list) or not 1 <= len(assets) <= a.MAX_ALERTS:
        raise ValueError('INVALID_INVENTORY_ASSET_COUNT')
    keys = {'manager', 'agent_id', 'os_family', 'os_version', 'deployment', 'role', 'source_ref'}
    seen = set()
    for item in assets:
        if not isinstance(item, dict) or set(item) != keys:
            raise ValueError('INVALID_INVENTORY_ASSET')
        identity = (a.text_value(item['manager']), a.text_value(item['agent_id']))
        if identity in seen:
            raise ValueError('DUPLICATE_INVENTORY_ASSET')
        seen.add(identity)
        if item['os_family'] not in ('linux', 'windows', 'network', 'unknown'):
            raise ValueError('INVALID_INVENTORY_OS')
        if item['deployment'] not in ('container', 'vm', 'physical', 'unknown'):
            raise ValueError('INVALID_INVENTORY_DEPLOYMENT')
        if item['role'] not in ('endpoint', 'server', 'network_device', 'unknown'):
            raise ValueError('INVALID_INVENTORY_ROLE')
        for field, size in (('os_version', 40), ('source_ref', 80)):
            if not re.fullmatch(r'[A-Za-z0-9._:-]{1,' + str(size) + '}', a.text_value(item[field], size)):
                raise ValueError('INVALID_INVENTORY_FIELD')
    return value


def enrich(context, rules_text, records, inventory_text=None, inventory_sha256=None, now=None):
    """Exact lookup only. All input copies, official text and inventory remain data."""
    result = a.strict_json(a.encoded(context))
    pack = load_pack(a.read_file(Path(__file__).with_name('mitre_subset.json')))
    rules_digest = digest(rules_text)
    reviewed = rules_digest == RULES_SHA256
    for item in result['knowledge']:
        if reviewed and item['rule_id'] in RULE_NOTES:
            item['explanation'] = RULE_NOTES[item['rule_id']]
            item['annotation_is_not_behavior_proof'] = True
    wanted = {tid for item in result['knowledge'] for tid in item['mitre_ids']}
    docs = []
    for item in pack['techniques']:
        if item['technique_id'] not in wanted:
            continue
        # Preserve the full source in the pack; explicitly identify excerpting.
        description = ' '.join(item['description'].split())
        docs.append({'ref': 'mitre:' + item['technique_id'], 'technique_id': item['technique_id'],
                     'name': item['name'], 'description_excerpt': description[:1600],
                     'excerpt_truncated': len(description) > 1600, 'url': item['url'],
                     'object_version': item['object_version'], 'modified': item['modified']})
    result.update(knowledge_scope='pinned_mitre_subset_and_repository_rules',
                  mitre_documents=docs,
                  mitre_missing_ids=sorted(wanted - {d['technique_id'] for d in docs}),
                  knowledge_provenance={'pack_sha256': PACK_SHA256, 'upstream': pack['source'],
                                        'rules_sha256': rules_digest, 'curated_rule_notes_applied': reviewed},
                  inventory={'status': 'not_supplied', 'assets': []})
    if inventory_text is None and inventory_sha256 is not None:
        raise ValueError('INVENTORY_FILE_REQUIRED')
    if inventory_text is not None:
        snapshot = load_inventory(inventory_text, inventory_sha256, now)
        by_key = {(v['manager'], v['agent_id']): v for v in snapshot['assets']}
        selected, seen = [], set()
        for alert in result['alerts']:
            original = records[alert['source_record'] - 1]
            key = (original['manager']['name'], original['agent']['id'])
            if key not in by_key or alert['agent'] in seen:
                continue
            seen.add(alert['agent'])
            asset = by_key[key]
            selected.append({'ref': 'inventory:' + alert['agent'], 'agent': alert['agent'],
                             **{name: asset[name] for name in ('os_family', 'os_version', 'deployment', 'role')}})
        result['inventory'] = {'status': 'operator_declared_snapshot', 'as_of': snapshot['as_of'],
                               'sha256': inventory_sha256, 'assets': selected,
                               'unmatched_agent_refs': sorted({v['agent'] for v in result['alerts']} - seen),
                               'historical_event_state_verified': False}
    if len(a.encoded(result)) > a.MAX_CONTEXT:
        raise ValueError('ENRICHED_CONTEXT_TOO_LARGE')
    return result
