"""Strict offline validation of Windows service producer bytes.

CIM creation timestamps identify process birth, not readiness. On-disk image
hashes do not authenticate loaded process pages or the Windows/NTFS host.
"""
import hashlib
import json
import ntpath
import re

LIMIT = 65536
EPOCH_TICKS = 621355968000000000
MAX_TICKS = 3155378975999999999


def require(ok, code):
    if not ok:
        raise ValueError(code)


def keys(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()), 'WINDOWS_SCHEMA')


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'WINDOWS_INTEGER')


def image_path(value):
    require(isinstance(value, str) and len(value) <= 1024 and
            re.match(r'^[A-Za-z]:\\', value) and not re.search(r'[/:*?"<>|\x00-\x1f\x7f]', value[2:]), 'WINDOWS_IMAGE_PATH')
    parts = value[3:].split('\\')
    require(all(x and x not in {'.', '..'} and not x.endswith((' ', '.')) for x in parts) and
            ntpath.normpath(value) == value and parts[-1].casefold() == 'wazuh-agent.exe', 'WINDOWS_IMAGE_PATH')
    return value


def digest(value):
    require(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value), 'WINDOWS_HASH')
    return value


def ticks(value):
    require(isinstance(value, str) and re.fullmatch(r'[1-9][0-9]{16,18}', value), 'WINDOWS_DATETIME_TICKS')
    number = int(value); integer(number, EPOCH_TICKS, MAX_TICKS)
    return number


def validate(obj, plan, cycle_id, plan_hash, producer_hash, expected_image):
    keys(expected_image, 'path sha256')
    expected_path = image_path(expected_image['path']); expected_hash = digest(expected_image['sha256'])
    keys(obj, 'schema_version producer capture_id producer_sha256 plan_sha256 run_id cycle_id clock_ref hostname '
         'expected_image_path expected_image_sha256 status samples boot_before_ticks boot_after_ticks boot_before_kind boot_after_kind '
         'start_ms end_ms start_ticks end_ticks tick_frequency acceptance_approved authenticity_verified loaded_image_hash_verified')
    require(type(obj['schema_version']) is int and obj['schema_version'] == 1 and
            obj['producer'] == 'soc-windows-service-v1', 'WINDOWS_VERSION')
    require(plan['identity']['os'] == 'windows' and obj['run_id'] == plan['run_id'] and obj['cycle_id'] == cycle_id and
            obj['hostname'] == plan['identity']['agent_name'] and obj['clock_ref'] == plan['clocks']['endpoint']['ref'] and
            obj['plan_sha256'] == plan_hash and obj['producer_sha256'] == producer_hash, 'WINDOWS_BINDING')
    require(isinstance(obj['capture_id'], str) and re.fullmatch(r'[0-9a-f]{32}', obj['capture_id']), 'WINDOWS_CAPTURE_ID')
    require(obj['acceptance_approved'] is False and obj['authenticity_verified'] is False and
            obj['loaded_image_hash_verified'] is False, 'WINDOWS_NONVERIFICATION')
    require(obj['status'] == 'complete', 'WINDOWS_INCOMPLETE')
    require(image_path(obj['expected_image_path']).casefold() == expected_path.casefold() and
            obj['expected_image_sha256'] == expected_hash, 'WINDOWS_IMAGE_BINDING')
    boot = ticks(obj['boot_before_ticks'])
    require(obj['boot_before_kind'] in ('Utc', 'Local') and obj['boot_after_kind'] == obj['boot_before_kind'], 'WINDOWS_DATETIME_KIND')
    require(obj['boot_after_ticks'] == obj['boot_before_ticks'], 'WINDOWS_BOOT_CHANGED')
    for name in ('start_ms', 'end_ms'): integer(obj[name], 0, 253402300799999)
    for name in ('start_ticks', 'end_ticks'): integer(obj[name], 0, 2**63-1)
    integer(obj['tick_frequency'], 1, 10**12)
    elapsed = obj['end_ticks']-obj['start_ticks']; frequency = obj['tick_frequency']
    require(0 <= elapsed*1000 <= 2000*frequency and obj['end_ms'] >= obj['start_ms'], 'WINDOWS_QUERY_OVERRUN')
    clock = plan['clocks']['endpoint']; error = clock['precision_ms']+clock['uncertainty_ms']
    require(abs((obj['end_ms']-obj['start_ms'])*frequency-elapsed*1000) <= 2*error*frequency, 'WINDOWS_CLOCK_JUMP')
    require(isinstance(obj['samples'], list) and len(obj['samples']) == 2, 'WINDOWS_TWO_SAMPLES')
    identities = []
    for sample in obj['samples']:
        keys(sample, 'service_name service_state process_id process_created_ticks process_datetime_kind executable_path image_sha256 configured_image_matches')
        require(sample['service_name'] == 'WazuhSvc' and sample['service_state'] == 'Running' and
                sample['configured_image_matches'] is True, 'WINDOWS_SERVICE_STATE')
        integer(sample['process_id'], 1, 2**32-1)
        require(sample['process_datetime_kind'] in ('Utc', 'Local'), 'WINDOWS_DATETIME_KIND')
        born = ticks(sample['process_created_ticks'])
        require(boot <= born and image_path(sample['executable_path']).casefold() == expected_path.casefold() and
                sample['image_sha256'] == expected_hash, 'WINDOWS_PROCESS_BINDING')
        identities.append((sample['process_id'], born))
    require(identities[0] == identities[1], 'WINDOWS_PROCESS_CHANGED')
    born_ms = (identities[0][1]-EPOCH_TICKS)//10000
    require(born_ms-error <= obj['end_ms']+error, 'WINDOWS_START_AFTER_SNAPSHOT')
    identity = json.dumps([str(boot), identities[0][0], str(identities[0][1])], separators=(',', ':')).encode()
    value = {'instance': 'windows-service:'+hashlib.sha256(identity).hexdigest(), 'running': True,
             'started_ms': born_ms, 'precision_ms': 1000, 'boot_ref': obj['boot_before_ticks'],
             'image_path': expected_path, 'image_sha256': expected_hash,
             'start_semantics': 'cim_process_creation_not_service_readiness', 'loaded_image_hash_verified': False,
             'producer_hash_attested': True, 'producer_authenticity_verified': False}
    query = {'start_ms': obj['start_ms'], 'end_ms': obj['end_ms'],
             'start_monotonic_ms': obj['start_ticks']*1000//frequency,
             'end_monotonic_ms': obj['end_ticks']*1000//frequency,
             'hostname': obj['hostname'], 'boot_id': obj['boot_before_ticks']}
    return value, query
