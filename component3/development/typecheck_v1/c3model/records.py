"""Lossless accepted-run admission and causal, public-wire-only feature adapter.

Truth is joined only after features are built. Private generator episode/scenario
fields never enter state, features, task selection or reset boundaries.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import hashlib
import ipaddress
import json
import math
import struct
from typing import TypedDict, cast

import pandas as pd
#feature definitions. CURRENT - Information from the current Modbus message, WIRE-Network and transaction-header information, CONTEXT-Information from previous communication
CURRENT = [
    'current_function', 'current_unit', 'current_is_request', 'current_pdu_length',
    'current_wire_address', 'current_wire_word', 'current_wire_quantity',
    'current_byte_count', 'current_request_object_role',
]
WIRE = ['current_numeric_tid', 'current_source_ip', 'current_destination_ip',
        'current_source_port', 'current_destination_port']
CONTEXT = ['earlier_observed_mode', 'earlier_acknowledged_setpoint',
           'paired_request_object_role', 'response_minus_acknowledged_setpoint',
           'context_available']
MAX_INTERVENING = 6 #This means a previous observation is used as context only if no more than six Modbus application messages occurred between that observation and the current message.
ROLE_CODE: dict[str | None, int] = {'mode': 1, 'setpoint': 2, 'pump': 3}
NAN = float('nan')
LABELS = {'normal', 'command_injection', 'response_injection'}


class Anchor(TypedDict):
    value: int
    ordinal: int
    event_id: str


class PendingRequest(TypedDict):
    decoded: dict
    object_role: str | None
    event_id: str


class ConnectionState(TypedDict):
    mode: Anchor | None
    setpoint: Anchor | None
    pending: dict[int, PendingRequest]
    offsets: dict[str, int]


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def _jsonl(path):
    with Path(path).open('r', encoding='utf-8-sig') as handle:
        for number, line in enumerate(handle, 1):
            if line.strip():
                row = json.loads(line)
                _require(isinstance(row, dict), f'{path}:{number}: object required')
                yield row


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(8 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _child(root, name):
    root = Path(root).resolve()
    _require(isinstance(name, str) and name and not Path(name).is_absolute(), 'Unsafe relative artifact path')
    candidate = (root / name).resolve()
    _require(candidate.is_relative_to(root), 'Artifact escaped source directory')
    return candidate

#converts raw Modbus/TCP bytes into understandable information.
def decode(raw: bytes, is_request: bool) -> dict:
    """Decode only the declared FC1/3/5/6 single-object subset, losslessly.

    Missing response addresses remain None. No paired request is consulted here.
    """
    _require(isinstance(raw, bytes) and 8 <= len(raw) <= 260, 'Invalid complete ADU size')
    tid, protocol, length, unit = struct.unpack('!HHHB', raw[:7])
    _require(protocol == 0 and 2 <= length <= 254 and len(raw) == 6 + length, 'Invalid MBAP')
    pdu = raw[7:]
    function = pdu[0] & 127
    exception = bool(pdu[0] & 128)
    _require(function in (1, 3, 5, 6), 'Unsupported function outside frozen subset')
    result = dict(tid=tid, unit=unit, function=function, function_code=function,
                  pdu=pdu, raw=raw, pdu_length=len(pdu), address=None, word=None,
                  quantity=None, byte_count=None, exception=exception, parse_ok=True)
    if exception:
        _require(not is_request and len(pdu) == 2, 'Invalid exception PDU')
        result['exception_code'] = pdu[1]
    elif is_request or function in (5, 6):
        _require(len(pdu) == 5, 'Request/write-echo PDU must contain five bytes')
        address, value = struct.unpack('!HH', pdu[1:])
        result['address'] = address
        if function in (1, 3):
            _require(value == 1, 'Frozen collection reads one object')
            result['quantity'] = value
        else:
            _require(function != 5 or value in (0, 0xff00), 'Illegal FC5 output word')
            result['word'] = value
    else:
        _require(len(pdu) >= 2 and pdu[1] == len(pdu) - 2, 'Response byte-count mismatch')
        result['byte_count'] = pdu[1]
        if function == 1:
            _require(len(pdu) == 3 and pdu[1] == 1 and pdu[2] in (0, 1), 'Invalid one-coil reply')
            result['word'] = pdu[2]
        else:
            _require(len(pdu) == 4 and pdu[1] == 2, 'Invalid one-register reply')
            result['word'] = int.from_bytes(pdu[2:], 'big')
    return result

#code which addresses correspond to these objects
def _public_map(membership, maps):
    if isinstance(maps, list):
        indexed = {m['id']: m for m in maps}
    elif isinstance(maps, dict) and 'maps' in maps:
        return _public_map(membership, maps['maps'])
    elif isinstance(maps, dict) and 'mode_register' in maps:
        indexed = {maps.get('id', membership.get('map', 'M0')): maps}
    elif isinstance(maps, dict):
        indexed = maps
    else:
        raise ValueError('Public maps must be a list or mapping')
    map_id = membership.get('map', membership.get('map_id'))
    if map_id is None and len(indexed) == 1:
        map_id = next(iter(indexed))
    _require(map_id in indexed, 'Run lacks a declared public map')
    mapping = indexed[map_id]
    for key in ('mode_register', 'setpoint_register', 'pump_coil'):
        _require(isinstance(mapping[key], int) and 0 <= mapping[key] <= 65535, 'Invalid public map')
    return mapping

#identifies whether a message refers to the mode, setpoint, or pump.
def _object_role(decoded, mapping):
    address, function = decoded['address'], decoded['function']
    if address is None:
        return None
    if function in (1, 5):
        return 'pump' if address == mapping['pump_coil'] else None
    if address == mapping['mode_register']:
        return 'mode'
    if address == mapping['setpoint_register']:
        return 'setpoint'
    return None


def _number(value):
    return NAN if value is None else value


def _ip(value):
    return NAN if value is None else int(ipaddress.ip_address(value))

#feature-engineering function. It processes one accepted recording and creates a DataFrame containing the decoded messages, features, context information, and verified labels.
def build_run(folder: Path, membership: dict, public_maps) -> pd.DataFrame:
    """Build every row's public features, then attach separate accepted truth.

    Event order is the captured application's validated stream order, not sorted
    wall-clock time, TID, private episode or scenario. No private oracle is read.
    """
    folder = Path(folder)
    mapping = _public_map(membership, public_maps)
    states: dict[str, ConnectionState] = {}
    records, seen = [], set()
    related_group = membership.get('related_group', membership.get('prospective_related_group'))
    evaluation_role = membership.get('evaluation_role', membership.get('intended_evaluation_role'))
    declared_run = membership.get('run_id')
    for ordinal, observed in enumerate(_jsonl(folder / 'application_ledger.jsonl')):
        # Explicit allow-list: ignore label/scenario/step/episode and all private fields.
        row = {key: observed[key] for key in (
            'event_id', 'run_id', 'connection_id', 'transaction_index', 'role', 'tid',
            'unit', 'adu_hex', 'stream_offset', 'observed_at_ns')}
        for name in ('direction', 'source_ip', 'destination_ip', 'source_port', 'destination_port', 'pdu_hex'):
            if name in observed:
                row[name] = observed[name]
        event_id, connection = row['event_id'], row['connection_id']
        _require(event_id not in seen, 'Duplicate event ID')
        seen.add(event_id)
        _require(declared_run is None or row['run_id'] == declared_run, 'Run membership identity mismatch')
        _require(row['role'] in ('request', 'response'), 'Invalid observation role')
        is_request = row['role'] == 'request'
        direction = 'client_to_server' if is_request else 'server_to_client'
        _require(row.get('direction', direction) == direction, 'Role/direction mismatch')
        raw = bytes.fromhex(row['adu_hex'])
        decoded = decode(raw, is_request)
        _require((row['tid'], row['unit']) == (decoded['tid'], decoded['unit']), 'Wire/ledger identity disagreement')
        if 'pdu_hex' in row:
            _require(bytes.fromhex(row['pdu_hex']) == decoded['pdu'], 'Wire/ledger PDU disagreement')
        state = states.setdefault(connection, {'mode': None, 'setpoint': None, 'pending': {},
                                               'offsets': {'client_to_server': 0, 'server_to_client': 0}})
        _require(row['stream_offset'] == state['offsets'][direction], 'Stream offset is not contiguous')
        state['offsets'][direction] += len(raw)
        transaction = row['transaction_index']
        _require(isinstance(transaction, int) and transaction >= 0, 'Invalid transaction ordinal')
        pending = state['pending'].get(transaction) if not is_request else None
        pair_ok = False
        if pending is not None:
            pair_ok = ((decoded['tid'], decoded['unit'], decoded['function']) ==
                       (pending['decoded']['tid'], pending['decoded']['unit'], pending['decoded']['function']))
            if pair_ok and decoded['function'] in (5, 6) and not decoded['exception']:
                pair_ok = decoded['pdu'] == pending['decoded']['pdu']
        public_role = _object_role(decoded, mapping) if is_request else None
        pair_role = pending['object_role'] if pending is not None and pair_ok else None
        task = ('command' if is_request and decoded['function'] == 5 and public_role == 'pump'
                and decoded['word'] == 0xff00 else
                'response' if not is_request and pair_ok and decoded['function'] == 3
                and pair_role == 'setpoint' and not decoded['exception'] else '')
        def usable(anchor):
            return anchor is not None and 0 <= ordinal - anchor['ordinal'] - 1 <= MAX_INTERVENING
        mode_anchor = state['mode'] if usable(state['mode']) else None
        setpoint_anchor = state['setpoint'] if usable(state['setpoint']) else None
        available = bool(mode_anchor if task == 'command' else setpoint_anchor if task == 'response' else False)
        rule = 'out_of_scope'
        if task:
            rule = 'abstain'
            if available:
                # available already establishes the corresponding anchor; casts add no new checks.
                rule = ('command_injection' if cast(Anchor, mode_anchor)['value'] == 0 else 'normal') if task == 'command' else \
                       ('response_injection' if decoded['word'] != cast(Anchor, setpoint_anchor)['value'] else 'normal')
        record = {
            'event_id': event_id, 'run_id': row['run_id'], 'connection_id': connection,
            'transaction_index': transaction, 'event_ordinal': ordinal,
            'related_group': related_group, 'evaluation_role': evaluation_role,
            'recording_mode': membership.get('recording_mode'), 'map_id': membership.get('map', membership.get('map_id')),
            'role': row['role'], 'direction': direction, 'observed_at_ns': int(row['observed_at_ns']),
            'stream_offset': row['stream_offset'], 'adu_hex': raw.hex(), 'pdu_hex': decoded['pdu'].hex(),
            'task': task, 'eligible': bool(task), 'context_available': available,
            'rule_prediction': rule, 'protocol_prediction': 'normal' if is_request or pair_ok else 'abstain',
            'current_function': decoded['function'], 'current_unit': decoded['unit'],
            'current_is_request': int(is_request), 'current_pdu_length': decoded['pdu_length'],
            'current_wire_address': _number(decoded['address']), 'current_wire_word': _number(decoded['word']),
            'current_wire_quantity': _number(decoded['quantity']), 'current_byte_count': _number(decoded['byte_count']),
            'current_request_object_role': ROLE_CODE.get(public_role, 0) if is_request else NAN,
            'current_numeric_tid': decoded['tid'], 'current_source_ip': _ip(row.get('source_ip')),
            'current_destination_ip': _ip(row.get('destination_ip')),
            'current_source_port': _number(row.get('source_port')),
            'current_destination_port': _number(row.get('destination_port')),
            'earlier_observed_mode': mode_anchor['value'] if mode_anchor else NAN,
            'earlier_acknowledged_setpoint': setpoint_anchor['value'] if setpoint_anchor else NAN,
            'paired_request_object_role': ROLE_CODE.get(pair_role, 0) if not is_request and pair_ok else NAN,
            'response_minus_acknowledged_setpoint': decoded['word'] - setpoint_anchor['value']
                if task == 'response' and setpoint_anchor else NAN,
            'mode_anchor_event_id': mode_anchor['event_id'] if mode_anchor else None,
            'setpoint_anchor_event_id': setpoint_anchor['event_id'] if setpoint_anchor else None,
            'paired_request_event_id': pending['event_id'] if pending is not None and pair_ok else None,
        }
        records.append(record)
        # State updates happen strictly after the current row's decision features.
        if is_request:
            _require(transaction not in state['pending'], 'Duplicate outstanding transaction ordinal')
            _require(not state['pending'], 'Multiple outstanding transactions outside frozen scope')
            if decoded['function'] == 6:
                if public_role == 'mode':
                    state['mode'] = None
                elif public_role == 'setpoint':
                    state['setpoint'] = None
            state['pending'][transaction] = {'decoded': decoded, 'object_role': public_role,
                                              'event_id': event_id}
        elif pending is not None:
            del state['pending'][transaction]
            if pair_ok and not decoded['exception']:
                if decoded['function'] == 3 and pair_role == 'mode':
                    _require(decoded['word'] in (0, 1), 'Mode observation outside public policy')
                    state['mode'] = {'value': decoded['word'], 'ordinal': ordinal, 'event_id': event_id}
                elif decoded['function'] == 6 and pair_role == 'setpoint':
                    state['setpoint'] = {'value': decoded['word'], 'ordinal': ordinal, 'event_id': event_id}
    _require(records, 'No observations')
    _require(all(not s['pending'] for s in states.values()), 'Accepted run ended with pending request')
    truth = {}
    capture_hashes = set()
    for annotation in _jsonl(folder / 'verified_labels.jsonl'):
        key, label = annotation['event_id'], annotation['label']
        _require(key not in truth and label in LABELS, 'Duplicate or unsupported accepted truth')
        truth[key] = label
        if annotation.get('capture_sha256'):
            capture_hashes.add(annotation['capture_sha256'])
    _require(set(truth) == seen, 'Accepted labels do not cover exactly the observation IDs')
    _require(len(capture_hashes) <= 1, 'Multiple capture hashes in one accepted run')
    capture_sha = next(iter(capture_hashes), None)
    for record in records:
        record['label'] = truth[record['event_id']]
        record['capture_sha256'] = capture_sha
    frame = pd.DataFrame.from_records(records)
    frame['observed_at_ns'] = frame['observed_at_ns'].astype('int64')
    return frame

#checks that dataset is complete and has not been unexpectedly modified.
def verify_collection(root) -> dict:
    """Verify frozen sources, accepted seals and all listed hashes, no row parsing.

    May hash final raw artifacts operationally, but never parses final examples.
    Failed attempts not named by the final accepted index are not admitted.
    """
    root = Path(root).resolve()
    index_path = root / 'collection_complete.json'
    index, collection = _read(index_path), _read(root / 'collection_manifest.json')
    _require(index.get('status') == 'ALL_104_VALIDATED', 'Collection is not complete')
    completed = index.get('completed', {})
    _require(set(completed) == {f'MX{i:03d}' for i in range(1, 105)}, 'Accepted index must contain exactly MX001..MX104')
    source = root / '_handover/source/collector'
    if not (source / 'frozen/freeze_manifest.json').is_file():
        source = root.parent.parent / 'component3_main_collection/v1_20261025'
    freeze = _read(source / 'frozen/freeze_manifest.json')
    bundle = freeze['bundle_id']
    _require(index['source_bundle_id'] == collection['source_bundle_id'] == bundle, 'Collection/frozen source identity differs')
    _require(index['collection_id'] == collection['collection_id'], 'Collection IDs differ')
    hashes = {}
    for name, expected in freeze['source_configuration_sha256'].items():
        path = _child(source, name)
        actual = _sha(path)
        _require(actual == expected, 'Frozen source changed: ' + name)
        hashes[str(path)] = actual
    protocol_path, roster_path = source / 'frozen/protocol.json', source / 'frozen/main_roster.json'
    _require(_sha(protocol_path) == freeze['protocol_sha256'], 'Protocol hash differs')
    _require(_sha(roster_path) == freeze['roster_sha256'] == collection['frozen_roster_sha256'], 'Roster hash differs')
    protocol, roster = _read(protocol_path), _read(roster_path)
    planned = {r['planned_run_id']: r for r in roster['runs']}
    _require(set(planned) == set(completed), 'Roster and accepted IDs differ')
    allowed_roles = {'train', 'validation', 'final_test_repeat', 'final_test_values',
                     'final_test_map', 'final_test_order', 'final_test_timing'}
    runs, groups, traces = [], {}, set()
    for planned_id in sorted(completed):
        entry, plan = completed[planned_id], planned[planned_id]
        folder = _child(root, entry['attempt'])
        receipt_path = folder / 'completion.json'
        _require(_sha(receipt_path) == entry['completion_sha256'], 'Completion receipt changed: ' + planned_id)
        receipt = _read(receipt_path)
        _require(receipt['status'] == 'VALIDATED' and receipt['planned_run_id'] == planned_id, 'Receipt is not an accepted matching run')
        _require(receipt['source_bundle_id'] == bundle and receipt['collection_id'] == index['collection_id'], 'Foreign receipt')
        _require(receipt['image_id'] == collection['image_id'], 'Receipt image identity differs')
        role = entry['intended_evaluation_role']
        group = entry['related_group']
        _require(role in allowed_roles and role == plan['intended_evaluation_role'], 'Role differs from frozen roster')
        _require(group == plan['prospective_related_group'], 'Related group differs from frozen roster')
        _require(group not in groups or groups[group] == role, 'Related history crosses roles')
        groups[group] = role
        for kind in ('ordered_adu_trace_sha256', 'ordered_pdu_trace_sha256'):
            trace = (kind, receipt[kind])
            _require(trace not in traces, 'Duplicate accepted ordered stream')
            traces.add(trace)
        required = {'application_ledger.jsonl', 'verified_labels.jsonl', 'capture.pcap',
                    'run_manifest.json', 'validation_report.json', 'planned_run.json'}
        _require(required <= set(receipt['artifact_sha256']), 'Seal lacks required evidence')
        for name, expected in receipt['artifact_sha256'].items():
            path = _child(folder, name)
            actual = _sha(path)
            _require(actual == expected, f'Accepted artifact changed: {planned_id}/{name}')
            hashes[str(path)] = actual
        actual_plan = _read(folder / 'planned_run.json')
        _require(actual_plan['planned_run_id'] == planned_id and actual_plan['seed'] == plan['seed'], 'Accepted plan identity differs')
        for key in ('map', 'values', 'ordering', 'timing', 'recording_mode', 'intended_evaluation_role', 'prospective_related_group'):
            _require(actual_plan[key] == plan[key], 'Accepted plan factor differs: ' + key)
        manifest = _read(folder / 'run_manifest.json')
        _require(manifest['run_id'] == entry['attempt'], 'Run ID/accepted folder differs')
        runs.append({'folder': str(folder), 'run_id': manifest['run_id'], 'planned_run_id': planned_id,
                     'related_group': group, 'evaluation_role': role, 'recording_mode': plan['recording_mode'],
                     'map': plan['map'], 'values': plan['values'], 'ordering': plan['ordering'],
                     'timing': plan['timing'], 'seed': plan['seed'], 'label_counts': receipt['label_counts'],
                     'completion_sha256': entry['completion_sha256'],
                     'capture_sha256': receipt['artifact_sha256']['capture.pcap']})
    counts = Counter(r['evaluation_role'] for r in runs)
    _require(counts == {'train': 32, 'validation': 16, 'final_test_repeat': 24,
                        'final_test_values': 8, 'final_test_map': 8, 'final_test_order': 8, 'final_test_timing': 8},
             'Unexpected frozen role support')
    return {'collection_id': index['collection_id'], 'source_bundle_id': bundle, 'root': str(root),
            'index': index, 'index_sha256': _sha(index_path), 'runs': runs,
            'public_maps': protocol['public_configuration']['maps'], 'protocol': protocol,
            'role_counts': dict(counts), 'verified_artifact_count': len(hashes),
            'input_sha256': hashes, 'protocol_sha256': freeze['protocol_sha256'],
            'roster_sha256': freeze['roster_sha256'],
            'final_payload_values_parsed': False,
            'limits': 'Artifact hashes and seals verified; this does not independently reconstruct all PCAPs or certify clock accuracy/industrial generalization.'}




