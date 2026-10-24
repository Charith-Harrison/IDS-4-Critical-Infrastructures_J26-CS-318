"""Adversarial SYNTHETIC fixtures. These are never measured dataset records."""
from pathlib import Path
import copy
import json
import struct
import tempfile
import unittest

from c3qual.config import object_map
from runtime.common import PURPOSE, planned, sha, source_inventory as source_hashes
from c3qual.protocol import Process, req
from c3qual.scenarios import build
from c3qual.validation import decode, pack, pair, save, validate
from c3qual.transport import ValidationError, _read_pcap
from c3qual.recorder import JsonLines
from pcap_fixtures import packet, write_pcap, jsonl


def reseal(folder):
    m = json.loads((folder / 'run_manifest.json').read_text())
    m['input_sha256'] = {p.name: sha(p) for p in folder.iterdir() if p.is_file() and p.name in
                         ('capture.pcap', 'capture.log', 'planned_run.json', 'scenario_plan.json',
                          'application_ledger.jsonl', 'server_audit.jsonl', 'intervention_audit.jsonl')}
    save(folder / 'run_manifest.json', m)


def fixture(folder, change_plan=None, run_id='MX001'):
    config = planned(run_id)
    mapping = object_map(config['map'])
    episodes = build(config)
    if change_plan:
        change_plan(episodes)
    state = dict(mode=0, setpoint=50, coil=0)
    rows, audit, hooks = [], [], []
    offsets = dict(client_to_server=0, server_to_client=0)
    bases = dict(client_to_server=10001, server_to_client=20001)
    frames = [packet(41000, 15020, 10000, flags=2), packet(15020, 41000, 20000, flags=18)]
    for ep in episodes:
        for step in ep['steps']:
            t = len(audit)
            tid = step['tid']
            pdu = bytes.fromhex(step['pdu_hex'])
            fc, address, word = struct.unpack('!BHH', pdu)
            before = dict(state)
            if fc == 1:
                genuine_pdu = bytes((1, 1, state['coil']))
            elif fc == 3:
                genuine_pdu = b'\x03\x02' + struct.pack('!H', state['mode' if address == mapping['mode_register'] else 'setpoint'])
            elif fc == 5:
                state['coil'] = int(word == 0xff00)
                genuine_pdu = pdu
            else:
                state['mode' if address == mapping['mode_register'] else 'setpoint'] = word
                genuine_pdu = pdu
            incoming, genuine = pack(tid, pdu), pack(tid, genuine_pdu)
            outgoing = pack(tid, b'\x03\x02' + struct.pack('!H', step['replacement'])) \
                       if step['intervention'] == 'response_injection' else genuine
            audit.append(dict(transaction_index=t, connection_id='fixture:c0', request_adu_hex=incoming.hex(),
                              expected_response_adu_hex=genuine.hex(), wire_response_adu_hex=outgoing.hex(),
                              response_overridden=outgoing != genuine,
                              **{k + '_before': v for k, v in before.items()},
                              **{k + '_after': v for k, v in state.items()}))
            hooks.append(dict(transaction_index=t, connection_id='fixture:c0', request_adu_hex=incoming.hex(),
                              kind=step['intervention'], replacement=step['replacement']))
            for j, (role, direction, raw) in enumerate((('request', 'client_to_server', incoming),
                                                       ('response', 'server_to_client', outgoing))):
                src, dst = (41000, 15020) if j == 0 else (15020, 41000)
                label = 'command_injection' if j == 0 and step['intervention'] == 'command_injection' else \
                        'response_injection' if j == 1 and step['intervention'] == 'response_injection' else 'normal'
                rows.append(dict(event_id=f'fixture:e{len(rows)}', run_id='fixture', connection_id='fixture:c0',
                                 transaction_index=t, episode_id=ep['episode_id'], scenario=ep['family'],
                                 block=ep['block'], tid_profile=ep['tid_profile'], anchor_poll_count=ep['anchor_poll_count'], step=step['step'], label=label, role=role, direction=direction, tid=tid, unit=1,
                                 adu_hex=raw.hex(), pdu_hex=raw[7:].hex(), stream_offset=offsets[direction],
                                 observed_at_ns=len(rows), source_ip='127.0.0.1', destination_ip='127.0.0.1',
                                 source_port=src, destination_port=dst))
                frames.append(packet(src, dst, bases[direction] + offsets[direction], raw))
                offsets[direction] += len(raw)
    write_pcap(folder / 'capture.pcap', frames)
    (folder / 'capture.log').write_text('listening on lo, synthetic fixture\n0 packets dropped by kernel\n')
    jsonl(folder / 'application_ledger.jsonl', rows)
    jsonl(folder / 'server_audit.jsonl', audit)
    jsonl(folder / 'intervention_audit.jsonl', hooks)
    save(folder / 'planned_run.json', config)
    save(folder / 'scenario_plan.json', episodes)
    save(folder / 'run_manifest.json', dict(status='CAPTURE_COLLECTED', purpose=PURPOSE,
         synthetic_test_fixture=True, capture_required=True, capture_exit_code=0, run_id='fixture',
         connection_id='fixture:c0', client_port=41000, observed_application_messages=len(rows),
         episodes=len(episodes), planned_run=config, source_sha256=source_hashes()))
    reseal(folder)
    return rows, audit, hooks, frames


