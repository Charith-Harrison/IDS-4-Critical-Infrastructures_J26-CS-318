"""Adversarial SYNTHETIC fixtures. These are never measured dataset records."""
from pathlib import Path
import copy
import json
import struct
import tempfile
import unittest

from c3qual.config import PURPOSE, object_map, planned, sha, source_hashes
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


def fixture(folder, change_plan=None, run_id='EQ01'):
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


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='c3-SYNTHETIC-ONLY-')
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def verify(self):
        return validate(self.folder, write=False, allow_synthetic=True)

    def fail(self, text):
        result = self.verify()
        self.assertEqual(result['status'], 'FAILED', result)
        self.assertIn(text, '; '.join(result['errors']))
        self.assertFalse((self.folder / 'verified_labels.jsonl').exists())

    def mutate_rows(self, name, change):
        path = self.folder / name
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        change(rows)
        jsonl(path, rows)
        reseal(self.folder)

    def test_complete_fixture_has_exact_labels_controls_and_causal_anchors(self):
        fixture(self.folder)
        r = self.verify()
        self.assertEqual(r['status'], 'SYNTHETIC_TEST_PASSED', r)
        self.assertFalse(r['accepted_labels'])
        self.assertEqual(r['episode_count'], 90)
        self.assertEqual(r['label_counts']['command_injection'], 9)
        self.assertEqual(r['label_counts']['response_injection'], 18)
        self.assertEqual(len(r['control_matches']), 27)
        self.assertTrue(all(c['normal_event_ids'] for c in r['control_matches']))
        self.assertEqual(set(r['forgery_variant_counts']), {'a_to_b', 'b_to_a'})
        self.assertEqual(r['containment']['connections'], 1)

    def test_runtime_private_ledger_writer_flushes_valid_json(self):
        path = self.folder / 'writer-test.jsonl'
        writer = JsonLines(path)
        try:
            writer.append({'transaction_index': 0, 'kind': 'none'})
            self.assertEqual(json.loads(path.read_text()), {'transaction_index': 0, 'kind': 'none'})
        finally:
            writer.close()
        with self.assertRaises(FileExistsError):
            JsonLines(path)

    def test_synthetic_fixture_never_emits_measured_labels(self):
        fixture(self.folder)
        self.assertEqual(validate(self.folder, write=True)['status'], 'FAILED')
        self.assertFalse((self.folder / 'verified_labels.jsonl').exists())

    def test_literal_tid5_reuse_does_not_merge_occurrences(self):
        rows, _, _, _ = fixture(self.folder)
        self.assertTrue(all(row['tid'] == 5 for row in rows if row['tid_profile']=='DREUSE'))
        r = self.verify()
        self.assertEqual(r['status'], 'SYNTHETIC_TEST_PASSED', r)
        self.assertEqual(r['message_count'], len(rows))
        self.assertGreater(r['repeated_genuine_writes_preserved']['coil'], 0)

    def test_missing_mode_observation_fails_even_with_private_truth(self):
        def remove(episodes):
            for ep in episodes:
                ep['steps'] = [s for s in ep['steps'] if bytes.fromhex(s['pdu_hex'])[:3] != b'\x03\x00\x00']
        fixture(self.folder, change_plan=remove)
        self.fail('no earlier visible mode')

    def test_no_op_mutation_is_not_an_injection(self):
        def noop(episodes):
            for ep in episodes:
                if ep['family'] == 'R_CHANGED_READBACK':
                    for s in ep['steps']:
                        if s['intervention'] == 'response_injection':
                            s['replacement'] = ep['b'] if ep['variant'] == 'b_to_a' else ep['a']
        fixture(self.folder, change_plan=noop)
        self.fail('intervention/bytes disagree')

    def test_command_hook_in_allowed_mode_rejects(self):
        def bad(episodes):
            for ep in episodes:
                if ep['family'] == 'N_PERMITTED_ON':
                    next(s for s in ep['steps'] if s['step'] == 'pump_on')['intervention'] = 'command_injection'
        fixture(self.folder, change_plan=bad)
        self.fail('intervention/policy evidence disagree')

    def test_ack_of_injected_command_must_stay_normal(self):
        fixture(self.folder)
        def wrong(rows):
            i = next(i for i, r in enumerate(rows) if r['label'] == 'command_injection')
            rows[i + 1]['label'] = 'response_injection'
        self.mutate_rows('application_ledger.jsonl', wrong)
        self.fail('Proposed label lacks direct intervention')

    def test_duplicate_event_identifier_rejects(self):
        fixture(self.folder)
        self.mutate_rows('application_ledger.jsonl', lambda rows: rows[1].update(event_id=rows[0]['event_id']))
        self.fail('Duplicate event')

    def test_connection_or_ordinal_identity_mismatch_rejects(self):
        fixture(self.folder)
        self.mutate_rows('server_audit.jsonl', lambda rows: rows[3].update(transaction_index=2))
        self.fail('ordinal differs')

    def test_false_server_state_rejects(self):
        fixture(self.folder)
        self.mutate_rows('server_audit.jsonl', lambda rows: rows[0].update(setpoint_before=999))
        self.fail('before-state contradicts')

    def test_wrong_genuine_reply_rejects(self):
        fixture(self.folder)
        self.mutate_rows('server_audit.jsonl', lambda rows: rows[0].update(expected_response_adu_hex='00'))
        self.fail('Genuine reply contradicts')

    def test_input_tampering_without_reseal_rejects(self):
        fixture(self.folder)
        with (self.folder / 'application_ledger.jsonl').open('a') as f:
            f.write('\n')
        self.fail('Input hash differs')

    def test_source_mismatch_rejects(self):
        fixture(self.folder)
        m = json.loads((self.folder / 'run_manifest.json').read_text())
        m['source_sha256'] = {}
        save(self.folder / 'run_manifest.json', m)
        self.fail('Source hashes differ')

    def test_nonzero_drop_rejects_and_quarantines_previous_labels(self):
        fixture(self.folder)
        (self.folder / 'capture.log').write_text('listening on lo\n1 packets dropped by kernel\n')
        reseal(self.folder)
        (self.folder / 'verified_labels.jsonl').write_text('synthetic prior result\n')
        result = validate(self.folder, write=True, allow_synthetic=True)
        self.assertEqual(result['status'], 'FAILED')
        self.assertIn('drop', '; '.join(result['errors']))
        self.assertFalse((self.folder / 'verified_labels.jsonl').exists())
        self.assertTrue((self.folder / result['quarantined_previous_labels']).exists())

    def test_missing_syn_rejects(self):
        _, _, _, frames = fixture(self.folder)
        write_pcap(self.folder / 'capture.pcap', frames[1:])
        reseal(self.folder)
        self.fail('SYN sequence bases')

    def test_retransmission_keeps_duplicate_observation_but_not_duplicate_event(self):
        _, _, _, frames = fixture(self.folder)
        write_pcap(self.folder / 'capture.pcap', frames + [frames[2]])
        reseal(self.folder)
        r = self.verify()
        self.assertEqual(r['status'], 'SYNTHETIC_TEST_PASSED', r)
        self.assertEqual(r['capture_statistics']['retransmitted_payload_bytes'], 12)

    def test_byte_gap_rejects(self):
        _, _, _, frames = fixture(self.folder)
        frames.pop(3)
        write_pcap(self.folder / 'capture.pcap', frames)
        reseal(self.folder)
        self.fail('gap or empty TCP')

    def test_conflicting_payload_overlap_rejects(self):
        _, _, _, frames = fixture(self.folder)
        f = frames[2]
        write_pcap(self.folder / 'capture.pcap', frames + [f[:-1] + bytes((f[-1] ^ 1,))])
        reseal(self.folder)
        self.fail('conflicting TCP')

    def test_missing_reply_rejects(self):
        fixture(self.folder)
        self.mutate_rows('application_ledger.jsonl', lambda rows: rows.pop())
        self.fail('Incomplete transaction')

    def test_complete_capture_frame_order_must_support_causal_pair_order(self):
        _, _, _, frames = fixture(self.folder)
        # Reorder complete request/reply frame records while retaining correct stream bytes.
        frames[2], frames[3] = frames[3], frames[2]
        write_pcap(self.folder / 'capture.pcap', frames)
        reseal(self.folder)
        self.fail('one-outstanding causal order')

    def test_truncated_capture_rejects(self):
        _, _, _, frames = fixture(self.folder)
        write_pcap(self.folder / 'capture.pcap', frames, truncate=True)
        reseal(self.folder)
        self.fail('truncated packet')

    def test_transport_wrap_segmentation_coalescing_and_linktypes(self):
        req_bytes = pack(5, req(6, 0, 1)) + pack(5, req(3, 0, 1))
        rep_bytes = pack(5, req(6, 0, 1)) + pack(5, b'\x03\x02\x00\x01')
        for linktype, endian, nano in ((1, '<', False), (113, '>', False), (276, '<', True)):
            base = 0xfffffffa
            frames = [packet(41000, 15020, base - 1, flags=2, linktype=linktype),
                      packet(15020, 41000, base - 1, flags=18, linktype=linktype),
                      packet(41000, 15020, base + 5, req_bytes[5:], linktype=linktype),
                      packet(41000, 15020, base, req_bytes[:5], linktype=linktype),
                      packet(15020, 41000, base, rep_bytes, linktype=linktype)]
            write_pcap(self.folder / 'transport-only.pcap', frames, linktype, endian, nano)
            streams, _, _ = _read_pcap(self.folder / 'transport-only.pcap', 15020, 41000)
            self.assertEqual(streams['client_to_server'], req_bytes)
            self.assertEqual(streams['server_to_client'], rep_bytes)

    def test_wrong_write_acknowledgement_rejects(self):
        m = object_map('M1')
        a = pack(5, req(6, m['setpoint_register'], 123))
        b = pack(5, req(6, m['setpoint_register'], 124))
        with self.assertRaisesRegex(ValidationError, 'ACK'):
            pair(a, b, m)

    def test_all_public_maps_round_trip_independently(self):
        for name in ('M0', 'M1', 'M2'):
            m = object_map(name)
            p = Process(m)
            for fc, addr, val in ((6, m['mode_register'], 1), (3, m['mode_register'], 1),
                                  (6, m['setpoint_register'], 1160), (3, m['setpoint_register'], 1),
                                  (5, m['pump_coil'], 0xff00), (1, m['pump_coil'], 1)):
                raw = req(fc, addr, val)
                _, reply = pair(pack(5, raw), pack(5, p.handle(raw)), m)
                if fc == 3:
                    self.assertEqual(reply['word'], 1 if addr == m['mode_register'] else 1160)

    def test_illegal_coil_quantity_mode_address_mbap_and_bytecount_reject(self):
        m = object_map('M0')
        cases = [(req(5, 1, 1), 'request'), (req(3, 0, 2), 'request'), (req(6, 0, 2), 'request'),
                 (req(5, 7, 0), 'request'), (b'\x03\x01\x00\x14', 'response'), (b'\x83\x02', 'response')]
        for pdu, role in cases:
            with self.subTest(pdu=pdu.hex()), self.assertRaises(ValidationError):
                decode(pack(1, pdu), role, m)
        with self.assertRaises(ValidationError):
            decode(b'\x00\x01\x00\x01' + pack(1, req(3, 0, 1))[4:], 'request', m)

    def test_main_collection_and_arbitrary_seed_are_not_enabled(self):
        for name in ('development-001', 'Q05', '../Q01'):
            with self.assertRaises(ValueError):
                planned(name)

    def test_multiple_qualification_positions_not_a_single_template_position(self):
        positions = set()
        for run_id in ('EQ01','EQ02','EQ03','EQ04'):
            for ep in build(planned(run_id)):
                for i, step in enumerate(ep['steps']):
                    if step['intervention'] != 'none':
                        positions.add(i)
        self.assertGreaterEqual(len(positions), 3)


if __name__ == '__main__':
    unittest.main()
