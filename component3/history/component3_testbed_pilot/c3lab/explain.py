"""Teach from verified evidence only; no model features are calculated."""
from pathlib import Path
import json
from .capture_validation import validate_capture


def explain_run(folder: Path) -> str:
    report = validate_capture(folder)
    if report['status'] != 'PASSED':
        raise ValueError('Evidence is not verified; read validation_report.json before explaining labels')
    rows = [json.loads(line) for line in (folder/'verified_labels.jsonl').read_text(encoding='utf-8').splitlines()]
    command = next(r for r in rows if r['label'] == 'command_injection')
    normal_command = next(r for r in rows if r['role'] == 'request' and r['label'] == 'normal' and r['pdu_hex'] == command['pdu_hex'])
    response = next(r for r in rows if r['label'] == 'response_injection')
    normal_response = next(r for r in rows if r['role'] == 'response' and r['label'] == 'normal' and r['pdu_hex'] == response['pdu_hex'])
    def frames(row):
        return ','.join(str(n) for n in sorted({s['frame_number'] for s in row['frame_byte_references']}))
    def prior_write(target, address):
        stop = rows.index(target)
        candidates = [r for r in rows[:stop] if r['episode_id'] == target['episode_id'] and r['role'] == 'request'
                      and bytes.fromhex(r['pdu_hex'])[:3] == bytes((6, 0, address))]
        return candidates[-1]
    mode_bad, mode_good = prior_write(command, 0), prior_write(normal_command, 0)
    set_bad, set_good = prior_write(response, 1), prior_write(normal_response, 1)
    def word(row):
        return int.from_bytes(bytes.fromhex(row['pdu_hex'])[-2:], 'big')
    return '\n'.join([
        'ONE VERIFIED PILOT, NOT A FINAL TRAINING DATASET',
        f"Messages: {report['message_count']}; labels: {report['label_counts']}",
        '', 'COMMAND EXAMPLE',
        f"Injected command: {command['event_id']} | frame(s) {frames(command)} | PDU {command['pdu_hex']}",
        f"Earlier visible mode write was {word(mode_bad)} (frame(s) {frames(mode_bad)}). Lab rule: ON requires mode1.",
        f"Normal identical PDU: {normal_command['event_id']} | frame(s) {frames(normal_command)}.",
        f"That episode's earlier mode write was {word(mode_good)} (frame(s) {frames(mode_good)}).",
        'The command is well-formed in both cases. Its meaning depends on earlier observed mode.',
        'The genuine acknowledgement of the injected command remains normal.',
        '', 'RESPONSE EXAMPLE',
        f"Forged reply: {response['event_id']} | frame(s) {frames(response)} | PDU {response['pdu_hex']}",
        f"Earlier acknowledged setpoint write was {word(set_bad)}; this reply reports {word(response)}.",
        f"Normal identical reply PDU: {normal_response['event_id']} | frame(s) {frames(normal_response)}.",
        f"Its earlier acknowledged setpoint write was {word(set_good)}.",
        'Stored setpoint cannot change except by a captured FC6 write in this toy lab.',
        '', 'The private server audit verifies labels. It is not an input to a detector.',
        'These simple history rules may solve this pilot; ML benefit and real-plant performance are unproved.',
    ])
