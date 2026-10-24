"""Validate the proposed collection contract and read existing pilot evidence.

No simulator execution, Docker build, capture, label rewrite, split or model work.
All writes are confined to this new design directory.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from zoneinfo import ZoneInfo
import csv
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REPO = next(p for p in HERE.parents if (p / 'component3_testbed_pilot/c3lab/pilot.py').is_file())
OUT = HERE / 'output'
PILOT = REPO / 'component3_testbed_pilot'


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def write(name, value):
    path = (OUT / name).resolve()
    if not path.is_relative_to(OUT.resolve()):
        raise ValueError('Design output escaped its own versioned directory')
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf8')


def protected_files():
    paths = []
    for root in (REPO / 'component3_preparation', REPO / 'component3_reassessment', PILOT / 'c3lab', PILOT / 'outputs', PILOT / 'docs'):
        if root.exists():
            paths.extend(p for p in root.rglob('*') if p.is_file())
    paths.extend(p for p in PILOT.iterdir() if p.is_file())
    return sorted(set(paths))


def snapshot():
    return {p.relative_to(REPO).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in protected_files()}


def validate_plan(plan):
    errors = []
    def need(condition, reason):
        if not condition:
            errors.append(reason)
    need(plan['status'] == 'PROPOSED_COLLECTION_PROTOCOL_NOT_A_COLLECTED_DATASET', 'Plan must not claim completed collection')
    need(plan['qualification']['ready_now'] is False, 'Qualification is not already complete under this proposed design')
    need(plan['limits']['function_codes'] == [1, 3, 5, 6], 'Unreviewed protocol scope change')
    scenarios = {s['id']: s for s in plan['scenarios']}
    need(len(scenarios) == len(plan['scenarios']), 'Duplicate scenario IDs')
    need(set(scenarios) == set(plan['qualification']['required_scenarios']), 'Qualification must cover every declared family')
    for s in scenarios.values():
        if s['label_family'] in ('command_injection', 'response_injection'):
            need(s.get('pdu_overlap_required') is True, s['id'] + ': missing current-PDU normal-control requirement')
            need(bool(s.get('matched_controls')), s['id'] + ': missing normal controls')
            for normal in s.get('matched_controls', []):
                need(normal in scenarios and scenarios[normal]['label_family'] == 'normal', s['id'] + ': invalid normal control ' + normal)
    maps = {m['id']: m for m in plan['maps']}
    schedules = {s['id'] for s in plan['schedules']}
    values = {v['id']: v for v in plan['value_profiles']}
    for m in maps.values():
        need(m['mode_register'] != m['setpoint_register'], m['id'] + ': holding-register roles overlap')
        need(all(0 <= m[k] <= 65535 for k in ('mode_register', 'setpoint_register', 'pump_coil')), m['id'] + ': address outside wire range')
    for v in values.values():
        need(0 <= v['minimum'] < v['maximum'] <= 65535, v['id'] + ': invalid raw-word range')
    roster = []
    for i, seed in enumerate(plan['qualification']['seeds'], 1):
        roster.append({'planned_run_id': f'Q{i:02d}', 'purpose': 'qualification_unscored', 'map': plan['qualification']['map'],
                       'schedule': plan['qualification']['schedule'], 'values': plan['qualification']['value_profile'], 'seed': seed})
    need(len(roster) == plan['qualification']['planned_runs'], 'Qualification run/seed count disagrees')
    for cell in plan['prospective_main_roster']['cells']:
        seed = cell['seed_start']
        number = 1
        for mapping in cell['maps']:
            need(mapping in maps, 'Unknown map ' + mapping)
            for schedule in cell['schedules']:
                need(schedule in schedules, 'Unknown schedule ' + schedule)
                need(cell['values'] in values, 'Unknown value profile ' + cell['values'])
                for repetition in range(1, cell['repetitions_per_cell'] + 1):
                    roster.append({'planned_run_id': f'{cell["role"]}-{number:03d}', 'purpose': cell['role'], 'map': mapping,
                                   'schedule': schedule, 'values': cell['values'], 'seed': seed, 'replication_in_cell': repetition})
                    seed += 1
                    number += 1
    need(len({r['seed'] for r in roster}) == len(roster), 'Seeds reused across prospective collection roles')
    need(len({r['planned_run_id'] for r in roster}) == len(roster), 'Duplicate planned run IDs')
    development = [r for r in roster if r['purpose'] in ('development', 'validation')]
    need(all(r['map'] != 'M2' and r['schedule'] != 'S2' and r['values'] != 'V1' for r in development), 'Held-out condition leaked into development/validation')
    need(all(r['map'] == 'M2' for r in roster if r['purpose'] == 'test_map'), 'Map test is not held out')
    need(all(r['values'] == 'V1' for r in roster if r['purpose'] == 'test_values'), 'Value test profile disagrees')
    need(all(r['schedule'] == 'S2' for r in roster if r['purpose'] == 'test_schedule'), 'Schedule test profile disagrees')
    need(plan['prospective_main_roster']['qualification_runs_included'] is False, 'Engineering runs must not be used for model selection/scoring')
    need(plan['causal_contract']['qualification_max_intervening_adus_from_anchor'] <= 10, 'Qualification context exceeds its declared prospective horizon')
    return errors, roster


def compact(row):
    return {'event_id': row['event_id'], 'label': row['label'], 'role': row['role'], 'pdu_hex': row['pdu_hex'],
            'tid': row['tid'], 'frame_numbers': sorted({r['frame_number'] for r in row['frame_byte_references']}),
            'frame_byte_references': row['frame_byte_references'], 'connection_direction': row['direction'],
            'stream_offset': row['stream_offset']}


def verify_local_pilot(plan):
    run = (REPO / plan['existing_local_pilot']).resolve()
    if not run.is_relative_to((PILOT / 'outputs').resolve()):
        raise ValueError('Existing pilot path is outside the declared pilot output directory')
    validation = read(run / 'validation_report.json')
    manifest = read(run / 'run_manifest.json')
    host = read(run / 'host_execution.json')
    rows = [json.loads(line) for line in (run / 'verified_labels.jsonl').read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    oracle = [json.loads(line) for line in (run / 'server_audit.jsonl').read_text(encoding='utf-8-sig').splitlines() if line.strip()]
    by_tid = {r['tid']: r for r in oracle}
    capture = (run / 'capture.pcap').read_bytes()
    errors = []
    input_hash_checks = {name: sha(run / name) == value for name, value in validation['input_sha256'].items()}
    source_hash_checks = {name: sha(PILOT / 'c3lab' / name) == value for name, value in manifest['source_sha256'].items()}
    if not all(input_hash_checks.values()) or not all(source_hash_checks.values()):
        errors.append('Pilot inputs/source bytes differ from their recorded hashes')
    spec = importlib.util.spec_from_file_location('c3_pilot_design_readonly_validator', PILOT / 'c3lab/capture_validation.py')
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    normal = {(r['role'], r['pdu_hex']) for r in rows if r['label'] == 'normal'}
    attacks = [r for r in rows if r['label'] != 'normal']
    for r in rows:
        references = sorted(r['frame_byte_references'], key=lambda x: x['message_byte_offset'])
        raw = b''.join(capture[x['pcap_file_byte_offset']:x['pcap_file_byte_offset'] + x['length']] for x in references)
        if raw != bytes.fromhex(r['adu_hex']):
            errors.append(r['event_id'] + ': capture-byte mismatch')
        try:
            validator._adu(raw, r['role'])
        except Exception as exc:
            errors.append(r['event_id'] + ': protocol check ' + str(exc))
    for r in attacks:
        truth = by_tid[r['tid']]
        if (r['role'], r['pdu_hex']) not in normal:
            errors.append(r['event_id'] + ': missing normal role/PDU control')
        if r['label'] == 'command_injection':
            if not (r['role'] == 'request' and truth['request_adu_hex'] == r['adu_hex'] and truth['mode_before'] == 0 and truth['coil_after'] == 1):
                errors.append(r['event_id'] + ': command/policy/private-state evidence mismatch')
            replies = [q for q in rows if q['tid'] == r['tid'] and q['role'] == 'response']
            if len(replies) != 1 or replies[0]['label'] != 'normal':
                errors.append(r['event_id'] + ': genuine acknowledgement target mislabelled')
        elif r['label'] == 'response_injection':
            if not (r['role'] == 'response' and truth['wire_response_adu_hex'] == r['adu_hex']
                    and truth['response_overridden'] and truth['expected_response_adu_hex'] != r['adu_hex']):
                errors.append(r['event_id'] + ': reply-mutation evidence mismatch')
    counts = dict(Counter(r['label'] for r in rows))
    if validation['status'] != 'PASSED' or counts != validation['label_counts']:
        errors.append('Validation status/counts disagree')
    examples = []
    for label in ('command_injection', 'response_injection'):
        target = next(r for r in rows if r['label'] == label)
        control = next(r for r in rows if r['label'] == 'normal' and r['role'] == target['role'] and r['pdu_hex'] == target['pdu_hex'] and r['step'] == target['step'])
        pair = []
        for r in (target, control):
            anchor_step = 'observe_mode' if r['role'] == 'request' else 'set_setpoint'
            anchors = [q for q in rows if q['episode_id'] == r['episode_id'] and q['step'] == anchor_step and q['role'] == 'response'
                       and int(q['event_id'].rsplit(':e', 1)[1]) < int(r['event_id'].rsplit(':e', 1)[1])]
            if not anchors:
                errors.append(r['event_id'] + ': missing earlier visible anchor')
                continue
            anchor = anchors[-1]
            value = int.from_bytes(bytes.fromhex(anchor['pdu_hex'])[-2:], 'big')
            pair.append({'current_event': compact(r), 'earlier_wire_anchor': compact(anchor),
                         'earlier_observed_raw_word': value, 'private_oracle_tid_reference': r['tid']})
        examples.append({'mechanism': label, 'matched_role_pdu': target['pdu_hex'], 'pair': pair})
    drop_text = (run / 'capture.log').read_text(encoding='utf8')
    if '0 packets dropped by kernel' not in drop_text:
        errors.append('Zero capture drops not established in the actual recorder log')
    result = {'run_id': run.name, 'run_relative_path': run.relative_to(REPO).as_posix(), 'status': validation['status'],
              'message_count': len(rows), 'transaction_count': validation['transaction_count'], 'label_counts': counts,
              'captured_frames': validation['capture_statistics']['frames'], 'capture_sha256': sha(run / 'capture.pcap'),
              'reported_capture_drops': 0, 'original_pcap_byte_checks': len(rows), 'protocol_checks': len(rows),
              'input_hash_checks': input_hash_checks, 'source_hash_checks': source_hash_checks,
              'direct_attack_targets_checked': len(attacks), 'normal_role_pdu_overlap_targets': len(attacks),
              'collection_started_utc': host['started_at_utc'], 'collection_ended_utc': host['ended_at_utc'],
              'collection_started_sri_lanka': datetime.fromisoformat(host['started_at_utc'].replace('Z', '+00:00')).astimezone(ZoneInfo('Asia/Colombo')).isoformat(),
              'compose_sha256': host['compose_sha256'], 'docker_exit_code': host['docker_exit_code'],
              'environment': {'python': manifest['python'], 'platform': manifest['platform'], 'network': manifest['isolation_requested']},
              'examples': examples, 'errors': errors, 'read_only_verification_passed': not errors,
              'scope': 'Read-only confirmation of the existing local pilot; no capture, annotation rewrite or model processing performed'}
    return result


def write_pilot_card(evidence):
    table = []
    for ex in evidence['examples']:
        for item in ex['pair']:
            r = item['current_event']; a = item['earlier_wire_anchor']
            table.append(f"| {r['event_id'].rsplit(':', 1)[1]} | {r['label']} | {','.join(map(str, r['frame_numbers']))} | `{r['pdu_hex']}` | {a['event_id'].rsplit(':', 1)[1]}, frame {','.join(map(str, a['frame_numbers']))}: `{a['pdu_hex']}` |")
    text = f"""# Local pilot card — user's new run

Run: `{evidence['run_id']}`. Started **{evidence['collection_started_sri_lanka']}** (Asia/Colombo), corresponding to `{evidence['collection_started_utc']}` UTC. This is the user's reported local execution in the current repository. Hardware ownership/operator identity is not independently attested by the manifests.

This card describes the new local run, not the collaborator's earlier `pilot-20261024T145730Z-4a7f6472`. Keep the original `component3_testbed_pilot/DATASET_CARD.md` and handover provenance unchanged.

| Measurement | Actual local result |
|---|---:|
| Transactions | {evidence['transaction_count']} |
| Complete messages | {evidence['message_count']} |
| Normal | {evidence['label_counts']['normal']} |
| Command targets | {evidence['label_counts']['command_injection']} |
| Response targets | {evidence['label_counts']['response_injection']} |
| Captured frames | {evidence['captured_frames']} |
| Reported kernel drops | 0 |
| Message-byte and protocol checks | {evidence['original_pcap_byte_checks']} each |
| Targets sharing role/PDU with normal controls | {evidence['normal_role_pdu_overlap_targets']} of {evidence['direct_attack_targets_checked']} |

Validation: **{evidence['status']}**. Current raw inputs and generator sources match the recorded hashes. The read-only follow-up check found {len(evidence['errors'])} errors. Capture SHA256: `{evidence['capture_sha256']}`.

## Explain two matched normal/attack pairs

Event suffixes and frame numbers below refer only to this capture. Each earlier anchor was observed before the current message; none uses a future recovery read as predictive evidence.

| Event | Direct label | Frame | Current PDU | Earlier visible anchor |
|---|---|---:|---|---|
{chr(10).join(table)}

For the command pair, the current pump-ON PDU is identical; the earlier mode is the relevant difference. For the reply pair, the reported PDU is identical; the relevant difference is the earlier acknowledged setpoint write. The separate private audit establishes the intervention and simulated before/after state. Private state, scenario/step IDs and true labels remain audit evidence, not detector inputs.

## What this supports

These are actual packets from a simulated software process. The run demonstrates collection, exact evidence and causal observability for this minimal lab. It does not establish physical-plant effects, multiple independent campaigns, adequate training size or ML superiority. Twelve episodes in one connection remain related observations.

All original run files are preserved. This run and the collaborator's run are engineering demonstrations excluded from the proposed main collection. No new labels, preprocessing, feature windows or model artifacts were created by this check. Detailed hashes, frame/file-byte references and examples are in `output/local_pilot_evidence.json`.
"""
    (HERE / 'LOCAL_PILOT_CARD.md').write_text(text, encoding='utf8')


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    before = snapshot()
    protected_path = OUT / 'protected_inputs.json'
    if protected_path.exists():
        recorded = read(protected_path)
        changed = [p for p, v in recorded.items() if before.get(p) != v]
        if changed:
            raise RuntimeError('Previously protected inputs changed; do not overwrite the baseline: ' + ', '.join(changed[:5]))
    else:
        write('protected_inputs.json', before)
    plan = read(HERE / 'collection_design.json')
    errors, roster = validate_plan(plan)
    evidence = verify_local_pilot(plan)
    errors.extend(evidence['errors'])
    if errors:
        write('plan_checks.json', {'status': 'FAILED', 'errors': errors})
        raise RuntimeError('; '.join(errors))
    fields = ['planned_run_id', 'purpose', 'map', 'schedule', 'values', 'seed', 'replication_in_cell', 'design_id', 'status']
    with (HERE / 'PROSPECTIVE_RUN_ROSTER.csv').open('w', newline='', encoding='utf8') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in roster:
            writer.writerow({**row, 'design_id': plan['design_id'], 'status': 'NOT_COLLECTED'})
    write('local_pilot_evidence.json', evidence)
    write_pilot_card(evidence)
    after = snapshot()
    changed = [p for p, v in before.items() if after.get(p) != v]
    result = {'status': 'DESIGN_VALID_IMPLEMENTATION_AND_QUALIFICATION_PENDING', 'errors': [],
              'plan_sha256': sha(HERE / 'collection_design.json'), 'checker_sha256': sha(Path(__file__)),
              'prospective_roster_sha256': sha(HERE / 'PROSPECTIVE_RUN_ROSTER.csv'),
              'prospective_counts': dict(Counter(r['purpose'] for r in roster)),
              'prospective_qualification_runs': 4, 'prospective_main_runs': len(roster) - 4,
              'actual_new_captures_collected': 0, 'actual_new_model_partitions_created': 0,
              'existing_pilot_readonly_checks': evidence['read_only_verification_passed'],
              'protected_files_checked': len(before), 'protected_existing_files_unchanged': not changed,
              'changed_protected_files': changed,
              'implementation_gaps': ['new normal scenario families', 'configurable M1/M2 object maps', 'S1/S2 dependency-safe scheduling',
                                      'expanded independent validator and per-run control audits', 'versioned collection launcher and role/condition gate'],
              'academic_source_change_approval_recorded': False, 'ready_for_bulk_collection': False,
              'next_technical_stage': 'Implement a separate generator/validator version against this protocol, then four unscored qualification captures',
              'no_model_preprocessing_or_training': True}
    write('plan_checks.json', result)
    input_paths = [PILOT / 'docs/EXPERIMENT.md', PILOT / 'DATASET_CARD.md', REPO / 'component3_preparation/REFERENCE_AUDIT.md',
                   REPO / 'component3_reassessment/v1_20261024/DECISION_REPORT.md',
                   REPO / 'references/component3_reference/IT4010-TAF-2026 J26-CS-318 (1).pdf',
                   REPO / 'references/component3_reference/IT23150270_Rathnayaka K.H..pdf']
    write('provenance.json', {'design_id': plan['design_id'], 'date': '2026-10-24', 'timezone': 'Asia/Colombo',
                             'exact_reproduction_command': './.venv/Scripts/python.exe -X utf8 -B component3_collection_design/v1_20261024/check_design.py',
                             'source_references': {p.relative_to(REPO).as_posix(): sha(p) for p in input_paths},
                             'design_files_sha256': {p.name: sha(p) for p in sorted(HERE.iterdir()) if p.is_file()},
                             'protected_snapshot_sha256': sha(protected_path), 'raw_cic_rehash_performed': False})
    if changed:
        raise RuntimeError('Protected files changed during a read-only design check')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
