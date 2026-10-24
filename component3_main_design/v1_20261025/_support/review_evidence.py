"""Read-only qualification audit. Writes only this proposed design's directory.

Run from repository root with .venv/Scripts/python.exe -X utf8 -B <this file>.
Never invokes Docker, simulator sockets, model code or the baseline writers.
"""
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import csv
import hashlib
import json
import re
import statistics
import struct
import sys

HERE = Path(__file__).resolve().parent.parent
REPO = next(p for p in HERE.parents if (p / 'component3_testbed_v02').is_dir())
BASE = REPO / 'component3_testbed_v02'
FROZEN = ['component3_preparation', 'component3_reassessment', 'component3_testbed_pilot',
          'component3_collection_design', 'component3_testbed_v02', 'component3_collection_runs']
sys.path.insert(0, str(BASE))
from c3qual.validation import validate as frozen_validate


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def lines(path):
    return [json.loads(s) for s in Path(path).read_text(encoding='utf8').splitlines() if s.strip()]


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(8 << 20), b''):
            h.update(b)
    return h.hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + '\n', encoding='utf8')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def protected_snapshot():
    return {p.relative_to(REPO).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)}
            for name in FROZEN for p in sorted((REPO / name).rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts}


def unwrap(value):
    if isinstance(value, dict) and 'value' in value:
        value = value['value']
    return value[0] if isinstance(value, list) else value


def capture_index(raw, client):
    """Separate review decoder for the actual Ethernet/IPv4 classic PCAPs."""
    magic = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\x4d\x3c\xb2\xa1': ('<', 1)}
    endian, scale = magic[raw[:4]]
    require(struct.unpack(endian + 'I', raw[20:24])[0] == 1, 'Review expects measured Ethernet link type')
    pos, frames, base = 24, {}, {}
    while pos < len(raw):
        sec, frac, size, original = struct.unpack(endian + 'IIII', raw[pos:pos+16])
        require(size == original, 'Truncated capture')
        frame = raw[pos+16:pos+16+size]
        require(len(frame) == size and frame[12:14] == b'\x08\x00', 'Unexpected frame/network')
        ihl = (frame[14] & 15) * 4
        total = int.from_bytes(frame[16:18], 'big')
        require(frame[23] == 6 and frame[26:34] == b'\x7f\x00\x00\x01' * 2, 'Unexpected TCP endpoint')
        tcp = 14 + ihl
        src, dst, seq = struct.unpack('!HHI', frame[tcp:tcp+8])
        direction = 'client_to_server' if (src, dst) == (client, 15020) else 'server_to_client'
        require((src, dst) in ((client, 15020), (15020, client)), 'Unexpected connection')
        flags = frame[tcp+13]
        if flags & 2:
            base[direction] = (seq + 1) & 0xffffffff
        data_start = tcp + (frame[tcp+12] >> 4) * 4
        payload = frame[data_start:14+total]
        frames[len(frames)+1] = dict(data_file_offset=pos+16, payload_offset=data_start,
                                     payload=payload, sequence=(seq + bool(flags & 2)) & 0xffffffff,
                                     direction=direction, timestamp_ns=sec*10**9 + frac*scale)
        pos += 16 + size
    require(pos == len(raw) and set(base) == {'client_to_server', 'server_to_client'}, 'Capture framing/SYN missing')
    streams = {d: {} for d in base}
    for frame in frames.values():
        start = (frame['sequence'] - base[frame['direction']]) & 0xffffffff
        for i, byte in enumerate(frame['payload']):
            stream = streams[frame['direction']]
            require(start+i not in stream or stream[start+i] == byte, 'Conflicting overlap')
            stream[start+i] = byte
    out = {}
    for d, stream in streams.items():
        require(stream and len(stream) == max(stream)+1, 'Stream byte gap')
        out[d] = bytes(stream[i] for i in range(len(stream)))
    return frames, base, out


def check_message(row, raw, frames, bases):
    expected = bytes.fromhex(row['adu_hex'])
    reconstructed = bytearray(len(expected))
    covered = set()
    for ref in row['frame_byte_references']:
        frame = frames[ref['frame_number']]
        a, n, b = ref['pcap_file_byte_offset'], ref['length'], ref['message_byte_offset']
        require(a == frame['data_file_offset'] + ref['frame_byte_offset'], 'File/frame byte offsets disagree')
        within = ref['frame_byte_offset'] - frame['payload_offset']
        require(0 <= within and within+n <= len(frame['payload']), 'Reference outside TCP payload')
        require(frame['direction'] == row['direction'] and ref['capture_timestamp_ns'] == frame['timestamp_ns'],
                'Reference direction/timestamp disagrees')
        position = (frame['sequence'] - bases[frame['direction']]) & 0xffffffff
        require(position + within == row['stream_offset'] + b, 'Reference is not this genuine stream occurrence')
        reconstructed[b:b+n] = raw[a:a+n]
        covered.update(range(b, b+n))
    require(covered == set(range(len(expected))) and bytes(reconstructed) == expected, 'Message reconstruction differs')
    tid, protocol, length, unit = struct.unpack('!HHHB', expected[:7])
    require(protocol == 0 and unit == 1 and length+6 == len(expected), 'MBAP malformed')
    require(expected[7:].hex() == row['pdu_hex'] and tid == row['tid'], 'Decoded current message differs')
    return expected


def main():
    snapshot_path = HERE / '_support/protected_sources.json'
    if not snapshot_path.exists():
        save(snapshot_path, protected_snapshot())
    before = read(snapshot_path)
    summary = read(BASE / 'evidence/qualification_summary.json')
    execution = read(BASE / 'evidence/execution-20261024T180504Z-42116f58.json')
    command_runs = [c for c in execution['commands'] if '--planned-run' in c['argv']]
    own_counts, totals, runs, representative, allrows = Counter(), Counter(), [], [], []
    all_capture_hashes, packet_spans, wall = [], [], []
    by_run = {}
    for run in summary['runs']:
        folder = REPO / run['recording']
        for name, digest in run['artifact_sha256'].items():
            require(sha(folder / name) == digest, 'Recorded artifact changed: ' + str(folder / name))
        fresh = frozen_validate(folder, write=False)
        require(fresh['status'] == 'PASSED', str(fresh['errors']))
        existing_report = read(folder / 'validation_report.json')
        for key in ('label_counts', 'message_count', 'transaction_count', 'episode_count', 'coverage_counts',
                    'control_matches', 'causal_dependencies', 'capture_statistics'):
            require(fresh[key] == existing_report[key], 'Re-executed validator differs: ' + key)
        manifest, host = read(folder / 'run_manifest.json'), read(folder / 'host_execution.json')
        ledger, oracle, hooks = (lines(folder / name) for name in
                                ('verified_labels.jsonl', 'server_audit.jsonl', 'intervention_audit.jsonl'))
        proposed = lines(folder / 'application_ledger.jsonl')
        require(len(ledger) == len(proposed) == len(oracle)*2 == len(hooks)*2, 'Message/transaction count differs')
        config = read(folder / 'planned_run.json')
        require((config['map'], config['values'], config['schedule']) == ('M0', 'V0', 'S1'), 'Measured scope differs')
        require(host['image_source_sha256'] == manifest['source_sha256'], 'Image/collection source identity differs')
        require(unwrap(host['image'])['Id'] == run['image_id'], 'Image identity differs')
        raw = (folder / 'capture.pcap').read_bytes()
        frames, bases, streams = capture_index(raw, manifest['client_port'])
        for d in streams:
            require(streams[d] == b''.join(bytes.fromhex(r['adu_hex']) for r in ledger if r['direction'] == d), 'Whole capture stream differs')
        payload_times = [f['timestamp_ns'] for f in frames.values() if f['payload']]
        duration = (max(payload_times)-min(payload_times))/10**9
        packet_spans.append(duration)
        byid = {r['event_id']: (i, r) for i, r in enumerate(ledger)}
        state = {'mode': 0, 'setpoint': 50, 'coil': 0}
        anchors, target_evidence, ack_ids = {}, [], []
        for t, (o, hook) in enumerate(zip(oracle, hooks)):
            i = 2*t
            request, response = ledger[i:i+2]
            rq = check_message(request, raw, frames, bases)
            rp = check_message(response, raw, frames, bases)
            require(request['transaction_index'] == response['transaction_index'] == o['transaction_index'] == hook['transaction_index'] == t,
                    'Ordinal lineage differs')
            require(o['request_adu_hex'] == hook['request_adu_hex'] == rq.hex() and o['wire_response_adu_hex'] == rp.hex(), 'Private/wire lineage differs')
            require(all(o[k+'_before'] == v for k, v in state.items()), 'Private before-state differs')
            fc, address, word = struct.unpack('!BHH', rq[7:])
            tid = int.from_bytes(rq[:2], 'big')
            if fc == 1:
                genuine_pdu = bytes((1, 1, state['coil']))
            elif fc == 3:
                genuine_pdu = b'\x03\x02'+struct.pack('!H', state['mode' if address == 0 else 'setpoint'])
            else:
                key = 'coil' if fc == 5 else 'mode' if address == 0 else 'setpoint'
                state[key] = int(word == 0xff00) if fc == 5 else word
                genuine_pdu = rq[7:]
            genuine = struct.pack('!HHHB', tid, 0, len(genuine_pdu)+1, 1) + genuine_pdu
            require(o['expected_response_adu_hex'] == genuine.hex(), 'Independent genuine response differs')
            require(all(o[k+'_after'] == v for k, v in state.items()), 'Private after-state differs')
            command = hook['kind'] == 'command_injection'
            changed = rp != genuine
            require(command == (fc == 5 and word == 0xff00 and o['mode_before'] == 0), 'Intervention/policy contradiction')
            require(changed == o['response_overridden'] == (hook['kind'] == 'response_injection'), 'Response intervention contradiction')
            require(request['label'] == ('command_injection' if command else 'normal') and
                    response['label'] == ('response_injection' if changed else 'normal'), 'Independent label replay differs')
            if command:
                anchor = anchors['mode']
                require(anchor[1] == 0 and 0 <= i-anchor[0]-1 <= 6, 'Command visible mode anchor differs')
                require(response['label'] == 'normal' and rp[7:] == rq[7:] and not changed, 'Command ACK mislabeled')
                ack_ids.append(response['event_id'])
                target_evidence.append((request, anchor[2], i-anchor[0]-1))
            if changed:
                anchor = anchors['setpoint']
                require(fc == 3 and address == 1 and anchor[1] == o['setpoint_before'], 'Forged reply lacks acknowledged-write anchor')
                require(0 <= (i+1)-anchor[0]-1 <= 6, 'Response visible anchor too old')
                target_evidence.append((response, anchor[2], i-anchor[0]))
            if fc == 6 and address == 0:
                anchors.pop('mode', None)
            if fc == 3 and address == 0:
                anchors['mode'] = (i+1, int.from_bytes(rp[9:11], 'big'), response)
            if fc == 6 and address == 1:
                anchors['setpoint'] = (i+1, word, response)
        for target, anchor, age in target_evidence:
            pool = [r for r in ledger if r['label'] == 'normal' and
                    (r['role'], r['object_role'], r['pdu_hex']) == (target['role'], target['object_role'], target['pdu_hex'])]
            require(pool, 'No role/PDU matched normal control')
            normal = pool[0]
            # One representative of each attack class per recording, plus both response directions globally.
            if not any(e['planned_run_id'] == run['planned_run_id'] and e['label'] == target['label'] for e in representative):
                compact = lambda r: {k: r[k] for k in ('event_id', 'transaction_index', 'role', 'label', 'adu_hex', 'pdu_hex',
                                                       'direction', 'stream_offset', 'frame_byte_references')}
                dep = next(d for d in fresh['causal_dependencies'] if d['event_id'] == normal['event_id'])
                representative.append(dict(planned_run_id=run['planned_run_id'], source=run['recording'], label=target['label'],
                                           target=compact(target), earlier_anchor=compact(anchor), intervening_adus=age,
                                           matching_normal=compact(normal),
                                           normal_earlier_anchor=compact(byid[dep['anchor_event_id']][1])))
        drops = re.findall(r'(?m)^(\d+) packets dropped by kernel$', (folder/'capture.log').read_text())
        require(drops == ['0'], 'Kernel-drop footer differs')
        count = Counter(r['label'] for r in ledger)
        own_counts.update(count)
        totals.update(adus=len(ledger), transactions=len(oracle), episodes=len({r['episode_id'] for r in ledger}), frames=len(frames))
        qid = run['planned_run_id']
        c = next(c for c in command_runs if c['argv'][-1] == qid)
        index = command_runs.index(c)
        next_start = command_runs[index+1]['started_at_utc'] if index+1<len(command_runs) else execution['ended_at_utc']
        wall_seconds = (datetime.fromisoformat(next_start.replace('Z','+00:00')) -
                        datetime.fromisoformat(c['started_at_utc'].replace('Z','+00:00'))).total_seconds()
        wall.append(wall_seconds)
        appspan = (ledger[-1]['observed_at_ns']-ledger[0]['observed_at_ns'])/10**9
        # Timing audit summaries only: no model features/matrices or fitting.
        gaps = [(ledger[i]['observed_at_ns']-ledger[i-1]['observed_at_ns'])/10**6 for i in range(2,len(ledger),2)]
        request_tids = [r['tid'] for r in ledger if r['role']=='request']
        sequential_transitions = sum(b == ((a+1)&65535) for a,b in zip(request_tids,request_tids[1:]))
        require(sequential_transitions == len(request_tids)-1, 'Observed TID schedule is not sequential as reported')
        positions = defaultdict(list)
        episode_lengths = Counter()
        for episode in {r['episode_id'] for r in ledger}:
            erows = [r for r in ledger if r['episode_id']==episode]
            episode_lengths[len(erows)//2] += 1
            for index,r in enumerate(erows):
                if r['label']!='normal':
                    positions[r['label']].append(index//2)
        trace_pdu_hash = hashlib.sha256('\n'.join(r['direction']+':'+r['pdu_hex'] for r in ledger).encode()).hexdigest()
        local_counts = Counter(r['scenario'] for r in ledger)
        runs.append(dict(planned_run_id=qid, source=run['recording'], label_counts=dict(count), adus=len(ledger),
                         transactions=len(oracle), episodes=len({r['episode_id'] for r in ledger}), frames=len(frames),
                         config=config, kernel_drops=0, frozen_validator_reexecuted_readonly='PASSED',
                         independent_byte_state_intervention_and_anchor_replay='PASSED',
                         genuine_command_ack_ids=ack_ids, target_anchor_intervening_adus=sorted({age for _,_,age in target_evidence}),
                         application_span_seconds=appspan, capture_payload_span_seconds=duration,
                         launch_until_next_launch_or_ledger_end_seconds=wall_seconds,
                         client_interexchange_gap_ms=dict(min=min(gaps), median=statistics.median(gaps), max=max(gaps)),
                         actual_tid_schedule=dict(first=request_tids[0], last=request_tids[-1],
                                                  sequential_transitions=sequential_transitions, total_transitions=len(request_tids)-1),
                         attack_transaction_positions_within_episode={k:sorted(v) for k,v in positions.items()},
                         episode_transaction_length_counts=dict(episode_lengths),
                         ordered_direction_pdu_trace_sha256=trace_pdu_hash,
                         all_artifact_bytes=sum(p.stat().st_size for p in folder.iterdir() if p.is_file()),
                         pcap_bytes=len(raw), scenario_message_counts=dict(local_counts),
                         image_id=run['image_id'], artifact_sha256=run['artifact_sha256']))
        all_capture_hashes.append(sha(folder/'capture.pcap'))
        by_run[qid] = ledger
        allrows.extend(ledger)
    require(dict(own_counts) == summary['label_counts'], 'Summary labels differ')
    require((totals['adus'], totals['transactions'], totals['episodes']) == (1846,923,80), 'Known totals differ')
    require(len(set(all_capture_hashes)) == 4, 'Whole-capture duplication')
    require(len({r['ordered_direction_pdu_trace_sha256'] for r in runs})==4, 'Ordered PDU trace duplication')
    with (BASE/'evidence/coverage_counts.csv').open(encoding='utf8', newline='') as f:
        coverage = list(csv.DictReader(f))
    key = lambda r: (r['scenario'], r['label'], r['role'], int(r['function_code']), r['object_role'], r['pdu_hex'])
    cc = Counter()
    for r in coverage:
        cc[(r['planned_run_id'],)+key(r)] += int(r['count'])
    require(cc == Counter((qid,)+key(r) for qid, rr in by_run.items() for r in rr), 'Coverage CSV differs from actual annotations')
    existing_examples = read(BASE/'evidence/evidence_examples.json')['examples']
    count_examples = 0
    for e in existing_examples:
        folder = REPO/e['source']
        actual = {r['event_id']: r for r in lines(folder/'verified_labels.jsonl')}
        for name in ('target','earlier_anchor','matching_normal','control_earlier_anchor'):
            item = e.get(name)
            if item:
                require(all(actual[item['event_id']][k] == v for k,v in item.items()), 'Existing example differs: '+name)
        count_examples += 1
    failed = REPO / summary['failed_attempts_preserved'][0]['path']
    fm = read(failed/'run_manifest.json')
    require(fm['status']=='FAILED' and fm['observed_application_messages']==0 and
            not (failed/'verified_labels.jsonl').exists(), 'Failed attempt unexpectedly accepted')
    # Check the older preservation receipt, without calling its mutating check CLI.
    old_before = read(BASE/'evidence/protected_before.json')
    require(all(sha(REPO/name)==row['sha256'] for name,row in old_before.items()), 'Older protected file changed')
    body_overlap = {}
    for label in ('command_injection','response_injection'):
        attacks = [r for r in allrows if r['label']==label]
        body_overlap[label] = dict(events=len(attacks), distinct_pdus=len({r['pdu_hex'] for r in attacks}),
                                   all_have_within_run_role_pdu_normal=True,
                                   unique_current_tids=len({r['tid'] for r in attacks}),
                                   tid_min=min(r['tid'] for r in attacks), tid_max=max(r['tid'] for r in attacks))
    timing_summary = dict(capture_payload_span_seconds=dict(min=min(packet_spans), median=statistics.median(packet_spans), max=max(packet_spans)),
                          launch_to_next_or_end_seconds=dict(min=min(wall), median=statistics.median(wall), max=max(wall)),
                          complete_successful_execution_seconds=(datetime.fromisoformat(execution['ended_at_utc'].replace('Z','+00:00'))-
                              datetime.fromisoformat(execution['started_at_utc'].replace('Z','+00:00'))).total_seconds(),
                          caveat='Launch intervals include Docker startup, capture drain, validation and host recording; intervals are not isolated simulator CPU time')
    filesizes = [r['all_artifact_bytes'] for r in runs]
    trace = (BASE/'evidence/execution-20261024T180504Z-42116f58.log').read_text(encoding='utf-8-sig')
    identity = dict(machine=re.search(r'(?m)^Machine: (.*)$',trace).group(1).strip(),
                    provenance='Self-reported collection transcript, corroborated by the host execution record; hardware/operator identity not independently attested',
                    image_ids=sorted({r['image_id'] for r in runs}), runtime='Linux Docker container; loopback only',
                    collector_username=re.search(r'(?m)^Username: (.*)$',trace).group(1).strip())
    after = protected_snapshot()
    require(before==after, 'Frozen roots changed during review')
    evidence = dict(status='REVIEW_REPRODUCED_QUALIFICATION_WITH_LIMITED_SCOPE', review_date_local='2026-10-25',
                    timezone='Asia/Colombo', total_counts=dict(totals), label_counts=dict(own_counts),
                    successful_measured_captures=4, measured_configurations=['M0/V0/S1'], runs=runs,
                    representative_direct_checks=representative, existing_evidence_examples_checked=count_examples,
                    preserved_failed_attempt=dict(source=failed.relative_to(REPO).as_posix(), observed_adus=0,
                                                  accepted_annotations_present=False, included_in_accepted_totals=False),
                    checks_independently_reproduced_in_this_review=[
                        'SHA256 of every run artifact against summary, all frozen source hashes through read-only validator',
                        'Independent review PCAP frame/stream/file-byte reconciliation for all 1846 ADUs',
                        'Independent review private-state/intervention/label replay for all 923 transactions',
                        'All 24 attack anchors and same-run role/PDU matched normal controls; all 8 command ACKs remain normal',
                        'Existing coverage CSV exactly equals annotation census; all 24 supplied evidence examples match actual rows',
                        'Preserved failed attempt excluded; four whole capture hashes distinct; earlier 201 protected files unchanged'],
                    reexecuted_existing_checks=['Frozen v0.2 validator, write=False, on all four captures; results match saved reports'],
                    supported_only_by_existing_reports=['28 offline adversarial tests previously passed; test suite inspected but not rerun',
                                                       'Original Docker build/execution success and network-none setup; execution records inspected, no current Docker daemon check'],
                    checks_not_performed=['No recapture, Docker build, simulator execution or fresh live isolation test',
                                          'No independent hardware/operator attestation or fresh physical process observation',
                                          'No rerender/re-extraction of TAF/proposal PDFs; selected existing cached page text read and source PDFs hashed',
                                          'No statistical shortcut classifier, preprocessing, fitted profiles, feature matrices or model scores',
                                          'No rehash/re-extraction of original multi-GB CIC raw sources; no writes to that tree'],
                    coverage_csv_rows=len(coverage), current_pdu_overlap=body_overlap,
                    intervention_mechanisms=['Compromised-controller protocol-valid FC5 ON while observed mode is 0',
                                             'Compromised-server replacement of one FC3 setpoint response, a-to-b or b-to-a'],
                    normal_families=6, attack_families=2, independent_industrial_campaigns_demonstrated=0,
                    experimental_environment_count=1, timing_measurements=timing_summary,
                    storage_measurements=dict(run_artifact_bytes=dict(min=min(filesizes), median=statistics.median(filesizes), max=max(filesizes)),
                                              total_successful_run_bytes=sum(filesizes), pcap_bytes=sum(r['pcap_bytes'] for r in runs)),
                    collection_machine_identity=identity,
                    preservation=dict(status='PASSED', files_compared=len(before), changed_files=[],
                                      snapshot='_support/protected_sources.json', snapshot_sha256=sha(snapshot_path)),
                    academic_acceptance=dict(status='NOT_RECORDED_IN_REVIEWED_MATERIAL',
                                             searched_scope=['TAF cached pages 6,7,9,10; individual proposal cached pages 21,22',
                                                             'Original design alignment/protocol and v0.2 decision/README/implementation notes',
                                                             'Supplied historical CIC decision/review background'],
                                             caveat='This bounded repository review cannot establish that no external conversation occurred'),
                    unresolved_assumptions=['No hidden writer/autonomous setpoint changes in the declared process',
                                            'Private intervention hooks accurately report actual interventions; byte/state checks provide internal consistency, not external attestation',
                                            'Observable history can be recovered without packet loss for future runs',
                                            'Existing matched PDUs do not establish absence of ordering/timing/TID cues'],
                    provenance=dict(repository_root_at_review=str(REPO),
                                    reviewer_code='_support/review_evidence.py', reviewer_code_sha256=sha(Path(__file__)),
                                    portable_paths='All source references are repository-relative except recorded original execution arguments',
                                    exact_review_command='.\\.venv\\Scripts\\python.exe -X utf8 -B component3_main_design/v1_20261025/_support/review_evidence.py'),
                    prohibited_work_performed=False)
    # Preserve hashes for the documents actually consulted, without trusting historical instructions.
    references = [BASE/'QUALIFICATION_REPORT.md', BASE/'evidence/qualification_summary.json',
                  BASE/'evidence/evidence_examples.json', BASE/'evidence/coverage_counts.csv',
                  BASE/'evidence/protected_after.json', BASE/'evidence/IMPLEMENTATION_NOTES.md',
                  REPO/'component3_collection_design/v1_20261024/collection_design.json',
                  REPO/'component3_collection_design/v1_20261024/RESEARCH_ALIGNMENT.md']
    references += list((REPO/'component3_preparation/output/reference_review').glob('*.json'))
    references += [p for p in (REPO/'references/component3_reference').glob('*.pdf')]
    evidence['reference_input_sha256'] = {p.relative_to(REPO).as_posix(): sha(p) for p in references}
    save(HERE/'evidence_checks.json', evidence)
    print(json.dumps({k:evidence[k] for k in ('total_counts','label_counts','current_pdu_overlap','timing_measurements','storage_measurements','preservation')},indent=2))


if __name__ == '__main__':
    main()
