"""Independent wire decoder/state replay; accept the whole run or no labels.

No imports from the generator's protocol, process or scenario implementation.
Private evidence is used for annotation only. Dependency ledgers are audit
diagnostics, not engineered detector features or model matrices.
"""
from collections import Counter, defaultdict
from pathlib import Path
import json
import re
import struct
import uuid

from .config import PURPOSE, ROOT, design, object_map, planned, read_json, sha, source_hashes
from .transport import ValidationError, _check as need, _read_pcap, _message_refs


def jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding='utf8').splitlines() if line.strip()]


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf8')


def decode(raw, role, m):
    need(8 <= len(raw) <= 260, 'ADU length outside limits')
    tid, pid, length, unit = struct.unpack('!HHHB', raw[:7])
    need(pid == 0 and unit == 1 and 2 <= length <= 254 and len(raw) == length + 6, 'MBAP mismatch')
    pdu = raw[7:]
    fc = pdu[0]
    need(fc in (1, 3, 5, 6), 'Unsupported/exception function')
    addr = word = None
    if role == 'request' or fc in (5, 6):
        need(len(pdu) == 5, 'Request/echo must contain five PDU bytes')
        addr, word = struct.unpack('!HH', pdu[1:])
        need(addr == m['pump_coil'] if fc in (1, 5) else addr in
             (m['mode_register'], m['setpoint_register']), 'Address outside public map')
        need(fc not in (1, 3) or word == 1, 'Read quantity must be one')
        need(fc != 5 or word in (0, 0xff00), 'Invalid coil encoding')
        need(not (fc == 6 and addr == m['mode_register']) or word in (0, 1), 'Invalid mode')
    elif fc == 1:
        need(len(pdu) == 3 and pdu[1] == 1 and pdu[2] in (0, 1), 'Invalid FC1 response')
        word = pdu[2]
    else:
        need(len(pdu) == 4 and pdu[1] == 2, 'Invalid FC3 response/byte count')
        word = int.from_bytes(pdu[2:], 'big')
    return dict(tid=tid, unit=unit, fc=fc, addr=addr, word=word, pdu=pdu)


def pair(req, reply, m):
    a, b = decode(req, 'request', m), decode(reply, 'response', m)
    need((a['tid'], a['unit'], a['fc']) == (b['tid'], b['unit'], b['fc']), 'Pair identity mismatch')
    need(a['fc'] not in (5, 6) or a['pdu'] == b['pdu'], 'Write ACK does not echo request')
    return a, b


def pack(tid, pdu):
    return struct.pack('!HHHB', tid, 0, len(pdu) + 1, 1) + pdu


def validate(folder, write=True, allow_synthetic=False):
    folder = Path(folder).resolve()
    labels_path = folder / 'verified_labels.jsonl'
    report = dict(schema_version=3, status='FAILED', accepted_labels=False, errors=[],
                  purpose=PURPOSE, no_model_preprocessing_or_training=True,
                  limitations=['One software testbed; runs are not independent industrial campaigns',
                               'Only single-connection IPv4 loopback FC1/3/5/6 supported',
                               'TCP/IP checksums not assessed (local offload); no physical impact inference',
                               'Qualification excluded from future model fitting, selection and scoring'])
    try:
        manifest = read_json(folder / 'run_manifest.json')
        config = read_json(folder / 'planned_run.json')
        synthetic = manifest.get('synthetic_test_fixture') is True
        need(not synthetic or allow_synthetic, 'Synthetic fixture cannot be accepted as measured qualification')
        need(manifest['purpose'] == PURPOSE, 'Not an unscored qualification run')
        need(manifest['status'] == 'CAPTURE_COLLECTED' and manifest['capture_required'] is True
             and manifest['capture_exit_code'] == 0, 'Incomplete or unsuccessful capture')
        need(config == planned(config['planned_run_id']), 'Planned run differs from frozen qualification roster')
        need(manifest['planned_run'] == config, 'Manifest/config mismatch')
        need(manifest['source_sha256'] == source_hashes(), 'Source hashes differ from current implementation')
        for name, digest in manifest['input_sha256'].items():
            need('/' not in name and '\\' not in name and name not in ('.', '..'), 'Unsafe input path')
            need(sha(folder / name) == digest, 'Input hash differs: ' + name)
        required = {'capture.pcap', 'capture.log', 'application_ledger.jsonl', 'server_audit.jsonl',
                    'intervention_audit.jsonl', 'planned_run.json', 'scenario_plan.json'}
        need(required <= set(manifest['input_sha256']), 'Missing required input hash')
        log = (folder / 'capture.log').read_text(encoding='utf8')
        drops = re.findall(r'(?m)^\s*(\d+) packets dropped by kernel\s*$', log)
        need(len(drops) == 1 and int(drops[0]) == 0, 'Missing/nonzero capture-drop footer')
        need('listening on lo' in log, 'Recorder readiness not evidenced')
        plan = read_json(folder / 'scenario_plan.json')
        normal_only = config['recording_mode']=='normal_only'
        expected_families = {s['id'] for s in design()['scenarios']}
        if normal_only:
            expected_families -= {'C_BLOCKED_ON','R_CHANGED_READBACK'}
            expected_families |= {'N_C_TEMPLATE_CONTROL','N_R_TEMPLATE_CONTROL'}
        need({p['family'] for p in plan} == expected_families, 'Scenario family coverage missing')
        need(len({p['episode_id'] for p in plan}) == len(plan), 'Duplicate planned episode')
        episode_plan = {p['episode_id']: p for p in plan}
        need(len(plan)==90, 'Expected 90 engineering episode slots')
        cells={(tid,q) for tid in ('DSEQ','DREUSE','DRANDOM') for q in (0,1,2)}
        block_cells={}
        for p in plan:
            cell=(p['tid_profile'],p['anchor_poll_count'])
            need(cell in cells, 'Invalid nuisance cell')
            need(p['block'] not in block_cells or block_cells[p['block']]==cell, 'Block/cell lineage differs')
            block_cells[p['block']]=cell
        need(set(block_cells.values())==cells and len(block_cells)==9, 'Missing crossed nuisance cells')
        family_expected=Counter({s:1 for s in expected_families})
        family_expected['N_GENUINE_READBACK']=2
        family_expected['N_R_TEMPLATE_CONTROL' if normal_only else 'R_CHANGED_READBACK']=2
        bounds=next(v for v in design()['collection_factors']['value_profiles'] if v['id']==config['values'])
        for block in block_cells:
            bp=[p for p in plan if p['block']==block]
            need(Counter(p['family'] for p in bp)==family_expected, 'Per-cell family coverage differs')
            need(all(bounds['minimum']<=p['a']<=bounds['maximum'] and bounds['minimum']<=p['b']<=bounds['maximum']
                     and p['a']!=p['b'] for p in bp), 'Invalid distinct raw value pair')
            need(len({(p['a'],p['b']) for p in bp})==1, 'Block value-pair lineage differs')
        ledger = jsonl(folder / 'application_ledger.jsonl')
        audit = jsonl(folder / 'server_audit.jsonl')
        interventions = jsonl(folder / 'intervention_audit.jsonl')
        need(ledger and len(ledger) == len(audit) * 2 == len(interventions) * 2, 'Incomplete transaction ledgers')
        need(len({r['event_id'] for r in ledger}) == len(ledger), 'Duplicate event ID')
        need(manifest['observed_application_messages'] == len(ledger), 'Manifest message count differs')
        need(manifest['episodes'] == len(plan), 'Manifest episode count differs')
        m = object_map(config['map'])
        state = dict(mode=0, setpoint=50, coil=0)
        anchors = {}  # only earlier successful on-wire observations
        rows, dependencies, controls = [], [], []
        offsets = dict(client_to_server=0, server_to_client=0)
        streams_expected = {key: bytearray() for key in offsets}
        episode_counts, label_counts, positions = Counter(), Counter(), defaultdict(set)
        family_counts, forgery_counts = Counter(), Counter()
        episode_indices = defaultdict(list)
        coil_repeats = []
        setpoint_repeats = []
        matched_pools = defaultdict(list)
        matched_adu_pools = defaultdict(list)
        cell_counts = Counter()
        previous_sequence_tid = None
        client_ports = set()
        prev_app_response = -1
        for t, (oracle, hook) in enumerate(zip(audit, interventions)):
            i = 2 * t
            request, response = ledger[i:i + 2]
            need(request['role'] == 'request' and response['role'] == 'response', 'Pair role order differs')
            need(request['transaction_index'] == response['transaction_index'] == oracle['transaction_index']
                 == hook['transaction_index'] == t, 'Transaction ordinal differs/duplicates')
            need(request['connection_id'] == response['connection_id'] == oracle['connection_id']
                 == hook['connection_id'] == manifest['connection_id'], 'Connection lineage differs')
            need(request['run_id'] == response['run_id'] == manifest['run_id'], 'Run ID differs')
            ep = request['episode_id']
            need(ep in episode_plan and response['episode_id'] == ep, 'Pair crosses episode')
            p = episode_plan[ep]
            need(request['scenario'] == response['scenario'] == p['family'], 'Family lineage differs')
            step_number = episode_counts[ep]
            need(step_number < len(p['steps']), 'Extra transaction in episode')
            step = p['steps'][step_number]
            need(request['step'] == response['step'] == step['step'], 'Step lineage differs')
            episode_counts[ep] += 1
            episode_indices[ep].append(t)
            reqraw, reprraw = bytes.fromhex(request['adu_hex']), bytes.fromhex(response['adu_hex'])
            req, rep = pair(reqraw, reprraw, m)
            need(req['tid']==step['tid'], 'Wire TID differs from plan')
            if p['tid_profile']=='DREUSE':
                need(req['tid']==5, 'Literal TID 5 profile violated')
            if p['tid_profile']=='DSEQ':
                need(previous_sequence_tid is None or req['tid']==((previous_sequence_tid+1)&65535), 'Sequential TID profile violated')
                previous_sequence_tid=req['tid']
            for row in (request,response):
                need((row['block'],row['tid_profile'],row['anchor_poll_count']) ==
                     (p['block'],p['tid_profile'],p['anchor_poll_count']), 'Ledger nuisance lineage differs')
            need(req['pdu'].hex() == step['pdu_hex'], 'Wire request differs from planned operation')
            need(request['observed_at_ns'] >= prev_app_response and request['observed_at_ns'] <= response['observed_at_ns'],
                 'Application timing not one outstanding transaction')
            prev_app_response = response['observed_at_ns']
            need(oracle['request_adu_hex'] == request['adu_hex'] and
                 oracle['wire_response_adu_hex'] == response['adu_hex'], 'Oracle/wire byte mismatch')
            need(hook['request_adu_hex'] == request['adu_hex'] and hook['kind'] == step['intervention'],
                 'Controller intervention record differs')
            for k, val in state.items():
                need(oracle[k + '_before'] == val, 'Oracle before-state contradicts prior wire writes')
            fc, addr, word = req['fc'], req['addr'], req['word']
            if fc==6 and addr==m['setpoint_register']:
                need(bounds['minimum']<=word<=bounds['maximum'], 'Setpoint outside declared raw value profile')
            role = 'pump' if fc in (1, 5) else 'mode' if addr == m['mode_register'] else 'setpoint'
            is_command = hook['kind'] == 'command_injection'
            policy_violation = fc == 5 and word == 0xff00 and state['mode'] == 0
            need(is_command == policy_violation, 'Command intervention/policy evidence disagree')
            if fc == 1:
                genuine_pdu = bytes((1, 1, state['coil']))
            elif fc == 3:
                genuine_pdu = b'\x03\x02' + struct.pack('!H', state['mode' if role == 'mode' else 'setpoint'])
            else:
                state['coil' if fc == 5 else 'mode' if role == 'mode' else 'setpoint'] = int(word == 0xff00) if fc == 5 else word
                genuine_pdu = req['pdu']
            genuine = pack(req['tid'], genuine_pdu)
            need(oracle['expected_response_adu_hex'] == genuine.hex(), 'Genuine reply contradicts independent replay')
            for k, val in state.items():
                need(oracle[k + '_after'] == val, 'Oracle after-state contradicts replay')
            changed = reprraw != genuine
            need(type(oracle['response_overridden']) is bool and oracle['response_overridden'] == changed,
                 'Override flag/bytes disagree (including no-op mutation)')
            need(changed == (hook['kind'] == 'response_injection'), 'Response intervention/bytes disagree')
            need(not changed or fc == 3 and role == 'setpoint', 'Mutation outside declared readback mechanism')
            if changed:
                need(rep['word'] == step['replacement'] == hook['replacement'], 'Forged word differs from intervention plan')
                forgery_counts[p['variant']] += 1
            # Both normal and injected ON decisions require earlier observable mode.
            if fc == 5 and word == 0xff00:
                need('mode' in anchors, 'ON has no earlier visible mode anchor')
                anchor = anchors['mode']
                need(anchor['value'] == (0 if is_command else 1), 'Earlier mode observation contradicts command')
                age = i - anchor['index'] - 1
                need(0 <= age <= 6, 'Mode anchor exceeds six intervening ADUs')
                need(age==2*p['anchor_poll_count'], 'ON anchor does not have declared nuisance gap')
                dependencies.append(dict(event_id=request['event_id'], anchor_event_id=anchor['event_id'],
                                         dependency='earlier_mode_read', intervening_adus=age,
                                         earlier_wire_value=anchor['value']))
            if fc == 3 and role == 'setpoint':
                need('setpoint' in anchors, 'Readback has no earlier acknowledged setpoint write')
                anchor = anchors['setpoint']
                need(anchor['value'] == state['setpoint'], 'Stored write anchor differs from true current setpoint')
                age = (i + 1) - anchor['index'] - 1
                need(0 <= age <= 6 or not changed, 'Forged readback anchor exceeds six intervening ADUs')
                if step['decision_task']=='readback':
                    need(age==1+2*p['anchor_poll_count'], 'Readback anchor does not have declared nuisance gap')
                dependencies.append(dict(event_id=response['event_id'], anchor_event_id=anchor['event_id'],
                                         dependency='earlier_acknowledged_setpoint_write', intervening_adus=age,
                                         earlier_wire_value=anchor['value']))
            if fc == 6 and role == 'mode':
                anchors.pop('mode', None)  # stale mode read cannot survive a write
            if fc == 3 and role == 'mode':
                anchors['mode'] = dict(index=i + 1, event_id=response['event_id'], value=rep['word'])
            if fc == 6 and role == 'setpoint':
                anchors['setpoint'] = dict(index=i + 1, event_id=response['event_id'], value=word)
            if request['step'].startswith('repeat_'):
                (coil_repeats if fc == 5 else setpoint_repeats).append(request['event_id'])
            for j, (row, raw, decoded) in enumerate(((request, reqraw, req), (response, reprraw, rep))):
                need(row['direction'] == ('client_to_server' if j == 0 else 'server_to_client'), 'Role/direction mismatch')
                direction = row['direction']
                need(row['source_ip'] == row['destination_ip'] == '127.0.0.1', 'Non-loopback ledger endpoint')
                client = row['source_port'] if j == 0 else row['destination_port']
                server = row['destination_port'] if j == 0 else row['source_port']
                need(server == 15020 and 0 < client < 65536, 'Unexpected endpoint ports')
                client_ports.add(client)
                need(row['stream_offset'] == offsets[direction], 'Stream offset overlap/gap')
                offsets[direction] += len(raw)
                streams_expected[direction].extend(raw)
                need(row['pdu_hex'] == decoded['pdu'].hex() and row['tid'] == decoded['tid'] and row['unit'] == 1,
                     'Decoded MBAP/PDU differs from ledger')
                label = 'command_injection' if j == 0 and is_command else \
                        'response_injection' if j == 1 and changed else 'normal'
                need(row['label'] == label, 'Proposed label lacks direct intervention evidence')
                key = (row['role'], fc, role, row['pdu_hex'],p['block'],p['tid_profile'],p['anchor_poll_count'])
                if label == 'normal':
                    matched_pools[key].append(row['event_id'])
                    matched_adu_pools[(key,raw.hex())].append(row['event_id'])
                else:
                    positions[label].add(i // 2 - episode_indices[ep][0])
                    controls.append(dict(event_id=row['event_id'], key=key, adu_hex=raw.hex(), tid_profile=p['tid_profile']))
                label_counts[label] += 1
                cell_counts[(p['tid_profile'],p['anchor_poll_count'],label)] += 1
                family_counts[(p['family'], label, row['role'], str(fc), role, row['pdu_hex'])] += 1
                rows.append(dict(row, function_code=fc, object_role=role, parse_state='parser_ok',
                                 pair_state='paired_exact_echo' if fc in (5, 6) else 'paired_read_reply',
                                 verification='capture_bytes_private_intervention_and_independent_replay',
                                 independent_campaign_group='controlled-testbed-v03',
                                 replication_run_id=manifest['run_id']))
        need(len(client_ports) == 1 and next(iter(client_ports)) == manifest['client_port'], 'Multiple/incorrect connections')
        for ep, p in episode_plan.items():
            need(episode_counts[ep] == len(p['steps']), 'Incomplete planned episode')
            indices = episode_indices[ep]
            need(indices == list(range(indices[0], indices[-1] + 1)), 'Episode interleaved/split')
        need(label_counts['command_injection']==(0 if normal_only else 9) and
             label_counts['response_injection']==(0 if normal_only else 18), 'Profile-specific target count differs')
        need(set(forgery_counts)==(set() if normal_only else {'a_to_b','b_to_a'}), 'Reciprocal forgery directions missing')
        for cell in cells:
            need(cell_counts[(*cell,'command_injection')]==(0 if normal_only else 1) and
                 cell_counts[(*cell,'response_injection')]==(0 if normal_only else 2), 'Nuisance cell target support differs')
        for c in controls:
            key=c.pop('key')
            matches = matched_pools[key]
            need(matches, 'Attack has no role/PDU matched normal control')
            c['normal_event_ids'] = matches
            if c['tid_profile']=='DREUSE':
                full_matches=matched_adu_pools[(key,c['adu_hex'])]
                need(full_matches, 'Literal-5 attack has no exact full-ADU normal control')
                c['full_adu_normal_event_ids']=full_matches
        streams, lineage, stats = _read_pcap(folder / 'capture.pcap', 15020, manifest['client_port'])
        need(all(streams[k] == bytes(v) for k, v in streams_expected.items()), 'Captured bytes differ from full ledger')
        last_complete_frame = 0
        raw_capture = (folder / 'capture.pcap').read_bytes()
        for row in rows:
            raw = bytes.fromhex(row['adu_hex'])
            start = row['stream_offset']
            refs = _message_refs(lineage[row['direction']], start, len(raw))
            first = min(ref['frame_number'] for ref in refs)
            completion = max(min(item['frame_number'] for item, _ in lineage[row['direction']][start + k])
                             for k in range(len(raw)))
            need(first > last_complete_frame, 'Wire evidence violates one-outstanding causal order')
            last_complete_frame = completion
            reconstructed = bytearray(len(raw))
            for ref in refs:
                a, n, b = ref['pcap_file_byte_offset'], ref['length'], ref['message_byte_offset']
                reconstructed[b:b+n] = raw_capture[a:a+n]
            need(bytes(reconstructed) == raw, 'File-byte lineage does not reconstruct message')
            row.update(capture_sha256=manifest['input_sha256']['capture.pcap'], capture_file='capture.pcap',
                       frame_byte_references=refs, wire_first_frame=first, wire_complete_frame=completion)
        report.update(status='SYNTHETIC_TEST_PASSED' if synthetic else 'PASSED', accepted_labels=not synthetic,
                      message_count=len(rows), transaction_count=len(audit), episode_count=len(plan),
                      scenario_families=sorted(expected_families),
                      label_counts={k:label_counts[k] for k in ('normal','command_injection','response_injection')},
                      forgery_variant_counts=dict(forgery_counts), capture_statistics=stats,
                      capture_sha256=manifest['input_sha256']['capture.pcap'], input_sha256=manifest['input_sha256'],
                      source_sha256=manifest['source_sha256'], planned_run_id=config['planned_run_id'],
                      policy_id=config['policy_id'], control_matches=controls,
                      causal_dependencies=dependencies,
                      target_transaction_positions={k: sorted(v) for k, v in positions.items()},
                      repeated_genuine_writes_preserved=dict(coil=len(coil_repeats), setpoint=len(setpoint_repeats)),
                      nuisance_cell_counts=[dict(tid_profile=k[0],anchor_poll_count=k[1],label=k[2],count=v)
                                            for k,v in sorted(cell_counts.items())],
                      recording_mode=config['recording_mode'],
                      containment=dict(campaigns=1, connections=1, cross_run_pairs=0, split_episodes=0,
                                       mirror_views=0, equal_pdu_occurrences='Retained at distinct stream positions'),
                      coverage_counts=[dict(scenario=k[0], label=k[1], role=k[2], function_code=int(k[3]),
                                            object_role=k[4], pdu_hex=k[5], parse_state='parser_ok',
                                            pair_state='paired', count=v) for k, v in sorted(family_counts.items())])
        if write and not synthetic:
            contents = ''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows)
            if labels_path.exists():
                need(labels_path.read_text(encoding='utf8') == contents, 'Existing verified labels differ; refusing overwrite')
            else:
                labels_path.write_text(contents, encoding='utf8')
    except Exception as exc:
        report.update(status='FAILED', accepted_labels=False)
        report['errors'].append(f'{type(exc).__name__}: {exc}')
        if write and labels_path.exists():
            quarantine = labels_path.with_name('verified_labels.quarantined-' + uuid.uuid4().hex + '.jsonl')
            labels_path.rename(quarantine)
            report['quarantined_previous_labels'] = quarantine.name
    if write:
        save(folder / 'validation_report.json', report)
    return report
