"""Independent evidence/metric audit, not training or another final evaluation.

The PCAP reader and label replay below do not import the generator/validator.
Only saved predictions are used for final metrics. Validation alone is predicted
to test deserialization and preprocessing. No original files are written.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import csv
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
LOCKED = ROOT/'component3/locked/v1_20261025'
sys.path.insert(0, str(LOCKED))
CLASSES = ['normal', 'command_injection', 'response_injection']

def need(ok, message):
    if not ok:
        raise ValueError(message)

def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))

def rows(path):
    with path.open(encoding='utf-8-sig') as stream:
        return [json.loads(line) for line in stream if line.strip()]

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def pcap(path):
    """Bounded classic-PCAP IPv4/TCP reader with SYN-based byte identity.

    Fail on unsupported traffic instead of silently dropping observations.
    Repeated bytes at different sequence positions remain distinct.
    """
    blob = path.read_bytes()
    magics = {b'\xd4\xc3\xb2\xa1': ('<', 1000), b'\xa1\xb2\xc3\xd4': ('>', 1000),
              b'\x4d\x3c\xb2\xa1': ('<', 1), b'\xa1\xb2\x3c\x4d': ('>', 1)}
    need(blob[:4] in magics, 'Unsupported PCAP magic')
    endian, scale = magics[blob[:4]]
    major, minor, _, _, snap, link = struct.unpack_from(endian+'HHIIII', blob, 4)
    need((major, minor) == (2, 4) and link in (1, 113, 276), 'PCAP header/link')
    frames, bases, streams = {}, {}, defaultdict(dict)
    cursor, number, retransmitted = 24, 0, 0
    while cursor < len(blob):
        sec, frac, size, original = struct.unpack_from(endian+'IIII', blob, cursor)
        need(size == original and size <= snap and cursor+16+size <= len(blob), 'Truncated capture')
        start = cursor+16
        packet = blob[start:start+size]
        cursor += 16+size
        number += 1
        ip = {1:14, 113:16, 276:20}[link]
        ether = int.from_bytes(packet[12:14] if link == 1 else packet[14:16] if link == 113 else packet[:2], 'big')
        while ether in (0x8100, 0x88a8):
            ether = int.from_bytes(packet[ip+2:ip+4], 'big'); ip += 4
        need(ether == 0x800 and packet[ip] >> 4 == 4, 'Non IPv4 frame')
        ihl, total = (packet[ip] & 15)*4, int.from_bytes(packet[ip+2:ip+4], 'big')
        need(ihl >= 20 and ip+total <= len(packet) and packet[ip+9] == 6, 'IPv4/TCP bounds')
        need(int.from_bytes(packet[ip+6:ip+8], 'big') & 0x3fff == 0, 'Fragmented IP')
        tcp = ip+ihl
        sport, dport, seq = struct.unpack_from('!HHI', packet, tcp)
        src = '.'.join(map(str, packet[ip+12:ip+16])); dst = '.'.join(map(str, packet[ip+16:ip+20]))
        key = (src, sport, dst, dport)
        flags, hlen = packet[tcp+13], (packet[tcp+12] >> 4)*4
        need(hlen >= 20 and tcp+hlen <= ip+total and not flags & 4, 'TCP bounds/reset')
        if flags & 2:
            base = (seq+1) & 0xffffffff
            need(key not in bases or bases[key] == base, 'Multiple connection generations')
            bases[key] = base
        payload_start = tcp+hlen
        payload = packet[payload_start:ip+total]
        frames[number] = {'file_start': start, 'length': size, 'payload_start': payload_start,
                          'payload_end': ip+total, 'key': key, 'time_ns': sec*10**9+frac*scale}
        if payload:
            need(key in bases, 'Payload without SYN')
            offset = (seq+bool(flags & 2)-bases[key]) & 0xffffffff
            need(offset+len(payload) < 16*1024*1024, 'Unexpected TCP span')
            for i, value in enumerate(payload):
                position = offset+i
                if position in streams[key]:
                    need(streams[key][position] == value, 'Conflicting TCP overlap')
                    retransmitted += 1
                streams[key][position] = value
    need(len(streams) == 2, 'Expected one bidirectional connection')
    for values in streams.values():
        need(len(values) == max(values)+1, 'TCP byte gap')
    return blob, frames, {k:bytes(v[i] for i in range(len(v))) for k,v in streams.items()}, retransmitted

def independent_metrics(truth, prediction):
    table = [[0]*3 for _ in CLASSES]
    for y, p in zip(truth, prediction, strict=True):
        need(y in CLASSES and p in CLASSES, 'Abstention/unknown silently entering scored cohort')
        table[CLASSES.index(y)][CLASSES.index(p)] += 1
    support = [sum(row) for row in table]
    f1 = [2*table[i][i]/(support[i]+sum(row[i] for row in table))
          if support[i]+sum(row[i] for row in table) else 0 for i in range(3)]
    return {'support': sum(support), 'class_support': dict(zip(CLASSES,support)),
            'confusion': table, 'macro_f1_fixed_three_classes': sum(f1)/3,
            'unsupported_classes': [c for c,n in zip(CLASSES,support) if n == 0]}

def audit(source, output):
    import numpy as np
    import pandas as pd
    import joblib
    from c3model.records import verify_collection, build_run
    from c3model.experiment import METHODS, feature_frame
    source, output = Path(source).resolve(), Path(output).resolve()
    need(not output.exists(), 'Choose a fresh output directory; audit results are not overwritten')
    need(not output.is_relative_to(source) and not output.is_relative_to(LOCKED), 'Output would alter evidence')
    output.mkdir(parents=True)
    artifacts = LOCKED/'artifacts'
    baseline = {p.relative_to(LOCKED).as_posix(): sha(p) for p in LOCKED.rglob('*') if p.is_file()}
    lock = read(artifacts/'experiment_lock.json')
    for name, digest in lock['code_sha256'].items():
        need(sha(LOCKED/'c3model'/name) == digest, 'Locked code changed')
    for name, digest in lock['artifact_sha256'].items():
        need(sha(artifacts/name) == digest, 'Locked artifact changed: '+name)
    info = verify_collection(source)
    need(info['collection_id'] == '40ae7a846cce48fc8e3c52ebfca7e2cd', 'Wrong collection')
    need(lock['collection']['canonical_index_sha256'] == info['index_sha256'], 'Lock/source mismatch')
    accepted = {m['run_id'] for m in info['runs']}
    excluded = sorted(p.name for p in source.iterdir() if p.is_dir() and p.name.startswith('MX') and p.name not in accepted)
    totals, coverage, per_run, example = Counter(), Counter(), [], {}
    all_truth, all_ordinal, all_members, decisions = {}, {}, {}, {}
    payload_roles, campaigns, repeats, frame_count, reference_count = defaultdict(set), set(), 0, 0, 0
    for index, member in enumerate(info['runs'], 1):
        folder = Path(member['folder'])
        ledger, labels = rows(folder/'application_ledger.jsonl'), rows(folder/'verified_labels.jsonl')
        hooks, oracle = rows(folder/'intervention_audit.jsonl'), rows(folder/'server_audit.jsonl')
        mapping = next(m for m in info['public_maps'] if m['id'] == member['map'])
        blob, frames, streams, retransmitted = pcap(folder/'capture.pcap')
        frame_count += len(frames)
        need(len(ledger) == len(labels) == len(hooks)*2 == len(oracle)*2, 'Evidence length mismatch')
        expected_streams = defaultdict(bytearray)
        counts, seen_pdus, state = Counter(), set(), {'mode':0, 'setpoint':50, 'coil':0}
        previous_complete, pending, tx = 0, None, 0
        mode_anchor, setpoint_anchor = None, None
        for ordinal, (row, ann) in enumerate(zip(ledger, labels, strict=True)):
            event = row['event_id']; raw = bytes.fromhex(row['adu_hex'])
            need(event == ann['event_id'] and event not in all_truth, 'Duplicate/misaligned event identity')
            need(row['adu_hex'] == ann['adu_hex'] and row['label'] == ann['label'], 'Annotation differs')
            need(row['run_id'] == member['run_id'], 'Foreign run')
            tid, pid, length, unit = struct.unpack_from('!HHHB', raw)
            fc, pdu = raw[7], raw[7:]
            need(pid == 0 and unit == 1 and len(raw) == length+6 and fc in (1,3,5,6), 'Unsupported ADU')
            key = (row['source_ip'],row['source_port'],row['destination_ip'],row['destination_port'])
            is_request = row['destination_port'] == 15020
            need(row['role'] == ('request' if is_request else 'response'), 'Direction not wire-derived')
            need((row['tid'],row['unit']) == (tid,unit) and row['pdu_hex'] == pdu.hex(), 'Decoded ledger fields differ')
            need(row['source_ip'] == row['destination_ip'] == '127.0.0.1', 'Outside qualified loopback scope')
            if not is_request:
                need((fc in (5,6) and len(pdu) == 5) or
                     (fc == 1 and len(pdu) == 3 and pdu[1] == 1 and pdu[2] in (0,1)) or
                     (fc == 3 and len(pdu) == 4 and pdu[1] == 2), 'Read/echo response format differs')
            need(row['stream_offset'] == len(expected_streams[key]), 'Ledger stream gap')
            expected_streams[key].extend(raw)
            reconstructed, covered = bytearray(len(raw)), set()
            refs = ann['frame_byte_references']
            for ref in refs:
                f = frames[ref['frame_number']]
                a,b,n = ref['pcap_file_byte_offset'],ref['message_byte_offset'],ref['length']
                need(f['key'] == key and a == f['file_start']+ref['frame_byte_offset'], 'Wrong packet lineage')
                need(f['payload_start'] <= ref['frame_byte_offset'] and ref['frame_byte_offset']+n <= f['payload_end'], 'Reference outside TCP payload')
                need(0 <= b and b+n <= len(raw) and f['time_ns'] == ref['capture_timestamp_ns'], 'Bad reference bounds/time')
                need(blob[a:a+n] == raw[b:b+n], 'Capture bytes differ from ADU')
                reconstructed[b:b+n] = blob[a:a+n]; covered.update(range(b,b+n)); reference_count += 1
            need(len(covered) == len(raw) and bytes(reconstructed) == raw, 'Incomplete byte lineage')
            first, last = min(r['frame_number'] for r in refs), max(r['frame_number'] for r in refs)
            need(first > previous_complete, 'Wire completion order overlaps')
            need((first,last) == (ann['wire_first_frame'],ann['wire_complete_frame']), 'Wire frame bounds differ')
            previous_complete = last
            if is_request:
                need(pending is None and len(pdu) == 5, 'Concurrent/invalid request')
                addr, word = struct.unpack_from('!HH', pdu,1)
                role = 'coil' if fc in (1,5) else 'mode' if addr == mapping['mode_register'] else 'setpoint'
                need(addr == mapping['pump_coil'] if fc in (1,5) else addr in (mapping['mode_register'],mapping['setpoint_register']), 'Unknown mapped address')
                need(fc not in (1,3) or word == 1, 'Unsupported read quantity')
                need(fc != 5 or word in (0,0xff00), 'Invalid coil word')
                need(not (fc == 6 and role == 'mode') or word in (0,1), 'Invalid mode write')
                hook, server = hooks[tx], oracle[tx]
                need(hook['request_adu_hex'] == server['request_adu_hex'] == raw.hex(), 'Private evidence byte mismatch')
                need(all(server[k+'_before'] == v for k,v in state.items()), 'Private before-state mismatch')
                violation = fc == 5 and word == 0xff00 and state['mode'] == 0
                need(violation == (hook['kind'] == 'command_injection'), 'Command evidence contradiction')
                label = 'command_injection' if violation else 'normal'
                if fc == 1: genuine = bytes([1,1,state['coil']])
                elif fc == 3: genuine = bytes([3,2])+struct.pack('!H',state[role])
                else:
                    state[role] = int(word == 0xff00) if fc == 5 else word
                    genuine = pdu
                need(all(server[k+'_after'] == v for k,v in state.items()), 'Private after-state mismatch')
                pending = (tid,unit,fc,key,raw,genuine,event)
            else:
                need(pending is not None, 'Reply has no earlier request')
                pt,pu,pf,pk,request,genuine,request_id = pending
                need((tid,unit,fc) == (pt,pu,pf) and key == (pk[2],pk[3],pk[0],pk[1]), 'Pair identity mismatch')
                need(fc not in (5,6) or pdu == request[7:], 'Echo mismatch')
                changed = pdu != genuine
                need(changed == (hook['kind'] == 'response_injection'), 'Response evidence contradiction')
                need(not changed or fc == 3 and int.from_bytes(pdu[2:],'big') == hook['replacement'], 'Forged replacement mismatch')
                need(server['expected_response_adu_hex'] == (raw[:7]+genuine).hex() and server['wire_response_adu_hex'] == raw.hex(), 'Genuine/wire oracle bytes')
                label = 'response_injection' if changed else 'normal'
                need(row['transaction_index'] == tx, 'Ledger ordinal differs from wire pairing')
                pending = None; tx += 1
            task = ('command' if is_request and fc == 5 and word == 0xff00 else
                    'response' if not is_request and fc == 3 and role == 'setpoint' else '')
            anchor = mode_anchor if task == 'command' else setpoint_anchor if task == 'response' else None
            available = anchor is not None and 0 <= ordinal-anchor[0]-1 <= 6
            decision = 'out_of_scope' if not task else 'abstain'
            if task and available:
                if task == 'command': decision = 'command_injection' if anchor[1] == 0 else 'normal'
                else: decision = 'response_injection' if int.from_bytes(pdu[2:],'big') != anchor[1] else 'normal'
            decisions[event] = (bool(task),available,task,decision)
            if is_request and fc == 6:
                if role == 'mode': mode_anchor = None
                elif role == 'setpoint': setpoint_anchor = None
            if not is_request:
                if fc == 3 and role == 'mode': mode_anchor = (ordinal,int.from_bytes(pdu[2:],'big'))
                if fc == 6 and role == 'setpoint': setpoint_anchor = (ordinal,word)
            need(ann['label'] == label, 'Independent label mismatch')
            need(ann['capture_sha256'] == member['capture_sha256'], 'Wrong capture seal')
            counts[label] += 1; totals[label] += 1
            all_truth[event], all_ordinal[event], all_members[event] = label, ordinal, member['evaluation_role']
            campaigns.add(ann['independent_campaign_group'])
            duplicate_key = (row['direction'],pdu.hex())
            repeats += int(duplicate_key in seen_pdus); seen_pdus.add(duplicate_key)
            payload_roles[(row['direction'],pdu.hex())].add(member['evaluation_role'])
            coverage[(member['evaluation_role'],member['planned_run_id'],member['map'],label,fc,ann['parse_state'],ann['pair_state'])] += 1
            if label not in example and member['evaluation_role'] == 'train':
                example[label] = {'annotation': ann, 'hook': hook, 'oracle': server, 'source':folder.relative_to(source).as_posix(), 'ledger_line':ordinal+1, 'private_line':ordinal//2+1}
        need(pending is None and {k:bytes(v) for k,v in expected_streams.items()} == streams, 'Full TCP stream/ledger mismatch')
        need(dict(counts) == {k:v for k,v in member['label_counts'].items() if v}, 'Receipt count mismatch')
        per_run.append({'planned_run_id':member['planned_run_id'], 'run_id':member['run_id'], 'role':member['evaluation_role'],
                        'group':member['related_group'], 'adus':len(ledger), 'label_counts':dict(counts), 'tcp_retransmitted_bytes':retransmitted})
        if index % 16 == 0: print(f'Independently checked {index}/104 accepted captures', flush=True)
    need(totals == Counter(normal=247906,command_injection=720,response_injection=1440), 'Unexpected class totals')
    # Reconstruct development only. Final predictions are inspected, never regenerated.
    stored = pd.read_parquet(artifacts/'development/all_adus.parquet')
    recreated = pd.concat([build_run(Path(m['folder']),m,info['public_maps']) for m in info['runs'] if m['evaluation_role'] in ('train','validation')],ignore_index=True)
    pd.testing.assert_frame_equal(stored,recreated,check_dtype=False)
    feature_columns = list(dict.fromkeys(c for cols in METHODS.values() for c in cols))
    pd.testing.assert_frame_equal(pd.read_parquet(artifacts/'development/candidate_features.parquet'),feature_frame(stored,feature_columns),check_like=True)
    validation = stored.loc[stored.evaluation_role == 'validation'].reset_index(drop=True)
    saved_validation = pd.read_parquet(artifacts/'validation_predictions.parquet')
    reload_checks = {}
    fit = stored.loc[(stored.evaluation_role == 'train') & stored.eligible & stored.context_available]
    for name, columns in METHODS.items():
        model = joblib.load(artifacts/'models'/f'{name}.joblib')
        need(list(model.feature_names_in_) == columns, 'Model schema mismatch')
        x = feature_frame(fit,columns)
        medians = x.median().fillna(0).to_numpy()
        need(np.array_equal(medians,model.named_steps['imputer'].statistics_), 'Training-only imputer median mismatch')
        mask = validation.eligible & (validation.context_available if name.startswith('D') else True)
        predicted = model.predict(feature_frame(validation.loc[mask],columns))
        need(np.array_equal(predicted,saved_validation.loc[mask,name]), 'Reload/validation predictions differ')
        reload_checks[name] = {'features':len(columns),'training_medians_equal':True,'validation_predictions_equal':True,'rows':int(mask.sum())}
    metric_reports, errors, final_seen = {}, [], set()
    for role in lock['final_roles']:
        pred = pd.read_parquet(artifacts/'final'/f'{role}_predictions.parquet')
        saved = read(artifacts/'final'/f'{role}_report.json')
        need(not pred.event_id.duplicated().any(), 'Duplicate saved final event')
        expected = {e for e,r in all_members.items() if r == role}
        need(set(pred.event_id) == expected and not final_seen & expected, 'Final source membership mismatch')
        final_seen.update(expected)
        need(all(all_truth[e] == y for e,y in zip(pred.event_id,pred.label)), 'Saved final truth differs from raw')
        for r in pred.itertuples(index=False):
            need(decisions[r.event_id] == (r.eligible,r.context_available,r.task,r.C), 'Independent causal eligibility/rule disagreement')
        mask = pred.eligible & pred.context_available
        methods = {}
        for method in ['A','B','C','D','B-wire','D-wire']:
            result = independent_metrics(pred.loc[mask,'label'],pred.loc[mask,method])
            old = saved['methods'][method]['common_cohort']
            need(result['confusion'] == old['confusion'] and abs(result['macro_f1_fixed_three_classes']-old['macro_f1']) < 1e-12, 'Stored metric disagreement')
            need((pred.loc[~pred.eligible,method] == 'out_of_scope').all(), 'Hidden out-of-scope scoring')
            if method in ('C','D','D-wire'):
                need((pred.loc[pred.eligible & ~pred.context_available,method] == 'abstain').all(), 'Hidden contextual abstention')
            methods[method] = result
        bad = pred.loc[mask & (pred.D != pred.label)]
        errors.extend(bad.to_dict(orient='records'))
        metric_reports[role] = {'adus':len(pred),'eligible':int(pred.eligible.sum()),'common':int(mask.sum()),
                                'abstained_context':int((pred.eligible & ~pred.context_available).sum()),'methods':methods,
                                'prediction_sha256':sha(artifacts/'final'/f'{role}_predictions.parquet')}
    need(baseline == {p.relative_to(LOCKED).as_posix():sha(p) for p in LOCKED.rglob('*') if p.is_file()}, 'Locked bundle changed during audit')
    result = {'status':'PASSED','kind':'RETROSPECTIVE_EVIDENCE_AUDIT_NOT_NEW_FINAL_EVALUATION',
              'created_at_utc':datetime.now(timezone.utc).isoformat(),'command':sys.argv,'source':str(source),
              'collection_id':info['collection_id'],'index_sha256':info['index_sha256'],
              'lock_sha256':sha(artifacts/'experiment_lock.json'),'final_summary_sha256':sha(artifacts/'final_summary.json'),
              'accepted_runs':len(per_run),'excluded_attempts':excluded,'label_counts':dict(totals),
              'frames_independently_parsed':frame_count,'byte_references_checked':reference_count,
              'campaigns':sorted(campaigns),'genuine_repeated_pdu_occurrences':repeats,
              'cross_role_shared_payload_patterns':sum(len(r)>1 for r in payload_roles.values()),
              'duplicate_note':'Shared PDU values are templates/repetitions, not shared observations. Whole traces verified unique by admission.',
              'role_counts':info['role_counts'],'raw_sealed_hashes_checked':info['verified_artifact_count'],
              'development_rows_reconstructed_equal':len(stored),'model_reload':reload_checks,
              'final_saved_prediction_audit':metric_reports,'D_errors':errors,'original_bundle_unchanged':True,
              'training_executed':False,'final_predictions_generated':False,
              'python':sys.version,'platform':platform.platform(),
              'packages':{n:importlib.metadata.version(n) for n in ('numpy','pandas','scikit-learn','joblib','pyarrow')},
              'audit_code_sha256':sha(Path(__file__)),
              'limits':['Same source authorship; independent implementation is not independent data collection.',
                        'No TCP/IP checksum validation; bounded single-connection captures only.',
                        'No industrial campaign/physical effect/clock accuracy claim.',
                        'Final eligibility and rules independently replayed; RF final predictions only read from saved evidence.']}
    (output/'audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    (output/'runs.json').write_text(json.dumps(per_run,indent=2)+'\n',encoding='utf-8')
    (output/'evidence_examples.json').write_text(json.dumps(example,indent=2)+'\n',encoding='utf-8')
    with (output/'coverage.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.writer(stream); writer.writerow(['role','run','map','label','function','parse_state','pair_state','rows'])
        writer.writerows([*k,v] for k,v in sorted(coverage.items()))
    print(json.dumps({'status':result['status'],'ADUs':sum(totals.values()),'D_errors':errors,'output':str(output)}),flush=True)
    return result

if __name__ == '__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=ROOT/'component3/data/collection')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); audit(a.source,a.output)
