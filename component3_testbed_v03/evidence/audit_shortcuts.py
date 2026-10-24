"""Post-capture independent byte/state and nuisance audit; no model features.

Only aggregate timing/position diagnostics are exported. Original captures and
annotations are read-only. This reporter is separately hashed, outside frozen
collection-source identity.
"""
from pathlib import Path
from collections import Counter,defaultdict
from datetime import datetime
import hashlib
import json
import statistics
import struct
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from c3qual.config import RUN_IDS,planned,object_map,read_json,sha


def rows(path):
    return [json.loads(s) for s in path.read_text(encoding='utf8').splitlines() if s.strip()]


def need(value,reason):
    if not value: raise ValueError(reason)


def stats(values):
    return dict(count=len(values),minimum=min(values),median=statistics.median(values),maximum=max(values)) if values else dict(count=0)


def complete_ns(row):
    return next(ref['capture_timestamp_ns'] for ref in row['frame_byte_references']
                if ref['frame_number']==row['wire_complete_frame'])


def main():
    output=ROOT.parent/'component3_collection_runs/engineering-v03'
    summaries=[]
    trace_hashes=[]
    totals=Counter()
    for run_id in RUN_IDS:
        good=[]
        for folder in output.glob(run_id+'-*'):
            report_path=folder/'validation_report.json'
            if report_path.exists() and read_json(report_path)['status']=='PASSED': good.append(folder)
        need(len(good)==1,run_id+': expected exactly one passed measured probe')
        folder=good[0]
        config=planned(run_id);m=object_map(config['map'])
        events=rows(folder/'verified_labels.jsonl')
        oracle=rows(folder/'server_audit.jsonl')
        hooks=rows(folder/'intervention_audit.jsonl')
        need(len(events)==2*len(oracle)==2*len(hooks),'Independent message/transaction accounting differs')
        raw=(folder/'capture.pcap').read_bytes()
        timing=defaultdict(list);positions=defaultdict(Counter);lengths=Counter()
        episode_first={};episode_lengths=Counter(r['episode_id'] for r in events)
        state={'mode':0,'setpoint':50,'coil':0};anchors={};checked_attacks=0;full_controls=0
        for i,event in enumerate(events):
            data=bytes.fromhex(event['adu_hex']);rebuilt=bytearray(len(data));covered=set()
            for ref in event['frame_byte_references']:
                a,b,n=ref['pcap_file_byte_offset'],ref['message_byte_offset'],ref['length']
                rebuilt[b:b+n]=raw[a:a+n];covered.update(range(b,b+n))
            need(bytes(rebuilt)==data and len(covered)==len(data),'Independent source-byte reconstruction differs')
            tid,pid,size,unit=struct.unpack('!HHHB',data[:7])
            need(pid==0 and size+6==len(data) and unit==1 and tid==event['tid'],'Independent MBAP decode differs')
            episode_first.setdefault(event['episode_id'],i)
            positions[(event['role'],event['label'])][(i-episode_first[event['episode_id']])//2]+=1
            if event['role']=='request' and i:
                timing[('request_gap_ms',event['label'],event['tid_profile'],event['anchor_poll_count'])].append(
                    (complete_ns(event)-complete_ns(events[i-1]))/10**6)
            if event['role']=='response':
                timing[('reply_elapsed_ms',event['label'],event['tid_profile'],event['anchor_poll_count'])].append(
                    (complete_ns(event)-complete_ns(events[i-1]))/10**6)
        for count in episode_lengths.values(): lengths[count//2]+=1
        for t,(o,h) in enumerate(zip(oracle,hooks)):
            i=2*t;request,response=events[i:i+2]
            rq,rp=bytes.fromhex(request['adu_hex']),bytes.fromhex(response['adu_hex'])
            tid=int.from_bytes(rq[:2],'big');fc,address,word=struct.unpack('!BHH',rq[7:])
            need(o['transaction_index']==h['transaction_index']==request['transaction_index']==response['transaction_index']==t,'Ordinal identity differs')
            need(rq.hex()==o['request_adu_hex']==h['request_adu_hex'] and rp.hex()==o['wire_response_adu_hex'],'Private byte identity differs')
            need(all(o[k+'_before']==v for k,v in state.items()),'Independent state before differs')
            command=h['kind']=='command_injection'
            need(command==(fc==5 and word==0xff00 and state['mode']==0),'Independent command evidence differs')
            if fc==1: genuine_pdu=bytes((1,1,state['coil']))
            elif fc==3: genuine_pdu=b'\x03\x02'+struct.pack('!H',state['mode' if address==m['mode_register'] else 'setpoint'])
            else:
                state['coil' if fc==5 else 'mode' if address==m['mode_register'] else 'setpoint']=int(word==0xff00) if fc==5 else word
                genuine_pdu=rq[7:]
            genuine=struct.pack('!HHHB',tid,0,len(genuine_pdu)+1,1)+genuine_pdu
            changed=rp!=genuine
            need(genuine.hex()==o['expected_response_adu_hex'] and changed==o['response_overridden']==(h['kind']=='response_injection'),'Independent genuine/altered reply differs')
            need(all(o[k+'_after']==v for k,v in state.items()),'Independent state after differs')
            need(request['label']==('command_injection' if command else 'normal') and response['label']==('response_injection' if changed else 'normal'),'Independent annotation differs')
            if command:
                anchor=anchors['mode']
                need(anchor[1]==0 and i-anchor[0]-1==2*request['anchor_poll_count'],'Independent command anchor differs')
                need(response['label']=='normal' and rp[7:]==rq[7:],'Genuine injected-command ACK differs')
            if changed:
                anchor=anchors['setpoint']
                need(fc==3 and address==m['setpoint_register'] and anchor[1]==state['setpoint'] and i-anchor[0]==1+2*response['anchor_poll_count'],'Independent response anchor differs')
            if command or changed:
                target=request if command else response
                matches=[r for r in events if r['label']=='normal' and r['block']==target['block'] and
                         r['role']==target['role'] and r['object_role']==target['object_role'] and r['pdu_hex']==target['pdu_hex']]
                need(matches,'Independent same-cell PDU control missing')
                checked_attacks+=1
                if target['tid_profile']=='DREUSE':
                    need(any(r['adu_hex']==target['adu_hex'] for r in matches),'Independent full-ADU control missing')
                    full_controls+=1
            if fc==6 and address==m['mode_register']: anchors.pop('mode',None)
            if fc==3 and address==m['mode_register']: anchors['mode']=(i+1,int.from_bytes(rp[9:11],'big'))
            if fc==6 and address==m['setpoint_register']: anchors['setpoint']=(i+1,word)
        trace=hashlib.sha256('\n'.join(r['direction']+':'+r['pdu_hex'] for r in events).encode()).hexdigest()
        trace_hashes.append(trace)
        times=[complete_ns(r) for r in events]
        counts=Counter(r['label'] for r in events);totals.update(counts)
        summaries.append(dict(planned_run_id=run_id,recording_mode=config['recording_mode'],label_counts=dict(counts),
                              messages=len(events),independent_attack_lineages_checked=checked_attacks,literal5_full_adu_targets=full_controls,
                              byte_state_label_anchor_control_checks='PASSED',
                              payload_span_seconds=(max(times)-min(times))/10**9,
                              capture_bytes=len(raw),all_run_artifact_bytes=sum(p.stat().st_size for p in folder.iterdir() if p.is_file()),
                              capture_sha256=sha(folder/'capture.pcap'),ordered_pdu_trace_sha256=trace,
                              timing_audit=[dict(measure=k[0],label=k[1],tid_profile=k[2],anchor_poll_count=k[3],**stats(v)) for k,v in sorted(timing.items())],
                              transaction_positions=[dict(role=k[0],label=k[1],counts=dict(sorted(v.items()))) for k,v in sorted(positions.items())],
                              episode_transaction_length_counts=dict(sorted(lengths.items())),
                              source_ports=sorted({r['source_port'] for r in events}),destination_ports=sorted({r['destination_port'] for r in events}),
                              current_pdu_counts_by_label=[dict(label=label,counts=dict(Counter(r['pdu_hex'] for r in events if r['label']==label))) for label in counts]))
    need(len(set(trace_hashes))==14,'Unexpected copied ordered PDU trace')
    result=dict(status='PASSED',read_only_independent_audit=True,code_sha256=sha(Path(__file__)),
                accepted_captures=14,label_counts=dict(totals),runs=summaries,
                aggregate_payload_span_seconds=sum(r['payload_span_seconds'] for r in summaries),
                total_run_artifact_bytes=sum(r['all_run_artifact_bytes'] for r in summaries),
                unique_ordered_pdu_traces=14,qualified_for_model_use=False,
                interpretation=['Literal-5 target and genuine-control ADUs are exactly equal in the same nuisance cell, so current content is insufficient for those contrasts',
                                'Timing, episode lengths and positions are measured here as audit aggregates; no classifier or sequence/features were created',
                                'A finite generator may still contain scheduling/template cues. This audit does not prove every method will learn causal semantics',
                                'No main runs or scored hold-out recordings exist; no cross-model-partition independence is asserted',
                                'Configured sleeps differ from actual elapsed wire times, which include platform IO and scheduling'])
    (ROOT/'evidence/shortcut_audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('runs','interpretation')},indent=2))


if __name__=='__main__': main()
