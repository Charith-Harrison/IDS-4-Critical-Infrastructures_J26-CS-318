"""Prove bounded view overlap and specify an unexecuted canonical expansion."""
from collections import defaultdict, Counter
from common import BASE, RAW, OUT, read, write, stats
from bounded_pilot import time_window, raw_record


def identity(record):
    d=record['decoded']
    if d['status']!='tcp' or not d['tcp_payload_hex']:return None
    return tuple(d[k] for k in ('source_ip','source_port','destination_ip','destination_port','tcp_sequence','tcp_ack','tcp_flags','tcp_payload_hex'))


def run():
    evidence=read(OUT/'bounded_raw_evidence.json')
    inventory=read(BASE/'output/inventory.json');files={f['path']:f for f in inventory['files']}
    current=[f for f in files.values() if f['path'].startswith('attack/compromised-scada/ied1a/') and f['format']=='pcap']
    overlaps=[];additional_bytes=0
    for w in evidence['target_windows']:
        log=w['log_signature_lineage']
        if log['target_ip']!='185.175.0.4':continue
        ts=log['timestamp_us_candidate_utc']
        hit=[f for f in current if f['capture']['minimum_ts_us']<=ts<=f['capture']['maximum_ts_us']]
        if not hit:continue
        other=time_window(hit[0],ts);additional_bytes+=other.get('record_bytes_read',0)
        right=defaultdict(list)
        for r in other.get('observations',[]):
            key=identity(r)
            if key:right[key].append(r)
        found=[]
        for r in w.get('observations',[]):
            for o in right.get(identity(r),[]):
                skew=r['timestamp_us']-o['timestamp_us']
                if abs(skew)<=1000:
                    found.append({'hmi':{k:r[k] for k in ('source_path','pcap_record_header_offset','timestamp_us','frame_sha256')},
                                  'ied':{k:o[k] for k in ('source_path','pcap_record_header_offset','timestamp_us','frame_sha256')},
                                  'hmi_minus_ied_us':skew,'same_tcp_tuple_sequence_ack_flags_payload':True,
                                  'whole_frame_sha256_equal':r['frame_sha256']==o['frame_sha256'],
                                  'adu_patterns':[a['pdu_hex'] for a in r['decoded'].get('adus',[])]})
        overlaps.append({'day':log['timestamp_us_candidate_utc'],'log_signature_id':log['log_signature_id'],
                         'matched_observation_copies':len(found),'copy_examples':found[:5],
                         'clock_skews_us':stats([r['hmi_minus_ied_us'] for r in found]),
                         'other_view_window':{k:v for k,v in other.items() if k!='observations'}})
    benign=[]
    cp=read(BASE/'output/extraction/benign_ied1b/checkpoint.json')
    chunks={r['chunk']:r['path'] for r in cp['contract']['sources']}
    for w in evidence.get('benign_write_seed_windows',[]):
        ev=w['documented_benign_seed_event'];seg=ev['segment_refs'][0]
        original=raw_record(RAW/chunks[seg['chunk']],seg['pcap_offset'],seg['frame'])
        matches=[r for r in w['observations'] if identity(r)==identity(original) and abs(r['timestamp_us']-original['timestamp_us'])<=1000]
        benign.append({'source_event_uid':ev['event_uid'],'pdu_hex':ev['pdu_bytes'],'endpoint_frame':original,
                       'hmi_same_observation_count':len(matches),'hmi_copies':matches[:2]})
    pilot=read(OUT/'bounded_pilot_summary.json')
    totals=pilot['chain_totals']; selected=read(BASE/'output/selected_source_manifest.json')
    sec_per_byte=[];out_per_byte=[]
    for view in ('benign_ied1b','scada_ied1a'):
        cp=read(BASE/f'output/extraction/{view}/checkpoint.json')
        size=sum(s['bytes'] for s in cp['contract']['sources'])
        sec_per_byte.append(cp['accounting']['elapsed_s']/size)
        out_per_byte.append(cp['output_bytes']/size)
    totalbytes=sum(v['bytes'] for v in totals.values())
    write('view_overlap_samples.json',{'scope':'Bounded matching of TCP tuple/sequence/ack/flags/payload plus<=1000us; no rows merged or removed.',
        'scada_hmi_vs_current_ied1a':overlaps,'benign_hmi_vs_current_ied1b':benign,
        'additional_record_bytes_read':additional_bytes,
        'interpretation':'These copies support one canonical campaign view. They are not additional independent episodes. A repeated PDU at a distinct genuine stream position is not duplicate observation.'})
    plan={'state':'PROPOSED_NOT_EXECUTED_REQUIRES_OBJECTIVE_AGREEMENT_AND_SEPARATE_AUTHORIZATION',
        'single_best_next_action':'Agree the academic objective: a CIC-only within-testbed temporal/evidence study, or retain the independent-campaign claim as unsupported. Do this before authorizing expanded extraction.',
        'canonical_replacements':[{'campaign':'cic_compromised_scada_march','replace_baseline_view':'scada_ied1a','candidate_view':'scada_hmi','sources':pilot['chain_sources']['scada_hmi'],**totals['scada_hmi']},
                                  {'campaign':'cic_benign_january','replace_baseline_view':'benign_ied1b','candidate_view':'benign_hmi','sources':pilot['chain_sources']['benign_hmi'],**totals['benign_hmi']}],
        'retained_separate_campaigns':['cic_compromised_ied_march: existing IED1b response evidence remains one campaign','cic_external_february: timestamp-only logs still cannot establish packet-level core labels'],
        'estimated_source_bytes':totalbytes,'estimated_sequential_extraction_seconds_range':[round(totalbytes*min(sec_per_byte)),round(totalbytes*max(sec_per_byte))],
        'estimated_event_connection_output_bytes_range':[round(totalbytes*min(out_per_byte)),round(totalbytes*max(out_per_byte))],
        'estimated_peak_worker_bytes_basis':'Existing complete extraction workers observed approximately248–252MB. Allow at least1GB per worker for variable parsing and subsequent audit states. These are estimates, not measurements of expanded extraction.',
        'disk_plan':'Reserve at least5GB free for independent versioned events, audit sorts, annotations and checkpoints in addition to the immutable baseline; measure pilot expansion before committing a full run.',
        'resource_limit':'Measured rates from existing endpoint views differ from HMI traffic mix and host contention; no guaranteed runtime or output size.',
        'dedup_contract':['Never append HMI events to overlapping endpoint events as independent observations. Replace canonical view within the SAME campaign in a NEW extraction version.',
            'Keep original chunk/frame/PCAP-byte-offset, endpoint tuple, observed SYN/reconnect generation, TCP direction/sequence-byte range and exact payload.',
            'Only merge suppressions when same observation is established by packet/stream lineage and justified capture-clock skew, preserving copy relations.',
            'Payload equality alone is insufficient: identical polls/writes at different genuine stream positions remain separate application events.',
            'A full expanded canonical stream can introduce extra competing log matches; re-audit identity and uniqueness from scratch against unchanged originals, not by transferring old targets.'],
        'continuity_and_risk_gates':['Use chronological same-interface rotations only; do not concatenate compromised-SCADA substation0 March23 with March15–22 files.',
            'All candidate chain chunks have complete record chains in the frozen inventory; this does not prove no TCP loss.',
            'Bounded boundary TCP sequence observations exist but do not validate all stream continuity; carry state and audit segmentation/retransmission/gaps under a separately authorized pilot.',
            'Reject/hold labels with conflicting/unverified overlap bytes, missing identity, ambiguous connection generation or incomplete log timing evidence.',
            'Confirm comparable benign endpoint/function/address controls; current broader benign pilot proves reads to all three IEDs but observed FC5 controls remain at .5addresses15/25, not attack address1.',
            'Do not promise response diversity recovery: all54 current FDIexamples retain ABCD, three patterns, onecampaign; command expansion does not repair this.'],
        'stop_conditions':['Independent-campaign claim remains required but no extra independent CIC class-bearing campaigns can be established.',
            'Original attacker timing/identity semantics cannot justify a revised event acceptance contract.',
            'Expanded views lack required target/time coverage, introduce unresolved copying/loss or lack comparable benign controls.',
            'A temporal design still lacks supported classes or valid-looking diversity after justified burst/connection/pair purges.',
            'Any raw/baseline fingerprint changes, resource gate fails, or work would cross into unapproved preprocessing/training.'],
        'full_expanded_extraction_performed':False,'labels_transferred_or_changed':False}
    write('expanded_scope_plan.json',plan)
    print('overlap',sum(x['matched_observation_copies'] for x in overlaps),'SCADA copies;',sum(x['hmi_same_observation_count'] for x in benign),'benign seed copies',flush=True)
    return plan


if __name__=='__main__':
    run()
