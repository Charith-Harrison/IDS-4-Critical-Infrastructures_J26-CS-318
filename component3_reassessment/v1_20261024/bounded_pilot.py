"""Bounded raw CIC packet inspections; no new ADU dataset or labels.

Mid-file searches retain exact PCAP byte offsets, never invent global frame IDs.
Partial/multi-segment ADUs are not reconstructed by this independent inspector.
"""
from collections import Counter, defaultdict
import hashlib
import mmap
import struct
import time

import pyarrow.parquet as pq
from common import BASE, RAW, OUT, CONFIG, read, write, day, stats


def decode(data):
    if len(data)<14:
        return {'status':'short_ethernet'}
    pos=14;etype=int.from_bytes(data[12:14],'big')
    while etype in (0x8100,0x88a8):
        if len(data)<pos+4:return {'status':'short_vlan'}
        etype=int.from_bytes(data[pos+2:pos+4],'big');pos+=4
    if etype!=0x0800:return {'status':'non_ipv4','ethertype':etype}
    if len(data)<pos+20:return {'status':'short_ipv4'}
    ip=data[pos:];ihl=(ip[0]&15)*4;total=int.from_bytes(ip[2:4],'big')
    if ip[9]!=6:return {'status':'non_tcp','ip_protocol':ip[9]}
    if int.from_bytes(ip[6:8],'big')&0x3fff:return {'status':'ip_fragment'}
    tcp=ip[ihl:total]
    if len(tcp)<20:return {'status':'short_tcp'}
    h=(tcp[12]>>4)*4
    if h<20 or len(tcp)<h:return {'status':'bad_tcp_header'}
    sp,dp,seq,ack=struct.unpack_from('!HHII',tcp)
    payload=tcp[h:]
    r={'status':'tcp','source_ip':'.'.join(str(x) for x in ip[12:16]),'destination_ip':'.'.join(str(x) for x in ip[16:20]),
       'source_port':sp,'destination_port':dp,'tcp_sequence':seq,'tcp_ack':ack,'tcp_flags':tcp[13],
       'tcp_payload_hex':payload.hex(),'captured_payload_bytes':len(payload),'ip_truncated':len(ip)<total,'adus':[]}
    p=0
    if 502 in (sp,dp):
        while len(payload)-p>=7:
            tid,proto,n,unit=struct.unpack_from('!HHHB',payload,p)
            if proto!=0 or n<2 or p+6+n>len(payload):
                r['noncomplete_or_unframed_remaining_hex']=payload[p:].hex();break
            adu=payload[p:p+6+n];pdu=adu[7:];fc=pdu[0]&127
            a={'adu_hex':adu.hex(),'pdu_hex':pdu.hex(),'transaction_id':tid,'unit':unit,'function_raw':pdu[0],
                'function':fc,'exception':bool(pdu[0]&128),'payload_byte_offset':p,'role_by_port':'request' if dp==502 else 'response'}
            if len(pdu)>=5 and ((a['role_by_port']=='request' and fc in (1,2,3,4)) or fc in (5,6,15,16)):
                a['address']=int.from_bytes(pdu[1:3],'big')
                a['word_or_quantity']=int.from_bytes(pdu[3:5],'big')
                if fc==5:
                    a['fc5_value_spec_valid']=a['word_or_quantity'] in (0,65280)
                    a['fc5_pdu_shape_ok']=len(pdu)==5 and a['fc5_value_spec_valid']
            if a['role_by_port']=='response' and not a['exception'] and fc in (1,2,3,4) and len(pdu)>=2:
                a['byte_count']=pdu[1]
                a['returned_data_hex']=pdu[2:].hex()
                a['byte_count_matches_returned_bytes']=pdu[1]==len(pdu)-2
                if fc in (3,4):
                    a['raw_register_words']=[int.from_bytes(pdu[i:i+2],'big') for i in range(2,len(pdu)-1,2)]
            if a['exception'] and len(pdu)>1:a['exception_code']=pdu[1]
            r['adus'].append(a);p+=6+n
    return r


def header_info(handle):
    h=handle.read(24)
    formats={b'\xd4\xc3\xb2\xa1':('<',1000000),b'\xa1\xb2\xc3\xd4':('>',1000000)}
    if h[:4] not in formats:raise ValueError('Independent pilot supports only observed microsecond classic-PCAP profile')
    endian,ticks=formats[h[:4]]
    return endian,struct.unpack_from(endian+'I',h,20)[0]&0x0fffffff


def raw_record(path,offset,frame=None):
    with path.open('rb') as f:
        endian,link=header_info(f);assert link==1
        f.seek(offset);head=f.read(16)
        sec,frac,n,orig=struct.unpack(endian+'IIII',head); data=f.read(n)
        assert len(data)==n
    return {'source_path':path.relative_to(RAW).as_posix(),'source_frame':frame,'pcap_record_header_offset':offset,
            'timestamp_us':sec*1000000+frac,'capture_length':n,'wire_length':orig,
            'frame_sha256':hashlib.sha256(data).hexdigest(),'decoded':decode(data)}


def near_header(buf,at,minsec,maxsec,endian):
    # Validate three consecutive record headers and Ethernet fields. No substring
    # is promoted to a frame without the structural chain check.
    upper=min(len(buf)-80,at+4096)
    for start in range(max(24,at),upper):
        pos=start;valid=True
        for _ in range(3):
            if pos+30>len(buf):valid=False;break
            sec,frac,n,orig=struct.unpack_from(endian+'IIII',buf,pos)
            if not (minsec<=sec<=maxsec and frac<1000000 and 14<=n<=262144 and n<=orig<=1048576 and pos+16+n<=len(buf)):
                valid=False;break
            if int.from_bytes(buf[pos+28:pos+30],'big') not in (0x0800,0x86dd,0x0806,0x8100,0x88a8):
                valid=False;break
            pos+=16+n
        if valid:return start
    return None


def time_window(item,target_us):
    path=RAW/item['path'];cap=item['capture'];half=CONFIG['target_window_halfwidth_us']
    observations=[]
    with path.open('rb') as f:
        endian,link=header_info(f);assert link==1
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as buf:
            lo=24;hi=len(buf)-100
            probes=[]
            for _ in range(35):
                if hi-lo<8192:break
                mid=(lo+hi)//2
                at=near_header(buf,mid,cap['minimum_ts_us']//1000000-1,cap['maximum_ts_us']//1000000+1,endian)
                if at is None:break
                sec,frac,_,_=struct.unpack_from(endian+'IIII',buf,at);ts=sec*1000000+frac
                probes.append({'offset':at,'timestamp_us':ts})
                if ts<target_us-half:lo=at+1
                else:hi=at-1
            at=near_header(buf,max(24,lo-8192),cap['minimum_ts_us']//1000000-1,cap['maximum_ts_us']//1000000+1,endian)
            if at is None:return {'source_path':item['path'],'status':'search_unresolved','target_us':target_us,'probes':probes}
            start=at;visited=0;selected=0;byte_count=0;reasons=Counter();reached_upper=False
            while at+16<=len(buf) and visited<CONFIG['max_frames_per_target_window'] and at-start<CONFIG['max_bytes_per_target_window']:
                sec,frac,n,orig=struct.unpack_from(endian+'IIII',buf,at)
                if at+16+n>len(buf):break
                ts=sec*1000000+frac;visited+=1;byte_count+=16+n
                if ts>target_us+half:
                    reached_upper=True
                    break
                if ts>=target_us-half:
                    data=buf[at+16:at+16+n];d=decode(data);reasons[d['status']]+=1
                    observations.append({'source_path':item['path'],'source_frame':None,'frame_number_status':'unknown_without_prefix_scan',
                        'relative_frame_in_bounded_read':visited,'pcap_record_header_offset':at,'timestamp_us':ts,
                        'frame_sha256':hashlib.sha256(data).hexdigest(),'decoded':d})
                    selected+=1
                at+=16+n
    return {'source_path':item['path'],'target_us':target_us,'status':'bounded_inspection','selection_halfwidth_us':half,
            'start_offset':start,'end_offset':at,'record_bytes_read':byte_count,'records_visited':visited,
            'limit_reached':visited>=CONFIG['max_frames_per_target_window'] or at-start>=CONFIG['max_bytes_per_target_window'],
            'selection_complete_under_search_assumption':bool(observations) and reached_upper,
            'decoded_status_counts':dict(reasons),'probes':probes,'observations':observations,
            'search_limit':'Timestamp-guided structural seek assumes approximate monotonicity. Existing inventory records reversals; bounded observations prove presence only, never full-view absence.'}


def run():
    t0=time.monotonic()
    inventory=read(BASE/'output/inventory.json');files={f['path']:f for f in inventory['files']}
    profiles={
        'scada_hmi':'attack/compromised-scada/scada-hmi/scada-hmi-network-capture/',
        'benign_hmi':'benign/scada-hmi/scada-hmi-network-capture/'}
    chains={name:sorted([f for f in files.values() if f['path'].startswith(prefix) and f['format']=='pcap'],key=lambda f:f['capture']['first_ts_us']) for name,prefix in profiles.items()}
    boundary_reports=[];plan_sources={};sample_rows=[];read_bytes=0
    for name,chain in chains.items():
        plan_sources[name]=[{'path':f['path'],'bytes':f['bytes'],'recorded_sha256':f['sha256'],'first_ts_us':f['capture']['first_ts_us'],'last_ts_us':f['capture']['last_ts_us'],
                             'inventory_record_chain':f['capture']['status'],'inventory_truncated_frames':f['capture']['capture_truncated_frames'],
                             'inventory_backwards_timestamps':f['capture']['backwards_timestamp_frames']} for f in chain]
        groups=[]
        for f in chain:
            cap=f['capture']; head=[raw_record(RAW/f['path'],r['offset'],r['frame']) for r in cap['head_sample'][:CONFIG['boundary_frames_per_side']]]
            tail=[raw_record(RAW/f['path'],r['offset'],r['frame']) for r in cap['tail_sample'][-CONFIG['boundary_frames_per_side']:]]
            groups.append((f,head,tail));sample_rows.extend(head+tail)
            read_bytes+=sum(r['capture_length']+16 for r in head+tail)
        for (a,ha,ta),(b,hb,tb) in zip(groups,groups[1:]):
            def keyed(rs):
                m=defaultdict(list)
                for r in rs:
                    d=r['decoded']
                    if d['status']=='tcp':m[(d['source_ip'],d['source_port'],d['destination_ip'],d['destination_port'])].append(r)
                return m
            left,right=keyed(ta),keyed(hb);same=[]
            for key in left.keys()&right.keys():
                l=left[key][-1];r=right[key][0];ld=l['decoded'];rd=r['decoded']
                end=(ld['tcp_sequence']+ld['captured_payload_bytes']+bool(ld['tcp_flags']&2)+bool(ld['tcp_flags']&1))&0xffffffff
                same.append({'tuple':key,'last_left_frame':l['source_frame'],'first_right_frame':r['source_frame'],
                    'left_sequence_end':end,'right_sequence':rd['tcp_sequence'],
                    'sequence_delta_mod32':(rd['tcp_sequence']-end)&0xffffffff,'left_flags':ld['tcp_flags'],'right_flags':rd['tcp_flags']})
            boundary_reports.append({'chain':name,'before':a['path'],'after':b['path'],
                'inventory_time_gap_us':b['capture']['first_ts_us']-a['capture']['last_ts_us'],
                'shared_directed_tuples_in_bounded_samples':same,
                'interpretation':'Sequence/timestamp evidence only in sampled boundary frames; full TCP continuity and loss require an explicitly authorized complete-chain audit.'})
    signature_rows=pq.read_table(BASE/'output/log_signatures.parquet').to_pylist()
    targets={}
    hmi=chains['scada_hmi']
    for r in sorted(signature_rows,key=lambda r:(r['timestamp_us_candidate_utc'],r['log_signature_id'])):
        if r['recording_id']!='cic_compromised_scada_march' or r['family']!='brute_force_or_specific_coil' or r['target_ip'] not in ('185.175.0.4','185.175.0.5','185.175.0.8'):continue
        hit=[f for f in hmi if f['capture']['minimum_ts_us']<=r['timestamp_us_candidate_utc']<=f['capture']['maximum_ts_us']]
        key=(r['target_ip'],day(r['timestamp_us_candidate_utc']))
        if hit and key not in targets:targets[key]=(r,hit[0])
    windows=[]
    for key,(log,item) in sorted(targets.items()):
        window=time_window(item,log['timestamp_us_candidate_utc']);read_bytes+=window.get('record_bytes_read',0)
        matching=[]
        for r in window.get('observations',[]):
            d=r['decoded']
            for a in d.get('adus',[]):
                if a['role_by_port']=='request' and d['destination_ip']==log['target_ip'] and a['transaction_id']==log['transaction_id'] and a['function']==5 and a.get('address')==log['coil_address']:
                    matching.append({'observation':r,'adu':a,'residual_us':r['timestamp_us']-log['timestamp_us_candidate_utc']})
        window['log_signature_lineage']=log;window['behavior_compatible_bounded_observations']=matching
        window['presence_state']='compatible_packet_observed_ambiguous_not_new_label' if matching else 'not_observed_in_this_bounded_window_only'
        windows.append(window)
    # The normal write controls are selected from documented benign source
    # observations, independently of attack labels or desired address matches.
    benign_write_rows=pq.read_table(BASE/'output/extraction/benign_ied1b/events.parquet',
        columns=['event_uid','ts_complete_us','client_ip','server_ip','pdu_bytes','address','single_value','segment_refs'],
        filters=[('func_code','=',5),('protocol_role','=','request')]).to_pylist()
    normal_choices={}
    for r in sorted(benign_write_rows,key=lambda r:r['ts_complete_us']):
        hit=[f for f in chains['benign_hmi'] if f['capture']['minimum_ts_us']<=r['ts_complete_us']<=f['capture']['maximum_ts_us']]
        key=(day(r['ts_complete_us']),r['pdu_bytes'].hex())
        if hit and key not in normal_choices:
            normal_choices[key]=(r,hit[0])
    normal_windows=[]
    for key,(event,item) in sorted(normal_choices.items()):
        w=time_window(item,event['ts_complete_us']);read_bytes+=w.get('record_bytes_read',0)
        w['documented_benign_seed_event']={**event,'pdu_bytes':event['pdu_bytes'].hex()}
        normal_windows.append(w)
    # Full compact endpoint/function/address counts from bounded source frames.
    counts=Counter();patterns=Counter();unique_frames={}
    for r in sample_rows+[r for w in windows+normal_windows for r in w.get('observations',[])]:
        unique_frames[(r['source_path'],r['pcap_record_header_offset'])]=r
    for r in unique_frames.values():
        d=r['decoded']
        for a in d.get('adus',[]):
            if a['role_by_port']=='request':
                counts[(r['source_path'].startswith('benign/'),d['destination_ip'],a['function'],a.get('address'),a.get('word_or_quantity'))]+=1
                patterns[(r['source_path'].startswith('benign/'),d['destination_ip'],a['pdu_hex'])]+=1
    summary={
        'scope':'Bounded raw packet pilot only; no expanded chain extraction, new labels or model datasets.',
        'chain_sources':plan_sources,'chain_totals':{k:{'files':len(v),'bytes':sum(f['bytes'] for f in v),'frames_in_existing_inventory':sum(f['capture']['frames'] for f in chains[k])} for k,v in plan_sources.items()},
        'boundary_audits':boundary_reports,'bounded_record_bytes_read':read_bytes,
        'bounded_unique_source_frames':len(unique_frames),'targeted_log_windows':len(windows),
        'benign_write_seed_windows':len(normal_windows),
        'presence_by_target':[{'target':t,'windows':sum(w['log_signature_lineage']['target_ip']==t for w in windows),'compatible_presence_windows':sum(w['log_signature_lineage']['target_ip']==t and bool(w['behavior_compatible_bounded_observations']) for w in windows)} for t in ('185.175.0.4','185.175.0.5','185.175.0.8')],
        'bounded_request_endpoint_function_address_value_counts':[{'benign_source':k[0],'target':k[1],'function':k[2],'address':k[3],'quantity_or_value':k[4],'sampled_adus':n} for k,n in sorted(counts.items(),key=lambda x:str(x[0]))],
        'bounded_request_pdu_patterns':[{'benign_source':k[0],'target':k[1],'pdu_hex':k[2],'sampled_adus':n} for k,n in patterns.items()],
        'loss_risk_limit':'Whole-chain checks reuse existing inventory structural/truncation metadata. A bounded prefix/suffix/time pilot cannot prove no TCP loss, full endpoint equivalence or completeness. No process success is inferred.',
        'elapsed_s':round(time.monotonic()-t0,3)}
    write('bounded_pilot_summary.json',summary)
    write('bounded_raw_evidence.json',{'boundary_observations':sample_rows,'target_windows':windows,'benign_write_seed_windows':normal_windows})
    print('bounded pilot',len(unique_frames),'frames;',read_bytes,'record bytes;',len(windows),'log windows',flush=True)
    return summary


if __name__=='__main__':
    run()
