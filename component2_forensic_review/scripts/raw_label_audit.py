"""Read-only reconstruction of label evidence from supplied derivatives.

No packet bytes, frame identities, TCP connections or original CIC log rows are
invented. A missing raw source remains missing. Outputs stay in this review.
"""
from pathlib import Path
import json
import hashlib
from collections import Counter
import numpy as np
import pandas as pd

OUT = Path(__file__).resolve().parents[1]
EVIDENCE = OUT / 'evidence'
MAIN = Path(r'D:\VSCode\GitHub\4th Year Cyber')
PRIOR_INV = MAIN / 'C3/component3_preparation/output/inventory.json'
PRIOR_LOG_SUMMARY = MAIN / 'C3/component3_preparation/output/log_summary.json'
MASTER = '185.175.0.3'
FIELDS = ['src_ip','dst_ip','unit_id','func_code']


def dump(name, value):
    (OUT / name).write_text(json.dumps(value, indent=2, default=str) + '\n', encoding='utf-8')


def summary(values):
    v = np.asarray(values, dtype=float)
    return {'n':len(v), **({str(q):float(np.quantile(v,q)) for q in [0,.01,.25,.5,.75,.99,1]} if len(v) else {})}


def campaign(name):
    if 'normal' in name:
        return 'CIC_benign_January_recording_family'
    if name.startswith('substation-'):
        return 'CIC_compromised_SCADA_March_recording_family'
    if name.startswith('veth3efd353'):
        return 'CIC_compromised_IED_March_recording_family'
    if name.startswith('veth'):
        return 'CIC_external_February_recording_family'
    return 'unknown_external_snippet'


def group(name):
    lookup = {'veth4edc015-normal-4.pcap':'G01_0122_normal4',
              'veth5bbeaa2-normal-13.pcap':'G02_0123_normal13',
              'substation-1.pcap':'G04_0315_sub1','substation-2.pcap':'G05_0315_sub2',
              'substation-4.pcap':'G06_0316_sub4','substation-10.pcap':'G07_0319_sub10',
              'substation-14.pcap':'G08_0320_sub14','veth3efd353-0.pcap':'G09_0323_veth3e0',
              'veth3efd353-1.pcap':'G10_0323_veth3e1'}
    return lookup.get(name, 'G03_0201_veth' if name.startswith('veth') else 'EXCLUDED_UNPLACEABLE')


def main():
    p = pd.read_csv(EVIDENCE/'recon_labeled_packets_ALL.csv')
    p.insert(0, 'original_processed_row_id', np.arange(len(p)))
    full_date=p.timestamp.astype(str).str.match(r'^\d{4}-\d{2}-\d{2}[T ]')
    p['ts'] = pd.to_datetime(p.timestamp.where(full_date),format='mixed',utc=True,errors='coerce')
    p['ts_ns'] = p.ts.astype('int64')
    p['campaign_family'] = p.file_source.map(campaign)
    p['configured_capture_group'] = p.file_source.map(group)
    e = pd.read_csv(EVIDENCE/'attack_events_mapped.csv')
    e.insert(0,'mapped_workbook_row', np.arange(2,len(e)+2))
    e['packet_ts'] = pd.to_datetime(e.packet_timestamp,format='mixed',utc=True)
    e['log_ts_candidate_utc'] = pd.to_datetime(e.log_timestamp,format='mixed',utc=True)
    e['packet_minus_log_seconds_assuming_log_UTC'] = (e.packet_ts-e.log_ts_candidate_utc).dt.total_seconds()
    e['packet_minus_log_seconds_assuming_log_Colombo'] = e.packet_minus_log_seconds_assuming_log_UTC + 19800
    keys=['timestamp','src_ip','dst_ip','file_source']
    em = e.rename(columns={'packet_timestamp':'timestamp'}).groupby(keys,dropna=False).agg(
        mapped_rows=('mapped_workbook_row',lambda x:';'.join(map(str,x))),
        n_map_rows=('mapped_workbook_row','size'),
        log_attack=('log_attack',lambda x:';'.join(sorted(set(x)))),
        log_timestamp=('log_timestamp',lambda x:';'.join(sorted(set(x)))),
        log_file=('log_file',lambda x:';'.join(sorted(set(x))))).reset_index()
    p = p.merge(em,on=keys,how='left',validate='many_to_one')
    p['is_mapped'] = p.n_map_rows.notna()
    p['cohort'] = np.select([
        p.file_source.eq('attached_recon_flows.csv'),
        p.modbus_len.eq(3)&p.func_code.eq(5),
        p.modbus_len.eq(3),p.is_mapped,
        p.func_code.isin([1,2,3,4])&p.modbus_len.eq(6)&p.quantity.gt(1)],
        ['external_time_only_snippet','fc5_short_response_shape','other_short_response_shape',
         'mapped_workbook_association','nonroutine_read_quantity_shape'],default='other')
    p['role_inference'] = np.select([
        p.modbus_len.eq(6)&p.func_code.isin([1,2,3,4])&p.quantity.gt(0),
        p.src_ip.eq(MASTER)&p.func_code.isin([5,6])&p.modbus_len.eq(6),
        p.dst_ip.eq(MASTER)],
        ['read_request_shape','write_request_shape','slave_to_master_response_shape'],
        default='unverified_role')
    pos=p.loc[p.label.eq(1)].copy()
    pos['label_state']=np.where(pos.is_mapped,'ambiguous','unsupported_heuristic')
    pos['source_reference']='evidence/recon_labeled_packets_ALL.csv'
    pos['source_workbook_excel_row']=pos.original_processed_row_id+2
    pos['original_log_row_reference']=''
    pos['original_log_target_ip']=''
    pos['original_log_transaction_id']=''
    pos['exact_packet_frame_identity']=''
    pos['raw_bytes']=''
    pos['raw_source_verified']=False
    pos['evidence_reason']=np.where(pos.is_mapped,
        'Exact derivative workbook tuple association only; original log row, TargetIP/TID and matching rule absent; variable clock offsets',
        'Supplied positive without original-source label evidence; cohort describes observed shape, not proven original labeling algorithm')
    provenance_cols=['source_reference','original_processed_row_id','source_workbook_excel_row','file_source',
        'campaign_family','configured_capture_group','timestamp','src_ip','dst_ip','unit_id','func_code',
        'modbus_len','register_start','quantity','packet_size','cohort','role_inference','label','label_state',
        'mapped_rows','log_attack','log_timestamp','log_file','original_log_row_reference','original_log_target_ip',
        'original_log_transaction_id','exact_packet_frame_identity','raw_bytes','raw_source_verified','evidence_reason']
    pos[provenance_cols].to_csv(OUT/'label_provenance.csv',index=False)

    # Match all event-map rows independently to processed observations, preserving duplicates.
    join = e.merge(p, left_on=['packet_timestamp','src_ip','dst_ip','file_source'],
                  right_on=['timestamp','src_ip','dst_ip','file_source'],how='left',suffixes=('_map','_pkt'))
    join[['mapped_workbook_row','packet_timestamp','src_ip','dst_ip','file_source','func_code_map','func_code_pkt',
          'quantity_map','quantity_pkt','log_attack_map','log_timestamp_map','log_file_map',
          'packet_minus_log_seconds_assuming_log_UTC','packet_minus_log_seconds_assuming_log_Colombo',
          'original_processed_row_id','label']].to_csv(EVIDENCE/'event_map_reconciliation.csv',index=False)
    offsets=e.groupby(['log_file','log_attack','log_timestamp']).agg(
        mapped_rows=('mapped_workbook_row','size'),
        min_delta_seconds=('packet_minus_log_seconds_assuming_log_UTC','min'),
        max_delta_seconds=('packet_minus_log_seconds_assuming_log_UTC','max')).reset_index()
    offsets.to_csv(EVIDENCE/'event_map_clock_offsets.csv',index=False)

    # Candidates stay explicitly unsupported/ambiguous. No class expansion is performed.
    c = p.loc[p.role_inference.eq('read_request_shape')&(p.label.eq(1)|p.is_mapped)].copy()
    c=c.sort_values(['file_source','src_ip','dst_ip','unit_id','ts_ns','original_processed_row_id'])
    c['sequence_position_after_ordering']=c.groupby(['file_source','src_ip','dst_ip','unit_id']).cumcount()
    c['candidate_id']='candidate_'+c.original_processed_row_id.astype(str)
    c['source_reference']='evidence/recon_labeled_packets_ALL.csv'
    c['capture_run']=c.file_source
    c['exact_packet_frame_identity']=''
    c['transaction_id']=''
    c['src_tcp_port']=''
    c['dst_tcp_port']=''
    c['tcp_connection_generation']=''
    c['raw_source_verified']=False
    c['evidence_supported_recon_request']=False
    c['matching_confidence']=np.where(c.is_mapped,'derivative_map_only','shape_candidate_only')
    c['label_state']=np.where(c.is_mapped,'ambiguous','unsupported_heuristic')
    c['address']=c.register_start
    c['quantity_value']=c.quantity
    c['attack_log_reference']=c.log_file.fillna('')+' | mapped workbook rows '+c.mapped_rows.fillna('none')
    c['previous_candidate_row_id']=c.groupby(['file_source','src_ip','dst_ip','unit_id']).original_processed_row_id.shift()
    c['next_candidate_row_id']=c.groupby(['file_source','src_ip','dst_ip','unit_id']).original_processed_row_id.shift(-1)
    c[['candidate_id','source_reference','original_processed_row_id','capture_run','campaign_family',
       'configured_capture_group','exact_packet_frame_identity','timestamp','src_ip','dst_ip','src_tcp_port',
       'dst_tcp_port','tcp_connection_generation','unit_id','func_code','address','quantity_value','modbus_len',
       'packet_size','transaction_id','attack_log_reference','log_attack','log_timestamp','matching_confidence',
       'label_state','raw_source_verified','evidence_supported_recon_request','label',
       'sequence_position_after_ordering','previous_candidate_row_id','next_candidate_row_id']].to_csv(
       OUT/'recon_request_candidates.csv',index=False)

    # Nearest reverse-direction same-function predecessor is a diagnostic association,
    # never a transaction match: no TCP ports/TID/payload survived extraction.
    associations=[]
    short=pos.loc[pos.modbus_len.eq(3)&pos.ts.notna()]
    requests=p.loc[p.ts.notna()&p.modbus_len.eq(6)]
    for (file,src,dst,unit,fc),rr in short.groupby(['file_source','src_ip','dst_ip','unit_id','func_code']):
        qq=requests.loc[requests.file_source.eq(file)&requests.src_ip.eq(dst)&requests.dst_ip.eq(src)
            &requests.unit_id.eq(unit)&requests.func_code.eq(fc)].sort_values('ts_ns')
        qts=qq.ts_ns.to_numpy();qids=qq.original_processed_row_id.to_numpy()
        rts=rr.ts_ns.to_numpy(); ins=np.searchsorted(qts,rts,side='right')
        for ri,rt,i in zip(rr.original_processed_row_id,rts,ins):
            if i:
                dt=(rt-qts[i-1])/1e9
                count=i-np.searchsorted(qts,rt-10_000_000,side='left')
                req=qq.iloc[i-1]
                associations.append({'positive_processed_row_id':int(ri),'file_source':file,
                    'positive_timestamp':p.loc[p.original_processed_row_id.eq(ri),'timestamp'].iloc[0],
                    'response_src':src,'response_dst':dst,'func_code':int(fc),
                    'preceding_request_processed_row_id':int(qids[i-1]),'preceding_request_timestamp':req.timestamp,
                    'preceding_request_label':int(req.label),'preceding_request_address':int(req.register_start),
                    'preceding_request_quantity':int(req.quantity),'delta_seconds':dt,
                    'same_key_predecessors_within_10ms':int(count),
                    'association_state':'contextual_direction_function_time_only' if dt<=.01 else 'no_close_candidate',
                    'exact_transaction_match':False,'raw_frame_bytes_available':False})
            else:
                associations.append({'positive_processed_row_id':int(ri),'file_source':file,'func_code':int(fc),
                    'association_state':'no_preceding_candidate','exact_transaction_match':False,
                    'raw_frame_bytes_available':False})
    a=pd.DataFrame(associations)
    a.to_csv(EVIDENCE/'short_response_predecessor_candidates.csv',index=False)
    examples=[]
    if len(a):
        for _,aa in a.groupby(['file_source','func_code']):
            examples.extend(aa.head(1).to_dict('records'))
    dump('evidence/len3_representative_evidence.json',{'raw_bytes_available':False,
        'interpretation':'Response shape and nearest request are derivative evidence; actual exception function high bit, exception code, TCP transaction and initiating mechanism are unverified.',
        'examples':examples})

    inv=json.loads(PRIOR_INV.read_text()) if PRIOR_INV.exists() else {'files':[]}
    bybase={}
    for row in inv['files']:
        bybase.setdefault(Path(row['path']).name,[]).append(row)
    campaigns=[]
    for name,pp in p.groupby('file_source'):
        hits=bybase.get(name,[])
        cp=c[c.file_source.eq(name)]
        campaigns.append({'file_source':name,'configured_capture_group':group(name),
            'conservative_campaign_dependency':campaign(name),'processed_packet_rows':len(pp),
            'positive_packet_rows':int(pp.label.sum()),'candidate_read_request_rows':len(cp),
            'evidence_supported_recon_requests':0,'derivative_mapped_rows':int(pp.is_mapped.sum()),
            'distinct_derivative_log_events':len(e[e.file_source.eq(name)][['log_file','log_attack','log_timestamp']].drop_duplicates()),
            'raw_original_log_events_verified':0,'independent_attack_campaign_count_verified':'UNKNOWN',
            'positive_windows':'NOT_AVAILABLE_OR_RECOMPUTED_ELSEWHERE',
            'prior_inventory_possible_source_paths':';'.join(x['path'] for x in hits),
            'prior_inventory_source_hashes':';'.join(x['sha256'] for x in hits),
            'raw_source_available':False,'source_path_status':'historical inventory match only; originals absent',
            'minimum_utc':str(pp.ts.min()),'maximum_utc':str(pp.ts.max())})
    pd.DataFrame(campaigns).to_csv(OUT/'capture_campaign_summary.csv',index=False)
    close=a[a.association_state.eq('contextual_direction_function_time_only')] if len(a) else a
    metrics={'scope':'All original processed workbook rows; no inherited rebuilt rows assumed',
        'packet_rows':len(p),'positive_rows':len(pos),'positive_cohort_counts':pos.cohort.value_counts().to_dict(),
        'positive_label_state_counts':pos.label_state.value_counts().to_dict(),
        'positive_role_shape_counts':pos.role_inference.value_counts().to_dict(),
        'event_map_rows':len(e),'event_map_distinct_log_signatures':len(e[['log_file','log_attack','log_timestamp']].drop_duplicates()),
        'map_join_rows':len(join),'mapped_observations_found':int(join.original_processed_row_id.notna().sum()),
        'map_function_disagreements':int(join.func_code_map.ne(join.func_code_pkt).sum()),
        'map_quantity_disagreements':int(join.quantity_map.ne(join.quantity_pkt).sum()),
        'map_packet_label_counts':join.label.value_counts().to_dict(),
        'map_utc_minus_log_seconds':summary(e.packet_minus_log_seconds_assuming_log_UTC),
        'map_log_clock_timezone_proven':False,'candidate_read_request_rows':len(c),
        'candidate_read_requests_by_cohort':c.cohort.value_counts().to_dict(),
        'evidence_supported_recon_request_rows':0,'short_response_rows':len(short),
        'short_responses_with_preceding_same_key_request_within_10ms':len(close),
        'close_predecessor_delta_seconds':summary(close.delta_seconds) if len(close) else {'n':0},
        'close_predecessor_label_counts':close.preceding_request_label.value_counts().to_dict() if len(close) else {},
        'close_predecessors_with_multiple_candidates_10ms':int(close.same_key_predecessors_within_10ms.gt(1).sum()) if len(close) else 0,
        'exact_transaction_pairings_verified':0,'original_pcap_bytes_available':False,'original_attack_logs_available':False}
    dump('evidence/label_forensic_metrics.json',metrics)
    print(json.dumps(metrics,indent=2,default=str))


if __name__=='__main__':
    main()
