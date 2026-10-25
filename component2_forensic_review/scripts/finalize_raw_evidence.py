"""Consolidate bounded raw recovery, preserve ambiguity, and enrich old-label audit.

This changes only new forensic artifacts. Existing packet labels are preserved.
"""
from pathlib import Path
import json,bisect,re
from collections import Counter
import pandas as pd
import numpy as np

OUT=Path(__file__).resolve().parents[1];E=OUT/'evidence'
RAW=Path(r'G:\modbus cic 2023\Modbus Dataset')


def dump(name,value):
    (OUT/name).write_text(json.dumps(value,indent=2,default=str)+'\n',encoding='utf8')


def broad(name):
    return 'external_February_recording' if name.startswith('veth') and not name.startswith('veth3efd353') else ('compromised_IED_March_recording' if name.startswith('veth3efd353') else 'compromised_SCADA_March_recording')


def main():
    c=pd.read_csv(OUT/'recon_request_candidates.csv',dtype={'adu_hex':str,'response_adu_hex':str})
    if (E/'hmi_prefix_recon_request_candidates.csv').exists():
        c=pd.concat([c,pd.read_csv(E/'hmi_prefix_recon_request_candidates.csv',dtype={'adu_hex':str,'response_adu_hex':str})],ignore_index=True)
    c=c.sort_values(['capture_run','src_ip','dst_ip','unit_id','timestamp_us','source_relative_path','frame_identity','adu_offset_in_tcp_payload'])
    # Idempotent consolidation by exact raw ADU identity (never feature signature).
    c=c.drop_duplicates(['source_relative_path','frame_identity','adu_offset_in_tcp_payload'])
    c['candidate_id']=['raw_recon_'+str(i).zfill(6) for i in range(len(c))]
    c['sequence_position_after_ordering']=c.groupby(['capture_run','src_ip','dst_ip','unit_id']).cumcount()
    c['event_correspondence_unique']=c.log_match_count.eq(1)
    c['contextual_recon_mechanism_supported']=True
    c['label_state']=np.where(c.event_correspondence_unique,'supported_contextual','ambiguous')
    c['evidence_supported_recon_request']=c.event_correspondence_unique
    c['ambiguity_reason']=np.where(c.event_correspondence_unique,
        'single contextual start candidate; logger clock semantics still unverified',
        'multiple equally eligible original log starts within25ms target/range join; function not explicitly logged')
    c['attack_log_references_json']=c.attack_log_reference.map(lambda x:json.dumps(re.split(r';(?=attack/)',x)))
    c['private_audit_metadata_not_predictors']='candidate_id,label_state,log_*,attack_log_reference,event_correspondence_unique,matching_confidence,evidence_supported_recon_request,source identities'
    c.to_csv(OUT/'recon_request_candidates.csv',index=False)
    m=json.loads((E/'raw_recovery_metrics.json').read_text())
    s=json.loads((E/'hmi_prefix_raw_recovery_metrics.json').read_text()) if (E/'hmi_prefix_raw_recovery_metrics.json').exists() else {}
    m['scope']='full original logs; canonical external-attacker capture plus all18 SCADA bridge files and non-overlap early HMI prefix; extra interfaces only reconcile legacy rows'
    m['hmi_prefix_supplement']=s
    m['candidate_requests']=len(c);m['label_states']=c.label_state.value_counts().to_dict()
    m['unambiguous_contextual_requests']=int(c.event_correspondence_unique.sum())
    m['ambiguous_exact_event_attribution_requests']=int((~c.event_correspondence_unique).sum())
    m['candidate_campaigns']=c.capture_run.value_counts().to_dict()
    m['candidate_function_codes']=c.func_code.value_counts().to_dict()
    m['candidate_quantities']=c.quantity_value.value_counts().to_dict()
    m['candidate_addresses']=c.address.value_counts().to_dict()
    m['candidates_with_response']=int(c.response_frame_identity.notna().sum())
    m['unambiguous_contextual_requests_by_campaign']=c[c.event_correspondence_unique].capture_run.value_counts().to_dict()
    m['candidate_current_shapes']=c.groupby(['func_code','address','quantity_value','modbus_len','packet_size']).size().reset_index(name='n').to_dict('records')
    m['unique_attack_log_source_rows_referenced']=len({ref for text in c.attack_log_reference for ref in re.split(r';(?=attack/)',text)})
    m['signed_log_delta_us_min']=float(c.log_delta_us_min.min());m['signed_log_delta_us_max']=float(c.log_delta_us_max.max())
    m['supported_exact_count']=0
    dump('evidence/raw_recovery_metrics.json',m)

    # Reconcile each mapped derivative row to the actual original log row(s).
    a=pd.read_csv(E/'attack_events_mapped.csv');a.insert(0,'mapped_workbook_row',range(2,len(a)+2))
    logs=pd.read_csv(E/'original_recon_log_rows.csv',keep_default_na=False)
    a['log_us']=pd.to_datetime(a.log_timestamp,format='mixed').dt.as_unit('us').astype('int64')
    logs['log_us']=pd.to_numeric(logs.timestamp_candidate_utc_us,errors='coerce')
    a['source_path']=a.log_file.map(lambda x:x.replace(chr(92),'/'))
    am=a.merge(logs,left_on=['source_path','log_us','log_attack'],right_on=['source_path','log_us','attack'],how='left')
    am['target_on_packet_endpoints']=am.target_ip.eq(am.src_ip)|am.target_ip.eq(am.dst_ip)
    am.to_csv(E/'original_log_map_reconciliation.csv',index=False)
    map_target=am.groupby('mapped_workbook_row').target_on_packet_endpoints.any().to_dict()

    prov=pd.read_csv(OUT/'label_provenance.csv',keep_default_na=False,dtype={'raw_bytes':str,'matching_request_adu_hex':str}).astype(object)
    for name in ['supplied_label_preserved','semantic_recon_ground_truth_proven','raw_evidence_status',
        'raw_transaction_id','raw_wire_function_code','raw_exception_code','raw_src_tcp_port','raw_dst_tcp_port',
        'raw_match_multiplicity','recovered_candidate_id','mapped_log_target_agrees_with_endpoint',
        'matching_request_reference','matching_request_adu_hex','request_response_delta_us',
        'associated_nonrecon_log_reference','associated_nonrecon_log_attack','associated_nonrecon_log_delta_us']:
        if name not in prov:prov[name]=pd.Series(['']*len(prov),dtype=object)
    rp=pd.read_csv(E/'raw_positive_packet_matches.csv',dtype={'adu_hex':str,'matching_request_adu_hex':str})
    raw_index={rid:rr for rid,rr in rp.groupby('original_processed_row_id',sort=False)}
    ci={k:g.sort_values('timestamp_us') for k,g in c.groupby(['capture_run','src_ip','dst_ip','unit_id','func_code','address','quantity_value'])}
    states=[];raw_counts=Counter();raw_roles=Counter()
    for i,r in prov.iterrows():
        rid=r.original_processed_row_id;rrs=raw_index.get(rid)
        prov.loc[i,'supplied_label_preserved']=r.label
        prov.loc[i,'semantic_recon_ground_truth_proven']=False
        if rrs is None:
            prov.loc[i,'raw_evidence_status']='unmatched_original_capture_or_nonCIC_snippet'
            states.append(r.label_state);continue
        rr=rrs.iloc[0];raw_counts['matched_positive_rows']+=1
        prov.loc[i,'raw_source_verified']=True
        prov.loc[i,'raw_evidence_status']='exact_timestamp_endpoints_base_function_length_match_to_original_capture'
        prov.loc[i,'exact_packet_frame_identity']=str(rr.source_relative_path)+'#frame='+str(int(rr.frame_identity))+';adu_offset='+str(int(rr.adu_offset_in_tcp_payload))
        prov.loc[i,'raw_bytes']=rr.adu_hex
        prov.loc[i,'raw_transaction_id']=rr.transaction_id
        prov.loc[i,'raw_wire_function_code']=rr.wire_function_code
        prov.loc[i,'raw_exception_code']=rr.exception_code if pd.notna(rr.exception_code) else ''
        prov.loc[i,'raw_src_tcp_port']=rr.src_tcp_port;prov.loc[i,'raw_dst_tcp_port']=rr.dst_tcp_port
        prov.loc[i,'raw_match_multiplicity']=len(rrs)
        prov.loc[i,'exact_message_correspondence_unique']=len(rrs)==1
        state='unsupported_heuristic';reason=r.evidence_reason
        if rr.is_request:
            raw_roles['request']+=1
            key=(rr.capture_run,rr.src_ip,rr.dst_ip,rr.unit_id,rr.func_code,rr.address,rr.quantity_value)
            possible=ci.get(key)
            if possible is not None:
                near=possible[np.abs(possible.timestamp_us-rr.timestamp_us)<=1000]
                if len(near)==1:
                    cc=near.iloc[0];state=cc.label_state
                    prov.loc[i,'recovered_candidate_id']=cc.candidate_id
                    prov.loc[i,'original_log_row_reference']=cc.attack_log_reference
                    prov.loc[i,'original_log_target_ip']=cc.log_target_ip if pd.notna(cc.log_target_ip) else ''
                    prov.loc[i,'original_log_transaction_id']=cc.log_transaction_id_original if pd.notna(cc.log_transaction_id_original) else ''
                    reason='Raw read request matches canonical request within1ms across interface views. '+cc.ambiguity_reason
                elif len(near)>1:
                    state='ambiguous';reason='Multiple recovered request observations share same shape/time neighborhood; no unique semantic attribution'
            if r.cohort=='mapped_workbook_association':
                rows=[int(x) for x in str(r.mapped_rows).split(';') if x]
                prov.loc[i,'mapped_log_target_agrees_with_endpoint']=any(map_target.get(x,False) for x in rows)
                if not any(map_target.get(x,False) for x in rows):
                    reason+=' Original mapped log TargetIP does not equal either packet endpoint.'
        else:
            raw_roles['response']+=1
            is_exception=bool(rr.is_exception)
            pairclose=pd.notna(rr.get('request_response_delta_us')) and 0<=rr.request_response_delta_us<=5_000_000
            nonreconclose=pd.notna(rr.get('nearest_nonrecon_log_delta_us')) and abs(rr.nearest_nonrecon_log_delta_us)<=25000
            if is_exception and pairclose:
                state='attack_associated_response' if nonreconclose else 'ambiguous'
                prov.loc[i,'matching_request_reference']=str(rr.matching_request_source)+'#frame='+str(int(rr.matching_request_frame))
                prov.loc[i,'matching_request_adu_hex']=rr.matching_request_adu_hex
                prov.loc[i,'request_response_delta_us']=rr.request_response_delta_us
                prov.loc[i,'associated_nonrecon_log_reference']=rr.get('nearest_nonrecon_log_reference','')
                prov.loc[i,'associated_nonrecon_log_attack']=rr.get('nearest_nonrecon_log_attack','')
                prov.loc[i,'associated_nonrecon_log_delta_us']=rr.get('nearest_nonrecon_log_delta_us','')
                reason='Actual Modbus exception response (wire function highbit set), matched reverse TCP endpoints/TID/unit/basefunction to request.'
                if nonreconclose:reason+=' Nearest original source log within25ms records brute-force/specific-coil mechanism, not reconnaissance.'
                else:reason+=' Original attack mechanism not uniquely established by this response alone.'
            else:
                state='ambiguous';reason='Raw slave-to-master response exists; original recon correspondence not established'
        if len(rrs)>1:
            state='ambiguous'
            reason+=' One original processed packet row corresponds to23 complete same-shape Modbus ADUs coalesced in one frame at distinct TCP byte offsets; unique message identity was lost.'
        prov.loc[i,'label_state']=state;prov.loc[i,'evidence_reason']=reason;states.append(state)
    prov.to_csv(OUT/'label_provenance.csv',index=False)
    lm=json.loads((E/'label_forensic_metrics.json').read_text())
    lm['stage']='pre-raw derivative-stage snapshot; raw outputs supersede source-absence interpretations'
    lm['superseded_by']=['evidence/raw_recovery_metrics.json','evidence/raw_positive_packet_matches.csv','label_provenance.csv']
    lm['raw_original_sources_now_available']=True
    dump('evidence/label_forensic_metrics.json',lm)
    old=json.loads((E/'len3_representative_evidence.json').read_text())
    old['stage']='pre-raw derivative-stage snapshot; superseded by exact source-byte matches'
    old['superseded_by']=['evidence/raw_positive_packet_matches.csv','evidence/len3_source_byte_examples.json']
    dump('evidence/len3_representative_evidence.json',old)
    ex=[]
    for _,g in rp[rp.modbus_len.eq(3)].groupby(['source_relative_path','wire_function_code']):
        ex.extend(g.iloc[[0,len(g)//2,len(g)-1]].drop_duplicates(['frame_identity']).to_dict('records'))
    dump('evidence/len3_source_byte_examples.json',{'scope':'Exact source bytes, frame numbers, reverse-endpoint/TID request association and nearest original non-recon log reference','examples':ex})
    summary={'all_original_positive_rows':len(prov),'label_state_counts':prov.label_state.value_counts().to_dict(),
        'raw_verified_positive_rows':int(prov.raw_source_verified.astype(str).str.lower().eq('true').sum()),
        'mapped_packet_rows':len(a),'mapped_original_source_join_rows':len(am),
        'mapped_rows_original_target_not_on_packet_endpoints':sum(not x for x in map_target.values()),
        'mapped_rows_original_target_on_packet_endpoints':sum(map_target.values()),
        'raw_positive_request_response_roles':raw_roles,'unique_raw_positive_matching_rows':len(raw_index)}
    dump('evidence/final_label_summary.json',summary)

    # Source/campaign counts retain rotated chunks and interface views explicitly.
    caps=pd.read_csv(OUT/'capture_campaign_summary.csv',keep_default_na=False)
    for column in ['original_time_only_values_json','timestamp_parse_status']:
        if column not in caps:caps[column]=pd.Series(['']*len(caps),dtype=object)
    raw_names={x.name for x in RAW.rglob('*.pcap')}
    for i,r in caps.iterrows():
        rr=rp[rp.capture_chunk.eq(r.file_source)]
        caps.loc[i,'raw_source_available']=r.file_source in raw_names
        caps.loc[i,'positive_packet_rows_raw_verified']=rr.original_processed_row_id.nunique()
        caps.loc[i,'supported_contextual_positive_requests']=int(prov[(prov.file_source.eq(r.file_source))&prov.label_state.eq('supported_contextual')].shape[0])
        caps.loc[i,'source_path_status']='raw byte matching performed' if len(rr) else ('original capture available; no positive rows required for reconciliation' if r.file_source in raw_names else 'nonCIC external snippet source not recovered')
        caps.loc[i,'independent_attack_campaign_count_verified']='UNKNOWN'
        if r.file_source=='attached_recon_flows.csv':
            caps.loc[i,'minimum_utc']='';caps.loc[i,'maximum_utc']=''
            packet_source=pd.read_csv(E/'recon_labeled_packets_ALL.csv',usecols=['timestamp','file_source'])
            caps.loc[i,'original_time_only_values_json']=json.dumps(packet_source.loc[packet_source.file_source.eq(r.file_source),'timestamp'].tolist())
            caps.loc[i,'timestamp_parse_status']='time_only_unplaceable_no_date_inferred'
    caps.to_csv(OUT/'capture_campaign_summary.csv',index=False)
    # Distinct log signatures/date counts are descriptive and cannot establish runs.
    cds=[]
    for camp,g in c.groupby('capture_run'):
        cds.append({'recording_family':camp,'candidate_requests':len(g),'supported_contextual_unique_event_requests':int(g.event_correspondence_unique.sum()),
            'ambiguous_exact_event_correspondence':int((~g.event_correspondence_unique).sum()),
            'source_chunks_with_candidates':g.capture_chunk.nunique(),'UTC_dates_with_candidates':g.timestamp.str[:10].nunique(),
            'first_timestamp':g.timestamp.min(),'last_timestamp':g.timestamp.max(),
            'verified_independent_campaigns':'UNKNOWN','independence_evidence':'continuous/rotated recordings; independent reset ledger absent'})
    pd.DataFrame(cds).to_csv(E/'recovered_request_campaign_summary.csv',index=False)
    print(json.dumps({'raw':{k:v for k,v in m.items() if k not in ['file_reports','hmi_prefix_supplement']},'labels':summary},indent=2,default=str))


if __name__=='__main__':main()
