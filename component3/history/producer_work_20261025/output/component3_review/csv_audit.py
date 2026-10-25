"""Read-only source CSV audit. Outputs JSON only; never modifies inputs."""
from pathlib import Path
import json, hashlib
import pandas as pd
import numpy as np

OUT = Path(__file__).parent
SOURCES = [Path('C:/Users/Thithira/Downloads/normal_traffic_baseline.csv'), Path('C:/Users/Thithira/Downloads/command_response_injection_attacks.csv')]

def norm(x):
    if isinstance(x, dict): return {str(k): norm(v) for k,v in x.items()}
    if isinstance(x, (list, tuple)): return [norm(v) for v in x]
    if isinstance(x, np.generic): return x.item()
    if pd.isna(x): return None
    return x

def counts(s, n=50):
    return {str(k): int(v) for k,v in s.value_counts(dropna=False).head(n).items()}

def audit(p):
    df = pd.read_csv(p)
    stats = {'path':str(p), 'bytes':p.stat().st_size, 'sha256':hashlib.sha256(p.read_bytes()).hexdigest(), 'rows':len(df), 'columns':list(df.columns), 'column_count':len(df.columns), 'dtypes':{c:str(t) for c,t in df.dtypes.items()}, 'nulls':df.isna().sum().to_dict(), 'nunique':df.nunique(dropna=False).to_dict()}
    stats['constant_columns'] = {c:norm(df[c].iloc[0]) for c in df if df[c].nunique(dropna=False)==1}
    stats['exact_duplicate_rows'] = int(df.duplicated().sum())
    ignore = [c for c in ['frame_number','timestamp','inter_arrival_time','packet_rate_1s','response_time','trans_id_diff','file_source'] if c in df]
    stats['duplicates_ignoring_time_frame_provenance'] = int(df.drop(columns=ignore).duplicated().sum())
    stats['value_counts'] = {c:counts(df[c]) for c in ['is_attack','attack_sub_type','attack_category','is_request','src_ip','dst_ip','src_port','dst_port','modbus_func_code','is_exception','modbus_exception_code','mbtcp_proto_id','mbtcp_unit_id','modbus_ref_num','modbus_word_cnt','modbus_bit_cnt','modbus_byte_cnt','modbus_val','len_discrepancy','has_stacked_frames','tcp_flags_syn','tcp_flags_ack','tcp_flags_fin','tcp_flags_rst','tcp_flags_psh','file_source'] if c in df}
    stats['numeric_summary'] = df.select_dtypes('number').describe(percentiles=[.01,.5,.95,.99]).to_dict()
    stats['timestamp'] = {'min':df.timestamp.min(), 'max':df.timestamp.max(), 'min_utc':pd.to_datetime(df.timestamp.min(),unit='s',utc=True).isoformat(),'max_utc':pd.to_datetime(df.timestamp.max(),unit='s',utc=True).isoformat(), 'decreases_in_file_order':int((df.timestamp.diff()<0).sum()), 'equal_adjacent':int((df.timestamp.diff()==0).sum()), 'unique':int(df.timestamp.nunique())}
    stats['frame_number_decreases_in_file_order'] = int((df.frame_number.diff()<0).sum())
    stats['crosstabs'] = {c:pd.crosstab(df[c],df.is_attack,dropna=False).to_dict() for c in ['attack_sub_type','attack_category','modbus_func_code','is_request','src_ip','dst_ip','modbus_ref_num','modbus_val','file_source'] if c in df}
    stats['label_combinations'] = df.groupby(['attack_sub_type','is_attack','attack_category'],dropna=False).size().reset_index(name='count').to_dict('records')
    stats['sample_rows'] = df.head(5).to_dict('records')+df.tail(5).to_dict('records')
    stats['samples_by_subtype'] = {str(k):g.head(3).to_dict('records') for k,g in df.groupby('attack_sub_type',dropna=False)}
    # Port-based direction is only a consistency diagnostic, not a proof of true role.
    stats['direction_consistency'] = {'request_dst_port_not_502':int(((df.is_request==1)&(df.dst_port!=502)).sum()), 'response_src_port_not_502':int(((df.is_request==0)&(df.src_port!=502)).sum()), 'both_ports_502':int(((df.src_port==502)&(df.dst_port==502)).sum()), 'neither_port_502':int(((df.src_port!=502)&(df.dst_port!=502)).sum())}
    df['_client_ip'] = np.where(df.is_request==1,df.src_ip,df.dst_ip)
    df['_server_ip'] = np.where(df.is_request==1,df.dst_ip,df.src_ip)
    df['_client_port'] = np.where(df.is_request==1,df.src_port,df.dst_port)
    df['_server_port'] = np.where(df.is_request==1,df.dst_port,df.src_port)
    conn = ['_client_ip','_server_ip','_client_port','_server_port']
    stats['connections'] = {'distinct_normalized_four_tuples':int(df[conn].drop_duplicates().shape[0]),'by_direction_and_label':df.groupby(['is_request','is_attack']).size().to_dict()}
    # Candidate matching only: no tcp.stream/session generation exists and trans IDs can repeat.
    key = conn + ['mbtcp_unit_id','mbtcp_trans_id']
    if 'file_source' in df: key = ['file_source']+key
    groups = df.groupby(key,dropna=False)['is_request'].agg(['count','sum'])
    groups['responses'] = groups['count']-groups['sum']
    stats['candidate_transaction_groups'] = {'total':len(groups),'one_request_one_response':int(((groups['sum']==1)&(groups.responses==1)).sum()),'request_only':int(((groups['sum']>0)&(groups.responses==0)).sum()),'response_only':int(((groups['sum']==0)&(groups.responses>0)).sum()),'multiple_requests_or_responses':int(((groups['sum']>1)|(groups.responses>1)).sum()),'row_count_in_one_request_one_response_groups':int(groups.loc[(groups['sum']==1)&(groups.responses==1),'count'].sum())}
    valid_idx = groups[(groups['sum']==1)&(groups.responses==1)].reset_index()[key]
    pairs = df.merge(valid_idx,on=key,how='inner')
    req=pairs[pairs.is_request==1][key+['timestamp','modbus_func_code','modbus_ref_num','modbus_word_cnt','modbus_bit_cnt','modbus_val','is_attack']]
    resp=pairs[pairs.is_request==0][key+['timestamp','modbus_func_code','response_time','is_attack']]
    matches = req.merge(resp,on=key,suffixes=('_request','_response'))
    dt=matches.timestamp_response-matches.timestamp_request
    stats['candidate_pairs']={'count':len(matches),'response_before_request':int((dt<0).sum()),'same_function_code':int((matches.modbus_func_code_request==matches.modbus_func_code_response).sum()),'request_response_label_disagreement':int((matches.is_attack_request!=matches.is_attack_response).sum()),'delta_seconds_summary':dt.describe(percentiles=[.5,.95,.99]).to_dict(),'recorded_response_time_matches_delta_tolerance_1us':int(((matches.response_time-dt).abs()<1e-6).sum())}
    stats['interarrival_vs_file_adjacent_delta']={'matches_tolerance_1us':int(((df.timestamp.diff()-df.inter_arrival_time).abs()<1e-6).sum()),'eligible':len(df)-1}
    if 'file_source' in df:
        stats['by_file_source'] = df.groupby('file_source').agg(rows=('timestamp','size'),timestamp_min=('timestamp','min'),timestamp_max=('timestamp','max'),requests=('is_request','sum'),attacks=('is_attack','sum')).reset_index().to_dict('records')
    stats['by_subtype'] = df.groupby('attack_sub_type').agg(rows=('timestamp','size'),timestamp_min=('timestamp','min'),timestamp_max=('timestamp','max'),requests=('is_request','sum'),attacks=('is_attack','sum')).reset_index().to_dict('records')
    return df.drop(columns=[c for c in df if c.startswith('_')]), stats

dfs=[]; results=[]
for source in SOURCES:
    d,r=audit(source); dfs.append(d); results.append(r)
common=[c for c in dfs[0] if c in dfs[1]]
hashes=[pd.util.hash_pandas_object(d[common],index=False) for d in dfs]
overlap=set(hashes[0])&set(hashes[1])
combined=pd.concat([d.assign(_dataset=i) for i,d in enumerate(dfs)],ignore_index=True)
features=[c for c in common if c not in ['attack_sub_type','is_attack','attack_category']]
feature_hashes=pd.util.hash_pandas_object(combined[features],index=False)
label_sets=combined.groupby(feature_hashes)['is_attack'].nunique()
cross={'schema_only_in_baseline':sorted(set(dfs[0])-set(dfs[1])),'schema_only_in_attacks':sorted(set(dfs[1])-set(dfs[0])),'exact_common_schema_shared_unique_rows':len(overlap),'baseline_rows_shared':int(hashes[0].isin(overlap).sum()),'attack_rows_shared':int(hashes[1].isin(overlap).sum()),'conflicting_is_attack_groups_identical_all_nonlabel_common_columns':int((label_sets>1).sum())}
result=norm({'sources':results,'cross_file':cross})
OUT.mkdir(parents=True,exist_ok=True)
(OUT/'csv_audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({'sources':[{k:r[k] for k in ['path','rows','column_count','constant_columns','exact_duplicate_rows','timestamp','candidate_transaction_groups','candidate_pairs','direction_consistency','label_combinations']} for r in result['sources']],'cross_file':cross},indent=2))
