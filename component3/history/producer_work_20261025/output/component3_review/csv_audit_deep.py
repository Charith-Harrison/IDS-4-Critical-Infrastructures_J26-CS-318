from pathlib import Path
import json
import pandas as pd
import numpy as np

OUT=Path(__file__).parent
paths=[Path('C:/Users/Thithira/Downloads/normal_traffic_baseline.csv'),Path('C:/Users/Thithira/Downloads/command_response_injection_attacks.csv')]

def norm(x):
    if isinstance(x,dict):return {str(k):norm(v) for k,v in x.items()}
    if isinstance(x,(list,tuple)):return [norm(v) for v in x]
    if isinstance(x,np.generic):return x.item()
    if pd.isna(x):return None
    return x

results=[];dfs=[]
for path in paths:
    d=pd.read_csv(path);dfs.append(d)
    # Preserve CSV physical line for examples (header = line 1).
    d['_csv_line']=np.arange(2,len(d)+2)
    d['_timestamp_delta']=d.timestamp.diff()
    d['_normalized_client_ip']=np.where(d.is_request==1,d.src_ip,d.dst_ip)
    d['_normalized_server_ip']=np.where(d.is_request==1,d.dst_ip,d.src_ip)
    d['_normalized_client_port']=np.where(d.is_request==1,d.src_port,d.dst_port)
    d['_normalized_server_port']=np.where(d.is_request==1,d.dst_port,d.src_port)
    conn=['_normalized_client_ip','_normalized_server_ip','_normalized_client_port','_normalized_server_port']
    r={'path':str(path),'timestamp_integer_rows':int((d.timestamp%1==0).sum()),'frame_duplicate_rows_beyond_first':int(d.frame_number.duplicated().sum()),'zero_response_time_by_direction':d.groupby('is_request').response_time.agg(rows='size',zeros=lambda x:(x==0).sum(),minimum='min',maximum='max').reset_index().to_dict('records'),'interarrival_negatives':int((d.inter_arrival_time<0).sum()),'interarrival_max':d.inter_arrival_time.max(),'interarrival_zeros':int((d.inter_arrival_time==0).sum()),'func_direction_value_counts':d.groupby(['modbus_func_code','is_request','modbus_val']).size().reset_index(name='rows').to_dict('records'),'func_direction_ref_counts':d.groupby(['modbus_func_code','is_request','modbus_ref_num']).size().reset_index(name='rows').to_dict('records'),'exception_direction':d.groupby(['is_exception','is_request','modbus_func_code','attack_sub_type']).size().reset_index(name='rows').to_dict('records')}
    r['sequence_decrease_examples']=d.loc[d._timestamp_delta<0].to_dict('records')
    boundary=(d.file_source!=d.file_source.shift()) if 'file_source' in d else (d._timestamp_delta<0)|(d.frame_number.diff()<0)
    r['boundary_examples']=d.loc[boundary].head(30).to_dict('records')
    r['source_order'] = d.loc[boundary,['file_source','_csv_line']].to_dict('records') if 'file_source' in d else None
    r['largest_interarrival_examples']=d.nlargest(5,'inter_arrival_time').to_dict('records')
    r['read_request_examples']=d[(d.is_request==1)&d.modbus_func_code.isin([1,2,3,4])].head(3).to_dict('records')
    r['fc3_response_examples']=d[(d.is_request==0)&(d.modbus_func_code==3)].head(3).to_dict('records')
    r['fc3_responses_val_counts']=d.loc[(d.is_request==0)&(d.modbus_func_code==3),'modbus_val'].value_counts().to_dict()
    # Measure global predecessor versus predecessor on same endpoint conversation.
    # Files are independent scopes if known. This does not invent TCP stream boundaries.
    conn_scope=(['file_source'] if 'file_source' in d else [])+conn
    d['_conn_timestamp_delta']=d.groupby(conn_scope,sort=False).timestamp.diff()
    r['interarrival_delta_consistency']={'file_predecessor_matches_1us':int(((d.inter_arrival_time-d._timestamp_delta).abs()<1e-6).sum()),'connection_predecessor_eligible':int(d._conn_timestamp_delta.notna().sum()),'connection_predecessor_matches_1us':int(((d.inter_arrival_time-d._conn_timestamp_delta).abs()<1e-6).sum())}
    r['interleaved_interarrival_example']=d.loc[(d._conn_timestamp_delta>1)&((d.inter_arrival_time-d._timestamp_delta).abs()<1e-6)&((d.inter_arrival_time-d._conn_timestamp_delta).abs()>.5)].head(5).to_dict('records')
    r['by_subtype_function_direction']=d.groupby(['attack_sub_type','modbus_func_code','is_request']).size().reset_index(name='rows').to_dict('records')
    r['len_discrepancy_examples']=d[d.len_discrepancy!=0].head(5).to_dict('records')
    r['request_value_mirrors_quantity']={'read_request_rows':int(((d.is_request==1)&d.modbus_func_code.isin([1,2,3,4])).sum()),'read_request_val_equals_quantity':int(((d.is_request==1)&d.modbus_func_code.isin([1,2,3,4])&(d.modbus_val==np.where(d.modbus_func_code.isin([1,2]),d.modbus_bit_cnt,d.modbus_word_cnt))).sum()),'read_response_rows':int(((d.is_request==0)&d.modbus_func_code.isin([1,2,3,4])).sum()),'read_response_value_zero':int(((d.is_request==0)&d.modbus_func_code.isin([1,2,3,4])&(d.modbus_val==0)).sum())}
    results.append(r)

combined=pd.concat(dfs,ignore_index=True)
truth=combined.is_attack==1
pred=combined.modbus_func_code.isin([5,6])|(combined.len_discrepancy!=0)
tn=int((~truth&~pred).sum());fp=int((~truth&pred).sum());fn=int((truth&~pred).sum());tp=int((truth&pred).sum())
rule={'rule':'modbus_func_code in {5,6} OR len_discrepancy != 0','tp':tp,'tn':tn,'fp':fp,'fn':fn,'precision':tp/(tp+fp),'recall':tp/(tp+fn),'accuracy':(tp+tn)/len(combined),'false_positive_rate':fp/(fp+tn),'f1':2*tp/(2*tp+fp+fn),'warning':'Dataset conditional shortcut diagnostic only, not a validated intrusion detector; legitimate writes must exist and contextual false positives require evaluation.'}
result=norm({'sources':results,'shortcut_rule_on_combined_supplied_csvs':rule})
(OUT/'csv_audit_deep.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
