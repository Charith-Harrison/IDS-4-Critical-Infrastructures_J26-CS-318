from pathlib import Path
import pandas as pd
import numpy as np
import json

OUT=Path(__file__).parent
a=pd.read_csv('C:/Users/Thithira/Downloads/normal_traffic_baseline.csv')
b=pd.read_csv('C:/Users/Thithira/Downloads/command_response_injection_attacks.csv')
a['_line']=np.arange(2,len(a)+2);b['_line']=np.arange(2,len(b)+2)
packet_keys=['frame_number','frame_len','src_ip','dst_ip','src_port','dst_port','payload_len','is_request','mbtcp_trans_id','mbtcp_proto_id','mbtcp_len','mbtcp_unit_id','modbus_func_code','is_exception','modbus_exception_code','modbus_ref_num','modbus_word_cnt','modbus_bit_cnt','modbus_byte_cnt','modbus_val','len_discrepancy','has_stacked_frames']
r={}
for method in ['floor','round']:
    a['_sec']=np.floor(a.timestamp) if method=='floor' else np.round(a.timestamp)
    b['_sec']=b.timestamp
    key=packet_keys+['_sec']
    m=a.merge(b,on=key,how='inner',suffixes=('_baseline','_derivative'))
    r[method]={'joined_rows':len(m),'unique_baseline_rows':int(m._line_baseline.nunique()),'unique_derivative_rows':int(m._line_derivative.nunique()),'label_disagreements':int((m.is_attack_baseline!=m.is_attack_derivative).sum()),'by_baseline_source':m.file_source.value_counts().to_dict(),'examples':m.head(5).to_dict('records')}
    derived=['inter_arrival_time','packet_rate_1s','response_time','trans_id_diff']
    exact_derived=pd.Series(True,index=m.index)
    for col in derived: exact_derived &= (m[col+'_baseline']==m[col+'_derivative'])
    r[method]['all_derived_fields_exactly_equal']=int(exact_derived.sum())
    r[method]['all_derived_fields_equal_and_label_conflict']=int((exact_derived&(m.is_attack_baseline!=m.is_attack_derivative)).sum())
# Derived trans-id differences look globally capture-scoped in baseline.
globaldiff=a.mbtcp_trans_id.diff()
r['baseline_txid_diff_global_predecessor_matches']=int((a.trans_id_diff==globaldiff).sum())
r['baseline_txid_diff_eligible']=len(a)-1

(OUT/'csv_audit_overlap.json').write_text(json.dumps(r,indent=2),encoding='utf8')
print(json.dumps({k:({kk:vv for kk,vv in v.items() if kk!='examples'} if isinstance(v,dict) else v) for k,v in r.items()},indent=2))
