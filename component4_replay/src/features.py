"""Request-arrival features: current fields plus strictly earlier request history.

No current response outcome, future timeout, label, source, or IP is an input.
Session = observed 4-tuple proxy, not a verified TCP connection.
Endpoint history crosses ports explicitly and is NOT called a TCP-session feature.
"""
from collections import deque
import numpy as np
import pandas as pd

SCHEMA_VERSION = 'c4-request-arrival-v1'
CURRENT = ['mbtcp_trans_id','mbtcp_unit_id','modbus_func_code','modbus_ref_num',
           'modbus_word_cnt','modbus_bit_cnt','modbus_byte_cnt','modbus_val',
           'frame_len','payload_len','mbtcp_len','mbtcp_proto_id','is_exception',
           'modbus_exception_code','len_discrepancy','has_stacked_frames',
           'tcp_flags_syn','tcp_flags_ack','tcp_flags_fin','tcp_flags_rst','tcp_flags_psh']
CONTEXT = ['session_tid_diff','session_tid_delta_mod65536','session_history_available',
           'session_tid_seen_recently','session_request_iat','endpoint_tid_diff',
           'endpoint_tid_delta_mod65536','endpoint_history_available','endpoint_request_iat',
           'endpoint_tid_seen_recently','observed_command_seen_recently',
           'time_since_observed_command','observed_command_count_window']
COMMAND = ['mbtcp_unit_id','modbus_func_code','modbus_ref_num','modbus_word_cnt','modbus_bit_cnt','modbus_val']


def extract_features(transactions, history_size=100, window_seconds=60.):
    if history_size<=0 or window_seconds<=0: raise ValueError('Positive history bounds required')
    if transactions.empty: return pd.DataFrame(columns=['transaction_id','request_label_target']+CURRENT+CONTEXT)
    out = transactions.copy()
    if 'partition' not in out: out['partition']='unassigned'
    for c in CURRENT:
        if c not in out: out[c]=np.nan
        out[c]=pd.to_numeric(out[c],errors='raise')
    records=[]
    for _,g in out.groupby(['partition','segment_id'],sort=False):
        sessions={}; endpoints={}
        for row in g.sort_values(['request_timestamp','source_row'],kind='stable').to_dict('records'):
            now=row['request_timestamp']; tid=row['mbtcp_trans_id']
            ep=(row['client_ip'],row['server_ip'],row['mbtcp_unit_id'])
            sk=row['session_proxy_id']
            for prefix,key,cache in [('session',sk,sessions),('endpoint',ep,endpoints)]:
                state=cache.setdefault(key,deque(maxlen=history_size))
                while state and now-state[0][0]>window_seconds: state.popleft()
                row[prefix+'_history_available']=int(bool(state))
                row[prefix+'_tid_diff']=tid-state[-1][1] if state else np.nan
                row[prefix+'_tid_delta_mod65536']=(tid-state[-1][1])%65536 if state else np.nan
                row[prefix+'_request_iat']=now-state[-1][0] if state else np.nan
                row[prefix+'_tid_seen_recently']=int(any(p[1]==tid for p in state))
                if prefix=='endpoint':
                    # Incomplete scalar fields support only an observed-command
                    # fingerprint. A missing field disables equality, not zero-fill.
                    command=tuple(row.get(c,np.nan) for c in COMMAND)
                    valid=not any(pd.isna(x) for x in command)
                    seen=[t for t,_,cmd in state if valid and cmd==command]
                    row['observed_command_seen_recently']=int(bool(seen))
                    row['time_since_observed_command']=now-seen[-1] if seen else np.nan
                    row['observed_command_count_window']=len(seen)
                    state.append((now,tid,command if valid else None))
                else: state.append((now,tid,None))
            records.append(row)
    return pd.DataFrame(records)


def rule_predictions(features):
    """Diagnostic consistency rule, NOT ground truth or proof of replay."""
    return (features.endpoint_tid_seen_recently.eq(1) & features.observed_command_seen_recently.eq(1)).astype(int)
