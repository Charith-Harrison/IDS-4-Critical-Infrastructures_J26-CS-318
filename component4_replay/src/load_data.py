"""Strict CSV ingestion. Provenance, missingness, and CSV order are preserved."""
from pathlib import Path
import hashlib
import numpy as np
import pandas as pd

REQUIRED = ['timestamp','frame_number','src_ip','dst_ip','src_port','dst_port',
            'is_request','mbtcp_trans_id','mbtcp_unit_id','modbus_func_code']
INTEGERS = ['frame_number','src_port','dst_port','is_request','mbtcp_trans_id',
            'mbtcp_unit_id','modbus_func_code']


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda: f.read(1024*1024), b''): h.update(b)
    return h.hexdigest()


def load_data(path, gap_seconds=100.):
    path = Path(path).resolve(strict=True)
    if gap_seconds <= 0: raise ValueError('gap_seconds must be positive')
    if path.suffix.lower() != '.csv':
        raise ValueError('Use a provenance-preserving, TCP-reassembled CSV export; raw PCAP parsing is outside this pipeline.')
    d = pd.read_csv(path)
    # Index exports are metadata, never inputs. Retain all real protocol columns.
    d = d.loc[:, ~d.columns.str.match(r'^Unnamed:')].copy()
    if not set(REQUIRED).issubset(d): raise ValueError(f'Missing fields: {sorted(set(REQUIRED)-set(d))}')
    for c in ['timestamp']+INTEGERS:
        d[c] = pd.to_numeric(d[c],errors='raise')
        if d[c].isna().any() or not np.isfinite(d[c]).all(): raise ValueError(f'Invalid {c}')
    for c in INTEGERS:
        if d[c].mod(1).ne(0).any(): raise ValueError(f'Noninteger {c}')
        d[c] = d[c].astype('int64')
    bounds = {'mbtcp_trans_id':(0,65535),'mbtcp_unit_id':(0,255),'modbus_func_code':(1,255),
              'src_port':(0,65535),'dst_port':(0,65535),'frame_number':(0,2**63-1),'is_request':(0,1)}
    for c,(lo,hi) in bounds.items():
        if not d[c].between(lo,hi).all(): raise ValueError(f'Out of range: {c}')
    for c in ['src_ip','dst_ip']:
        if d[c].isna().any() or d[c].astype(str).str.strip().eq('').any(): raise ValueError(f'Missing {c}')
    if 'is_attack' not in d: d['is_attack'] = -1
    d['is_attack'] = pd.to_numeric(d.is_attack,errors='raise')
    if not d.is_attack.isin([-1,0,1]).all(): raise ValueError('Labels must be -1 (unknown), 0, or 1; no automatic relabelling')
    checksum = digest(path)
    d['input_sha256'] = checksum
    d['input_csv'] = path.name
    d['source_row'] = np.arange(len(d))
    d['source_row_id'] = [f'{checksum}:{i}' for i in range(len(d))]
    # A source CSV is NOT a source PCAP. Missing PCAP provenance stays missing.
    d['source_pcap'] = d['file_source'] if 'file_source' in d else pd.NA
    src = d.source_pcap.fillna('UNKNOWN').astype(str)
    source_change = src.ne(src.shift())
    time_back = d.timestamp.diff().lt(0)
    frame_back = d.frame_number.diff().lt(0)
    gap = d.timestamp.diff().gt(gap_seconds)
    cuts = source_change | time_back | frame_back | gap
    d['segment_index'] = cuts.cumsum()-1
    d['segment_id'] = checksum+':segment:'+d.segment_index.astype(str)
    d['boundary_reason'] = [';'.join(k for k,v in [('source_change',a),('time_backward',b),('frame_reset',c),('gap_heuristic',e)] if v)
                            for a,b,c,e in zip(source_change,time_back,frame_back,gap)]
    d['provenance_status'] = np.where(d.source_pcap.notna(),'source_filename_only','unknown_source')
    req = d.is_request.eq(1)
    for target,a,b in [('client_ip','src_ip','dst_ip'),('server_ip','dst_ip','src_ip'),
                       ('client_port','src_port','dst_port'),('server_port','dst_port','src_port')]:
        d[target] = d[a].where(req,d[b])
    # Four-tuple reuse is not distinguishable without full TCP history. Explicitly
    # identify this scope as a proxy; do not invent tcp.stream or campaign IDs.
    keys = ['segment_id','client_ip','server_ip','client_port','server_port']
    # On observed SYN (without ACK), start a new lifetime; FIN/RST closes it.
    epochs = {}; sessions = []
    for row in d.to_dict('records'):
        key = tuple(row[c] for c in keys)
        epoch = epochs.get(key,0)
        if row.get('tcp_flags_syn',0)==1 and row.get('tcp_flags_ack',0)==0: epoch += 1
        sessions.append('|'.join(map(str,key))+f'|tcp_proxy:{epoch}')
        epochs[key] = epoch + int(row.get('tcp_flags_fin',0)==1 or row.get('tcp_flags_rst',0)==1)
    d['session_proxy_id'] = sessions
    return d
