"""No inferred campaigns, label-driven row moves, or random row splitting."""
from pathlib import Path
import pandas as pd


def apply_manifest(transactions, manifest):
    """Manifest: segment_id, independence_group, partition, evidence.

    The human-supplied evidence must establish campaign/recording independence.
    Every segment of the same source recording, related mirrored recordings,
    and related replay episodes must share one independence_group.
    """
    m=pd.read_csv(manifest) if isinstance(manifest,(str,Path)) else manifest.copy()
    needed={'segment_id','independence_group','partition','evidence'}
    if not needed.issubset(m): raise ValueError(f'Manifest requires {sorted(needed)}')
    if m.empty or m[list(needed)].isna().any().any(): raise ValueError('Empty/incomplete independence manifest')
    if m.segment_id.duplicated().any(): raise ValueError('A segment has multiple assignments')
    if not m.partition.isin(['train','validation','test']).all(): raise ValueError('Use train/validation/test only')
    if m.evidence.astype(str).str.strip().eq('').any(): raise ValueError('Missing independence evidence')
    if m.independence_group.astype(str).str.strip().eq('').any(): raise ValueError('Missing independence group')
    if m.groupby('independence_group').partition.nunique().gt(1).any():
        raise ValueError('Related groups cross partitions')
    if set(m.segment_id)!=set(transactions.segment_id): raise ValueError('Manifest must cover exactly all observed segments')
    result=transactions.drop(columns=['partition','independence_group','evidence'],errors='ignore').merge(m,on='segment_id',validate='many_to_one')
    if result.transaction_id.duplicated().any(): raise ValueError('Repeated observation ID')
    # A known source filename cannot occur in multiple partitions, even if someone
    # has incorrectly assigned distinct independence_group strings to its segments.
    known=result[result.source_pcap.notna()]
    if known.groupby('source_pcap').partition.nunique().gt(1).any(): raise ValueError('Source recording crosses partitions')
    event=['request_timestamp','client_ip','server_ip','client_port','server_port',
           'mbtcp_trans_id','mbtcp_unit_id','modbus_func_code']
    if set(event).issubset(result) and result.groupby(event,dropna=False).partition.nunique().gt(1).any():
        raise ValueError('Same observed event crosses partitions (possible duplicate/mirror)')
    for part in ['train','validation','test']:
        labels=set(result.loc[result.partition.eq(part),'request_label_target'])
        if labels!={0,1}: raise ValueError(f'UNSUPPORTED: {part} must contain both verified classes (no row reassignment)')
    return result
