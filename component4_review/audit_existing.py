"""Read-only audit of historical files. Writes only to a NEW output directory.

Run with the repository .venv Python: python component4_review/audit_existing.py
"""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
import sys
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
GIT = Path.home() / '.cache/codex-runtimes/codex-primary-runtime/dependencies/native/git/cmd/git.exe'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def counts(s):
    return {str(k): int(v) for k, v in s.value_counts(dropna=False).items()}


def stats(s):
    s = pd.to_numeric(s, errors='coerce')
    return {'null': int(s.isna().sum()), 'unique': int(s.nunique()),
            'negative': int(s.lt(0).sum()), 'zero': int(s.eq(0).sum()),
            'quantiles': {str(k): float(v) for k, v in s.quantile([0, .01, .5, .95, .99, 1]).items()}}


def metric(y, pred):
    y, pred = np.asarray(y), np.asarray(pred).astype(bool)
    tp, fp = int(((y == 1) & pred).sum()), int(((y == 0) & pred).sum())
    tn, fn = int(((y == 0) & ~pred).sum()), int(((y == 1) & ~pred).sum())
    div = lambda a, b: a / b if b else 0.
    p, r = div(tp, tp + fp), div(tp, tp + fn)
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, precision=p, recall=r,
                F1=div(2*p*r, p+r), false_positive_rate=div(fp, fp+tn),
                accuracy=div(tp+tn, len(y)), balanced_accuracy=(r+div(tn,tn+fp))/2)


def annotate(d):
    """Observed discontinuities only, NEVER PCAP/campaign identities."""
    d = d.copy()
    if 'file_source' in d:
        source = d.file_source.fillna('UNKNOWN').astype(str)
    else:
        source = pd.Series('UNKNOWN', index=d.index)
    cut = source.ne(source.shift()) | d.timestamp.diff().lt(0) | d.frame_number.diff().lt(0) | d.timestamp.diff().gt(100)
    d['observed_segment'] = cut.cumsum()
    req = d.is_request.eq(1)
    d['client_ip'] = d.src_ip.where(req, d.dst_ip)
    d['server_ip'] = d.dst_ip.where(req, d.src_ip)
    d['client_port'] = d.src_port.where(req, d.dst_port)
    d['server_port'] = d.dst_port.where(req, d.src_port)
    return d


def profile(d, path):
    result = dict(rows=len(d), columns=list(d.columns), dtypes={c: str(v) for c,v in d.dtypes.items()},
                  nulls={c:int(v) for c,v in d.isna().sum().items()}, exact_duplicate_rows=int(d.duplicated().sum()))
    for target in ['is_attack', 'target_is_attack', 'transaction_is_attack', 'request_is_attack']:
        if target in d:
            result[target] = counts(d[target])
            result[target+'_percent'] = {k:100*v/len(d) for k,v in result[target].items()}
    for c in ['mbtcp_trans_id', 'response_time', 'trans_id_diff', 'request_iat', 'response_latency', 'outstanding_requests']:
        if c in d:
            result[c] = stats(d[c])
    for c in ['file_source','capture_id','source_file','src_ip','dst_ip','src_port','dst_port',
              'modbus_func_code','is_request','modbus_ref_num','modbus_word_cnt','modbus_bit_cnt',
              'modbus_byte_cnt','modbus_val','payload_len','frame_len','mbtcp_len','is_exception',
              'mbtcp_proto_id','len_discrepancy','has_stacked_frames','partition','match_status']:
        if c in d:
            vc = counts(d[c])
            result[c+'_counts'] = vc if len(vc) <= 100 else {'distinct':len(vc), 'top_30':dict(list(vc.items())[:30])}
    ts = next((c for c in ['timestamp','request_timestamp'] if c in d), None)
    if ts:
        result['timestamp'] = stats(d[ts])
        result['timestamp']['backward_steps'] = int(d[ts].diff().lt(0).sum())
        result['timestamp']['equal_adjacent'] = int(d[ts].diff().eq(0).sum())
        # Preserve textual precision independently of binary float representation.
        text_ts = pd.read_csv(path, usecols=[ts], dtype=str)[ts]
        result['timestamp']['decimal_digits'] = counts(text_ts.str.partition('.')[2].str.len())
    if 'frame_number' in d:
        result['frame_resets'] = d.index[d.frame_number.diff().lt(0)].tolist()
    if {'src_ip','dst_ip'}.issubset(d):
        result['endpoint_pairs'] = counts(d.src_ip.astype(str)+' -> '+d.dst_ip.astype(str))
    result['payload_columns'] = [c for c in d if any(w in c.lower() for w in ['payload','hash','byte','val','stack'])]
    if {'timestamp','frame_number','is_request'}.issubset(d):
        a = annotate(d)
        result['observed_segments'] = a.groupby('observed_segment').agg(
            rows=('is_attack','size'), positives=('is_attack','sum'),
            start=('timestamp','min'), end=('timestamp','max'),
            frame_start=('frame_number','first'),frame_end=('frame_number','last')).reset_index().to_dict('records')
        reads = d[d.is_request.eq(0)&d.modbus_func_code.isin([1,2,3,4])]
        result['read_response_values'] = dict(rows=len(reads), values=counts(reads.modbus_val))
    return result


def tid_audit(d):
    d = annotate(d)
    variants = {'global_csv_order':d.mbtcp_trans_id.diff(),
                'within_observed_segment':d.groupby('observed_segment').mbtcp_trans_id.diff(),
                'directed_ip_pair':d.groupby(['observed_segment','src_ip','dst_ip']).mbtcp_trans_id.diff(),
                'directed_4tuple':d.groupby(['observed_segment','src_ip','dst_ip','src_port','dst_port']).mbtcp_trans_id.diff(),
                'bidirectional_4tuple_proxy':d.groupby(['observed_segment','client_ip','server_ip','client_port','server_port']).mbtcp_trans_id.diff()}
    q = d[d.is_request.eq(1)]
    variants['request_only_ip_pair'] = q.groupby(['observed_segment','client_ip','server_ip','mbtcp_unit_id']).mbtcp_trans_id.diff().reindex(d.index)
    variants['request_only_4tuple_proxy'] = q.groupby(['observed_segment','client_ip','server_ip','client_port','server_port','mbtcp_unit_id']).mbtcp_trans_id.diff().reindex(d.index)
    result = {}
    for name,v in variants.items():
        mask=v.notna()
        result[name] = dict(comparable_rows=int(mask.sum()), stored_equal=int(v[mask].eq(d.loc[mask,'trans_id_diff']).sum()),
                            negative=int(v.lt(0).sum()), zero=int(v.eq(0).sum()), first_or_missing=int(v.isna().sum()))
    # A CSV can omit intermediate source rows; test whether each stored diff implies
    # a previous TID that occurs among ANY source rows already retained in this CSV.
    prev=d.mbtcp_trans_id-d.trans_id_diff
    result['implied_previous_tid_in_csv_range'] = int(prev.between(0,65535).sum())
    result['tcp_connection_identity'] = 'UNAVAILABLE: no tcp.stream/sequence/handshake history; 4-tuple is a proxy only'
    return result


def diagnostics(n,r):
    result={}
    for name,d in [('derivative',r),('full_normal_plus_replay_positives',pd.concat([n,r[r.is_attack.eq(1)]],ignore_index=True))]:
        # Frozen descriptive rules, no tuning or generalization claims.
        sig=['src_ip','dst_ip','src_port','dst_port','is_request','mbtcp_trans_id','mbtcp_unit_id',
             'modbus_func_code','modbus_ref_num','modbus_word_cnt','modbus_bit_cnt','modbus_val','payload_len']
        rules={'stored_tid_negative':d.trans_id_diff.lt(0),'stored_tid_zero':d.trans_id_diff.eq(0),
               'stored_tid_abs_gt_1000':d.trans_id_diff.abs().gt(1000),
               'earlier_observed_signature_in_table':d.duplicated(sig),
               'request_direction':d.is_request.eq(1),'function_3':d.modbus_func_code.eq(3),
               'frame_length_78':d.frame_len.eq(78),'response_time_zero':d.response_time.eq(0),
               'iat_gt_1_second':d.inter_arrival_time.gt(1)}
        result[name]={k:metric(d.is_attack,v) for k,v in rules.items()}
        # In-sample prevalence of each single categorical value: artifact probe ONLY.
        result[name]['single_field_in_sample_majority']={}
        for c in ['src_ip','dst_ip','modbus_func_code','is_request','frame_len','payload_len','modbus_ref_num']:
            pred=d[c].map(d.groupby(c).is_attack.mean()).gt(.5)
            result[name]['single_field_in_sample_majority'][c]=metric(d.is_attack,pred)
    return result


def overlap(n,r):
    a=r[r.is_attack.eq(1)]
    normal=pd.concat([n,r[r.is_attack.eq(0)]],ignore_index=True)
    base=['is_request','mbtcp_proto_id','mbtcp_unit_id','modbus_func_code','modbus_ref_num','modbus_word_cnt',
          'modbus_bit_cnt','modbus_byte_cnt','modbus_val','mbtcp_len','payload_len','frame_len','is_exception','modbus_exception_code']
    out={}
    for name,cols in [('current_message',base),('command_semantics',base[:9]),('current_plus_tid',base+['mbtcp_trans_id'])]:
        pool=set(normal[cols].itertuples(index=False,name=None))
        matches=a[cols].apply(tuple,axis=1).isin(pool)
        out[name]={'columns':cols,'replay_rows_matching_normal':int(matches.sum()),'replay_rows':len(a),'fraction':float(matches.mean()),
                   'unique_positive_signatures':int(a[cols].drop_duplicates().shape[0])}
    out['unique_positive_request_command_signatures']=int(a[a.is_request.eq(1)][base[:9]].drop_duplicates().shape[0])
    out['positive_structure']={c:counts(a[c]) for c in ['is_request','modbus_func_code','mbtcp_proto_id','is_exception','len_discrepancy','has_stacked_frames','mbtcp_len','payload_len']}
    return out


def saved_results():
    f=pd.read_csv(ROOT/'artifacts/results/extracted_features.csv')
    p=pd.read_csv(ROOT/'artifacts/predictions/test_predictions.csv')
    out={'saved_prediction_metrics':metric(p.target_is_attack,p.xgb_pred),
         'saved_rule_metrics':metric(p.target_is_attack,p.rule_pred),
         'train_test_capture_overlap':sorted(set(f[f.partition.eq('train')].capture_id)&set(f[f.partition.eq('test')].capture_id)),
         'partition_by_capture':f.groupby(['partition','capture_id','target_is_attack']).size().rename('rows').reset_index().to_dict('records'),
         'unique_transaction_ids':int(f.transaction_id.nunique()),
         'label_conflict_by_class':f.groupby('target_is_attack').label_conflict.sum().to_dict()}
    from sklearn.metrics import roc_auc_score, average_precision_score
    out['saved_prediction_metrics']['ROC_AUC_rounded_probabilities']=roc_auc_score(p.target_is_attack,p.replay_probability)
    out['saved_prediction_metrics']['PR_AUC_average_precision_rounded_probabilities']=average_precision_score(p.target_is_attack,p.replay_probability)
    # Replay legacy pipeline from source IN MEMORY; do not modify historical outputs.
    sys.path.insert(0,str(ROOT))
    from src.data_loader import load_datasets
    from src.transaction_context import reconstruct_transactions
    from src.feature_engineering import extract_features
    n,r,summary=load_datasets('data/raw/normal_traffic_baseline.csv','data/raw/replay_attacks.csv',base_dir=str(ROOT))
    tx,orph,coverage=reconstruct_transactions(n,r)
    out['reconstructed_legacy_coverage']=coverage
    oldtx=pd.read_csv(ROOT/'artifacts/audits/reconstructed_transactions.csv')
    out['legacy_reconstruction_count_matches']=len(tx)==len(oldtx)
    # Reuse STORED manifest to prevent a later split fix changing the retrospective experiment.
    manifest=pd.read_csv(ROOT/'artifacts/splits/split_manifest.csv')
    tx=tx.merge(manifest[['transaction_id','partition']],on='transaction_id',how='left',validate='one_to_one')
    fresh,_=extract_features(tx,trailing_time_window_seconds=60)
    from src.feature_engineering import MODEL_FEATURE_COLUMNS
    aligned=fresh.set_index('transaction_id').reindex(f.transaction_id)
    out['feature_reproduction_max_abs_difference']={c:float(np.nanmax(np.abs(aligned[c].to_numpy()-f[c].to_numpy()))) for c in MODEL_FEATURE_COLUMNS}
    import xgboost as xgb
    model=xgb.XGBClassifier(); model.load_model(ROOT/'artifacts/models/xgboost_model.json')
    test=f[f.partition.eq('test')]
    prob=model.predict_proba(test[MODEL_FEATURE_COLUMNS].to_numpy())[:,1]
    out['saved_model_direct_metrics']=metric(test.target_is_attack,prob>=.5)
    out['saved_model_prediction_agreement']=float(np.mean((prob>=.5)==p.xgb_pred.to_numpy()))
    out['ROC_AUC']=float(roc_auc_score(test.target_is_attack,prob))
    out['PR_AUC_average_precision']=float(average_precision_score(test.target_is_attack,prob))
    out['libraries']={m:__import__(m).__version__ for m in ['pandas','numpy','sklearn','xgboost']}
    out['model_configuration']=json.loads(model.get_booster().save_config())
    out['outstanding_by_class']={str(y):stats(g.outstanding_requests) for y,g in f.groupby('target_is_attack')}
    out['latency_by_class']={str(y):stats(g.response_latency) for y,g in f.groupby('target_is_attack')}
    return out


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',default='component4_review/evidence/audit_v1'); args=ap.parse_args()
    out=ROOT/args.out; out.mkdir(parents=True,exist_ok=False)
    inventory=[]; profiles={}; cache={}
    for p in sorted(ROOT.rglob('*')):
        rel=p.relative_to(ROOT)
        if any(part in {'.git','.venv','__pycache__','component4_review','component4_replay'} for part in rel.parts) or not p.is_file(): continue
        digest=sha(p)
        inventory.append(dict(path=rel.as_posix(),size=p.stat().st_size,sha256=digest))
        if p.suffix.lower()=='.csv':
            if digest not in cache: cache[digest]=profile(pd.read_csv(p),p)
            profiles[rel.as_posix()]={'sha256':digest,**cache[digest]}
    n=pd.read_csv(ROOT/'normal_traffic_baseline.csv'); r=pd.read_csv(ROOT/'replay_attacks.csv')
    evidence=dict(inventory=inventory,datasets=profiles,tid=dict(normal=tid_audit(n),replay=tid_audit(r)),
                  diagnostics=diagnostics(n,r),overlap=overlap(n,r),saved_results=saved_results())
    (out/'audit.json').write_text(json.dumps(evidence,indent=2,default=lambda x: int(x) if isinstance(x,np.integer) else str(x),allow_nan=False),encoding='utf-8')
    print(json.dumps({k:evidence[k] for k in ['tid','diagnostics','overlap']},indent=2))
    print('Saved',out/'audit.json')


if __name__=='__main__': main()
