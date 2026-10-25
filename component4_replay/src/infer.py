"""Inference on prepared request-arrival features; batch history starts cold.

Use the same feature builder/config as training. This is offline batch inference,
not a TCP sensor or a state-preserving live stream API.
"""
import argparse
import json
import time
from pathlib import Path
import numpy as np
import pandas as pd
import xgboost as xgb
from .features import SCHEMA_VERSION


def infer(features, artifact_dir, comparison='C_transaction_context'):
    root=Path(artifact_dir)
    meta=json.loads((root/'experiment.json').read_text(encoding='utf-8'))
    if meta['schema_version']!=SCHEMA_VERSION or meta['decision_point']!='request_arrival': raise ValueError('Unsupported model/decision schema')
    cols=meta['comparisons'][comparison]['feature_order']
    if features.empty or not set(cols).issubset(features): raise ValueError('Nonempty compatible feature table required')
    # Features must have been constructed with the artifact's history/window
    # configuration; CLI verifies prepared metadata below.
    x=features[cols].to_numpy(dtype=float)
    if np.isinf(x).any(): raise ValueError('Infinite feature input')
    model=xgb.XGBClassifier(); model.load_model(root/(comparison+'.json'))
    start=time.perf_counter(); prob=model.predict_proba(x)[:,1]; elapsed=time.perf_counter()-start
    result=features[['transaction_id','request_timestamp','session_proxy_id']].copy()
    result['replay_probability']=prob
    result['prediction']=(prob>=meta['threshold']).astype(int)
    result['label']=np.where(result.prediction.eq(1),'Replay','Normal')
    result['schema_version']=SCHEMA_VERSION
    result['decision_point']='request_arrival'
    result['observed_command_seen_recently']=features.observed_command_seen_recently.to_numpy()
    result['endpoint_tid_seen_recently']=features.endpoint_tid_seen_recently.to_numpy()
    return result,{'batch_inference_seconds':elapsed,'amortized_inference_ms':elapsed*1000/len(features),
                   'operational_end_to_end_latency_ms':None,'note':'Excludes parsing, feature construction, scheduling and sensor delay'}


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--prepared',required=True); ap.add_argument('--artifacts',required=True)
    ap.add_argument('--out',required=True); args=ap.parse_args()
    prepared=Path(args.prepared)
    data_meta=json.loads((prepared/'metadata.json').read_text(encoding='utf-8'))
    model_meta=json.loads((Path(args.artifacts)/'experiment.json').read_text(encoding='utf-8'))
    for key in ['history_size','window_seconds','observed_boundary_gap_seconds','pair_timeout_seconds']:
        if data_meta['config'][key]!=model_meta['config'][key]: raise ValueError(f'Preparation config mismatch: {key}')
    if data_meta['schema_version']!=SCHEMA_VERSION: raise ValueError('Feature schema mismatch')
    from .load_data import digest
    source=prepared/'request_features.csv.gz'
    if digest(source)!=data_meta['outputs'][source.name]: raise ValueError('Prepared features changed')
    pred,timing=infer(pd.read_csv(source),args.artifacts)
    out=Path(args.out); out.mkdir(parents=True,exist_ok=False)
    pred.to_csv(out/'predictions.csv',index=False)
    (out/'timing.json').write_text(json.dumps(timing,indent=2),encoding='utf-8')


if __name__=='__main__': main()
