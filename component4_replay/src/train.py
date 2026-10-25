"""Fair A/B/C comparison, enabled only with an explicit independence manifest."""
import argparse
import json
import platform
from pathlib import Path
import numpy as np
import pandas as pd
import xgboost as xgb
from .load_data import digest
from .split import apply_manifest
from .features import CURRENT, CONTEXT, SCHEMA_VERSION, extract_features, rule_predictions
from .evaluate import evaluate


def train(prepared, manifest, out):
    prepared=Path(prepared); out=Path(out)
    if out.exists(): raise FileExistsError(f'Choose a NEW output directory: {out}')
    meta=json.loads((prepared/'metadata.json').read_text(encoding='utf-8'))
    if meta['schema_version']!=SCHEMA_VERSION: raise ValueError('Prepared schema version mismatch')
    for name,checksum in meta['outputs'].items():
        if digest(prepared/name)!=checksum: raise ValueError(f'Prepared file changed: {name}')
    tx=apply_manifest(pd.read_csv(prepared/'transactions.csv.gz',low_memory=False),manifest)
    cfg=meta['config']
    f=extract_features(tx,cfg['history_size'],cfg['window_seconds'])
    # Identical target rows and partitions, models, weights, threshold, and missing
    # value handling for B and C. XGBoost handles missing numeric values natively.
    tr=f[f.partition.eq('train')]; val=f[f.partition.eq('validation')]; te=f[f.partition.eq('test')]
    y=tr.request_label_target.astype(int)
    params={**cfg['model'],'scale_pos_weight':float(y.eq(0).sum()/y.eq(1).sum())}
    results={'scope':'group-held-out; independence depends on supplied evidence',
             'schema_version':SCHEMA_VERSION,'decision_point':'request_arrival',
             'threshold':cfg['probability_threshold'],'config':cfg,'model_params':params,
             'input_metadata_sha256':digest(prepared/'metadata.json'),'manifest_sha256':digest(manifest),
             'training_source_sha256':digest(__file__),
             'python':platform.python_version(),'numpy':np.__version__,'pandas':pd.__version__,'xgboost':xgb.__version__,
             'partition_support':{p:g.request_label_target.value_counts().to_dict() for p,g in f.groupby('partition')},
             'comparisons':{}}
    models={}; predictions=te[['transaction_id','request_label_target','partition','independence_group']].copy()
    for name,cols in [('B_current_message',CURRENT),('C_transaction_context',CURRENT+CONTEXT)]:
        model=xgb.XGBClassifier(**params)
        model.fit(tr[cols].to_numpy(dtype=float),y.to_numpy())
        pv=model.predict_proba(val[cols].to_numpy(dtype=float))[:,1]
        pt=model.predict_proba(te[cols].to_numpy(dtype=float))[:,1]
        threshold=cfg['probability_threshold']
        results['comparisons'][name]={'validation':evaluate(val.request_label_target,pv>=threshold,pv),
                                      'test':evaluate(te.request_label_target,pt>=threshold,pt),
                                      'feature_order':cols,'importance':dict(zip(cols,map(float,model.feature_importances_)))}
        predictions[name+'_probability']=pt
        predictions[name+'_prediction']=(pt>=threshold).astype(int)
        models[name]=model
    rule=rule_predictions(te)
    results['comparisons']['A_recent_observed_command_and_tid_rule']={'test':evaluate(te.request_label_target,rule)}
    predictions['A_rule_prediction']=rule.to_numpy()
    out.mkdir(parents=True,exist_ok=False)
    for name,model in models.items(): model.save_model(out/(name+'.json'))
    tx[['transaction_id','segment_id','independence_group','partition','evidence']].to_csv(out/'split_manifest.csv',index=False)
    predictions.to_csv(out/'test_predictions.csv',index=False)
    (out/'experiment.json').write_text(json.dumps(results,indent=2,allow_nan=False),encoding='utf-8')
    return results


def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('--prepared',required=True)
    ap.add_argument('--manifest',required=True,help='Verified independent recording/campaign grouping; never inferred from labels')
    ap.add_argument('--out',required=True); args=ap.parse_args()
    print(json.dumps(train(args.prepared,args.manifest,args.out),indent=2))


if __name__=='__main__': main()
