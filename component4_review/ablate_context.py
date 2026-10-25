"""Fixed feature-group diagnostics; same limited historical split, no tuning."""
from pathlib import Path
import json
import sys
import pandas as pd
import xgboost as xgb
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from component4_replay.src.features import CURRENT,CONTEXT,extract_features
from component4_replay.src.evaluate import evaluate


def main():
    output=ROOT/'component4_review/evidence/retrospective_v1/feature_group_ablation.json'
    if output.exists(): raise FileExistsError('Ablation evidence already exists')
    tx=pd.read_csv(ROOT/'component4_replay/data/processed/audit_v2/transactions.csv.gz',low_memory=False)
    old=pd.read_csv(ROOT/'artifacts/results/extracted_features.csv')
    tx=tx.merge(old[['source_file','request_row','partition']],left_on=['input_csv','source_row'],
                right_on=['source_file','request_row'],validate='one_to_one')
    f=extract_features(tx); tr=f[f.partition.eq('train')]; te=f[f.partition.eq('test')]
    params=json.loads((output.parent/'diagnostics.json').read_text())['parameters']
    timing=[c for c in CONTEXT if 'iat' in c or c=='time_since_observed_command']
    tid_context=[c for c in CONTEXT if '_tid_' in c]
    variants={'timing_only':['endpoint_request_iat'],
              'current_plus_timing':CURRENT+timing,
              'C_without_timing':[c for c in CURRENT+CONTEXT if c not in timing],
              'C_without_tid_context':[c for c in CURRENT+CONTEXT if c not in tid_context]}
    result={'scope':'diagnostic feature ablation on SAME historical split, not independent evaluation','variants':{}}
    for name,cols in variants.items():
        m=xgb.XGBClassifier(**params); m.fit(tr[cols].to_numpy(dtype=float),tr.request_label_target.to_numpy())
        p=m.predict_proba(te[cols].to_numpy(dtype=float))[:,1]
        result['variants'][name]={'features':cols,'metrics':evaluate(te.request_label_target,p>=.5,p)}
        print(name,result['variants'][name]['metrics'],flush=True)
    with output.open('x',encoding='utf-8') as file: json.dump(result,file,indent=2,allow_nan=False)


if __name__=='__main__': main()
