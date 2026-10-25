"""Limited diagnostic refits on the HISTORICAL split, not independent evaluation.

No tuning, no final model, no historical writes. Every score is conditional on the
same inferred replay segment being present in train/test. Output directory must be new.
"""
from pathlib import Path
import argparse
import json
import sys
import numpy as np
import pandas as pd
import xgboost as xgb

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from component4_replay.src.features import CURRENT,CONTEXT,extract_features,rule_predictions
from component4_replay.src.evaluate import evaluate
from component4_replay.src.load_data import digest
from src.feature_engineering import MODEL_FEATURE_COLUMNS
from src.pcap_loader import parse_modbus_pdu


def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--out',default='component4_review/evidence/retrospective_v1')
    ap.add_argument('--prepared',default='component4_replay/data/processed/audit_v2'); args=ap.parse_args()
    out=ROOT/args.out
    if out.exists(): raise FileExistsError('Choose a new retrospective output directory')
    f=pd.read_csv(ROOT/'artifacts/results/extracted_features.csv')
    tr=f[f.partition.eq('train')]; te=f[f.partition.eq('test')]
    params=dict(random_state=42,n_estimators=100,max_depth=4,learning_rate=.1,
                subsample=.8,colsample_bytree=.8,eval_metric='logloss',n_jobs=1,tree_method='hist',
                scale_pos_weight=float(tr.target_is_attack.eq(0).sum()/tr.target_is_attack.eq(1).sum()))
    result={'scope':'DIAGNOSTIC ONLY: stored historical split; no independent campaign generalization',
            'parameters':params,'threshold':.5,'training_feature_csv_sha256':digest(ROOT/'artifacts/results/extracted_features.csv'),
            'trained_final_model':False,'models':{}}
    for name,cols in [('legacy_21_feature_refit',MODEL_FEATURE_COLUMNS),
                      ('legacy_response_latency_only',['response_latency']),
                      ('legacy_outstanding_only',['outstanding_requests'])]:
        m=xgb.XGBClassifier(**params); m.fit(tr[cols].to_numpy(),tr.target_is_attack.to_numpy())
        prob=m.predict_proba(te[cols].to_numpy())[:,1]
        result['models'][name]={'metrics':evaluate(te.target_is_attack,prob>=.5,prob),
                                'importance':dict(zip(cols,map(float,m.feature_importances_)))}
        print(name,result['models'][name]['metrics'],flush=True)
    saved=xgb.XGBClassifier(); saved.load_model(ROOT/'artifacts/models/xgboost_model.json')
    x=te[MODEL_FEATURE_COLUMNS].to_numpy(); y=te.target_is_attack.to_numpy()
    base=evaluate(y,saved.predict_proba(x)[:,1]>=.5)['F1']
    rng=np.random.default_rng(42); permutation={}
    for i,c in enumerate(MODEL_FEATURE_COLUMNS):
        altered=x.copy(); altered[:,i]=rng.permutation(altered[:,i])
        permutation[c]=base-evaluate(y,saved.predict_proba(altered)[:,1]>=.5)['F1']
    result['saved_model_test_F1_drop_one_permutation']=permutation
    result['permutation_scope']='One fixed-seed permutation per field, descriptive only; correlated features can mask attribution'
    tx=pd.read_csv(ROOT/args.prepared/'transactions.csv.gz')
    tx=tx.merge(f[['source_file','request_row','partition','target_is_attack']],
                left_on=['input_csv','source_row'],right_on=['source_file','request_row'],validate='one_to_one')
    if len(tx)!=len(f) or not tx.request_label_target.eq(tx.target_is_attack).all(): raise ValueError('Target mismatch')
    fresh=extract_features(tx)
    tr=fresh[fresh.partition.eq('train')]; te=fresh[fresh.partition.eq('test')]
    result['new_causal_diagnostics']={'train_support':tr.request_label_target.value_counts().to_dict(),
                                     'test_support':te.request_label_target.value_counts().to_dict(),
                                     'scope':'same OLD conditional train/test targets, partition-reset history; NOT an independent experiment',
                                     'A_rule':evaluate(te.request_label_target,rule_predictions(te))}
    for name,cols in [('B_current_request',CURRENT),('C_current_plus_causal_context',CURRENT+CONTEXT),
                      ('B_without_absolute_tid',[c for c in CURRENT if c!='mbtcp_trans_id']),
                      ('C_without_absolute_tid',[c for c in CURRENT+CONTEXT if c!='mbtcp_trans_id'])]:
        m=xgb.XGBClassifier(**params); m.fit(tr[cols].to_numpy(dtype=float),tr.request_label_target.to_numpy())
        prob=m.predict_proba(te[cols].to_numpy(dtype=float))[:,1]
        result['new_causal_diagnostics'][name]={'metrics':evaluate(te.request_label_target,prob>=.5,prob),
                                               'importance':dict(zip(cols,map(float,m.feature_importances_)))}
        print(name,result['new_causal_diagnostics'][name]['metrics'],flush=True)
    # Nonzero true read data is ignored by the historical scalar parser. This
    # tiny synthetic check requires no PCAP extraction and no actual process claim.
    result['synthetic_read_response_nonzero_data']={'pdu_hex':'03021234',
                    'returned_parser_tuple':parse_modbus_pdu(bytes.fromhex('03021234'),0),
                    'expected_payload_register_value':4660,
                    'interpretation':'parser scalar is zero despite nonzero process data; original CSV producer absent'}
    out.mkdir(parents=True,exist_ok=False)
    (out/'diagnostics.json').write_text(json.dumps(result,indent=2,allow_nan=False),encoding='utf-8')
    print('Saved',out/'diagnostics.json')


if __name__=='__main__': main()
