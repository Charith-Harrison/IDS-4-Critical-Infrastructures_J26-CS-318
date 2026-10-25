# Compare the active adapter with the original development implementation and measure inference time.
"""Development-only adapter equivalence, saved preprocessing and latency checks."""
import json
from pathlib import Path
import platform
import sys
import time
import hashlib

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from runtime import Detector,load_locked_models,LOCKED,VERSION

# Replay accepted development observations and compare adapter outputs and saved-model behavior.
def run(source,artifacts,output):
    import numpy as np
    import pandas as pd
    from c3model.experiment import METHODS,feature_frame
    source,artifacts,output=Path(source),Path(artifacts),Path(output)
    if output.exists(): raise ValueError('Choose a fresh result path')
    if output.resolve().is_relative_to(source.resolve()) or output.resolve().is_relative_to(LOCKED):
        raise ValueError('Output cannot alter preserved evidence')
    index=json.loads((source/'collection_complete.json').read_text())
    protocol=json.loads((source/'_handover/source/collector/frozen/protocol.json').read_text())
    saved=pd.read_parquet(artifacts/'development/all_adus.parquet')
    columns=list(dict.fromkeys(c for cols in METHODS.values() for c in cols))
    count=0; run_count=0; validation=[]
    for planned,entry in sorted(index['completed'].items()):
        if entry['intended_evaluation_role'] not in ('train','validation'): continue
        folder=(source/entry['attempt']).resolve()
        if not folder.is_relative_to(source.resolve()): raise ValueError('Unsafe accepted path')
        plan=json.loads((folder/'planned_run.json').read_text())
        mapping=next(m for m in protocol['public_configuration']['maps'] if m['id']==plan['map'])
        d=Detector(mapping,trusted_single_writer=True)
        with (folder/'application_ledger.jsonl').open() as stream:
            results=[d.observe(json.loads(line)) for line in stream if line.strip()]
        frame=pd.DataFrame([r['features'] for r in results])
        old=saved.loc[saved.run_id==entry['attempt']].reset_index(drop=True)
        pd.testing.assert_frame_equal(feature_frame(frame,columns),feature_frame(old,columns))
        for r,original in zip(results,old.itertuples(index=False),strict=True):
            assert r['prediction']==original.rule_prediction
            assert (r['eligible'],r['context_available'])==(original.eligible,original.context_available)
            for key in ('paired_request_event_id','mode_anchor_event_id','setpoint_anchor_event_id'):
                expected=getattr(original,key)
                assert r['evidence'][key] == (None if pd.isna(expected) else expected)
        count+=len(frame); run_count+=1
        if entry['intended_evaluation_role']=='validation':
            validation.append(frame.assign(event_id=old.event_id,eligible=old.eligible,context_available=old.context_available))
    val=pd.concat(validation,ignore_index=True)
    predictions=pd.read_parquet(artifacts/'validation_predictions.parquet')
    if list(val.event_id)!=list(predictions.event_id): raise ValueError('Validation identity order mismatch')
    models=load_locked_models(artifacts); checks={}
    for name,cols in METHODS.items():
        mask=val.eligible & (val.context_available if name.startswith('D') else True)
        actual=models[name].predict(feature_frame(val.loc[mask],cols))
        if not np.array_equal(actual,predictions.loc[mask,name]): raise ValueError('v2 validation prediction mismatch')
        checks[name]={'predictions_equal':True,'rows':int(mask.sum())}
    # Already prepared VALIDATION observations only; excludes capture/decoder.
    pool=feature_frame(val.loc[val.eligible & val.context_available],METHODS['D'])
    latency={}
    for size in (1,32,128):
        batch=pool.iloc[:size]
        models['D'].predict(batch)
        measurements=[]
        for _ in range(30):
            start=time.perf_counter_ns(); models['D'].predict(batch)
            measurements.append((time.perf_counter_ns()-start)/1e6)
        latency[str(size)]={'batch_rows':size,'repetitions':30,'median_batch_ms':float(np.median(measurements)),
                            'p95_batch_ms':float(np.quantile(measurements,.95)),
                            'median_prepared_rows_per_second':float(1000*size/np.median(measurements))}
    result={'status':'PASSED','version':VERSION,'scope':'DEVELOPMENT_ONLY_ENGINEERING_VALIDATION_NOT_FINAL_CONFIRMATION',
            'development_runs':run_count,'development_adus':count,'all_features_pairing_anchors_rules_equal':True,
            'models':checks,'training_executed':False,'final_rows_read':False,
            'latency':latency,'latency_scope':'Warm saved D imputer+RF predict on prepared validation rows; not TCP/end-to-end latency; not confidence/explanation generation.',
            'scalability_limit':'Small batch-size benchmark only. Sustained load, memory growth, live loss and production capacity unmeasured.',
            'platform':platform.platform(),'processor':platform.processor(),'python':sys.version,
            'code_sha256':{str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE/'runtime.py',Path(__file__))}}
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x',encoding='utf-8') as stream: json.dump(result,stream,indent=2)
    print(json.dumps(result,indent=2))
    return result
