"""Read-only PP1 demonstration data. Only accepted development runs are replayed."""
import hashlib
import json
from pathlib import Path
from runtime import Detector,load_locked_models,predict_batch,LOCKED

HERE=Path(__file__).resolve().parent

def read(path): return json.loads(path.read_text(encoding='utf-8-sig'))
def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream,'sha256').hexdigest()

def checked_child(root,name):
    target=(root/name).resolve()
    if not target.is_relative_to(root.resolve()): raise ValueError('Unsafe evidence path')
    return target

def _saved_examples():
    """Select byte-identical validation pairs; never refit or predict.

    Labels select explanatory examples only. The saved prediction table supplies
    model outputs; it has no stored probabilities, so confidence stays missing.
    """
    import pandas as pd
    artifacts=LOCKED/'artifacts'
    lock=read(artifacts/'experiment_lock.json')
    if sha(artifacts/'experiment_lock.json') != 'f59f8e8922de62afd28f610a2521d9c45c0ebc46cec35b587210f4da0c6181c9':
        raise ValueError('Unexpected experiment lock')
    path=artifacts/'development/all_adus.parquet'
    if sha(path) != lock['artifact_sha256']['development/all_adus.parquet']:
        raise ValueError('Development records differ from the lock')
    saved_path=artifacts/'validation_predictions.parquet'
    preservation=read(HERE/'reports/preservation.json')
    original=next(m for m in preservation['moves'] if m['after']=='component3/locked')
    expected=original['files']['v1_20261025/artifacts/validation_predictions.parquet']['sha256']
    if sha(saved_path) != expected: raise ValueError('Saved validation predictions changed')
    saved=pd.read_parquet(saved_path)
    if saved.event_id.duplicated().any(): raise ValueError('Duplicate saved prediction identity')
    records=pd.read_parquet(path,columns=['event_id','run_id','evaluation_role','task','eligible','context_available','adu_hex','label'])
    eligible=records.loc[(records.evaluation_role=='validation') & records.eligible & records.context_available]
    examples=[]
    for task,attack in [('command','command_injection'),('response','response_injection')]:
        for _,group in eligible.loc[eligible.task==task].groupby('adu_hex',sort=False):
            if {'normal',attack} <= set(group.label):
                for label in ('normal',attack):
                    item=group.loc[group.label==label].iloc[0]
                    examples.append({'event_id':item.event_id,'run_id':item.run_id,'task':task})
                break
        else: raise ValueError('No matched saved validation examples: '+task)
    return examples,saved.set_index('event_id').to_dict(orient='index')

def load_demo(source=None, *, saved_predictions_only=False):
    source=Path(source or HERE/'data/collection').resolve()
    models=None if saved_predictions_only else load_locked_models()
    lock=read(LOCKED/'artifacts/experiment_lock.json')
    if sha(source/'collection_complete.json') != lock['collection']['canonical_index_sha256']:
        raise ValueError('Collection index differs from original lock')
    index=read(source/'collection_complete.json')
    protocol=source/'_handover/source/collector/frozen/protocol.json'
    if sha(protocol) != '7634b3187e53c029db5d4755c6c3cf9df6a7985ab8ad1c67d3ebf00662a43c48':
        raise ValueError('Public protocol identity differs')
    maps=read(protocol)['public_configuration']['maps']
    reference_examples=read(LOCKED/'reports/viva_examples.json')
    examples,saved=(_saved_examples() if (LOCKED/'artifacts/validation_predictions.parquet').is_file()
                    else (reference_examples,{})) if saved_predictions_only else (reference_examples,{})
    wanted={r['event_id'] for r in examples}
    reference_ids={r['event_id'] for r in reference_examples}
    cases={}; abstention=None; seals=[]
    for run_id in sorted({r['run_id'] for r in examples+reference_examples}):
        entry=next(e for e in index['completed'].values() if e['attempt']==run_id)
        if entry['intended_evaluation_role'] not in ('train','validation'):
            raise ValueError('Frontend examples must be accepted development runs')
        folder=checked_child(source,run_id)
        if sha(folder/'completion.json') != entry['completion_sha256']: raise ValueError('Receipt differs')
        receipt=read(folder/'completion.json')
        for name,digest in receipt['artifact_sha256'].items():
            if sha(checked_child(folder,name)) != digest: raise ValueError('Changed run evidence: '+name)
        plan=read(folder/'planned_run.json')
        detector=Detector(next(m for m in maps if m['id']==plan['map']),trusted_single_writer=True)
        ledger=[json.loads(l) for l in (folder/'application_ledger.jsonl').read_text().splitlines()]
        public=('event_id','connection_id','direction','stream_offset','adu_hex','observed_at_ns',
                'source_ip','destination_ip','source_port','destination_port')
        observed=[detector.observe({k:r[k] for k in public}) for r in ledger]
        # Truth is opened separately, after causal features exist.
        truth={r['event_id']:r for r in (json.loads(l) for l in (folder/'verified_labels.jsonl').read_text().splitlines())}
        chosen=[(i,r) for i,r in enumerate(observed) if r['event_id'] in wanted | reference_ids]
        if abstention is None:
            missing=next((i,r) for i,r in enumerate(observed) if r['eligible'] and not r['context_available'])
            chosen.append(missing)
        if saved_predictions_only:
            scored={name:[{'prediction':saved.get(r['event_id'],{}).get(name),
                           'confidence':None,'available':r['event_id'] in saved,
                           'source':'artifacts/validation_predictions.parquet' if r['event_id'] in saved else None}
                          for _,r in chosen] for name in ('B','D','B-wire','D-wire')}
        else:
            scored={name:predict_batch([r for _,r in chosen],models,name) for name in ('B','D','B-wire','D-wire')}
        lookup={r['event_id']:r for r in ledger}
        for j,(i,r) in enumerate(chosen):
            ann=truth[r['event_id']]
            if r['event_id'] in saved:
                item=saved[r['event_id']]
                if (item['run_id'],item['label'],item['task'],item['eligible'],item['context_available']) != (
                    run_id,ann['label'],r['task'],r['eligible'],r['context_available']):
                    raise ValueError('Saved prediction/source association differs')
            references={name:lookup[event] for name,event in r['evidence'].items()
                        if name.endswith('_event_id') and event is not None}
            case={'event_id':r['event_id'],'run_id':run_id,'evaluation_role':entry['intended_evaluation_role'],
                  'observation':ledger[i],'decision':r,'annotation':ann,'earlier':references,
                  'predictions':{name:results[j] for name,results in scored.items()},
                  'source_relative':folder.relative_to(HERE.parent).as_posix(),'ledger_line':i+1}
            if r['event_id'] in wanted | reference_ids: cases[r['event_id']]=case
            elif abstention is None: abstention=case
        seals.append({'run_id':run_id,'receipt_sha256':entry['completion_sha256'],'artifacts_checked':len(receipt['artifact_sha256'])})
    paired={task:[cases[r['event_id']] for r in examples if r['task']==task] for task in ('command','response')}
    for task,items in paired.items():
        if len(items)!=2 or items[0]['observation']['adu_hex'] != items[1]['observation']['adu_hex']:
            raise ValueError('Expected matched complete current ADUs')
    return {'pairs':paired,'abstention':abstention,'checked_run_seals':seals,
            'reference_cases':[cases[r['event_id']] for r in reference_examples],
            'prediction_source':('saved_validation' if saved else 'unavailable') if saved_predictions_only else 'live_development_inference',
            'collection_id':index['collection_id'],'lock_sha256':sha(LOCKED/'artifacts/experiment_lock.json')}
