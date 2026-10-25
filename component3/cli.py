# Choose a verification or development-demo command; this entry point does not train models.
import argparse
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent

# Parse the command and run only the requested inspection or development action.
def main():
    p=argparse.ArgumentParser(description='Component 3: inspect preserved evidence and demonstrate label-free inference. Never trains or evaluates final sets.')
    p.add_argument('action',choices=['check','audit','test','demo','replay-check'])
    p.add_argument('--source',type=Path,default=HERE/'data/collection')
    p.add_argument('--artifacts',type=Path,default=HERE/'locked/v1_20261025/artifacts')
    p.add_argument('--output',type=Path)
    p.add_argument('--run',default='MX001')
    p.add_argument('--method',choices=['B','D','B-wire','D-wire'],default='D')
    a=p.parse_args()
    from runtime import load_locked_models,Detector,predict_batch,LOCKED
    if a.action == 'test':
        env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',PYTHONPATH=os.pathsep.join([str(HERE),str(LOCKED)]))
        for folder in [HERE/'tests',LOCKED/'tests']:
            subprocess.run([sys.executable,'-B','-m','unittest','discover','-s',str(folder),'-v'],env=env,check=True,cwd=ROOT)
        return
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:6]
    if a.action == 'audit':
        if a.artifacts.resolve() != (LOCKED/'artifacts').resolve():
            p.error('The independent audit uses the intact locked bundle; place artifacts there')
        from tools.audit import audit
        audit(a.source,a.output or HERE/'local'/('audit-'+stamp)); return
    if a.action == 'replay-check':
        from tools.runtime_check import run
        run(a.source,a.artifacts,a.output or HERE/'local'/('runtime-'+stamp+'.json')); return
    models=load_locked_models(a.artifacts)
    index=json.loads((a.source/'collection_complete.json').read_text(encoding='utf-8-sig'))
    if index['collection_id'] != '40ae7a846cce48fc8e3c52ebfca7e2cd' or len(index['completed']) != 104:
        raise ValueError('Wrong/incomplete collection')
    if a.action == 'check':
        print(json.dumps({'status':'LOCKED_MODELS_LOADED','collection_id':index['collection_id'],
                          'source':str(a.source.resolve()),'models':list(models),'training':False,
                          'scope':'Quick index/model identity check. Use audit for full raw verification.'},indent=2)); return
    entry=index['completed'].get(a.run)
    if not entry or entry['intended_evaluation_role'] not in ('train','validation'):
        raise ValueError('Demo is restricted to accepted training/validation runs')
    folder=(a.source/entry['attempt']).resolve()
    if not folder.is_relative_to(a.source.resolve()): raise ValueError('Unsafe accepted path')
    config=json.loads((folder/'planned_run.json').read_text(encoding='utf-8-sig'))
    protocol=json.loads((a.source/'_handover/source/collector/frozen/protocol.json').read_text(encoding='utf-8-sig'))
    mapping=next(m for m in protocol['public_configuration']['maps'] if m['id'] == config['map'])
    detector=Detector(mapping,trusted_single_writer=True)
    observed=[]
    public=('event_id','connection_id','direction','stream_offset','adu_hex','observed_at_ns',
            'source_ip','destination_ip','source_port','destination_port')
    with (folder/'application_ledger.jsonl').open(encoding='utf-8-sig') as stream:
        for line in stream:
            row=json.loads(line)
            observed.append(detector.observe({k:row[k] for k in public if k in row}))
    result=predict_batch(observed,models,a.method)
    output=a.output or HERE/'local'/('demo-'+stamp+'.jsonl')
    resolved=output.resolve()
    if resolved.is_relative_to(a.source.resolve()) or resolved.is_relative_to(LOCKED):
        raise ValueError('Output cannot alter source or locked bundle')
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('x',encoding='utf-8') as stream:
        for row in result: stream.write(json.dumps(row,allow_nan=False)+'\n')
    from collections import Counter
    print(json.dumps({'status':'DEVELOPMENT_DEMO_ONLY','rows':len(result),
                      'processing_status':dict(Counter(r['processing_status'] for r in result)),
                      'output':str(output.resolve()),'method':a.method,'training':False},indent=2))
