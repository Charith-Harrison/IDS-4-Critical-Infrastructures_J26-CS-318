"""Reconcile final output populations and verify the forensic package. No source writes."""
from pathlib import Path
import json,csv,hashlib,math,sys,re,importlib.metadata as metadata
from collections import Counter
import numpy as np
import pandas as pd

R=Path(__file__).resolve().parents[1];E=R/'evidence'
REQUIRED=['FULL_FINDINGS_REPORT.md','source_manifest.json','requirements_matrix.csv','REQUIREMENTS_MATRIX.md','DATA_LINEAGE.md',
    'legacy_sequence_audit.json','rebuilt_sequence_audit.json','WINDOW_INTEGRITY_REPORT.json','label_provenance.csv',
    'recon_request_candidates.csv','shortcut_analysis.csv','capture_campaign_summary.csv','split_feasibility.json','UNRESOLVED_ASSUMPTIONS.md']
def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()
def clean(x):
    if isinstance(x,float) and not math.isfinite(x):return None
    if isinstance(x,dict):return {k:clean(v) for k,v in x.items()}
    if isinstance(x,list):return [clean(v) for v in x]
    return x
def fail_constant(x):raise ValueError('nonstandard JSON constant '+x)

def enrich_campaigns():
    summary=pd.read_csv(R/'capture_campaign_summary.csv',keep_default_na=False).astype(object)
    d=pd.read_csv(E/'diagnostic_reconstruction/packets_rebuilt.csv',usecols=['file_source','label'])
    w=pd.read_csv(E/'diagnostic_reconstruction/windows.csv');ix=np.load(E/'diagnostic_reconstruction/window_index.npy')
    file=d.file_source.to_numpy();wf=file[ix[:,0]];assert (file[ix]==wf[:,None]).all()
    c=pd.read_csv(R/'recon_request_candidates.csv');rr=c[c.label_state.eq('supported_contextual')]
    allc=c.capture_chunk.value_counts();sup=rr.capture_chunk.value_counts()
    for i,row in summary.iterrows():
        f=row.file_source;dd=d[d.file_source.eq(f)];mask=wf==f
        summary.at[i,'diagnostic_retained_packets']=len(dd)
        summary.at[i,'diagnostic_retained_positive_packets']=int(dd.label.sum())
        summary.at[i,'diagnostic_excluded_original_rows']=int(row.processed_packet_rows)-len(dd)
        summary.at[i,'diagnostic_windows']=int(mask.sum())
        summary.at[i,'diagnostic_positive_windows']=int(w.loc[mask,'label'].sum())
        summary.at[i,'positive_windows']=int(w.loc[mask,'label'].sum())
        summary.at[i,'raw_canonical_recon_request_candidates_in_this_chunk']=int(allc.get(f,0))
        summary.at[i,'raw_canonical_supported_contextual_requests_in_this_chunk']=int(sup.get(f,0))
        summary.at[i,'raw_canonical_ambiguous_requests_in_this_chunk']=int(allc.get(f,0)-sup.get(f,0))
        refs=set()
        for v in c.loc[c.capture_chunk.eq(f),'attack_log_reference'].dropna():refs.update(re.split(r';(?=attack/)',str(v)))
        summary.at[i,'original_recon_log_rows_referenced_by_canonical_chunk']=len(refs)
        summary.at[i,'evidence_supported_recon_requests']=int(float(row.get('supported_contextual_positive_requests',0) or 0))
        summary.at[i,'count_interpretation']='Raw canonical chunk counts do not include mirror-equivalent requests in other files; packet and message counts are distinct.'
    summary=summary.drop(columns=['raw_original_log_events_verified'],errors='ignore')
    for col in ['positive_windows','evidence_supported_recon_requests','positive_packet_rows_raw_verified','supported_contextual_positive_requests',
        'diagnostic_retained_packets','diagnostic_retained_positive_packets','diagnostic_excluded_original_rows','diagnostic_windows',
        'diagnostic_positive_windows','raw_canonical_recon_request_candidates_in_this_chunk','raw_canonical_supported_contextual_requests_in_this_chunk',
        'raw_canonical_ambiguous_requests_in_this_chunk','original_recon_log_rows_referenced_by_canonical_chunk']:
        if col in summary:summary[col]=pd.to_numeric(summary[col],errors='coerce').fillna(0).astype('int64')
    summary.to_csv(R/'capture_campaign_summary.csv',index=False)
    return summary

def main():
    summary=enrich_campaigns();repaired=[]
    for p in R.rglob('*.json'):
        if '.deps' in p.parts or '__pycache__' in p.parts:continue
        raw=p.read_text('utf8')
        try:json.loads(raw,parse_constant=fail_constant)
        except ValueError:
            x=clean(json.loads(raw));p.write_text(json.dumps(x,indent=2,allow_nan=False)+'\n',encoding='utf8');repaired.append(str(p.relative_to(R)))
    checks=[]
    def check(name,ok,detail=None):
        checks.append(dict(check=name,passed=bool(ok),detail=detail))
        if not ok:raise AssertionError(name+': '+str(detail))
    for f in REQUIRED:check('required_output_'+f,(R/f).is_file())
    m=json.loads((R/'source_manifest.json').read_text())
    check('source_immutability',m['modified_source_count']==0 and not m['missing_since_baseline'],{'files':len(m['files']),'verification_utc':m['verification_utc']})
    check('source_hash_schema',all(len(x['sha256'])==64 and x['sha256_before']==x['sha256'] and x['modified_during_task'] is False for x in m['files']))
    check('raw_capture_inventory',sum(x['file_type']=='.pcap' for x in m['files'])==170)
    c=pd.read_csv(R/'recon_request_candidates.csv',dtype={'adu_hex':str,'response_adu_hex':str})
    check('candidate_population',len(c)==468 and c.label_state.value_counts().to_dict()=={'ambiguous':320,'supported_contextual':148})
    check('ambiguity_not_positive',not c.loc[c.label_state.eq('ambiguous'),'evidence_supported_recon_request'].any())
    check('no_supported_exact',not c.label_state.eq('supported_exact').any())
    check('raw_request_hex_strings',c.adu_hex.map(lambda v:bool(re.fullmatch(r'[0-9a-fA-F]+',v)) and len(v)%2==0).all())
    rh=c.response_adu_hex.dropna();check('raw_response_hex_strings',len(rh)==269 and rh.map(lambda v:bool(re.fullmatch(r'[0-9a-fA-F]+',v)) and len(v)%2==0).all())
    lab=pd.read_csv(R/'label_provenance.csv');check('all_positive_provenance_rows',len(lab)==8699)
    check('campaign_population_total',int(summary.processed_packet_rows.sum())==879225 and int(summary.diagnostic_retained_packets.sum())==597135)
    check('campaign_window_total',int(summary.diagnostic_windows.sum())==119237 and int(summary.diagnostic_positive_windows.sum())==1878)
    split=json.loads((R/'split_feasibility.json').read_text())
    check('honest_split_feasibility',split['status']=='UNSUPPORTED' and split['independence']['verified_independent_attack_campaign_count'] is None)
    check('log_reference_population',split['raw_recon_request_evidence']['distinct_original_log_row_references_attached_to_candidates']==411)
    b=json.loads((E/'benign_raw_extraction.json').read_text());check('benign_census',b['counts']['read_requests']==2042925 and len(b['files'])==19)
    t=json.loads((E/'temporal_signal_summary.json').read_text());check('temporal_population',t['supported_contextual_requests']==148 and t['ambiguous_or_other_candidates']==320 and t['candidate_requests_with_exact_shape_benign_overlap']==0)
    check('no_final_models_created',not any(p.suffix in ['.pt','.h5','.joblib','.pkl'] for p in R.rglob('*') if p.is_file() and '.deps' not in p.parts))
    for p in R.rglob('*.json'):
        if '.deps' not in p.parts and '__pycache__' not in p.parts:json.loads(p.read_text('utf8'),parse_constant=fail_constant)
    text=(R/'FULL_FINDINGS_REPORT.md').read_text('utf8')
    action=text.split('### Single best next action\n',1)[1].strip()
    check('one_final_next_action',action=='Conduct a controlled Modbus/TCP testbed pilot with matched normal/recon request shapes and independently recorded run ground truth.')
    check('verdict_complete',all('**'+s+':**' in text for s in ['Raw-source provenance','Legacy sequence construction','Rebuilt sequence construction','Recon label provenance','Recon-request recovery','Static shortcut risk','Temporal reconnaissance signal','Independent evaluation feasibility','CIC suitability for Component 2','Need for controlled-testbed supplement']))
    parser=R/'scripts/pcapio.py';orig=Path(r'D:\VSCode\GitHub\4th Year Cyber\C3\component3_preparation\c3prep\pcapio.py')
    check('preserved_parser_copy',digest(parser)==digest(orig))
    versions={'python':sys.version}
    sys.path.insert(0,str(R/'.deps'))
    for package in ['numpy','pandas','openpyxl','scikit-learn','matplotlib','pyarrow','scapy']:
        try:versions[package]=metadata.version(package)
        except metadata.PackageNotFoundError:versions[package]=None
    (R/'audit_completion_checks.json').write_text(json.dumps(dict(status='PASS',checks=checks,
        strict_json_missing_value_normalizations=repaired,versions=versions,
        no_final_training=True,scope='Forensic review completion; PASS does not mean research dataset validity or independent evaluation readiness.'),indent=2,allow_nan=False)+'\n',encoding='utf8')
    files=[]
    for p in sorted(R.rglob('*')):
        if not p.is_file() or '.deps' in p.parts or '__pycache__' in p.parts or p.name=='review_output_manifest.json':continue
        files.append(dict(path=str(p.relative_to(R)),size=p.stat().st_size,sha256=digest(p)))
    (R/'review_output_manifest.json').write_text(json.dumps(dict(files=files,exclusions=['.deps/','__pycache__/','review_output_manifest.json itself']),indent=2)+'\n',encoding='utf8')
    print(json.dumps({'status':'PASS','checks':len(checks),'output_files':len(files),'strict_json_normalized':repaired},indent=2),flush=True)

if __name__=='__main__':main()
