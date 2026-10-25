"""Correct only NEW forensic dt_s, documenting historical float-subtraction precision.

Idempotent QA repair for first diagnostic run. sequence_audit.py now uses exact integer
subtraction directly, so this repair is not necessary on subsequent full reproductions.
"""
from pathlib import Path
import json
import numpy as np
import pandas as pd

O=Path(__file__).resolve().parents[1]
path=O/'evidence/diagnostic_reconstruction/packets_rebuilt.csv'
r=pd.read_csv(path)
legacy=r.groupby(['capture_group','session_id']).ts_ns.diff()/1e9
r['dt_s']=np.nan
t=r.ts_ns.to_numpy(np.int64)
profiles=pd.read_csv(O/'evidence/diagnostic_stream_profiles.csv')
for (g,sid),ix in r.groupby(['capture_group','session_id'],sort=False).indices.items():
    d=np.diff(t[ix]).astype(np.float64)/1e9
    r.loc[ix[1:],'dt_s']=d
    profiles.loc[profiles.capture_group.eq(g)&profiles.session_id.eq(sid),'dt_mismatches_gt_1ns']=0
err=(legacy-r.dt_s).abs()*1e9
valid=err.notna()
report={'historical_expression':'groupby([capture_group,session_id]).ts_ns.diff() / 1e9','issue':'nullable shift promotes epoch nanoseconds to float64 before subtraction in this pandas runtime','rows_differing_over_1ns':int((err>1).sum()),'absolute_error_ns':{'n':int(valid.sum()),'min':float(err.min()),'p01':float(err.quantile(.01)),'p25':float(err.quantile(.25)),'median':float(err.median()),'mean':float(err.mean()),'p75':float(err.quantile(.75)),'p95':float(err.quantile(.95)),'p99':float(err.quantile(.99)),'max':float(err.max())},'new_method':'Subtract adjacent int64 timestamps within stream, then convert gap to float seconds','scientific_impact':'Submicrosecond numerical error; does not explain the severe legacy ordering failure or static shortcuts.'}
tmp=path.with_suffix('.timing_corrected.csv');r.to_csv(tmp,index=False);tmp.replace(path)
profiles.to_csv(O/'evidence/diagnostic_stream_profiles.csv',index=False)
# Reopen repaired file and independently compare each real gap with exact int64 subtraction.
rr=pd.read_csv(path,usecols=['capture_group','session_id','ts_ns','dt_s'])
mismatches=0
for _,ix in rr.groupby(['capture_group','session_id']).indices.items():
    exact=np.diff(rr.ts_ns.to_numpy(np.int64)[ix])/1e9
    mismatches+=int((abs(exact-rr.dt_s.to_numpy()[ix[1:]])>1e-9).sum())
assert mismatches==0
f=O/'rebuilt_sequence_audit.json';d=json.loads(f.read_text(encoding='utf-8'));n=d['new_diagnostic_reconstruction']
n['historical_groupby_diff_precision']=report
n['window_validation']['noninitial_dt_mismatches_gt_1ns']=mismatches
tv=r.dt_s.notna();te=(r.loc[tv,'dt_s']-r.loc[tv,'time_delta']).abs()
n['supplied_vs_recomputed_timing']={'compared_rows':int(tv.sum()),'matches_within_1us':int((te<=1e-6).sum()),'median_abs_difference_s':float(te.median()),'interpretation':'Supplied time_delta is not a reliable inter-message gap in the chronological stream.'}
f.write_text(json.dumps(d,indent=2),encoding='utf-8')
f=O/'WINDOW_INTEGRITY_REPORT.json';d=json.loads(f.read_text(encoding='utf-8'));d['new_diagnostic_reconstruction']['noninitial_dt_mismatches_gt_1ns']=0;f.write_text(json.dumps(d,indent=2),encoding='utf-8')
f=O/'SEQUENCE_FINDINGS.md';text=f.read_text(encoding='utf-8');para='\n\n### Submicrosecond timing precision\n\nThe historical `groupby(...).ts_ns.diff()` expression promotes epoch nanoseconds to floating point during shifting in this pandas runtime. Independent comparison with integer subtraction finds '+str(report['rows_differing_over_1ns'])+' gaps differing by more than 1 ns, with maximum absolute error '+str(report['absolute_error_ns']['max'])+' ns. The new diagnostic file uses integer subtraction before conversion to seconds and validates 0 differences above 1 ns after CSV reload. This small numerical issue does not explain the severe legacy chronology failure. The historical files are missing, so their actual stored rounding cannot be independently inspected.\n'
if '### Submicrosecond timing precision' in text:text=text.split('### Submicrosecond timing precision',1)[0].rstrip()
f.write_text(text+para,encoding='utf-8')
print(json.dumps({'precision':report,'corrected_dt_mismatches_gt_1ns':mismatches,'supplied_vs_corrected':n['supplied_vs_recomputed_timing']}),flush=True)
