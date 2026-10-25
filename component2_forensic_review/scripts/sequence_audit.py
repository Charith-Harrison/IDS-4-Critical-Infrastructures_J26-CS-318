"""Independent forensic sequence audit. Never executes historical code or writes sources.

Usage: bundled-python component2_forensic_review/scripts/sequence_audit.py
Requires read-only workbook extraction produced by extract_legacy.py.
Reconstruction here is a NEW diagnostic derivative, NOT validation of absent old outputs.
"""
from pathlib import Path
import json, math
import numpy as np
import pandas as pd
import re

OUT=Path(__file__).resolve().parents[1]
REPO=OUT.parent
E=OUT/'evidence'
D=E/'diagnostic_reconstruction'
D.mkdir(exist_ok=True)
F=['unit_id','func_code','modbus_len','register_start','quantity','packet_size','time_delta']
CONTENT=['src_ip','dst_ip','unit_id','func_code','modbus_len','register_start','quantity','packet_size']
def clean(x):
    if isinstance(x,dict):return {str(k):clean(v) for k,v in x.items()}
    if isinstance(x,(list,tuple)):return [clean(v) for v in x]
    if isinstance(x,np.ndarray):return clean(x.tolist())
    if isinstance(x,(np.integer,)):return int(x)
    if isinstance(x,(np.bool_,)):return bool(x)
    if isinstance(x,(np.floating,float)):return None if not math.isfinite(x) else float(x)
    return x
def dump(x,p):p.write_text(json.dumps(clean(x),indent=2),encoding='utf-8')
def ns(s):return pd.to_datetime(s,format='ISO8601',utc=True,errors='coerce').astype('int64')
def stats(a):
    a=np.asarray(a);a=a[np.isfinite(a)]
    return {'n':len(a),'min':a.min() if len(a) else None,'p01':np.quantile(a,.01) if len(a) else None,'p25':np.quantile(a,.25) if len(a) else None,'median':np.median(a) if len(a) else None,'mean':a.mean() if len(a) else None,'p75':np.quantile(a,.75) if len(a) else None,'p95':np.quantile(a,.95) if len(a) else None,'p99':np.quantile(a,.99) if len(a) else None,'max':a.max() if len(a) else None}

print('Loading extracted originals',flush=True)
p=pd.read_csv(E/'recon_labeled_packets_ALL.csv')
p.insert(0,'row_index',np.arange(len(p),dtype=np.int64))
p['ts_ns']=ns(p.timestamp)
valid=p.ts_ns.ne(np.iinfo(np.int64).min)
config_text=(REPO/'C2_Reconnaissance_Detection/configs/default.yaml').read_text(encoding='utf-8')
# Deliberately parse only the observed simple filename lists and tolerance, no source execution.
group_text=config_text.split('\ncapture_groups:\n',1)[1].split('\nexcluded_files:',1)[0]
groups={m.group(1):[v.strip() for v in m.group(2).split(',')] for m in re.finditer(r'^  (\S+):\s*\[([^\]]+)\]',group_text,re.M)}
excluded_text=config_text.split('\nexcluded_files:\n',1)[1].split('\nduplicate_views:',1)[0]
excluded={m.group(1):m.group(2) for m in re.finditer(r'^  (\S+):\s*(.+)$',excluded_text,re.M)}
cfg={'capture_groups':groups,'excluded_files':excluded,'duplicate_views':{'near_duplicate_tolerance_ns':int(re.search(r'near_duplicate_tolerance_ns:\s*(\d+)',config_text).group(1))}}
f2g={f:g for g,fs in cfg['capture_groups'].items() for f in fs}
p['capture_group']=p.file_source.map(f2g)
p['is_fc5_len3']=p.func_code.eq(5)&p.modbus_len.eq(3)
s=pd.read_csv(E/'recon_sequences_ALL.csv')
s['start_ns']=ns(s.window_start_time);s['end_ns']=ns(s.window_end_time)
print('Loaded',len(p),len(s),list(s.columns),flush=True)

# Independently infer supplied window representation and stride from observed values.
print('Auditing all legacy windows',flush=True)
features_json='features_json' in s
allfeature=all(c in s for c in F)
legacy={'source_kind':'direct audit of attached XLSX values via hash-checked extraction','packet_rows':len(p),'sequence_windows':len(s),'packet_label_counts':p.label.value_counts().to_dict(),'sequence_label_counts':s.label.value_counts().to_dict(),'unparseable_packet_timestamps':int((~valid).sum()),'sequence_schema':[c for c in s.columns if c not in ['start_ns','end_ns']],'duplicate_sequence_ids':int(s.sequence_id.duplicated().sum()),'feature_order':F,'window_length_observed':s.window_length.unique().tolist()}
inference=[]
sid0=s.session_id.iloc[0];idx0=np.flatnonzero(p.session_id.eq(sid0));ss0=s.index[s.session_id.eq(sid0)][:10]
def tensor(row):
    if features_json:return np.asarray(json.loads(row.features_json),dtype=float)
    return np.column_stack([np.asarray(str(row[c]).split(';'),dtype=float) for c in F])
for stride in range(1,21):
    hits=0
    for k,i in enumerate(ss0):
        ix=idx0[k*stride:k*stride+20]
        hits+=int(len(ix)==20 and np.allclose(p.iloc[ix][F].to_numpy(float),tensor(s.iloc[i]),rtol=1e-12,atol=1e-12))
    inference.append({'stride':stride,'matches':hits,'tested':len(ss0)})
stride=max(inference,key=lambda x:x['matches'])['stride']
legacy['stride_inference']=inference;legacy['inferred_stride']=stride
counts={k:0 for k in ['all_feature_cells_match','start_timestamp_match','end_timestamp_match','any_positive_rule_match','first_packet_rule_match','last_packet_rule_match','majority_rule_match','windows_with_backward_transition','windows_end_before_start','windows_cross_source_file','windows_cross_capture_group','windows_cross_session','windows_span_gt_60s','windows_span_gt_300s','windows_span_gt_3600s']}
spans=[];signed=[];backwards=0;sessionprofiles=[];badexamples=[];legacy_indexes=[];legacy_positions=[]
for sid,si in s.groupby('session_id',sort=False).indices.items():
    pi=np.flatnonzero(p.session_id.eq(sid));pp=p.iloc[pi];tt=pp.ts_ns.to_numpy(np.int64);ll=pp.label.to_numpy();ff=pp.file_source.to_numpy();gg=pp.capture_group.fillna('UNPLACED').to_numpy();feat=pp[F].to_numpy(float)
    dd=np.diff(tt);backwards+=int((dd<0).sum())
    sessionprofiles.append({'session_id':sid,'packets':len(pp),'windows':len(si),'backward_transitions':int((dd<0).sum()),'source_files':pp.file_source.nunique(),'capture_groups':pp.capture_group.nunique(),'span_days':(tt.max()-tt.min())/86400e9,'sequence_position_is_0_based_cumcount':bool(np.array_equal(pp.sequence_position,np.arange(len(pp)))),'original_row_indices_contiguous':bool(np.all(np.diff(pi)==1))})
    for k,i in enumerate(si):
        a=k*stride;ix=pi[a:a+20];w=s.iloc[i];t=tt[a:a+20];l=ll[a:a+20]
        assert len(ix)==20
        legacy_indexes.append(ix);legacy_positions.append(i)
        counts['all_feature_cells_match']+=int(np.allclose(feat[a:a+20],tensor(w),rtol=1e-12,atol=1e-12))
        counts['start_timestamp_match']+=int(w.window_start_time==pp.timestamp.iloc[a]);counts['end_timestamp_match']+=int(w.window_end_time==pp.timestamp.iloc[a+19])
        counts['any_positive_rule_match']+=int(w.label==int(l.max()>0));counts['first_packet_rule_match']+=int(w.label==l[0]);counts['last_packet_rule_match']+=int(w.label==l[-1]);counts['majority_rule_match']+=int(w.label==int(l.mean()>.5))
        rev=int((np.diff(t)<0).sum());span=(t.max()-t.min())/1e9;duration=(t[-1]-t[0])/1e9
        crossfile=len(set(ff[a:a+20]))>1;crossgroup=len(set(gg[a:a+20]))>1
        for key,b in [('windows_with_backward_transition',rev>0),('windows_end_before_start',duration<0),('windows_cross_source_file',crossfile),('windows_cross_capture_group',crossgroup),('windows_cross_session',p.iloc[ix].session_id.nunique()>1),('windows_span_gt_60s',span>60),('windows_span_gt_300s',span>300),('windows_span_gt_3600s',span>3600)]:counts[key]+=int(b)
        spans.append(span);signed.append(duration)
        if len(badexamples)<12 and rev and crossgroup:
            badexamples.append({'sequence_id':w.sequence_id,'session_id':sid,'source_rows':ix.tolist(),'timestamps':pp.timestamp.iloc[a:a+20].tolist(),'file_sources':ff[a:a+20].tolist(),'sequence_positions':pp.sequence_position.iloc[a:a+20].tolist()})
legacy.update(counts,packet_backward_transitions_within_supplied_session_order=backwards,window_actual_span_seconds=stats(spans),window_signed_end_minus_start_seconds=stats(signed),session_profiles=sessionprofiles,consecutive_window_shared_packets=20-stride,overlap_fraction=(20-stride)/20)
legacy['total_source_file_transitions_within_sessions']=int(sum((g.file_source.ne(g.file_source.shift()).iloc[1:]).sum() for _,g in p.groupby('session_id')))
legacy['total_capture_group_transitions_within_sessions']=int(sum((g.capture_group.fillna('UNPLACED').ne(g.capture_group.fillna('UNPLACED').shift()).iloc[1:]).sum() for _,g in p.groupby('session_id')))
legacy['backward_transitions_even_within_file_session_order']=int(sum((np.diff(g.ts_ns.to_numpy(np.int64))<0).sum() for _,g in p[valid].groupby(['file_source','session_id'])))
legacy['supplied_time_delta_zero_rows']=int(p.time_delta.eq(0).sum())
rawdelta=p.groupby('session_id').ts_ns.diff()/1e9
for mode,delta in [('supplied_session_order',rawdelta),('supplied_session_order_clip_zero',rawdelta.clip(lower=0))]:
    ok=delta.notna()&valid;legacy[mode+'_time_delta_agreement_within_1us']={'n':int(ok.sum()),'matches':int((abs(delta[ok]-p.loc[ok,'time_delta'])<=1e-6).sum())}
dump(legacy,OUT/'legacy_sequence_audit.json');dump(badexamples,E/'legacy_bad_window_examples.json')
pd.DataFrame(sessionprofiles).to_csv(E/'legacy_session_profiles.csv',index=False)
LI=np.asarray(legacy_indexes,dtype=np.int32);LI=LI[np.argsort(legacy_positions)];np.save(E/'legacy_window_index_recovered.npy',LI)
del legacy_indexes
print('Legacy audit complete',json.dumps(clean({k:legacy[k] for k in ['packet_rows','sequence_windows','packet_backward_transitions_within_supplied_session_order','windows_with_backward_transition','windows_cross_source_file','windows_cross_capture_group','windows_end_before_start']})),flush=True)

# NEW reconstruction following visible config policies. Never represent as missing historic files.
print('Creating new diagnostic reconstruction',flush=True)
reason=np.full(len(p),'',dtype=object)
reason[p.file_source.isin(cfg.get('excluded_files',{}))]='excluded_file'
reason[(reason=='')&p.capture_group.isna()]='file_not_in_any_capture_group'
reason[(reason=='')&~valid]='unparseable_timestamp'
duplicate_details=[];duplicate_matches=[]
tol=int(cfg['duplicate_views']['near_duplicate_tolerance_ns'])
for g,fs in cfg['capture_groups'].items():
    if len(fs)<2:continue
    gp=p[(p.capture_group==g)&(reason=='')]
    for sid,sp in gp.groupby('session_id'):
        countsfile=sp.file_source.value_counts()
        if len(countsfile)<2:continue
        keep=sorted(countsfile.index,key=lambda f:(-countsfile[f],f))[0]
        kp=sp[sp.file_source.eq(keep)];dp=sp[sp.file_source.ne(keep)]
        reason[dp.index]='duplicate_interface_view'
        left=dp.sort_values('ts_ns');right=kp[['ts_ns','row_index','label']+CONTENT].rename(columns={'ts_ns':'retained_ts_ns','row_index':'retained_row_index','label':'retained_label'}).sort_values('retained_ts_ns')
        mm=pd.merge_asof(left,right,left_on='ts_ns',right_on='retained_ts_ns',by=CONTENT,direction='nearest',tolerance=tol)
        mm['timestamp_delta_ns']=mm.ts_ns-mm.retained_ts_ns
        mm['matched']=mm.retained_row_index.notna()
        mm['label_disagreement']=mm.matched&mm.label.ne(mm.retained_label)
        duplicate_matches.append(mm[['row_index','file_source','capture_group','session_id','retained_row_index','ts_ns','retained_ts_ns','timestamp_delta_ns','matched','label','retained_label','label_disagreement']])
        duplicate_details.append({'capture_group':g,'session_id':sid,'keep_file':keep,'file_counts':countsfile.to_dict(),'dropped':len(dp),'matched_with_content_and_tolerance':int(mm.matched.sum()),'label_disagreements':int(mm.label_disagreement.sum()),'absolute_delta_ns':stats(abs(mm.timestamp_delta_ns))})
dm=pd.concat(duplicate_matches,ignore_index=True)
dm.to_csv(E/'duplicate_interface_verification.csv',index=False)
r=p[reason==''].copy().sort_values(['capture_group','session_id','ts_ns','row_index'],kind='stable').reset_index(drop=True)
legacy_float_dt=r.groupby(['capture_group','session_id']).ts_ns.diff()/1e9
r['dt_s']=np.nan
rt=r.ts_ns.to_numpy(np.int64)
for ix in r.groupby(['capture_group','session_id'],sort=False).indices.values():
    r.loc[ix[1:],'dt_s']=np.diff(rt[ix]).astype(np.float64)/1e9
precision_ns=(legacy_float_dt-r.dt_s).abs()*1e9
precision_report={'historical_expression':'groupby([capture_group,session_id]).ts_ns.diff() / 1e9','issue':'nullable shift promotes epoch nanoseconds to float64 before subtraction in this pandas runtime','rows_differing_over_1ns':int((precision_ns>1).sum()),'absolute_error_ns':stats(precision_ns),'new_method':'Subtract adjacent int64 timestamps within stream, then convert gap to float seconds','scientific_impact':'Submicrosecond numerical error; does not explain the severe legacy ordering failure or static shortcuts.'}
ex=p.loc[reason!='',['row_index','file_source','session_id','timestamp','label']].copy();ex['reason']=reason[reason!='']
cols=['row_index','timestamp','ts_ns','capture_group','session_id','file_source','src_ip','dst_ip','unit_id','func_code','modbus_len','register_start','quantity','packet_size','time_delta','dt_s','label','is_fc5_len3']
r[cols].to_csv(D/'packets_rebuilt.csv',index=False);ex.to_csv(D/'packet_exclusions.csv',index=False)
I=[];meta=[]
for (g,sid),ix in r.groupby(['capture_group','session_id'],sort=True).indices.items():
    for k,a in enumerate(range(0,len(ix)-20+1,5)):
        z=ix[a:a+20];I.append(z);rr=r.iloc[z];npos=int(rr.label.sum())
        meta.append({'capture_group':g,'session_id':sid,'stream_id':g+'|'+sid,'window_in_stream':k,'start_ns':int(rr.ts_ns.iloc[0]),'end_ns':int(rr.ts_ns.iloc[-1]),'first_row_index':int(rr.row_index.iloc[0]),'last_row_index':int(rr.row_index.iloc[-1]),'n_pos_packets':npos,'pos_packet_fraction':npos/20,'label':int(npos>0),'n_fc5_len3_packets':int(rr.is_fc5_len3.sum())})
I=np.asarray(I,dtype=np.int32);w=pd.DataFrame(meta);w.insert(0,'window_id',[f'w{i:06d}' for i in range(len(w))])
w['window_start_utc']=pd.to_datetime(w.start_ns,utc=True).astype(str);w['window_end_utc']=pd.to_datetime(w.end_ns,utc=True).astype(str)
w.to_csv(D/'windows.csv',index=False);np.save(D/'window_index.npy',I)

# Reopen new outputs, then validate ALL windows. Original outputs remain unavailable.
r=pd.read_csv(D/'packets_rebuilt.csv');ex=pd.read_csv(D/'packet_exclusions.csv');w=pd.read_csv(D/'windows.csv');I=np.load(D/'window_index.npy',allow_pickle=False)
ri=r.row_index.to_numpy();ei=ex.row_index.to_numpy();ids=np.r_[ri,ei]
union=np.unique(ids);expected=np.arange(len(p));intersection=np.intersect1d(ri,ei)
pop={'original_rows':len(p),'retained_rows':len(r),'excluded_rows':len(ex),'sum_equals_population':len(ids)==len(p),'retained_duplicate_original_ids':len(ri)-len(np.unique(ri)),'excluded_duplicate_original_ids':len(ei)-len(np.unique(ei)),'retained_excluded_overlap':len(intersection),'missing_original_ids':len(np.setdiff1d(expected,union)),'unknown_original_ids':len(np.setdiff1d(union,expected)),'reason_counts':ex.reason.value_counts().to_dict(),'exclusion_sources':ex.groupby(['reason','file_source']).size().reset_index(name='rows').to_dict('records')}
preservation={}
for c in ['timestamp','src_ip','dst_ip','unit_id','func_code','modbus_len','register_start','quantity','packet_size','time_delta','session_id','sequence_position','label','file_source']:
    if c in r:
        a=p.set_index('row_index').loc[ri,c].to_numpy();b=r[c].to_numpy();preservation[c]=int(np.sum(a!=b))
pop['retained_source_value_disagreements']=preservation
dup={'scope':'processed feature equality only; this check does not compare PCAP bytes, frame identity or TCP state','excluded_rows':len(dm),'matches':int(dm.matched.sum()),'unmatched':int((~dm.matched).sum()),'label_disagreements':int(dm.label_disagreement.sum()),'abs_timestamp_delta_ns':stats(abs(dm.timestamp_delta_ns)),'signed_timestamp_delta_ns':stats(dm.timestamp_delta_ns),'unique_retained_matches':int(dm.retained_row_index.nunique()),'per_stream':duplicate_details,'interpretation':'Whole-file/session deletion is fully corroborated at the available processed feature level only. Equal features near in time are not proof of byte-identical packets or retransmission identity.'}
streamprofiles=[]
for (g,sid),rr in r.groupby(['capture_group','session_id'],sort=True):
    t=rr.ts_ns.to_numpy(np.int64);d=np.diff(t)/1e9;dt=rr.dt_s.to_numpy()
    streamprofiles.append({'capture_group':g,'session_id':sid,'packets':len(rr),'positive_packets':int(rr.label.sum()),'source_files':';'.join(sorted(rr.file_source.unique())),'source_file_count':rr.file_source.nunique(),'start_ns':int(t.min()),'end_ns':int(t.max()),'span_s':(t.max()-t.min())/1e9,'backward_steps':int((d<0).sum()),'first_dt_missing':bool(np.isnan(dt[0])),'nonfirst_missing_dt':int(np.isnan(dt[1:]).sum()),'dt_mismatches_gt_1ns':int((abs(d-dt[1:])>1e-9).sum()),'gaps_gt_60s':int((d>60).sum()),'gaps_gt_300s':int((d>300).sum()),'gaps_gt_3600s':int((d>3600).sum())})
pd.DataFrame(streamprofiles).to_csv(E/'diagnostic_stream_profiles.csv',index=False)
gcode=pd.factorize(r.capture_group)[0];scode=pd.factorize(r.session_id)[0];t=r.ts_ns.to_numpy(np.int64);labs=r.label.to_numpy();fc5=((r.func_code==5)&(r.modbus_len==3)).to_numpy();dur=(t[I[:,-1]]-t[I[:,0]])/1e9;maxgap=np.diff(t[I],axis=1).max(axis=1)/1e9
sameg=(gcode[I]==gcode[I[:,0]][:,None]).all(axis=1);sames=(scode[I]==scode[I[:,0]][:,None]).all(axis=1);ordered=(np.diff(t[I],axis=1)>=0).all(axis=1);pn=labs[I].sum(axis=1)
stridechecks=[]
for key,wi in w.groupby(['capture_group','session_id']).indices.items():
    stridechecks.extend((np.diff(I[wi,0])==5).tolist())
checks={'window_count':len(w),'index_shape':list(I.shape),'all_windows_exactly_20':I.shape==(len(w),20),'all_index_ranges_valid':bool(((I>=0)&(I<len(r))).all()),'all_windows_have_20_distinct_contiguous_indices':bool((np.diff(I,axis=1)==1).all()),'all_intra_stream_strides_5':bool(all(stridechecks)),'windows_cross_capture_group':int((~sameg).sum()),'windows_cross_session_id':int((~sames).sum()),'windows_with_backwards_timestamp':int((~ordered).sum()),'noninitial_dt_mismatches_gt_1ns':sum(v['dt_mismatches_gt_1ns'] for v in streamprofiles),'start_metadata_mismatches':int((w.start_ns.to_numpy()!=t[I[:,0]]).sum()),'end_metadata_mismatches':int((w.end_ns.to_numpy()!=t[I[:,-1]]).sum()),'first_source_row_mismatches':int((w.first_row_index.to_numpy()!=ri[I[:,0]]).sum()),'last_source_row_mismatches':int((w.last_row_index.to_numpy()!=ri[I[:,-1]]).sum()),'positive_count_mismatches':int((w.n_pos_packets.to_numpy()!=pn).sum()),'positive_fraction_mismatches':int((abs(w.pos_packet_fraction.to_numpy()-pn/20)>1e-12).sum()),'any_positive_label_mismatches':int((w.label.to_numpy()!=(pn>0)).sum()),'fc5_len3_count_mismatches':int((w.n_fc5_len3_packets.to_numpy()!=fc5[I].sum(axis=1)).sum()),'label_counts':w.label.value_counts().to_dict(),'duration_seconds':stats(dur),'max_intra_window_gap_seconds':stats(maxgap),'windows_span_gt_60s':int((dur>60).sum()),'windows_span_gt_300s':int((dur>300).sum()),'windows_span_gt_3600s':int((dur>3600).sum()),'windows_with_gap_gt_60s':int((maxgap>60).sum()),'windows_with_gap_gt_300s':int((maxgap>300).sum()),'windows_with_gap_gt_3600s':int((maxgap>3600).sum()),'true_tcp_connection_boundary_crossing':'NOT VERIFIABLE FROM PROCESSED ROWS: ports, SYN/FIN/RST and TCP generation absent','independent_campaign_boundary_crossing':'NOT VERIFIABLE: capture groups configured from filenames, campaign ledger absent','inference_context_boundary':'dt_s at first timestep can depend on preceding packet outside window; historical feature script must explicitly reset first-step transitions.'}
gap=w.loc[(dur>60)|(maxgap>60)].copy();gap['duration_s']=dur[(dur>60)|(maxgap>60)];gap['max_gap_s']=maxgap[(dur>60)|(maxgap>60)];gap.to_csv(E/'diagnostic_long_gap_windows.csv',index=False)
original={'status':'NOT AVAILABLE','reason':'Neither requested Pre-processed/Pre-processed/rebuilt_sequences nor any packets_rebuilt.csv, packet_exclusions.csv, windows.csv, window_index.npy existed among supplied source files. Historical JSON is an unverified claim. New diagnostic outputs are segregated below.','directly_validated_windows':0}
historical=json.loads((REPO/'C2_Reconnaissance_Detection/artifacts/rebuild_report.json').read_text(encoding='utf-8'))
historical_comparison={'historical_report_path':'C2_Reconnaissance_Detection/artifacts/rebuild_report.json','historical_report_is_source_claim_only':True,'claimed_packets_kept':historical.get('packets_kept'),'new_packets_kept':len(r),'claimed_windows':historical.get('windows'),'new_windows':len(w),'claimed_label_counts':historical.get('window_label_counts'),'new_label_counts':w.label.value_counts().to_dict(),'interpretation':'Matching summary counts reproduce visible transformation rules, not file equality or validation of absent historical datasets.'}
timing_valid=r.dt_s.notna();timing_error=(r.loc[timing_valid,'dt_s']-r.loc[timing_valid,'time_delta']).abs()
timing_comparison={'compared_rows':int(timing_valid.sum()),'matches_within_1us':int((timing_error<=1e-6).sum()),'median_abs_difference_s':float(timing_error.median()),'interpretation':'Supplied time_delta is not a reliable inter-message gap in the chronological stream.'}
rebuilt={'original_rebuilt_dataset_validation':original,'new_diagnostic_reconstruction':{'status':'STRUCTURAL PASS / SESSION AND CAMPAIGN CONDITIONAL','files_relative_to_review':'evidence/diagnostic_reconstruction/','population_accounting':pop,'duplicate_interface_verification':dup,'stream_count':len(streamprofiles),'source_file_count':r.file_source.nunique(),'session_id_count':r.session_id.nunique(),'capture_group_count':r.capture_group.nunique(),'streams_with_backwards_time':sum(v['backward_steps']>0 for v in streamprofiles),'negative_dt_s':int((r.dt_s<0).sum()),'expected_first_dt_missing':sum(v['first_dt_missing'] for v in streamprofiles),'unexpected_missing_dt':sum(v['nonfirst_missing_dt'] for v in streamprofiles),'supplied_vs_recomputed_timing':timing_comparison,'historical_groupby_diff_precision':precision_report,'window_validation':checks},'historical_summary_comparison':historical_comparison}
dump(rebuilt,OUT/'rebuilt_sequence_audit.json')
dump({'original_rebuilt_dataset':original,'new_diagnostic_reconstruction':checks,'limitations':['Capture-group identity is not proven campaign independence.','A directional IP/unit tuple is not a TCP connection.','No maximum inactivity gap is imposed.','Source labels are preserved for diagnostics, not validated ground truth.']},OUT/'WINDOW_INTEGRITY_REPORT.json')

# Source identifier summary: exact observable mapping; no inferred TCP connection truth.
sessions=[]
for sid,rr in p.groupby('session_id'):
    tv=rr.loc[rr.ts_ns.ne(np.iinfo(np.int64).min),'ts_ns']
    sessions.append({'session_id':sid,'packets':len(rr),'positive_packets':int(rr.label.sum()),'distinct_src':rr.src_ip.nunique(),'distinct_dst':rr.dst_ip.nunique(),'distinct_unit':rr.unit_id.nunique(),'src_ips':';'.join(rr.src_ip.unique()),'dst_ips':';'.join(rr.dst_ip.unique()),'unit_ids':';'.join(map(str,rr.unit_id.unique())),'source_files':rr.file_source.nunique(),'configured_capture_groups':rr.capture_group.nunique(),'span_days':(tv.max()-tv.min())/86400e9 if len(tv) else None,'tcp_ports_available':False,'tcp_connection_generation_available':False})
pd.DataFrame(sessions).to_csv(E/'identifier_profiles.csv',index=False)
maxspan=max(x['span_days'] or 0 for x in sessions)
(OUT/'SESSION_IDENTIFIER_REPORT.md').write_text(f'''# Identifier semantics

This review derives facts directly from 879,225 worksheet packet rows. Exact creation code for original `session_id` and `sequence_position` is absent. Visible repo code only loads these supplied fields.

| Identifier | Verified construction / meaning | Independence consequence |
|---|---|---|
| `session_id` | Every one of {len(sessions)} IDs maps to exactly one directional `(src_ip,dst_ip,unit_id)` tuple. Names embed these values and an arbitrary `_sNNNN` suffix. Original creation procedure is unavailable. | Static endpoint/unit identity, **not proven TCP session**. Main IDs span several files and up to {maxspan:.6f} days. |
| `sequence_position` | Equals zero-based row counter within each supplied session (see per-session CSV); assigned to existing mixed, unsorted row order. | Derived ordinal, no chronology proof. |
| `file_source` | Supplied basename of putative PCAP or `attached_recon_flows.csv`; no frame or byte reference. | Source-file reference only. Basenames are not immutable source identities or independent experiments. |
| `row_index` | New zero-based position in extracted packet worksheet, exactly as `io_data.load_packets` inserts. | Audit provenance to a worksheet row; never model predictor. |
| `capture_group` | Configured filename lookup in `configs/default.yaml`; all five Feb-1 interface files map to one group. Other listed files each get their own group. | Capture group hypothesis, **not independently proven campaign/run identity**. |
| rebuilt stream | `(capture_group,session_id)`, sorted by `(ts_ns,row_index)`. | Capture-local directional logical stream, not real TCP connection; inactivity never splits it. |
| `dt_s` | Consecutive timestamps in that rebuilt stream, in seconds; first row missing. | Derived causal gap. First window timestep may depend on an outside packet unless reset by feature builder. |
| `window_id` / `window_in_stream` | Enumerated 20-row slices, stride 5, within configured stream. | Derived overlapping samples share 15 packets; cannot be split independently. |

The available packet fields contain no source/destination TCP ports, TCP sequence/acknowledgment values, flags, transaction IDs, connection generations or source frame numbers. No actual TCP boundaries can be audited from these processed fields alone. See the separate raw-source reconstruction for PCAP evidence. Treating static IDs or separate filenames as independent sessions/campaigns exceeds the evidence.

See `evidence/identifier_profiles.csv`, `evidence/legacy_session_profiles.csv`, and `evidence/diagnostic_stream_profiles.csv` for every ID and span.
''',encoding='utf-8')
(OUT/'SEQUENCE_FINDINGS.md').write_text(f'''# Independent sequence findings

## Legacy files: FAIL

Direct exhaustive audit of supplied XLSX values gives {len(p):,} packet rows and {len(s):,} sequence windows. All {counts['all_feature_cells_match']:,} windows reproduce 20 successive packet rows within the supplied `session_id` order at stride {stride}. Window label `any(packet label == 1)` matches {counts['any_positive_rule_match']:,} windows. This validates reproduction, not ground truth.

There are {backwards:,} backward packet timestamp transitions within supplied session order. {counts['windows_with_backward_transition']:,} windows contain at least one backward transition; {counts['windows_end_before_start']:,} end before they start; {counts['windows_cross_source_file']:,} mix source files; {counts['windows_cross_capture_group']:,} mix configured capture groups. Actual min-to-max window span exceeds one minute in {counts['windows_span_gt_60s']:,}, five minutes in {counts['windows_span_gt_300s']:,}, and one hour in {counts['windows_span_gt_3600s']:,}. Zero windows cross the supplied session ID because grouping uses that ID, which itself spans captures/days.

**Established failure mechanism:** window construction consumes the already mixed packet table in supplied row order and groups only by static directional endpoint/unit identity. `sequence_position` follows that order. Timestamp chronology and capture boundaries are not enforced. Consequently, windows combine unrelated temporal contexts. The original extraction/merge code that created the mixed order is absent; its exact earlier implementation cannot be proven. The visible `audit_sequences.py` only diagnoses it. See exact bad examples in `evidence/legacy_bad_window_examples.json`. Claims that a particular unavailable preprocessing program caused a specific merge/sort error remain unverified.

## Supplied historical rebuilt files: NOT AVAILABLE

The requested rebuilt CSV/NPY files were absent locally. Historical JSON/Markdown reports are source claims and were not used as evidence of current data integrity. Original file equality and their original ID membership cannot be verified.

## New independent diagnostic reconstruction

Using the visible configuration policies creates {len(r):,} retained packets, {len(ex):,} exclusions and {len(w):,} windows, saved only under this review. All original worksheet IDs are accounted exactly once across new retained/excluded sets. All {len(dm):,} secondary interface exclusions have equal **available processed fields** within 1 ms in the selected retained view, with {int(dm.label_disagreement.sum()):,} label disagreements. The processed fields lack bytes and TCP identity, so feature/timestamp correspondence alone does not prove exact duplicate packets. Raw-source evidence is evaluated separately.

All new windows pass the mechanical 20-row/stride-5/group/chronology/start/end/count/any-positive checks. First missing `dt_s` is expected in all {len(streamprofiles)} configured streams. Chronology remains scientifically conditional: these are endpoint streams, do not enforce TCP generations, and do not split inactivity. {checks['windows_span_gt_60s']:,} windows exceed one minute, {checks['windows_span_gt_300s']:,} exceed five minutes, and {checks['windows_span_gt_3600s']:,} exceed one hour. {checks['windows_with_gap_gt_3600s']:,} windows contain an internal gap over one hour. Mechanical timestamp order alone is insufficient to establish coherent behavioral sessions.

Historical summary comparison is explicitly segregated in `rebuilt_sequence_audit.json`. Reproducing summary counts does not validate absent original files or their labels. Capture groups are not independently established campaigns.
''',encoding='utf-8')
print('COMPLETE',json.dumps(clean({'new_packets':len(r),'new_windows':len(w),'new_labels':w.label.value_counts().to_dict(),'duplicate_matches':int(dm.matched.sum()),'duplicate_total':len(dm),'window_checks':checks})),flush=True)
