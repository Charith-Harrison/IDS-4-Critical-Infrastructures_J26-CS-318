"""Descriptive temporal evidence and exact-shape lookalikes. No model fitting."""
from pathlib import Path
import sys,json
import numpy as np
import pandas as pd

R=Path(__file__).resolve().parents[1];E=R/'evidence'
FEATURES=['previous_request_delta_s','address_delta','absolute_address_delta','unique_addresses_previous20',
    'register_span_previous20','monotonic_increasing_fraction_previous20','function_transitions_previous20',
    'previous20_interval_mean_s','previous20_interval_cv','previous20_requests_per_s']
SHAPE=['func_code','quantity_value','modbus_len','packet_size','unit_id']

def stat(a):
    a=pd.to_numeric(pd.Series(a),errors='coerce').dropna()
    return dict(n=len(a),mean=float(a.mean()) if len(a) else None,**{
        k:float(a.quantile(q)) if len(a) else None for k,q in [('min',0),('p25',.25),('median',.5),('p75',.75),('p95',.95),('max',1)]})

def mdtable(d):return d.to_markdown(index=False) if False else '\n'.join(['| '+' | '.join(map(str,d.columns))+' |','| '+' | '.join(['---']*len(d.columns))+' |']+['| '+' | '.join(map(str,x))+' |' for x in d.itertuples(index=False,name=None)])

def main():
    all_candidates=pd.read_csv(R/'recon_request_candidates.csv')
    c=all_candidates[all_candidates.label_state.isin(['supported_exact','supported_contextual'])].copy()
    ambiguous=all_candidates[~all_candidates.label_state.isin(['supported_exact','supported_contextual'])].copy()
    n=pd.read_csv(E/'benign_read_request_evidence.csv');sh=pd.read_csv(E/'benign_request_shapes.csv')
    if 'context_sampling' in n:
        ns=n[n.context_sampling.eq('systematic_every_100_per_logical_stream')].copy()
    else:ns=n.copy()
    rows=[]
    for cohort,d in [('supported_contextual_recon_requests',c),('ambiguous_recon_request_candidates',ambiguous),('documented_benign_systematic_sample',ns)]:
        for scope,dd in [('full20_prior_context',d[d.previous_context_n>=20]),('partial_prior_context',d[d.previous_context_n<20])]:
            for f in FEATURES:rows.append(dict(cohort=cohort,feature=f,context=scope+';logical_endpoint_unit_max_gap60s',**stat(dd[f])))
    pd.DataFrame(rows).to_csv(R/'temporal_signal_analysis.csv',index=False)
    normal_shape=sh.groupby(SHAPE)['count'].sum();normal_full=sh.groupby(SHAPE+['address'])['count'].sum()
    look=[]
    for key,cc in c.groupby(SHAPE,dropna=False):
        kk=tuple(int(x) for x in key)
        normal_count=int(normal_shape.get(kk,0));full_count=sum(int(normal_full.get(kk+(int(a),),0)) for a in cc.address.unique())
        look.append(dict(zip(SHAPE,kk))|dict(candidate_requests=len(cc),candidate_unique_addresses=int(cc.address.nunique()),
            benign_requests_same_shape=normal_count,benign_requests_same_shape_and_candidate_address=full_count,
            matching_status='overlap_present' if normal_count else 'no_match_in_all_canonical_benign_read_requests'))
    look=pd.DataFrame(look);look.to_csv(R/'normal_lookalike_analysis.csv',index=False)
    matched=[];match_candidates=0
    for key,cc in c.groupby(SHAPE,dropna=False):
        mask=np.ones(len(ns),bool)
        for f,v in zip(SHAPE,key):mask&=ns[f].to_numpy()==v
        nn=ns[mask];cf=cc[cc.previous_context_n>=20];nf=nn[nn.previous_context_n>=20]
        if int(normal_shape.get(tuple(int(x) for x in key),0))>0:match_candidates+=len(cc)
        for f in FEATURES:
            matched.append(dict(zip(SHAPE,key))|dict(feature=f,recon_contexts_full20=len(cf),normal_sample_contexts_full20=len(nf),
                recon_median=stat(cf[f])['median'],normal_median=stat(nf[f])['median'],
                recon_p25=stat(cf[f])['p25'],recon_p75=stat(cf[f])['p75'],
                normal_p25=stat(nf[f])['p25'],normal_p75=stat(nf[f])['p75']))
    pd.DataFrame(matched).to_csv(E/'matched_shape_temporal_analysis.csv',index=False)
    example=[]
    for run,cc in c.groupby('capture_run'):
        cc=cc.sort_values('timestamp_us')
        for _,row in cc.head(32).iterrows():
            example.append({k:row.get(k) for k in ['candidate_id','capture_run','source_relative_path','frame_identity','timestamp_us',
                'src_ip','dst_ip','func_code','address','quantity_value','transaction_id','attack_log_reference','previous_context_n',*FEATURES]})
    pd.DataFrame(example).to_csv(E/'temporal_candidate_examples.csv',index=False)
    summary=dict(candidate_requests=len(all_candidates),supported_contextual_requests=len(c),ambiguous_or_other_candidates=len(ambiguous),
        contextual_candidates_by_family=c.capture_run.value_counts().to_dict(),
        candidate_states=all_candidates.label_state.value_counts().to_dict(),benign_all_read_requests=int(sh['count'].sum()),
        benign_saved_contexts=len(n),benign_systematic_contexts=len(ns),
        candidate_requests_with_exact_shape_benign_overlap=match_candidates,
        candidate_requests_without_exact_shape_benign_overlap=len(c)-match_candidates,
        candidate_full_previous20_contexts=int(c.previous_context_n.ge(20).sum()),candidate_partial_previous20_contexts=int(c.previous_context_n.lt(20).sum()),
        candidate_unit_ids=sorted(map(int,c.unit_id.unique())),candidate_target_ips=sorted(c.dst_ip.unique().tolist()),
        candidate_start_addresses=c.address.value_counts().to_dict(),candidate_quantities=c.quantity_value.value_counts().to_dict(),
        unit_enumeration_observed=bool(c.unit_id.nunique()>1),
        current_message_shape_normalization='exact FC,quantity,MBAP length,captured frame length,unit; address overlap additionally reported',
        evidence_limits=['contextual log matches are not exact ground truth','normal packet shape counts are complete within canonical benign HMI view',
            'benign temporal distributions are deterministic every100 request sample; shape exemplars excluded from distributions',
            'raw temporal history is logical actor/target/unit, not one TCP connection; gap limit60s chosen for diagnosis',
            'all history excludes future events; no train preprocessing, classification, tuning or LSTM here',
            'marginal or shape-matched timing differences do not prove generalization across independent runs'])
    (E/'temporal_signal_summary.json').write_text(json.dumps(summary,indent=2,default=str))
    # Standalone scientific figure, exported alongside source numerical tables.
    sys.path.insert(0,str(R/'.deps'))
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    (R/'figures').mkdir(exist_ok=True)
    fig,axes=plt.subplots(1,3,figsize=(12,3.8))
    for ax,col,title in zip(axes,['unique_addresses_previous20','previous20_interval_mean_s','monotonic_increasing_fraction_previous20'],
        ['Unique prior addresses','Prior inter-request interval (s)','Increasing-address fraction']):
        aa=pd.to_numeric(c.loc[c.previous_context_n>=20,col],errors='coerce').dropna()
        bb=pd.to_numeric(ns.loc[ns.previous_context_n>=20,col],errors='coerce').dropna()
        ax.boxplot([bb,aa],tick_labels=['Benign sample','Recon candidates'],showfliers=False)
        ax.set_title(title,fontsize=10);ax.grid(axis='y',alpha=.2)
        if 'interval' in col:ax.set_yscale('symlog',linthresh=.001)
    fig.suptitle('Causal request context: descriptive evidence, 20 prior requests',fontsize=12)
    fig.text(.5,.01,'Source-family differences and packet-shape confounding remain. Candidates carry contextual labels.',ha='center',fontsize=8)
    fig.tight_layout(rect=(0,.05,1,.94));fig.savefig(R/'figures/temporal_context_distributions.png',dpi=180);plt.close(fig)
    short=json.loads((E/'shortcut_summary.json').read_text())['diagnostic_reconstruction']
    fig,ax=plt.subplots(figsize=(7,3.8))
    ax.barh(['Positive packets','Positive windows'],[100*short['len3_positive_packets']/short['positives'],100*short['len3_positive_windows']/short['positive_windows']],color=['#b03a2e','#ce6b59'])
    ax.set_xlim(0,100);ax.set_xlabel('Percentage containing Modbus length 3');ax.set_title('Inherited labels have a dominant static response shortcut')
    ax.text(2,-.08,f"{short['len3_positive_packets']:,}/{short['positives']:,}",color='white');ax.text(2,.92,f"{short['len3_positive_windows']:,}/{short['positive_windows']:,}",color='white')
    ax.grid(axis='x',alpha=.2);fig.tight_layout();fig.savefig(R/'figures/static_shortcut_coverage.png',dpi=180);plt.close(fig)
    text=f'''# Temporal reconnaissance evidence and normal lookalikes

This is descriptive source reconstruction. No LSTM was fitted, and no classification score is used as proof of temporal learning.

The raw recovery retained **{len(all_candidates):,} request candidates**: **{len(c):,} supported-contextual requests** and **{len(ambiguous):,} ambiguous/other candidates**. Ambiguous candidates remain separate and are not treated as attack targets in the main comparison. The canonical documented-benign HMI view contains **{int(sh['count'].sum()):,} read requests** across all its rotation chunks. All current-message shapes were counted. Causal contexts were sampled every100 requests per logical actor/target/unit stream; first-three shape exemplars are retained for traceability but excluded from the temporal distribution sample.

**{match_candidates:,}/{len(c):,} candidates** have a benign counterpart sharing FC, quantity, MBAP length, frame length and unit. Exact requested-address overlap is separately tabulated below. Absence of a counterpart refers to this canonical benign view, not every possible legitimate deployment.

{mdtable(look)}

The feature distributions are in `temporal_signal_analysis.csv`; within-shape, full20-context comparisons are in `evidence/matched_shape_temporal_analysis.csv`. `evidence/temporal_candidate_examples.csv` gives source/frame/log references. The candidate-only sequence is a subsequence of all requests, so gaps between candidate rows must not be mistaken for the actual polling interval. The `previous_*` columns instead use all preceding parsed requests, causally, with a60s idle reset.

Unit IDs observed among candidates: **{summary['candidate_unit_ids']}**. Requested start-address counts: **{summary['candidate_start_addresses']}**. Quantities: **{summary['candidate_quantities']}**. A range read from one address is not evidence of a sequential sweep over start addresses. Multiple read functions or targets do not establish unit-ID enumeration when the unit is constant.

The figures show marginal distributions before matching; they must not be interpreted as a controlled temporal ablation. Where current-message shapes do not overlap, differences may already be explained by packet contents. Where they do overlap, causal histories can reveal observable timing or access-pattern differences, but source-family and repeated-episode dependencies remain. This audit establishes observations and limitations; it does not establish temporal generalization or an independent three-way experiment.

Raw controls taken from attack recordings are separately marked unlabeled and never called benign solely because no nearby recon log start was found. The documented-benign comparison above uses the explicit benign source scenario.
'''
    (R/'TEMPORAL_SIGNAL_REPORT.md').write_text(text,encoding='utf8')
    print(json.dumps(summary,indent=2,default=str),flush=True)

if __name__=='__main__':main()
