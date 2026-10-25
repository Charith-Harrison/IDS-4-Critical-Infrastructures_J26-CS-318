"""Bounded consistency QA of finalized benign/temporal outputs; no source rewrite."""
from pathlib import Path
import json,sys,importlib.util,struct
import numpy as np
import pandas as pd
sys.dont_write_bytecode=True
O=Path(__file__).resolve().parents[1];E=O/'evidence'
spec=importlib.util.spec_from_file_location('temporal_qa_pcapio',O/'scripts/pcapio.py')
pc=importlib.util.module_from_spec(spec);sys.modules[spec.name]=pc;spec.loader.exec_module(pc)
c=pd.read_csv(O/'recon_request_candidates.csv');b=pd.read_csv(E/'benign_read_request_evidence.csv');sh=pd.read_csv(E/'benign_request_shapes.csv')
t=pd.read_csv(O/'temporal_signal_analysis.csv');lo=pd.read_csv(O/'normal_lookalike_analysis.csv')
m=json.loads((E/'temporal_signal_summary.json').read_text());bm=json.loads((E/'benign_raw_extraction.json').read_text());errors=[]
def check(condition,detail):
    if not condition:errors.append(detail)
s=c[c.label_state.isin(['supported_exact','supported_contextual'])];a=c[~c.label_state.isin(['supported_exact','supported_contextual'])]
n=b[b.context_sampling.eq('systematic_every_100_per_logical_stream')]
check(len(c)==m['candidate_requests'],'candidate total summary')
check(len(s)==m['supported_contextual_requests'],'supported contextual summary')
check(len(a)==m['ambiguous_or_other_candidates'],'ambiguous summary')
check(int(sh['count'].sum())==m['benign_all_read_requests']==bm['counts']['read_requests'],'benign census totals')
check(len(b)==m['benign_saved_contexts']==bm['counts']['context_rows_saved'],'benign saved contexts')
check(len(n)==m['benign_systematic_contexts'],'systematic sample total')
check((n.read_request_ordinal_in_logical_stream%100==0).all(),'every100 systematic sample flags')
check(not b.duplicated(['source_relative_path','frame_identity','adu_offset_in_tcp_payload']).any(),'duplicate benign sample ADU identities')
check(len(bm['files'])==19,'canonical benign chunk count')
check(sum(x['counts']['read_requests'] for x in bm['files'])==int(sh['count'].sum()),'per-file benign request accounting')
check((sh.quantity_value==1).all() and (sh.modbus_len==6).all() and (sh.packet_size==78).all(),'benign packet shape claim')
check(int(lo.candidate_requests.sum())==len(s),'lookalike supported target population')
check((lo.benign_requests_same_shape==0).all(),'no matched normal shape claim')
features=['previous_request_delta_s','address_delta','absolute_address_delta','unique_addresses_previous20','register_span_previous20','monotonic_increasing_fraction_previous20','function_transitions_previous20','previous20_interval_mean_s','previous20_interval_cv','previous20_requests_per_s']
for name,df in [('supported_contextual_recon_requests',s),('ambiguous_recon_request_candidates',a),('documented_benign_systematic_sample',n)]:
    check(df.previous_context_n.between(0,20).all(),name+' prior context bounds')
    check(df.previous_request_delta_s.dropna().ge(0).all(),name+' negative prior gap')
    check(df.unique_addresses_previous20.le(df.previous_context_n).all(),name+' unique prior addresses exceeds history')
    check(df.monotonic_increasing_fraction_previous20.dropna().between(0,1).all(),name+' monotonic fraction bounds')
    check(df.function_transitions_previous20.le((df.previous_context_n-1).clip(lower=0)).all(),name+' function transition count bounds')
    for scope,dd in [('full20_prior_context',df[df.previous_context_n>=20]),('partial_prior_context',df[df.previous_context_n<20])]:
        for f in features:
            rr=t[(t.cohort==name)&t.context.str.startswith(scope)&t.feature.eq(f)]
            check(len(rr)==1,name+' '+scope+' '+f+' row uniqueness')
            if len(rr)!=1:continue
            rr=rr.iloc[0];v=dd[f].dropna()
            check(int(rr['n'])==len(v),name+' '+scope+' '+f+' n')
            if len(v):check(abs(float(rr['median'])-float(v.median()))<1e-9,name+' '+scope+' '+f+' median')
# Source-check one mid-record systematic request from every benign file, without rescanning it.
sample=[]
for _,g in n.groupby('source_relative_path'):
    row=g.iloc[len(g)//2];path=Path(row.source_reference)
    with path.open('rb') as fh:
        h=pc.open_pcap(fh);fh.seek(int(row.pcap_record_offset));sec,frac,caplen,_=struct.unpack(h.endian+'IIII',fh.read(16));data=fh.read(caplen)
    _,seg=pc.decode_l2l3l4(data,h.linktype);off=int(row.adu_offset_in_tcp_payload);adu=bytes.fromhex(str(row.adu_hex))
    check(seg.payload[off:off+len(adu)]==adu,'benign source ADU '+row.source_relative_path)
    check(sec*1_000_000+frac*1_000_000//h.ticks_per_second==int(row.timestamp_us),'benign source timestamp '+row.source_relative_path)
    check(seg.dst_port==502 and adu[7] in [1,2,3,4] and int.from_bytes(adu[10:12],'big')==1,'benign source request role '+row.source_relative_path)
    sample.append(dict(source_relative_path=row.source_relative_path,frame_identity=int(row.frame_identity),pcap_record_offset=int(row.pcap_record_offset)))
result={'candidate_rows':len(c),'supported_contextual_rows':len(s),'ambiguous_rows':len(a),'benign_census_read_requests':int(sh['count'].sum()),'benign_saved_context_rows':len(b),'benign_systematic_rows':len(n),'benign_full20_systematic_rows':int(n.previous_context_n.ge(20).sum()),'source_byte_sample_files':len(sample),'source_byte_samples':sample,'temporal_distribution_rows':len(t),'errors':errors,'all_performed_checks_pass':len(errors)==0,'limitations':['Benign population counts are checked against extracted per-file totals; this bounded QA does not independently rescan 21.9 million frames.','Temporal context causality was reviewed in extraction code; full histories are not independently reconstructed here.','No matched normal current-message shapes were found in this canonical census, so the temporal novelty comparison remains unsupported.']}
(E/'quality_temporal_checks.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in result.items() if k!='source_byte_samples'},indent=2))
