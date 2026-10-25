"""Describe current split feasibility from completed evidence, never invent a split."""
from pathlib import Path
import json,re
import pandas as pd

OUT=Path(__file__).resolve().parents[1]
E=OUT/'evidence'

def main():
    metrics_path=E/'raw_recovery_metrics.json'
    if not metrics_path.exists():
        raise SystemExit('Completed canonical raw_recovery_metrics.json is required before finalizing split evidence.')
    m=json.loads(metrics_path.read_text(encoding='utf-8'))
    c=pd.read_csv(OUT/'recon_request_candidates.csv')
    raw_verified=c[c.raw_source_verified.eq(True)] if 'raw_source_verified' in c else c.iloc[:0]
    states=raw_verified.label_state.value_counts().to_dict() if len(raw_verified) else {}
    supported=raw_verified[raw_verified.label_state.isin(['supported_exact','supported_contextual'])]
    date_col=raw_verified.timestamp.astype(str).str[:10] if len(raw_verified) else pd.Series(dtype=str)
    candidates_by_family=raw_verified.groupby('capture_run').size().to_dict() if len(raw_verified) else {}
    dates_by_family={str(g):sorted(d.timestamp.astype(str).str[:10].unique().tolist()) for g,d in raw_verified.groupby('capture_run')} if len(raw_verified) else {}
    refs=set()
    if len(raw_verified):
        for s in raw_verified.attack_log_reference.dropna(): refs.update(re.split(r';(?=attack/)',str(s)))
    original_log_inv=json.loads((E/'original_log_inventory.json').read_text())
    rot=sorted([x for x in m.get('file_reports',[]) if x.get('canonical') and '/substation-wide-capture/' in x.get('source','')],key=lambda x:x['min_timestamp_us'])
    boundaries=[]
    for previous,current in zip(rot,rot[1:]):
        gap=current['min_timestamp_us']-previous['max_timestamp_us']
        boundaries.append({'previous_chunk':previous['source'],'next_chunk':current['source'],
            'previous_end_us':previous['max_timestamp_us'],'next_start_us':current['min_timestamp_us'],
            'boundary_gap_us':gap,'boundary_gap_s':gap/1e6,
            'interpretation':'rotation_continuity_supported' if 0<=gap<=1_000_000 else 'gap_or_overlap_requires_source_interpretation'})
    pd.DataFrame(boundaries).to_csv(E/'rotation_continuity_independent_check.csv',index=False)
    verified_independent_attack_campaign_count=None
    result={
        'status':'UNSUPPORTED',
        'question':'Can the currently reconstructed CIC evidence support a class-complete independent fit/validation/test experiment for temporal reconnaissance?',
        'scope':'Completed source-byte candidate recovery in this review; no claim that the entire CIC archive has been exhausted by a bounded extractor',
        'reason':'Raw contextual requests are recovered, but no source-backed independent run/campaign boundary within the recording families has been established. PCAP rotations, mirrors, dates, static sessions and repeated log invocations cannot supply manufactured independence.',
        'raw_recon_request_evidence':{
            'raw_source_verified_candidate_rows':int(len(raw_verified)),
            'label_state_counts':{str(k):int(v) for k,v in states.items()},
            'supported_request_candidates_excluding_ambiguous':int(len(supported)),
            'ambiguous_request_candidates_not_final_positive_labels':int(states.get('ambiguous',0)),
            'supported_requests_by_recording_family':{str(k):int(v) for k,v in supported.groupby('capture_run').size().items()} if len(supported) else {},
            'candidate_rows_by_conservative_recording_family':{str(k):int(v) for k,v in candidates_by_family.items()},
            'observed_positive_recording_families':len(candidates_by_family),
            'candidate_rows_by_capture_chunk':{str(k):int(v) for k,v in raw_verified.capture_chunk.value_counts().items()} if len(raw_verified) else {},
            'candidate_observation_dates':sorted(date_col.unique().tolist()),
            'candidate_dates_by_recording_family':dates_by_family,
            'supported_candidate_observation_dates':sorted(supported.timestamp.astype(str).str[:10].unique().tolist()),
            'distinct_original_log_row_references_attached_to_candidates':len(refs),
            'all_source_recon_log_rows':original_log_inv.get('recon_rows'),
            'all_source_valid_distinct_start_signatures':original_log_inv.get('distinct_start_signatures'),
            'counts_are_independent_campaigns':False,
            'final_target_labels_frozen':False,
        },
        'independence':{
            'verified_independent_attack_campaign_count':verified_independent_attack_campaign_count,
            'unknown_is_not_zero_campaigns':True,
            'minimum_distinct_class_bearing_units_for_three_disjoint_partitions':3,
            'minimum_unit_count_is_not_sample_size_justification':True,
            'independent_train_validation_test_supported':False,
            'run_reset_or_acquisition_ledger_available_for_recovered_CIC_units':False,
            'configured_capture_groups_are_verified_campaigns':False,
            'SCADA_chunks_in_source_time_order':[x['source'] for x in rot],
            'SCADA_adjacent_chunk_boundaries_with_gap_at_most_1_second':sum(0<=x['boundary_gap_us']<=1_000_000 for x in boundaries),
            'SCADA_continuous_rotation_evidence':'See evidence/rotation_continuity_independent_check.csv; canonical source boundaries computed independently from observed first/last frame times, not inferred from names.',
            'conservative_dependency_unit':'Whole scenario recording family until finer independence is supported by source acquisition/episode evidence',
            'rotation_rule':'All sequential chunks from a continuous capture remain together',
            'mirror_rule':'Canonical and mirrored observations, including byte/sequence/time matches, remain together',
            'episode_rule':'All requests/responses, tool-invocation context and overlapping windows from an episode remain together',
        },
        'current_possible_analyses':[
            'Descriptive raw-request mechanism and temporal distributions versus documented benign source traffic',
            'Historical supplied-label static shortcut diagnostics, explicitly not recon-ground-truth model validation',
            'Exploratory recording-family-held-out diagnostics only when valid labels and both classes exist; never presented as confirmatory independent three-way evaluation',
        ],
        'prohibited_shortcuts':[
            'Random row or window splitting',
            'Separating rotated chunks, mirrors or the same attack episode across partitions',
            'Calling each date, TCP connection, static endpoint tuple or log row an independent campaign',
            'Using labels, audit state, confidence, log references or group identity as model predictors',
            'Treating absence of a nearby attack log as benign truth',
            'Fitting scaler, imputer, encoding, class rebalance or threshold outside training/validation discipline',
        ],
        'future_split_contract':{
            'partition_assignment_file':None,
            'frozen_predictor_schema':None,
            'same_target_event_ids_across_all_models':True,
            'same_campaign_partitions_across_all_models':True,
            'target_context':'Prespecified current request t and its causal last20 context, or explicitly frozen any-positive windows, identical for all models',
            'fit_preprocessing_on':'training groups only',
            'choose_threshold_and_early_stop_on':'validation groups only',
            'test_access':'once after prespecification and validity gate',
            'required_zero_overlap':['original messages','mirrored views','TCP retransmissions','window dependencies','attack episodes','capture campaigns'],
        },
        'normal_lookalike_truth':'See temporal/normal-lookalike evidence. Benign-source requests are legitimate controls; attack-recording no-match samples are unlabelled lookalikes, not automatic negatives.',
        'CIC_archive_globally_insufficient_claimed_by_this_file':False,
        'testbed_supplement_design':'TESTBED_SUPPLEMENT_DESIGN.md; conditional on completed full-report suitability verdict',
        'final_preprocessing_performed':False,
        'final_LSTM_trained':False,
        'random_split_performed':False,
    }
    (OUT/'split_feasibility.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':result['status'],'candidate_rows':len(raw_verified),'recording_families':candidates_by_family,'independent_campaign_count':verified_independent_attack_campaign_count},indent=2))

if __name__=='__main__':main()
