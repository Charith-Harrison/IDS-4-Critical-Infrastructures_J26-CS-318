"""Aggregate hypothetical chronological feasibility, never replacement splits."""
from collections import Counter, defaultdict

import pyarrow.compute as pc
import pyarrow.parquet as pq
from common import BASE, OUT, read, write, day


def run():
    accepted=read(OUT/'event_examples.json')['accepted_attacks']
    rec_view={'cic_benign_january':'benign_ied1b','cic_compromised_scada_march':'scada_ied1a','cic_compromised_ied_march':'ied_ied1b'}
    bounds={}
    for rec,view in rec_view.items():
        cp=read(BASE/f'output/extraction/{view}/checkpoint.json')
        inv={r['path']:r for r in read(BASE/'output/inventory.json')['files']}
        sources=[inv[s['path']]['capture'] for s in cp['contract']['sources']]
        lo=min(s['minimum_ts_us'] for s in sources);hi=max(s['maximum_ts_us'] for s in sources)
        bounds[rec]={'view':view,'first_us':lo,'last_us':hi,'probes_us':[lo+(hi-lo)//3,lo+2*(hi-lo)//3]}
    counts=Counter()
    for r in accepted:
        cuts=bounds[r['recording_id']]['probes_us']; phase=sum(r['ts_complete_us']>=t for t in cuts)
        counts[(phase,r['component_label'],r['parse_status'])]+=1
    normal_bounds=bounds['cic_benign_january']
    cuts=normal_bounds['probes_us']
    for b in pq.ParquetFile(BASE/'output/extraction/benign_ied1b/events.parquet').iter_batches(columns=['ts_complete_us']):
        x=b.column(0)
        n0=pc.sum(pc.cast(pc.less(x,cuts[0]),'int64')).as_py() or 0
        n1=pc.sum(pc.cast(pc.and_(pc.greater_equal(x,cuts[0]),pc.less(x,cuts[1])),'int64')).as_py() or 0
        counts[(0,'normal','ok')]+=n0;counts[(1,'normal','ok')]+=n1;counts[(2,'normal','ok')]+=len(x)-n0-n1
    boundary_counts=[]
    for rec,entry in bounds.items():
        for probe in entry['probes_us']:
            boundary_counts.append({'campaign':rec,'hypothetical_probe_us':probe,'day_utc':day(probe),
                'crossing_connection_generations':0,'crossing_pair_relations':0,'crossing_candidate_tool_intervals':0,
                'connection_ids_first_five':[]})
        items=[r for r in boundary_counts if r['campaign']==rec]
        for b in pq.ParquetFile(BASE/f"output/extraction/{entry['view']}/connections.parquet").iter_batches(columns=['conn_uid','first_ts_us','last_ts_us','midstream','gaps']):
            for r in b.to_pylist():
                for item in items:
                    if r['first_ts_us']<item['hypothetical_probe_us']<=r['last_ts_us']:
                        item['crossing_connection_generations']+=1
                        if len(item['connection_ids_first_five'])<5:item['connection_ids_first_five'].append(r['conn_uid'])
        for b in pq.ParquetFile(BASE/f"output/extraction/{entry['view']}/pairs.parquet").iter_batches(columns=['request_complete_us','response_complete_us']):
            for r in b.to_pylist():
                if r['request_complete_us'] is not None and r['response_complete_us'] is not None:
                    for item in items:
                        if r['request_complete_us']<item['hypothetical_probe_us']<=r['response_complete_us']:
                            item['crossing_pair_relations']+=1
    for b in pq.ParquetFile(BASE/'output/log_episodes.parquet').iter_batches(columns=['recording_id','start_ts_us','end_ts_us']):
        for r in b.to_pylist():
            if r['start_ts_us'] is not None and r['end_ts_us'] is not None:
                for item in boundary_counts:
                    if item['campaign']==r['recording_id'] and r['start_ts_us']<item['hypothetical_probe_us']<=r['end_ts_us']:
                        item['crossing_candidate_tool_intervals']+=1
    phases=[]
    for phase in range(3):
        classes={label:sum(n for (p,l,s),n in counts.items() if p==phase and l==label) for label in ('normal','command_injection','response_injection')}
        parse={label:{s:counts[(phase,label,s)] for s in ('ok','malformed','exception') if counts[(phase,label,s)]} for label in classes}
        phases.append({'diagnostic_phase':['early','middle','late'][phase], 'accepted_adu_counts':classes,'parse_counts':parse,
                       'all_three_classes_present_before_any_purge':all(classes.values()),
                       'is_train_validation_test_assignment':False})
    result={'claim_A':{'status':'UNSUPPORTED','basis':'Exactly one conservative capture campaign bears each accepted class. Additional days, rows, views and candidate-window recovery do not create independent campaigns.'},
        'claim_B_global_calendar':{'status':'UNSUPPORTED_WITH_FROZEN_LABELS','basis':'Documented normal January23–31, accepted commands March15–21 and responses March23–29 occupy separated calendar periods. No globally chronological class-complete repeated blocks exist from this frozen cohort.'},
        'claim_B_per_campaign_chronology':{'status':'CONDITIONAL_DIFFERENT_RESEARCH_OBJECTIVE_NOT_ADOPTED',
            'basis':'Predeclared one-third/two-third duration probes within each selected campaign provide an aggregate feasibility diagnostic. Corresponding phases combine different calendar periods and reuse the same campaigns/testbed, not independent generalization. No membership or replacement split generated.',
            'campaign_duration_probes':bounds,'aggregate_phase_counts_before_purge':phases,'boundary_crossings':boundary_counts},
        'purge_and_warmup_requirements':['Agree on the narrower academic objective before adopting a design.',
            'Expanded canonical coverage changes source spans and may reveal additional competitors; recompute all diagnostics before freezing anything.',
            'Do not cut any logged candidate tool interval or evidenced wire burst. Burst semantics remain uncertain without original tool source; connection containment is necessary but not sufficient.',
            'Move boundaries to verified quiet points or exclude entire crossing connections and dependent pairs; preserve a boundary ledger rather than deleting intervening rows.',
            'All mirrored observations remain one campaign. Canonical replacement must not append overlapping endpoint copies.',
            'Declare causal decision time, maximum event/time lookback and label horizon before setting purge duration. No universal seconds value is invented.',
            'Later K3/5/10 histories need warm-up exclusions after each boundary, reconnect and loss/gap; no history/windows are created here.',
            'Pending and late responses cannot be resolved across scored partitions; no capture-end status may leak into request-time predictors.'],
        'independent_episodes':'Not established. Original tool start/completion intervals and connection generations are audit units, not independent experiments.',
        'no_replacement_split_created':True}
    write('temporal_feasibility.json',result)
    print('temporal feasibility',[(p['diagnostic_phase'],p['accepted_adu_counts']) for p in phases],flush=True)
    return result


if __name__=='__main__':
    run()
