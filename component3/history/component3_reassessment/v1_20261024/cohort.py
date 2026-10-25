"""Reproduce immutable cohort and edge sensitivity; never accept new labels."""
from collections import Counter, defaultdict
import csv
import json
import time

import pyarrow.parquet as pq

from common import BASE, OUT, REVIEW, CONFIG, day, stats, write, read

WINDOWS = CONFIG['diagnostic_windows_us']
ROOT = BASE / 'output/extraction'


def rows(path, columns=None, filters=None):
    if filters:
        # Predicate-pushdown here reads audit subsets, not a model feature table.
        yield from pq.read_table(path, columns=columns, filters=filters).to_pylist()
    else:
        for batch in pq.ParquetFile(path).iter_batches(batch_size=20000, columns=columns):
            yield from batch.to_pylist()


def run():
    t0 = time.monotonic()
    views, accepted, event_targets = {}, {}, {}
    for folder in sorted(ROOT.iterdir()):
        annotations = folder / 'annotations.parquet'
        if not annotations.exists():
            continue
        count, states, targets = Counter(), Counter(), {}
        for r in rows(annotations, ['event_uid','component_label','annotation_state','label_evidence_refs','matched_log_signature_ids']):
            count[r['component_label'] or 'unlabelled'] += 1
            states[r['annotation_state']] += 1
            if r['component_label'] in ('command_injection', 'response_injection'):
                targets[r['event_uid']] = r
                event_targets[r['event_uid']] = r
        views[folder.name] = {'events': pq.ParquetFile(folder/'events.parquet').metadata.num_rows,
                             'labels': dict(count), 'states': dict(states)}
        if targets:
            for r in rows(folder/'events.parquet', filters=[('event_uid','in',list(targets))]):
                r.update(targets[r['event_uid']])
                accepted[r['event_uid']] = r
    pair_for = {}
    normal_covered = bytearray(views['benign_ied1b']['events'])
    normal_pair_states = Counter()
    for folder in sorted(ROOT.iterdir()):
        if not (folder/'pairs.parquet').exists():
            continue
        for p in rows(folder/'pairs.parquet'):
            if folder.name == 'benign_ied1b':
                normal_pair_states[p['status']] += 1
                for uid in (p['request_uid'], p['response_uid']):
                    if uid:
                        seq = int(uid.rsplit(':e',1)[1])
                        assert normal_covered[seq-1] == 0
                        normal_covered[seq-1] = 1
            for uid in (p['request_uid'],p['response_uid']):
                if uid in accepted:
                    pair_for[uid] = p
    assert all(normal_covered) and set(normal_pair_states) == {'matched'}
    joints, parse_counts, patterns = Counter(), Counter(), Counter()
    accepted_pair = Counter()
    for uid,r in accepted.items():
        p = pair_for.get(uid, {})
        r['pair_audit'] = p
        pstatus = p.get('status','no_relation')
        label = r['component_label']
        joints[(label,r['recording_id'],day(r['ts_complete_us']),r['client_ip'],r['server_ip'],r['func_code'],r['pdu_bytes'].hex(),r['parse_status'],pstatus)] += 1
        parse_counts[(label,r['parse_status'])] += 1
        patterns[(label,r['pdu_bytes'].hex())] += 1
        accepted_pair[(label,pstatus)] += 1
    normal_patterns = Counter()
    normal_control = Counter()
    cols = ['ts_complete_us','recording_id','client_ip','server_ip','func_code','protocol_role','address','pdu_bytes','parse_status']
    for r in rows(ROOT/'benign_ied1b/events.parquet', cols):
        key = ('normal',r['recording_id'],day(r['ts_complete_us']),r['client_ip'],r['server_ip'],r['func_code'],r['pdu_bytes'].hex(),r['parse_status'],'matched')
        joints[key] += 1
        if r['func_code'] == 5 and r['protocol_role'] == 'request':
            normal_patterns[r['pdu_bytes'].hex()] += 1
            normal_control[(r['server_ip'],r['address'],r['pdu_bytes'].hex(),day(r['ts_complete_us']))] += 1
    headers = ['class','campaign','utc_day','client','server','function','pdu_hex','parse_status','pair_state','adu_count']
    with (OUT/'accepted_class_campaign_day_endpoint_function_pdu_parse_pair.csv').open('w',newline='',encoding='utf8') as f:
        w=csv.writer(f); w.writerow(headers)
        for key,n in sorted(joints.items(),key=lambda x:str(x[0])):
            w.writerow([*key,n])
    scada = ROOT/'scada_ied1a'
    bad = set()
    for r in rows(scada/'connections.parquet',['conn_uid','retrans_conflicts','unverified_retrans_segments']):
        if r['retrans_conflicts'] or r['unverified_retrans_segments']:
            bad.add(r['conn_uid'])
    fc5 = {r['event_uid']: r for r in rows(scada/'events.parquet', filters=[('func_code','=',5),('protocol_role','=','request')])}
    eligible = {uid for uid,r in fc5.items() if r['conn_uid'] not in bad and not r['reasm_after_gap']}
    deg_event = {t:Counter() for t in WINDOWS}
    deg_log = {t:Counter() for t in WINDOWS}
    edge_counts = Counter()
    def edges():
        for r in rows(scada/'log_matches.parquet',['event_uid','log_signature_id','log_event_id','residual_us','family','behavior_supported','candidate_clock_offset_us','status']):
            if r['family']=='brute_force_or_specific_coil' and r['behavior_supported'] and r['candidate_clock_offset_us']==0 and r['event_uid'] in eligible:
                yield r
    for r in edges():
        for t in WINDOWS:
            if abs(r['residual_us']) <= t:
                deg_event[t][r['event_uid']] += 1
                deg_log[t][r['log_signature_id']] += 1
                edge_counts[t] += 1
    unique = {t:[] for t in WINDOWS}
    selected_edges = defaultdict(list)
    for r in edges():
        uid=r['event_uid']
        for t in WINDOWS:
            if abs(r['residual_us'])<=t and deg_event[t][uid]==1 and deg_log[t][r['log_signature_id']]==1:
                unique[t].append(r)
        if len(selected_edges[uid]) < 3:
            selected_edges[uid].append(r)
    sensitivity, sets = {}, {}
    for t, es in unique.items():
        evs=[fc5[e['event_uid']] for e in es]
        sets[t]={e['event_uid'] for e in es}
        sensitivity[str(t)]={'window_us':t,'eligible_edges':edge_counts[t],'two_sided_unique_candidates':len(es),
            'parse_status_counts':dict(Counter(e['parse_status'] for e in evs)),
            'pdu_patterns':dict(Counter(e['pdu_bytes'].hex() for e in evs)),
            'day_counts':dict(Counter(day(e['ts_complete_us']) for e in evs)),
            'residual_us':stats([e['residual_us'] for e in es]),
            'newly_diagnostic_not_accepted':len(sets[t] - set(accepted)),
            'frozen_accepted_retained':len(sets[t] & set(accepted)),
            'frozen_accepted_not_unique_at_this_window':len(set(uid for uid,r in accepted.items() if r['component_label']=='command_injection')-sets[t])}
    comparisons=[]
    for a,b in zip(WINDOWS,WINDOWS[1:]):
        comparisons.append({'from_us':a,'to_us':b,'retained':len(sets[a]&sets[b]),'appearing':len(sets[b]-sets[a]),'disappearing':len(sets[a]-sets[b]),
             'appearing_examples':sorted(sets[b]-sets[a])[:5],'disappearing_examples':sorted(sets[a]-sets[b])[:5]})
    diagnostic_uids=set.union(*sets.values())
    for r in rows(scada/'pairs.parquet'):
        uid=r['request_uid']
        if uid in diagnostic_uids:
            pair_for[uid]=r
    # Purposive, reproducible examples across days, shapes and identity outcomes.
    examples=[]
    seen=Counter()
    for uid,r in sorted(fc5.items(),key=lambda x:(x[1]['ts_complete_us'],x[0])):
        category='unique_25ms' if uid in sets[25000] else ('unique_1ms_only' if uid in sets[1000] else ('ambiguous_25ms' if deg_event[25000][uid] else 'unmatched_25ms'))
        key=(day(r['ts_complete_us']),r['parse_status'],category)
        if seen[key] >= 1:
            continue
        seen[key]+=1
        examples.append({'category':category,'diagnostic_only':True,'event':r,'edges_first_three':selected_edges.get(uid,[]),
                         'event_degree_25ms':deg_event[25000][uid], 'pair_audit':pair_for.get(uid),
                         'unique_at_windows_us':[t for t in WINDOWS if uid in sets[t]]})
    candidate_details=[]
    edge_map={e['event_uid']:e for es in unique.values() for e in es}
    for uid in sorted(diagnostic_uids):
        r=fc5[uid]; e=edge_map[uid]
        candidate_details.append({'event_uid':uid,'utc_day':day(r['ts_complete_us']),'pdu_hex':r['pdu_bytes'].hex(),
            'parse_status':r['parse_status'],'conn_uid':r['conn_uid'],'target':r['server_ip'],'address':r['address'],
            'value':r['single_value'],'timestamp_us':r['ts_complete_us'],'log_signature_id':e['log_signature_id'],
            'residual_us':e['residual_us'],'unique_at_windows_us':[t for t in WINDOWS if uid in sets[t]],
            'frozen_accepted':uid in accepted,'pair_state':pair_for.get(uid,{}).get('status')})
    source_signatures=list(rows(BASE/'output/log_signatures.parquet'))
    sig_by_id={r['log_signature_id']:r for r in source_signatures}
    for ex in examples:
        ex['log_lineage']=[sig_by_id[e['log_signature_id']] for e in ex['edges_first_three']]
    for r in accepted.values():
        r['log_signature_lineage']=[sig_by_id[s] for s in r['matched_log_signature_ids']]
    scope=Counter((r['family'],r['target_ip'],r['status']) for r in source_signatures)
    tid_conn=Counter(r['conn_uid'] for r in fc5.values() if r['mbap_trans_id']==5)
    result={'scope':'Frozen accepted labels and unchanged-edge diagnostics. No relabelling, transforms or split creation.',
        'views':views,'accepted_parse_counts':[{'class':a,'parse':b,'adus':n} for (a,b),n in parse_counts.items()],
        'accepted_pdu_patterns':[{'class':a,'pdu_hex':b,'adus':n} for (a,b),n in patterns.items()],
        'accepted_pair_counts':[{'class':a,'pair_state':b,'adus':n} for (a,b),n in accepted_pair.items()],
        'scada_fc5_request_rows':len(fc5),'scada_fc5_parse_counts':dict(Counter(r['parse_status'] for r in fc5.values())),
        'scada_fc5_literal_tid_counts':dict(Counter(str(r['mbap_trans_id']) for r in fc5.values())),
        'tid5_connection_audit':{'requests':sum(tid_conn.values()),'connection_generations':len(tid_conn),'max_requests_same_generation':max(tid_conn.values(),default=0)},
        'risk_connection_count':len(bad),'eligible_fc5_request_rows':len(eligible),
        'command_candidate_sensitivity':sensitivity,'window_transitions':comparisons,
        'normal_fc5_request_patterns':dict(normal_patterns),
        'normal_endpoint_address_day_counts':[{'target':k[0],'address':k[1],'pdu_hex':k[2],'utc_day':k[3],'normal_adus':n} for k,n in normal_control.items()],
        'log_scope_counts':[{'family':f,'target':t,'status':s,'unique_log_signatures':n} for (f,t,s),n in sorted(scope.items(),key=lambda x:str(x[0]))],
        'denominators':{'all_extracted_records':sum(v['events'] for v in views.values()),'accepted_attack_adus':len(accepted),
            'unique_candidate_log_signatures':len(source_signatures),'normal_pair_relations':dict(normal_pair_states),
            'independent_campaigns':4,'class_bearing_independent_campaigns':{'normal':1,'command_injection':1,'response_injection':1}},
        'elapsed_s':round(time.monotonic()-t0,3)}
    independent=read(REVIEW/'cohort_audit.json')
    checks=[]
    for t in WINDOWS:
        old=independent['command_candidate_sensitivity'][str(t)]
        new=sensitivity[str(t)]
        checks.append({'metric':f'two_sided_unique_{t}us','review':old['two_sided_unique_candidates'],'local':new['two_sided_unique_candidates'],'agrees':old['two_sided_unique_candidates']==new['two_sided_unique_candidates']})
        checks.append({'metric':f'parse_counts_{t}us','review':old['parse_status_counts'],'local':new['parse_status_counts'],'agrees':old['parse_status_counts']==new['parse_status_counts']})
    review_scope=read(REVIEW/'scope_and_pairs_audit.json')
    outside=sum(n for (f,t,s),n in scope.items() if f=='brute_force_or_specific_coil' and s=='outside_selected_endpoint_scope_not_absent_from_raw_dataset')
    checks.append({'metric':'outside_selected_endpoint_brute_signatures','review':153560,'local':outside,'agrees':outside==153560})
    write('cohort_diagnostics.json',result)
    write('review_reproduction.json',{'checks':checks,'all_checked_counts_agree':all(r['agrees'] for r in checks),'scope_differences':'None forced. Baseline code sensitivity includes one-sided diagnostics; this reproduction retains review two-sided uniqueness and current stream-risk filters.'})
    write('diagnostic_candidates.json',{'warning':'These are diagnostic candidates, not revised accepted labels. No candidate is promoted in this run.','records':candidate_details})
    write('event_examples.json',{'examples':examples,'accepted_attacks':list(accepted.values())})
    print('cohort',len(fc5),'FC5;', {t:sensitivity[str(t)]['two_sided_unique_candidates'] for t in WINDOWS},flush=True)
    return result


if __name__=='__main__':
    run()
