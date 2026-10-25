"""Original log serialization, scope and candidate episode diagnostics."""
from collections import Counter, defaultdict
from decimal import Decimal
import re
import time

import pyarrow.parquet as pq
from common import BASE, RAW, OUT, read, write, day, sha, stats


def run():
    t0=time.monotonic()
    inventory=read(BASE/'output/inventory.json')
    captures=[r for r in inventory['files'] if r['format']=='pcap']
    def campaign(p):
        if p.startswith('benign/'):
            return 'cic_benign_january'
        if p.startswith('attack/external/'):
            return 'cic_external_february'
        if p.startswith('attack/compromised-ied/') or p.endswith('substation-0.pcap'):
            return 'cic_compromised_ied_march'
        return 'cic_compromised_scada_march'
    cap_by_campaign=defaultdict(list)
    for c in captures:
        cap_by_campaign[campaign(c['path'])].append(c)
    bysource=defaultdict(lambda:{'rows':0,'fractional_digit_widths':Counter(),'time_shapes':Counter(),'wire_tid_states':Counter(),
                                 'literal_tid_common':Counter(),'families':Counter(),'targets':Counter(),'days':Counter(),
                                 'serial_examples':[],'fractional_microsecond_examples':[],'timestamp_min_us':None,'timestamp_max_us':None})
    joint=Counter()
    original_hashes={}
    for b in pq.ParquetFile(BASE/'output/logs.parquet').iter_batches(batch_size=20000):
        for r in b.to_pylist():
            key=(r['source_path'],r['source_sheet'])
            s=bysource[key];s['rows']+=1
            text=r['timestamp_original'] or ''
            s['time_shapes'][r['timestamp_status']]+=1
            if r['excel_serial_original']:
                if len(s['serial_examples'])<2:
                    s['serial_examples'].append({'original_serial':r['excel_serial_original'],'exact_epoch_us_decimal':r['excel_epoch_us_decimal'],'join_epoch_us':r['timestamp_us'],'date_system':r['excel_date_system']})
                if len(s['fractional_microsecond_examples'])<5 and Decimal(r['excel_epoch_us_decimal'])%1:
                    s['fractional_microsecond_examples'].append(r['excel_epoch_us_decimal'])
            else:
                fraction=re.search(r'\.(\d+)$',text)
                s['fractional_digit_widths'][len(fraction.group(1)) if fraction else 0]+=1
            state='missing' if r['transaction_id'] is None else ('uint16_literal' if r['wire_tid_valid'] else 'out_of_uint16_tool_metadata')
            s['wire_tid_states'][state]+=1
            s['literal_tid_common'][str(r['transaction_id_original'])]+=1
            s['families'][r['family']]+=1
            s['targets'][str(r['target_ip'])]+=1
            s['days'][str(day(r['timestamp_us']))]+=1
            ts=r['timestamp_us']
            if ts is not None:
                s['timestamp_min_us']=min(s['timestamp_min_us'],ts) if s['timestamp_min_us'] is not None else ts
                s['timestamp_max_us']=max(s['timestamp_max_us'],ts) if s['timestamp_max_us'] is not None else ts
            joint[(r['recording_id'],day(ts),r['family'],r['target_ip'],r['completion'],r['evidence_eligibility'])]+=1
            original_hashes[r['source_path']]=r['source_sha256']
    for s in bysource.values():
        s['literal_tid_common']=dict(s['literal_tid_common'].most_common(12))
    coverage=Counter()
    coverage_examples=defaultdict(list)
    signatures=pq.read_table(BASE/'output/log_signatures.parquet').to_pylist()
    selected=read(BASE/'output/label_report.json')['selected_endpoint_scope']
    hmi=[c for c in captures if c['path'].startswith('attack/compromised-scada/scada-hmi/')]
    coverage_rows=[]
    for r in signatures:
        ts=r['timestamp_us_candidate_utc']; rec=r['recording_id']
        campaign_hits=[c for c in cap_by_campaign[rec] if c['capture']['minimum_ts_us']<=ts<=c['capture']['maximum_ts_us']]
        hmi_hits=[c['path'] for c in hmi if c['capture']['minimum_ts_us']<=ts<=c['capture']['maximum_ts_us']] if rec=='cic_compromised_scada_march' else []
        state='outside_all_supplied_campaign_capture_intervals' if not campaign_hits else ('selected_endpoint_omission' if r['status']=='outside_selected_endpoint_scope_not_absent_from_raw_dataset' else r['status'])
        k=(rec,r['family'],r['target_ip'],day(ts),state,bool(hmi_hits))
        coverage[k]+=1
        exkey=(r['family'],r['target_ip'],state)
        if len(coverage_examples[exkey])<2:
            coverage_examples[exkey].append({**r,'capture_interval_candidate_paths':[c['path'] for c in campaign_hits], 'hmi_interval_candidate_paths':hmi_hits})
    episode_counts=Counter(); starts=Counter(); matching_episodes=[]
    accepted_sigs={r['log_signature_id'] for r in signatures if r['status']=='accepted_core_mechanism_event_evidence'}
    accepted_logids={r['source_event_id'] for r in signatures if r['log_signature_id'] in accepted_sigs}
    durations=defaultdict(list)
    for b in pq.ParquetFile(BASE/'output/log_episodes.parquet').iter_batches(batch_size=20000):
        for r in b.to_pylist():
            episode_counts[(r['recording_id'],r['family'],r['target_ip'],r['status'])]+=1
            if r['start_ts_us'] is not None and r['end_ts_us'] is not None:
                durations[r['family']].append(r['end_ts_us']-r['start_ts_us'])
            if r['start_event_id'] in accepted_logids:
                matching_episodes.append(r)
    hashes=[{'path':p,'recorded_sha256':h,'current_sha256':sha(RAW/p)} for p,h in sorted(original_hashes.items())]
    scriptfiles=[f['path'] for f in inventory['files'] if f['format'] in ('py','sh','json','yaml','yml','conf','ini')]
    result={'scope':'All original log rows and distinct eligible signatures; no packet counts inferred from log rows.',
        'source_families':[{'source_path':p,'sheet':s,**v} for (p,s),v in bysource.items()],
        'original_log_hashes':hashes,'all_original_log_hashes_match':all(r['recorded_sha256']==r['current_sha256'] for r in hashes),
        'timestamp_contract':{'csv':'Naive calendar strings, serialized fractional decimal seconds; widths1/2/3 pad on the right. Millisecond serialization does not prove millisecond accuracy or truncation vs rounding.',
            'xlsx':'1900/1904 system retained; original numeric serial and exact decimal conversion preserved. Rounded microsecond integer only a join convenience; extra Excel decimals do not prove source-clock accuracy.',
            'pcap_precision_histogram':dict(Counter(str(c['capture']['ticks_per_second']) for c in captures)),
            'matched_event_time':'ts_complete_us, based on epoch of the latest contributing reassembled-segment timestamp; ts_first_us and all segment timestamps retained.',
            'unknowns':['Actual logger call position relative to send/write','Clock synchronization/configuration','CSV rounding vs truncation implementation','Global timezone/offset and capture-vs-tool clock drift']},
        'raw_attacker_source_or_configuration':{'files_found':scriptfiles,'status':'absent from supplied CIC source inventory' if not scriptfiles else 'inspect original files explicitly before using'},
        'raw_row_joint_counts':[{'campaign':k[0],'candidate_utc_day':k[1],'mechanism_family':k[2],'target':k[3],'completion_record':k[4],'evidence_eligibility':k[5],'original_source_rows':n} for k,n in joint.items()],
        'signature_coverage':[{'campaign':k[0],'family':k[1],'target':k[2],'candidate_utc_day':k[3],'coverage_state':k[4],'within_hmi_interval':k[5],'unique_log_signatures':n} for k,n in coverage.items()],
        'coverage_examples':[{'family':k[0],'target':k[1],'coverage_state':k[2],'examples':v} for k,v in coverage_examples.items()],
        'candidate_tool_intervals':[{'campaign':k[0],'family':k[1],'target':k[2],'interval_status':k[3],'interval_rows':n} for k,n in episode_counts.items()],
        'candidate_tool_duration_us':{k:stats(v) for k,v in durations.items()},
        'accepted_command_candidate_tool_intervals':matching_episodes,
        'episode_limit':'Adjacent start/completion tool intervals are candidate episodes only. Repeated source rows, zero-duration intervals and completion sentinels do not prove separate attacks, wire ranges or successful manipulation. No independent episode count is fabricated.',
        'capture_coverage_limit':'Inventory intervals are candidate time coverage, not proof that a targeted packet was present. Absent-from-inspected-view can be stated only for the bounded pilot interval.',
        'elapsed_s':round(time.monotonic()-t0,3)}
    write('original_log_timing_and_coverage.json',result)
    print('logs',sum(s['rows'] for s in bysource.values()),'original rows;',len(signatures),'eligible signatures',flush=True)
    return result


if __name__=='__main__':
    run()
