"""Read-only cohort and matching-sensitivity review; no labels or splits changed."""
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import pyarrow.parquet as pq

bundle = Path('D:/VSCode/GitHub/4th Year Cyber/C3/component3_preparation')
out = Path(__file__).parent
root = bundle/'output/extraction'
summary = {}
accepted = {}

for folder in sorted(root.iterdir()):
    if not (folder/'events.parquet').exists():
        continue
    annotations = pq.read_table(folder/'annotations.parquet', columns=['component_label','annotation_state'])
    labels = Counter(annotations.column('component_label').to_pylist())
    states = Counter(annotations.column('annotation_state').to_pylist())
    small = pq.read_table(folder/'annotations.parquet', columns=['event_uid','component_label'],
                         filters=[('component_label','in',['command_injection','response_injection'])]).to_pylist()
    targets = {r['event_uid']:r['component_label'] for r in small}
    details = []
    if targets:
        rows = pq.read_table(folder/'events.parquet', columns=['event_uid','parse_status','shape_reason','func_code',
                'protocol_role','pdu_bytes','ts_complete_us','address','single_value','reg_values'],
                filters=[('event_uid','in',list(targets))]).to_pylist()
        for r in rows:
            r['component_label'] = targets[r['event_uid']]
            r['date_utc'] = datetime.fromtimestamp(r['ts_complete_us']/1e6,timezone.utc).date().isoformat()
            r['pdu_hex'] = r.pop('pdu_bytes').hex()
            details.append(r)
    summary[folder.name] = {'events':pq.ParquetFile(folder/'events.parquet').metadata.num_rows,
        'annotations':annotations.num_rows,'labels':{str(k):v for k,v in labels.items()},'annotation_states':dict(states),
        'accepted_by_class_date':dict(Counter(r['component_label']+'|'+r['date_utc'] for r in details)),
        'accepted_by_class_shape':dict(Counter(r['component_label']+'|'+r['parse_status'] for r in details)),
        'accepted_pdu_patterns':dict(Counter(r['component_label']+'|'+r['pdu_hex'] for r in details))}
    accepted[folder.name] = details

folder = root/'scada_ied1a'
bad = set()
for b in pq.ParquetFile(folder/'connections.parquet').iter_batches(columns=['conn_uid','retrans_conflicts','unverified_retrans_segments']):
    for r in b.to_pylist():
        if r['retrans_conflicts'] or r['unverified_retrans_segments']:
            bad.add(r['conn_uid'])
events = pq.read_table(folder/'events.parquet', columns=['event_uid','conn_uid','reasm_after_gap','parse_status','pdu_bytes',
                'ts_complete_us','first_chunk','first_frame','address','single_value'],
                filters=[('func_code','=',5),('protocol_role','=','request')]).to_pylist()
event_map = {r['event_uid']:r for r in events}
eligible_ids = {r['event_uid'] for r in events if r['conn_uid'] not in bad and not r['reasm_after_gap']}
matches = pq.read_table(folder/'log_matches.parquet', columns=['event_uid','log_signature_id','residual_us'],
              filters=[('family','=','brute_force_or_specific_coil'),('behavior_supported','=',True),('candidate_clock_offset_us','=',0)]).to_pylist()
matches = [m for m in matches if m['event_uid'] in eligible_ids]
sensitivity = {}
for tolerance in (0,1000,5000,25000):
    edges = [m for m in matches if abs(m['residual_us']) <= tolerance]
    log_degrees = Counter(m['log_signature_id'] for m in edges)
    event_degrees = Counter(m['event_uid'] for m in edges)
    unique = [m for m in edges if log_degrees[m['log_signature_id']] == 1 and event_degrees[m['event_uid']] == 1]
    selected = [event_map[m['event_uid']] for m in unique]
    sensitivity[str(tolerance)] = {
        'two_sided_unique_candidates':len(unique),
        'parse_status_counts':dict(Counter(e['parse_status'] for e in selected)),
        'unique_pdu_patterns':len({e['pdu_bytes'] for e in selected}),
        'pdu_patterns':dict(Counter(e['pdu_bytes'].hex() for e in selected)),
        'days_utc':dict(Counter(datetime.fromtimestamp(e['ts_complete_us']/1e6,timezone.utc).date().isoformat() for e in selected)),
        'note':'Diagnostic sensitivity only; no new labels accepted or annotations changed. Not a tolerance recommendation.'}
result = {'scope':'Read-only extraction/annotation cohort audit, no preprocessing/training.',
          'views':summary,'command_candidate_sensitivity':sensitivity,
          'all_observed_fc5_request_patterns_scada_view':dict(Counter(r['pdu_bytes'].hex() for r in events)),
          'scada_fc5_request_rows':len(events),'accepted_examples':accepted}
(out/'cohort_audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k not in ('accepted_examples','all_observed_fc5_request_patterns_scada_view')},indent=2))
