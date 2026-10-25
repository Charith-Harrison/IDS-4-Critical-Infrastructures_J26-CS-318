"""Read-only source-scope and current matching metadata diagnostics."""
from pathlib import Path
from collections import Counter
import json
import pyarrow.parquet as pq

bundle = Path('D:/VSCode/GitHub/4th Year Cyber/C3/component3_preparation')
output = bundle/'output'
out = Path(__file__).parent
coverage = Counter()
core_scope_targets = Counter()
for batch in pq.ParquetFile(output/'log_signatures.parquet').iter_batches(columns=['family','status','target_ip']):
    for r in batch.to_pylist():
        coverage[(r['family'],r['status'])] += 1
        if r['family'] in ('brute_force_or_specific_coil','false_data_injection'):
            core_scope_targets[(r['family'],r['target_ip'],r['status'])] += 1

accepted_pair_outcomes = {}
normal_control_patterns = Counter()
for view in ('scada_ied1a','ied_ied1b'):
    directory = output/'extraction'/view
    anns = pq.read_table(directory/'annotations.parquet',columns=['event_uid','component_label'],
        filters=[('component_label','in',['command_injection','response_injection'])]).to_pylist()
    targets = {r['event_uid']:r['component_label'] for r in anns}
    relations = []
    for batch in pq.ParquetFile(directory/'pairs.parquet').iter_batches(columns=['request_uid','response_uid','status','reasons']):
        for r in batch.to_pylist():
            if r['request_uid'] in targets or r['response_uid'] in targets:
                relations.append(r)
    accepted_pair_outcomes[view] = {
        'accepted_events':len(targets),'relations_with_directly_accepted_events':len(relations),
        'pair_statuses':dict(Counter(r['status'] for r in relations)),
        'pair_reasons':dict(Counter(reason for r in relations for reason in (r['reasons'] or [])))}

normal_path = output/'extraction/benign_ied1b/events.parquet'
normal = pq.read_table(normal_path,columns=['func_code','protocol_role','pdu_bytes','address','single_value'],
    filters=[('func_code','=',5),('protocol_role','=','request')]).to_pylist()
for r in normal:
    normal_control_patterns[r['pdu_bytes'].hex()] += 1

result = {
    'scope':'Read-only scope/label/pair checks; no new accepted labels, split or model data.',
    'log_signature_coverage_by_family_and_state':[{'family':f,'state':s,'signatures':n} for (f,s),n in sorted(coverage.items())],
    'core_log_scope_by_target':[{'family':f,'target':t,'state':s,'signatures':n} for (f,t,s),n in sorted(core_scope_targets.items())],
    'accepted_pair_outcomes':accepted_pair_outcomes,
    'normal_fc5_request_patterns':dict(normal_control_patterns),
}
(out/'scope_and_pairs_audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({'core_log_scope_by_target':result['core_log_scope_by_target'],
                  'accepted_pair_outcomes':accepted_pair_outcomes,'normal_fc5_request_patterns':dict(normal_control_patterns)},indent=2))
