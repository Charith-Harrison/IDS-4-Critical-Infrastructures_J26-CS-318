"""Read-only review of downloaded reassessment; writes only this review's result."""
from pathlib import Path
from collections import Counter
import hashlib
import json
import pyarrow.parquet as pq

ROOT = Path(r'D:\VSCode\GitHub\4th Year Cyber')
REASSESS = ROOT/'C3/component3_reassessment/v1_20261024'
BASE = ROOT/'C3/component3_preparation'
OUT = ROOT/'output/component3_execution/reassessment_review'

def read(p):
    return json.loads(p.read_text(encoding='utf-8'))

def sha(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(8 << 20), b''):
            h.update(b)
    return h.hexdigest()

manifest = read(REASSESS/'output/execution_manifest.json')
checks = []
for name, expected in manifest['contract']['code_sha256'].items():
    checks.append({'kind':'code', 'path':name, 'matches':sha(REASSESS/name) == expected})
checks.append({'kind':'config', 'path':'config.json',
               'matches':sha(REASSESS/'config.json') == manifest['contract']['config_sha256']})
for stage, row in manifest['stages'].items():
    for name, expected in row.get('output_sha256', {}).items():
        p = REASSESS/'output'/name
        checks.append({'kind':'stage_output', 'stage':stage, 'path':name,
                       'matches':p.is_file() and sha(p) == expected})

temporal = read(REASSESS/'output/temporal_feasibility.json')['claim_B_per_campaign_chronology']
counts = Counter()
shapes = Counter()
label_totals = Counter()
for campaign, info in temporal['campaign_duration_probes'].items():
    directory = BASE/'output/extraction'/info['view']
    cut1, cut2 = info['probes_us']
    if campaign == 'cic_benign_january':
        # Baseline annotations identify every retained row in this view as normal.
        annotation_counts = Counter()
        for b in pq.ParquetFile(directory/'annotations.parquet').iter_batches(columns=['component_label']):
            annotation_counts.update(b.column(0).to_pylist())
        assert set(annotation_counts) == {'normal'}
        for b in pq.ParquetFile(directory/'events.parquet').iter_batches(columns=['ts_complete_us']):
            for t in b.column(0).to_pylist():
                counts[(int(t >= cut1) + int(t >= cut2), 'normal')] += 1
        label_totals.update(annotation_counts)
    else:
        accepted = pq.read_table(directory/'annotations.parquet', columns=['event_uid','component_label'],
            filters=[('component_label','in',['command_injection','response_injection'])]).to_pylist()
        labels = {r['event_uid']:r['component_label'] for r in accepted}
        events = pq.read_table(directory/'events.parquet', columns=['event_uid','ts_complete_us','parse_status'],
                              filters=[('event_uid','in',list(labels))]).to_pylist()
        for r in events:
            label = labels[r['event_uid']]
            phase = int(r['ts_complete_us'] >= cut1) + int(r['ts_complete_us'] >= cut2)
            counts[(phase,label)] += 1
            shapes[(phase,label,r['parse_status'])] += 1
            label_totals[label] += 1

phases = []
for index, recorded in enumerate(temporal['aggregate_phase_counts_before_purge']):
    actual = {label:counts[(index,label)] for label in ('normal','command_injection','response_injection')}
    phases.append({'phase':recorded['diagnostic_phase'], 'accepted_counts_from_baseline_parquet':actual,
                   'matches_report':actual == recorded['accepted_adu_counts'],
                   'parser_ok_commands':shapes[(index,'command_injection','ok')],
                   'parser_ok_responses':shapes[(index,'response_injection','ok')]})

result = {'scope':'Read-only downloaded-reassessment integrity and independent temporal-count review. No extraction, labels, split, model preprocessing or training executed.',
          'integrity_checks':checks, 'all_recorded_hashes_match':all(r['matches'] for r in checks),
          'independent_accepted_label_totals':dict(label_totals),
          'independent_phase_counts':phases, 'all_phase_counts_match_report':all(r['matches_report'] for r in phases),
          'limits':'Recorded hashes validate transfer consistency, not scientific correctness. Phase counts are probes before purging; no replacement split is endorsed. No new independent raw-pilot validation was performed in this step.'}
OUT.mkdir(parents=True,exist_ok=True)
(OUT/'independent_checks.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k != 'integrity_checks'},indent=2))
print('Hash checks:',len(checks),'mismatches:',[r for r in checks if not r['matches']])
