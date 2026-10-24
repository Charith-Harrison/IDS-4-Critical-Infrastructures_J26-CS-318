"""Read-only replay and evidence report for EQ01-EQ14; no models or main splits."""
from pathlib import Path
from collections import Counter
import csv
import json
from c3qual.config import ROOT,RUN_IDS,planned,read_json,sha,source_hashes
from c3qual.validation import validate,jsonl,save
from audit_workspace import check


def unwrap(value):
    if isinstance(value,dict) and 'value' in value: value=value['value']
    return value[0] if isinstance(value,list) else value


def main():
    runs_root=ROOT.parent/'component3_collection_runs/engineering-v03'
    rows,examples,coverage,failed=[],[],[],[]
    totals=Counter()
    for qid in RUN_IDS:
        accepted=[]
        for folder in sorted(runs_root.glob(qid+'-*')):
            if not folder.is_dir(): continue
            report=validate(folder,write=False)
            if report['status']=='PASSED': accepted.append((folder,report))
            else: failed.append(dict(source=folder.relative_to(ROOT.parent).as_posix(),errors=report['errors']))
        if len(accepted)!=1: raise ValueError(f'{qid}: expected one accepted capture, got {len(accepted)}')
        folder,report=accepted[0]
        manifest=read_json(folder/'run_manifest.json')
        host=read_json(folder/'host_execution.json')
        if host['docker_exit_code']!=0 or host['image_source_sha256']!=manifest['source_sha256']:
            raise ValueError('Host/image/source evidence differs')
        annotations=jsonl(folder/'verified_labels.jsonl')
        capture=(folder/'capture.pcap').read_bytes()
        for row in annotations:
            raw=bytes.fromhex(row['adu_hex'])
            rebuilt=bytearray(len(raw))
            for ref in row['frame_byte_references']:
                a,n,b=ref['pcap_file_byte_offset'],ref['length'],ref['message_byte_offset']
                rebuilt[b:b+n]=capture[a:a+n]
            if bytes(rebuilt)!=raw: raise ValueError('Report byte-reference reread differs')
        counts=report['label_counts']
        totals.update(counts)
        config=planned(qid)
        event_index={r['event_id']:r for r in annotations}
        target_ages={d['event_id']:d for d in report['causal_dependencies']}
        for c in report['control_matches'][:3]:
            target=event_index[c['event_id']]
            dep=target_ages[c['event_id']]
            examples.append(dict(planned_run_id=qid,source=folder.relative_to(ROOT.parent).as_posix(),
                                 target=target,earlier_anchor=event_index[dep['anchor_event_id']],
                                 normal_control=event_index[c['normal_event_ids'][0]],
                                 intervening_adus=dep['intervening_adus']))
        row=dict(planned_run_id=qid,source=folder.relative_to(ROOT.parent).as_posix(),status='PASSED',
                 mode=config['recording_mode'],map=config['map'],values=config['values'],ordering=config['ordering'],timing=config['timing'],
                 messages=report['message_count'],transactions=report['transaction_count'],episodes=report['episode_count'],
                 label_counts=counts,kernel_drops=0,image_id=unwrap(host['image'])['Id'],
                 collector_machine=host['collector_machine'],host_os=host['host_os'],host_timezone=host['host_timezone'],
                 docker_version=host['docker_version'],compose_version=host['compose_version'],
                 literal5_full_adu_control_targets=sum('full_adu_normal_event_ids' in c for c in report['control_matches']),
                 target_anchor_ages=sorted({target_ages[c['event_id']]['intervening_adus'] for c in report['control_matches']}),
                 artifact_bytes=sum(p.stat().st_size for p in folder.iterdir() if p.is_file()),
                 artifact_sha256={p.name:sha(p) for p in folder.iterdir() if p.is_file()})
        rows.append(row)
        for c in report['nuisance_cell_counts']:
            coverage.append(dict(planned_run_id=qid,mode=config['recording_mode'],**c))
    if totals['command_injection']!=108 or totals['response_injection']!=216:
        raise ValueError('Expected 12 mixed and 2 normal-only probe totals')
    preservation=check()
    if preservation['status']!='PASSED': raise ValueError('Frozen predecessors changed')
    summary=dict(status='FOURTEEN_ENGINEERING_PROBES_PASSED',version='0.3.0',engineering_adoption='User approved engineering scope only',
                 academic_supervisor_approval='NOT_RECORDED',source_sha256=source_hashes(),runs=rows,
                 accepted_measured_captures=14,failed_attempts_preserved=failed,
                 total_messages=sum(r['messages'] for r in rows),total_transactions=sum(r['transactions'] for r in rows),
                 total_episodes=sum(r['episodes'] for r in rows),label_counts=dict(totals),
                 independent_industrial_campaigns=0,software_environment_count=1,
                 main_runs_collected=0,final_partition_memberships=0,no_model_preprocessing_or_training=True,
                 qualification_excluded_from_all_model_work=True,preservation=preservation,
                 notes=['All 14 probes are unscored engineering data, including the alternate configurations; no tuning or scored evaluation',
                        'All mixed targets have same-block/timing/map/TID/gap PDU controls; literal-5 target ADUs also match full normal ADUs',
                        'Causal anchors cover 0/2/4 ADUs for requests and 1/3/5 for responses',
                        'Byte/sequence/pair/state consistency qualifies collection, not ML benefit or industrial generalization',
                        'Actual timing includes IO/scheduler jitter; configured delays are not exact measured wire delays',
                        'The 104 main executions remain proposed and unreachable from this loader'])
    save(ROOT/'evidence/engineering_summary.json',summary)
    save(ROOT/'evidence/evidence_examples.json',dict(examples=examples))
    with (ROOT/'evidence/nuisance_cell_counts.csv').open('w',encoding='utf8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(coverage[0]));writer.writeheader();writer.writerows(coverage)
    table=['| Probe | Mode | Map/value/order/time | ADUs | Command | Response | Drops |','|---|---|---|---:|---:|---:|---:|']
    for r in rows:
        table.append(f"| {r['planned_run_id']} | {r['mode']} | {r['map']}/{r['values']}/{r['ordering']}/{r['timing']} | {r['messages']} | {r['label_counts']['command_injection']} | {r['label_counts']['response_injection']} | 0 |")
    report=f'''# Component 3 v0.3 engineering qualification

**All 14 targeted engineering probes passed. Main collection remains disabled.**
User approval adopted engineering scope. Supervisor acceptance of the testbed-primary methodology
is not recorded; no academic approval is invented.

{chr(10).join(table)}

Totals: {summary['total_messages']} ADUs, {summary['total_transactions']} complete transactions,
{summary['total_episodes']} episodes; {totals['normal']} normal, 108 command injections, 216 response injections.
All 14 captures are excluded from fitting, tuning, feature/threshold selection and scored evaluation.
They are replications in one simulator, not independent industrial campaigns.

## What is established

The separate generator and independent decoder/replay support M0/M1/M2, V0/V1, O0/O1/O2,
T0/T1/T2 and normal-only operation in the planned engineering combinations. Every mixed probe
crosses three TID policies with three context distances, nine direct command and eighteen
forged-response messages. Every target has a same-cell genuine PDU control; the nine literal-5
targets per mixed run also have an identical full-ADU normal control. Normal-only probes have
zero direct attack annotations. Genuine ACKs remain normal. Reused TIDs are never identity alone.

Exact captured bytes, stream positions, private interventions, independently replayed state,
pair identities and earlier anchors reconcile. All kernel-drop footers report zero.
Preservation checks passed for {preservation['protected_files']} earlier files, including CIC preparation,
reassessment, both previous pilots, old captures and the proposed main-design package.

## Limits and next action

These engineering probes establish collection controls under the declared single-writer software
policy. They do not establish absence of every generator cue, physical-process fidelity,
independent-campaign generalization or additional ML benefit over simple causal rules. Supplied
public maps are configuration; no private role/scenario fields may become predictors.
Configured delays have real scheduler/IO overhead; future timing claims must use measured times.

No main recording, actual train/validation/test membership, feature engineering, imputation,
scaling, resampling, profiling, sequence matrix or model training/evaluation was performed.
The 104 main executions remain proposed. The next action is to review this measured evidence,
record the academic methodology decision and explicitly adopt/freeze or amend the main protocol
before separately authorizing any main collection. Do not reuse EQ data as scored data.

## Reproduce and hand over

Read `README.md`. `evidence/engineering_summary.json` carries portable run paths and artifact hashes,
source/configuration identities, actual self-reported collection machine and Docker image identity.
Each run retains raw PCAP, application observations, private intervention/state audits, config/plan,
validation report, annotations and host execution record. The exact Docker argument arrays and
host clock/timezone/OS/engine identities are retained in `evidence/execution-*.json`.
`evidence/nuisance_cell_counts.csv` and `evidence/evidence_examples.json` are audit-only outputs.
The machine/clock record is self-reported, not externally attested.
'''
    (ROOT/'ENGINEERING_REPORT.md').write_text(report,encoding='utf8')
    print(json.dumps({k:summary[k] for k in ('status','total_messages','total_transactions','label_counts')},indent=2))


if __name__=='__main__': main()
