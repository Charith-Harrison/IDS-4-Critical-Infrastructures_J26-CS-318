"""One-time preparation/freeze. Never calls a collector or generates traffic."""
from pathlib import Path
from collections import Counter
from datetime import datetime
import argparse
import json
import statistics
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from runtime.common import read,sha,atomic,source_inventory,digest


def prepare():
    if (ROOT/'frozen/protocol.json').exists(): raise ValueError('Protocol already prepared; never silently rewrite it')
    repo=ROOT.parent.parent
    source=read(ROOT/'engine/design/proposed_main_design.json')
    summary=read(repo/'component3_testbed_v03/evidence/engineering_summary.json')
    audit=read(repo/'component3_testbed_v03/evidence/shortcut_audit.json')
    roster=read(ROOT/'frozen/main_roster.json')['runs']
    qualified={(r['map'],r['values'],r['ordering'],r['timing'],r['mode']) for r in summary['runs']}
    required={(r['map'],r['values'],r['ordering'],r['timing'],r['recording_mode']) for r in roster}
    if len(roster)!=104 or len({r['seed'] for r in roster})!=104: raise ValueError('Roster ID/seed defect')
    for row in roster:
        if row['blocks']!=9 or row['tid_profiles']!=['DSEQ','DREUSE','DRANDOM'] or row['anchor_poll_counts']!=[0,1,2]:
            raise ValueError('A main condition needs an unqualified engine variant')
        if row['map'] not in ('M0','M1','M2') or row['values'] not in ('V0','V1') or row['ordering'] not in ('O0','O1','O2') or row['timing'] not in ('T0','T1','T2'):
            raise ValueError('Unknown main condition')
    protocol=dict(protocol_id='c3-main-manual-v1-20261025',status='FROZEN_FOR_MANUAL_EXECUTION_ONLY',
                  engineering_authorization='User requested protocol freeze and manual launcher preparation; agent must not start collection',
                  academic_supervisor_acceptance='NOT_RECORDED',actual_collection_started=False,
                  original_design_sha256=sha(ROOT/'engine/design/proposed_main_design.json'),
                  frozen_roster_sha256=sha(ROOT/'frozen/main_roster.json'),qualified_engine_version='0.3.0',
                  qualified_engine_receipt_sha256=sha(ROOT/'frozen/qualified_engine_receipt.json'),
                  total=104,modes=dict(Counter(r['recording_mode'] for r in roster)),
                  intended_roles=dict(Counter(r['intended_evaluation_role'] for r in roster)),
                  execution_order='Existing roster order MX001-MX104, unchanged; it is not counterbalanced across roles. Record time/host drift as a limitation.',
                  qualification_basis=dict(measured_configurations=len(qualified),main_condition_cells=len(required),
                       directly_measured_main_cells=len(required&qualified),compositional_main_cells=len(required-qualified),
                       note='Not all cross-factor cells were measured. The same separable public-map/value/order/delay engine supports these combinations; no new intervention, decoder or template introduced.'),
                  generator_decoder='Copied byte-identically. Adapter changes planned IDs/purpose/provenance and cooperative lifecycle only; actual wire timing retains platform/monitoring overhead.',
                  qualification_exclusion='All pilots/EQ remain excluded from fitting, tuning, feature/threshold selection and scored evaluation',
                  observation_rules=source['observation_contract'],scenario_control_contract=source['scenarios'],
                  public_configuration=source['public_detector_configuration'],comparison=source['comparison'],grouping=source['grouping'],
                  limitations=source['explicit_nonclaims'],stop_conditions=source['stop_conditions'],
                  retry_policy='No automatic retry. Resume -RetryFailed creates at most one new attempt per invocation, preserving earlier attempts; maximum three attempts per planned ID.',
                  main_output='Measured raw PCAPs, observations, exact evidence annotations and prospective-role provenance only; no model matrices or preprocessing')
    atomic(ROOT/'frozen/protocol.json',protocol)
    executions=[read(p) for p in (repo/'component3_testbed_v03/evidence').glob('execution-*.json')]
    durations={key:[] for key in ('T0','T1','T2')}
    categories=Counter()
    for row in summary['runs']:
        folder=repo/row['source'];host=read(folder/'host_execution.json')
        starts=[c['started_at_utc'] for e in executions for c in e['commands'] if '--planned-run' in c['argv'] and c['argv'][-1]==row['planned_run_id']]
        end=host['recorded_at_utc']
        seconds=(datetime.fromisoformat(end.replace('Z','+00:00'))-datetime.fromisoformat(starts[0].replace('Z','+00:00'))).total_seconds()
        durations[row['timing']].append(seconds)
        for p in folder.iterdir():
            if not p.is_file(): continue
            category='pcap_and_capture_log' if p.name in ('capture.pcap','capture.log') else \
                     'private_and_observation_ledgers' if p.suffix=='.jsonl' and p.name!='verified_labels.jsonl' else \
                     'accepted_annotations' if p.name=='verified_labels.jsonl' else 'reports_plans_and_metadata'
            categories[category]+=p.stat().st_size
    upper=int(max(r['artifact_bytes'] for r in summary['runs'])*1.5+(1<<20))
    central=sum(statistics.mean(r['artifact_bytes'] for r in summary['runs'] if r['mode']==row['recording_mode']) for row in roster)
    policy=dict(status='FROZEN_OPERATIONAL_DEFAULTS_OPERATOR_OVERRIDES_RECORDED',qualified_runs=14,
                qualified_total_artifact_bytes=audit['total_run_artifact_bytes'],qualified_category_bytes=dict(categories),
                qualified_max_run_bytes=max(r['artifact_bytes'] for r in summary['runs']),upper_run_artifact_bytes=upper,
                estimated_main_originals_bytes=int(central),estimated_main_originals_upper_bytes=104*upper,
                qualified_wall_seconds_by_timing=durations,
                default_safety_factor=2,default_planned_copies=2,default_output_reserve_gib=2,default_docker_reserve_gib=2,
                formula='output reserve + SafetyFactor * (remaining originals + one full planned handover copy + two run-sized temporary/retry allowances). Add Docker backing reserve when on the same filesystem.',
                assumptions=['1.5x largest measured run plus 1 MiB bounds adapter/progress/report overhead; not a statistical upper confidence bound',
                             'PlannedCopies reserves future copies; no backup is auto-created. Existing qualified data/runtime archives are not removed.',
                             'Docker guest free space and actual backing host drives are checked. VM nominal capacity alone is insufficient.',
                             'Source/runtime image archive is about 45 MB; fixed reserves cover metadata/image handover overhead.',
                             'Estimates use one host and 14 measured runs; concurrent workloads, retries and host IO can change storage/time. Stop on errors.'])
    atomic(ROOT/'frozen/storage_policy.json',policy)
    schema=dict(status='RAW_EVIDENCE_SCHEMA_NOT_MODEL_INPUT_MATRIX',observation_format='application_ledger.jsonl, one complete observed request or reply ADU per row',
                required_observation_fields=['event_id','run_id','connection_id','transaction_index','role','direction','tid','unit','adu_hex','pdu_hex','stream_offset','observed_at_ns'],
                annotation_format='verified_labels.jsonl adds exact capture SHA256, frame/file byte references, parse/pair evidence and direct evidence label',
                private_evidence=['server_audit.jsonl','intervention_audit.jsonl','scenario_plan.json'],
                forbidden_predictor_metadata=source.get('forbidden_predictor_metadata',[])+['label','scenario','step','episode_id','run_id','block','tid_profile','anchor_poll_count','seed','planned role','private oracle/state','intervention flags','source/partition IDs'],
                response_fields='Request-derived address/object roles are context/audit, not fields carried by a current FC3 reply',
                pair_identity='Connection generation plus stream/transaction ordinal; literal TID alone is never unique')
    atomic(ROOT/'frozen/schema.json',schema)
    print(json.dumps(dict(main_cells=len(required),directly_measured=len(required&qualified),upper_run_bytes=upper,central_main_bytes=int(central)),indent=2))


def seal():
    target=ROOT/'frozen/freeze_manifest.json'
    if target.exists(): raise ValueError('Freeze already sealed; use a new version for any change')
    inventory=source_inventory()
    atomic(target,dict(status='SEALED_IMMUTABLE_BY_HASH',bundle_id=digest(inventory),source_configuration_sha256=inventory,
                       protocol_sha256=sha(ROOT/'frozen/protocol.json'),roster_sha256=sha(ROOT/'frozen/main_roster.json'),
                       no_main_collection_started=True))
    print(json.dumps(read(target),indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--seal',action='store_true');a=p.parse_args()
    seal() if a.seal else prepare()
