"""Read-only revalidation and coverage reporting; no model tables or partitions."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import csv
import json
import sys

from c3qual.config import ROOT, read_json, sha, source_hashes
from c3qual.validation import jsonl, save, validate

REPO = ROOT.parent
RUNS = REPO / 'component3_collection_runs/design-v1'
EVIDENCE = ROOT / 'evidence'


def main():
    rows, examples, count_rows, failures = [], [], [], []
    total = Counter()
    for qid in ('Q01', 'Q02', 'Q03', 'Q04'):
        folders = sorted(RUNS.glob(qid + '-*'))
        passed = []
        for folder in folders:
            if not folder.is_dir():
                continue
            report = validate(folder, write=False)
            if report['status'] == 'PASSED':
                passed.append((folder, report))
            else:
                failures.append(dict(path=folder.relative_to(REPO).as_posix(), errors=report['errors']))
        if len(passed) != 1:
            raise ValueError(f'{qid}: expected exactly one verified capture, found {len(passed)}')
        folder, report = passed[0]
        manifest = read_json(folder / 'run_manifest.json')
        host = read_json(folder / 'host_execution.json')
        if host['docker_exit_code'] != 0 or host['image_source_sha256'] != manifest['source_sha256']:
            raise ValueError('Host/image/source provenance mismatch: ' + folder.name)
        ledger = jsonl(folder / 'verified_labels.jsonl')
        by_id = {r['event_id']: r for r in ledger}
        dependencies = {r['event_id']: r for r in report['causal_dependencies']}
        total.update(report['label_counts'])
        config = manifest['planned_run']
        image = host['image'][0] if isinstance(host['image'], list) else host['image']
        row = dict(planned_run_id=qid, recording=folder.relative_to(REPO).as_posix(),
                   created_at_utc=manifest['created_at_utc'], purpose=manifest['purpose'], seed=config['seed'],
                   map=config['map'], schedule=config['schedule'], values=config['values'],
                   status='PASSED', messages=report['message_count'], transactions=report['transaction_count'],
                   episodes=report['episode_count'], normal=report['label_counts']['normal'],
                   command_injection=report['label_counts']['command_injection'],
                   response_injection=report['label_counts']['response_injection'],
                   frames=report['capture_statistics']['frames'], drops=0,
                   image_id=image['Id'],
                   capture_sha256=sha(folder / 'capture.pcap'),
                   artifact_sha256={p.name: sha(p) for p in sorted(folder.iterdir()) if p.is_file()},
                   target_transaction_positions=report['target_transaction_positions'])
        rows.append(row)
        for item in report['coverage_counts']:
            count_rows.append(dict(planned_run_id=qid, campaign='controlled-testbed-v02',
                                   day_utc=manifest['created_at_utc'][:8], endpoint='127.0.0.1:15020/unit1',
                                   **item))
        for match in report['control_matches']:
            event = by_id[match['event_id']]
            dependency = dependencies[event['event_id']]
            control_id = match['normal_event_ids'][0]
            def compact(item):
                return {k: item[k] for k in ('event_id', 'episode_id', 'transaction_index', 'label', 'role',
                                             'adu_hex', 'pdu_hex', 'stream_offset', 'direction',
                                             'wire_first_frame', 'wire_complete_frame', 'frame_byte_references')}
            examples.append(dict(planned_run_id=qid, source=folder.relative_to(REPO).as_posix(),
                                 capture_sha256=row['capture_sha256'], target=compact(event),
                                 earlier_anchor=compact(by_id[dependency['anchor_event_id']]),
                                 intervening_adus=dependency['intervening_adus'],
                                 matching_normal=compact(by_id[control_id]),
                                 control_earlier_anchor=compact(by_id[dependencies[control_id]['anchor_event_id']])
                                 if control_id in dependencies else None,
                                 private_lineage=dict(server_audit_transaction_index=event['transaction_index'],
                                                      intervention_audit_transaction_index=event['transaction_index'])))
    # Input provenance is checked again by validation; whole-run grouping is reported only.
    summary = dict(schema_version=2, status='FOUR_ENGINEERING_QUALIFICATIONS_PASSED',
                   generated_at_utc=datetime.now(timezone.utc).isoformat(),
                   original_design_sha256=sha(ROOT / 'design/collection_design.json'),
                   source_sha256=source_hashes(), runs=rows, failed_attempts_preserved=failures,
                   message_count=sum(r['messages'] for r in rows),
                   transaction_count=sum(r['transactions'] for r in rows),
                   episode_count=sum(r['episodes'] for r in rows), label_counts=dict(total),
                   independent_campaigns=1, measured_recordings=4, qualification_only=True,
                   actual_model_partitions=0, main_roster_collected=False,
                   no_model_preprocessing_or_training=True, academic_approval_asserted=False,
                   execution_ledgers=[p.name for p in EVIDENCE.glob('execution-*.json')],
                   limitations=['Q runs are engineering evidence, excluded from model development and scoring',
                                'One simulated process, one controller, one connection per run; no industrial generalization claim',
                                'Only M0/V0/S1 measured; M1/M2/V1/S2 not qualified by these captures',
                                'Normal/target PDU overlap is checked, but timing, ordering and metadata shortcuts remain research risks',
                                'All defined policy violations can be checked by simple causal rules; no ML advantage established',
                                'Captures are measured software traffic; no physical process manipulation or MITM claim'])
    save(EVIDENCE / 'qualification_summary.json', summary)
    save(EVIDENCE / 'evidence_examples.json', dict(examples=examples, count=len(examples)))
    with (EVIDENCE / 'coverage_counts.csv').open('w', encoding='utf8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(count_rows[0]))
        writer.writeheader()
        writer.writerows(count_rows)
    table = ['| Run | Messages | Normal | Command | Response | Episodes | Drops |',
             '|---|---:|---:|---:|---:|---:|---:|']
    table.extend(f"| {r['planned_run_id']} | {r['messages']} | {r['normal']} | {r['command_injection']} | {r['response_injection']} | {r['episodes']} | 0 |" for r in rows)
    report = f'''# Component 3 v0.2 qualification decision

**Four measured engineering qualification captures passed. Main collection remains disabled.**

{chr(10).join(table)}

Total: {summary['message_count']} ADUs, {summary['transaction_count']} complete transactions,
{summary['episode_count']} episodes. The four fresh runs are replications of **one software testbed**,
not four independent industrial campaigns. Their labels are raw evidence annotations,
not a final model dataset; these qualification captures are excluded from later fitting,
selection and scoring.

## What is established

Each run covers all eight scenario families, protocol-valid direct commands and both reciprocal
readback mutations. Every attack has a normal example with the same object role and current PDU.
All message bytes reconcile to PCAP frames/file offsets and private intervention/state records.
The independent decoder/replay checked earlier visible mode or acknowledged-write anchors,
zero recorded kernel drops, complete pairs and preserved repeated genuine writes. An ordinary
ACK of an injected request stays normal. Parser shape, mechanism and software state effect are
separate; no physical process effect is inferred. All raw/application records are retained.

## What remains limited

Only M0/V0/S1 was collected. Other maps have offline protocol checks; proposed numerical/map/
ordering hold-outs have no measured qualification evidence. Current qualification has two
commands and four forged responses per run; many normal rows do not increase attack diversity.
Static-PDU overlap is necessary but cannot prove absence of timing, episode-position, TID or
template shortcuts. Scenario, step, private state, intervention flags, source filenames, seed,
run/group IDs and labels must remain outside later predictor inputs.

The policy is deliberately simple and fully expressible as causal rules. No trained detector,
context-window construction, feature transformation or score comparison occurred. Nothing here
repairs CIC's unsupported independent-campaign three-class claim or establishes superiority
of contextual ML. Changing the proposal from CIC-primary to testbed-primary still needs an
explicit academic methodology decision.

## Preservation and reproducibility

Original CIC preparation, reassessment, old pilot, design and captures were preserved.
See `protected_after.json` for the separately checked frozen-file result. Each new run contains
its original PCAP, application ledger, separate private audits, design/roster/config hashes,
source hashes, image identity, host execution record, validation report and verified annotations.
`execution-*.json` records exact Docker argument arrays; the matching transcript records output.
`qualification_summary.json` records artifact hashes; `evidence_examples.json` gives paired
normal/attack examples with earlier anchors and frame/file-byte lineage. `coverage_counts.csv`
contains audit counts by run, family, class, function/object, PDU and parse/pair state only.

Preserved failed collection attempts: {len(failures)}. The initial Q01 implementation failure
emitted no verified labels; its missing writer import was fixed and covered by a runtime-writer
test before retry. See `IMPLEMENTATION_NOTES.md` and the distinct failed/successful execution
ledgers; the failed attempt is excluded from all accepted counts above.

## Single best next action

Review this evidence and agree the testbed-primary, within-testbed academic claim. Then freeze
or prospectively revise the main design, collection budget and held-out conditions before any
main collection. Do not count this engineering material as train/validation/test data.

Stop if observable anchors, exact intervention/byte reconciliation or normal controls fail;
if capture loss or pairing ambiguity occurs; if shortcuts remain uncontrolled for the intended
claim; or if work would enter unapproved main collection or student-owned preprocessing.
'''
    (ROOT / 'QUALIFICATION_REPORT.md').write_text(report, encoding='utf8')
    print(json.dumps({k: summary[k] for k in ('status', 'message_count', 'label_counts', 'episode_count')}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
