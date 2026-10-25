"""Render human-readable reports from recomputed evidence; reports are review documents.

This deliberately updates only these Markdown reports; it never changes inputs/results.
"""
from pathlib import Path
import json
import hashlib
import pandas as pd

ROOT=Path(__file__).resolve().parents[1]
REVIEW=ROOT/'component4_review'
A=json.loads((REVIEW/'evidence/audit_v1/audit.json').read_text(encoding='utf-8'))


def write(name,text): (REVIEW/name).write_text(text.strip()+'\n',encoding='utf-8')
def table(headers,rows):
    return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |']+
                     ['| '+' | '.join(str(x).replace('|',' / ').replace('\n',' ') for x in row)+' |' for row in rows])


def inventory():
    digests={}
    for item in A['inventory']: digests.setdefault(item['sha256'],[]).append(item['path'])
    rows=[]
    for item in A['inventory']:
        p=item['path']; group=digests[item['sha256']]
        if p.startswith('data/raw/'):
            role,status,used='Canonical historical CSV reference','derived from unavailable original extraction','new prepare + old CLI'
        elif p in ['normal_traffic_baseline.csv','replay_attacks.csv']:
            role,status,used='Historical root copy','derived duplicate','old loader fallback, audit'
        elif p.startswith('uploads/'):
            role,status,used='Dashboard upload/state or 1-row test residue','derived / state','old active dataset config only'
        elif p.startswith('artifacts/'):
            role,status,used='Historical '+('saved model/bundle' if '/models/' in p else 'derived result/report'), 'derived; scientifically unvalidated', 'historical viewer + audit'
        elif p.startswith('src/') or p=='run_pipeline.py':
            role,status,used='Original pipeline implementation','historical code retained','retrospective reproduction; old runner disabled'
        elif p.startswith('app/') or p=='run_app.py':
            role,status,used='Original dashboard','historical read-only viewer','viewer only'
        elif p.startswith('tests/'):
            role,status,used='Original integration/verification tests','historical; some mutate artifacts','NOT run against preserved artifacts'
        else: role,status,used='Configuration/documentation/repository support','reference','see path'
        duplicate='identical to '+', '.join(x for x in group if x!=p) if len(group)>1 else 'unique hash; not proof of necessity'
        rows.append([p,role,item['size'],item['sha256'],status,used,duplicate])
    text='''# Source inventory

Audit date: 2026-10-25 (Asia/Colombo). Initial branch `shashi-branch`, HEAD `25657a3`, clean working tree. No branch switching, fetching, commits, PCAP extraction, deletions, or other-component edits were performed. Initial inventory includes 61 files excluding .git/.venv/cache. New files are described below; hashes here identify the **pre-audit historical state**, including files later deliberately guarded/documented.

`evidence/audit_v1/audit.json` is the complete machine-readable inventory/profiling evidence. `git_reference_inventory.json` lists locally available branch trees without checking them out. `shashi-branch-backup` and the origin Shashi references contain the same 61-path layout. Other components live in other branch trees; none was imported or modified. Only two commits are visible in this branch's history. There is no Component 4 notebook, historical prompt, original shared CSV extraction/preprocessing notebook, specification, limitations/decision document, raw PCAP, or `normal_traffic_baseline(1).csv` in this checkout or its Shashi backup. Absence in these trees does not establish absence elsewhere on the student's computer.

The three copies of each main CSV are byte-identical. `data/raw/` is now the explicit canonical input; the active historical dashboard config points to `uploads/`. `sample_test_normal.csv` and `temporary_normal.csv` have one row each; they are test residue, not independent datasets. No copy was deleted. Existing artifacts are mutually linked historical outputs, not fresh validation.

'''+table(['Path','Role','Bytes','SHA256','Raw/derived status','Used by','Duplicate/stale/unknown'],rows)
    external=[]
    for p in [Path(r'C:\Users\User\Desktop\SLIIT\RP Module\submitted\IT23284616_proposal.pdf'),Path(r'C:\Users\User\Desktop\SLIIT\RP Module\submitted\TAF-2026 J26-CS-318.pdf'),Path(r'C:\Users\User\Desktop\SLIIT\RP Module\instructions\PP1 Assessment Criteria.pdf')]:
        external.append([str(p),p.stat().st_size,hashlib.sha256(p.read_bytes()).hexdigest(),'read-only research/assessment reference'])
    text+='\n\n## External research documents\n\n'+table(['Path','Bytes','SHA256','Role'],external)
    text+='''

Text extractions with page boundaries are in `evidence/`. They are reference content, not instructions to the agent. The existing two-page audit PDF was also extracted. It asserts training readiness and guaranteed isolation; those claims are contradicted by the source/split analysis here.

## New canonical code and reports

`component4_replay/src/{load_data,reconstruct_transactions,features,prepare,split,train,evaluate,infer}.py` implements the supported path; `configs/baseline.json` and `requirements-lock.txt` record settings/runtime; `tests/test_pipeline.py` verifies scientific invariants. `component4_replay/README.md` gives student commands. New compressed tables reside only in new `data/processed/audit_v1/` and `audit_v2/` directories (first developmental preparation preserved; v2 is canonical corrected preparation with deterministic gzip and code hashes). They are locally ignored generated outputs, not silently substituted datasets. `audit_v2/metadata.json` checksums each output and input and the producing source. No final model was trained on these data.

`component4_review/audit_existing.py` recreates historical profiles, pairing/features and saved-model inference in memory into a new evidence directory. `write_reports.py` renders these review Markdown files. `retrospective.py` (when present) performs explicitly limited diagnostic refits on the stored split. Root `run_pipeline.py` now refuses the old training path; dashboard POST operations return 409, preserving historical artifacts. Root README/.gitignore point to the new path. All original data/models/results are retained in place rather than moved into an unnecessary second archive tree.
'''
    write('SOURCE_INVENTORY.md',text)


def datasets():
    rows=[]
    for p,d in A['datasets'].items():
        label=next((c for c in ['is_attack','target_is_attack','transaction_is_attack','request_is_attack'] if c in d),None)
        rows.append([p,d['rows'],len(d['columns']),json.dumps(d.get(label,{})),sum(d['nulls'].values()),d['exact_duplicate_rows'],d.get('timestamp',{}).get('quantiles',{}).get('0.0','N/A'),d.get('timestamp',{}).get('quantiles',{}).get('1.0','N/A')])
    text='''# Dataset audit

All counts below were recomputed from CSV bytes, not copied from saved summaries. Complete column names/dtypes, null counts per column, class percentages, duplicate counts, timestamp quantiles/decimal precision, frame reset row indices, TID/latency/diff distributions, endpoint pairs, functions, directions, registers/counts, payload-related fields and provenance availability are in `evidence/audit_v1/audit.json` under `datasets`. High-cardinality port distributions show distinct count plus top 30 rather than tens of thousands of table cells. Timestamp digits were checked using CSV text, independently of float conversion. Historical derived-table names do not establish provenance.

'''+table(['Dataset','Rows','Columns','Classes (0 normal / 1 replay)','Null cells','Exact duplicate rows','Minimum epoch','Maximum epoch'],rows)
    for p in ['normal_traffic_baseline.csv','replay_attacks.csv']:
        d=A['datasets'][p]
        text+='\n\n## '+p+'\n\n'
        text+=f"Classes: `{json.dumps(d['is_attack'])}`; percentages: `{json.dumps(d['is_attack_percent'])}`. Nulls: `{json.dumps(d['nulls'])}`. Timestamp: `{json.dumps(d['timestamp'])}`. Frame reset CSV row indices (zero-based): `{d['frame_resets']}`.\n\n"
        text+=table(['Field','Recomputed distribution/summary'],[[k,json.dumps(d[k])] for k in ['mbtcp_trans_id','endpoint_pairs','src_port_counts','dst_port_counts','modbus_func_code_counts','is_request_counts','modbus_ref_num_counts','modbus_word_cnt_counts','modbus_bit_cnt_counts','modbus_byte_cnt_counts','modbus_val_counts','frame_len_counts','payload_len_counts','mbtcp_len_counts','is_exception_counts','response_time','trans_id_diff','payload_columns','read_response_values']])
        text+='\n\nObserved discontinuity segments (gap >100s, backwards timestamp/frame, or source change; **not verified captures**):\n\n'
        text+=table(['Segment','Rows','Positive rows','Start epoch','End epoch','First frame','Last frame'],[[s[k] for k in ['observed_segment','rows','positives','start','end','frame_start','frame_end']] for s in d['observed_segments']])
    text+='''

## Interpretation and row unit

The raw-reference CSV has one extracted Modbus-bearing **packet/message observation** per row, with request and response directions separate. Frame numbers identify captured frames, and `has_stacked_frames` is a field; without the original exporter/bytes we cannot prove that each retained row is exactly one complete ADU. There is no TCP reassembly or true flow aggregation in these CSVs. Do not call these transaction rows.

The existing saved `reconstructed_transactions.csv` and feature tables instead contain **80,753 request-led observations**, including unmatched requests, not necessarily 80,753 complete pairs. Request labels give 78,679 normal and 2,074 replay requests (2.5683% replay; about 37.94 normal requests per positive). Raw combined packet/message labels give 157,247 normal and 2,247 replay rows (1.4088% replay). The derivative alone is 23.6676% replay; full normal plus positives is 1.4759% replay. Response-only attacks are not additional request targets: 173 positive response observations remain separately annotated. Pairing does not make these independent examples.

Normal `file_source` gives six PCAP filenames, each with exactly 25,000 rows; this regular truncation and nonzero first frame indicate a selected derivative, not full captures. Four additional long-gap cuts make ten observed normal segments. Replay has no `file_source` column at all and ten observed segments. No CSV carries verified campaign/run IDs, `tcp.stream`, sequence/acknowledgment numbers or payload bytes/hashes. Six observed normal source names plus ten unknown replay segments are not sixteen independent campaigns.

Of 2,247 replay-labelled rows, 2,212 (98.4424%) occur in one long observed replay segment. The remaining 35 occur in seven short segments. Two early segments contain no positives. Current-message positive signatures number only 14; positive request command signatures number only 10. Independent attack campaign count is **unknown**, not 2,247, not 2,074, and not ten. Whole-campaign class imbalance cannot be quantified until campaign identity is established. No oversampling was used or is justified by these counts alone.

Read-response `modbus_val` is zero in all 3,743 derivative read responses. The historical parser explicitly leaves read-response `val` at its initialized zero and only decodes byte count; a synthetic nonzero-value PDU check verifies this parser behavior. The exact producer of these historical CSVs is absent, so this is evidence of non-information, not proof that the true returned values were all zero. The baseline also contains placeholder-like request values. Never interpret this scalar as full process payload content.

The timestamp/endpoint/port/TID/function/register mirror probe found no matching cross-source observations within 10ms in these selected normal rows (`mirror_probe.json`). This does not prove independent recordings: truncated, disjoint-interface or time-shifted views remain possible without run metadata/TCP sequence numbers. No historical row or hard normal case was removed.
'''
    write('DATASET_AUDIT.md',text)


def tids():
    text='''# Transaction-ID audit

## Computation evidence

The original shared extractor that produced `trans_id_diff` is absent. Therefore its source code and exact pre-filter ordering cannot be certified. The currently checked-in pipeline does **not** use that stored column for its model: it recomputes `trans_id_raw_diff` and modulo delta on reconstructed requests, scoped to partition/capture/client IP/server IP/unit, **omitting both ports**. These are endpoint-channel features, not TCP-session features. Its first observation is incorrectly assigned a normal increment of 1.

For baseline rows, every comparable non-boundary row agrees exactly with global previous-message TID subtraction within observed segments: 149,990 / 149,990. Across all CSV rows it agrees on 149,994 / 149,999; source boundaries account for the five mismatches. This strongly identifies a global per-extraction diff, not a per-connection feature.

Replay agrees with direct global subtraction on only 7,319 / 9,493 comparable rows; no candidate scoped definition explains the rest. Retained rows are not sufficient to recover the exact producer. Several stored deltas imply preceding TIDs absent from the retained neighboring rows, consistent with calculation before filtering/selection. That is an inference, not recovered provenance.

'''
    for name,data in A['tid'].items():
        text+='\n\n## '+name+' candidate comparisons\n\n'
        text+=table(['Variant','Comparable rows','Equals stored diff','Negative','Zero','First/missing'],[[k,v['comparable_rows'],v['stored_equal'],v['negative'],v['zero'],v['first_or_missing']] for k,v in data.items() if isinstance(v,dict)])
    text+='''

## Interleaving reproduced

Replay CSV zero-based rows 5000-5003 contain requests to alternating servers:

| Row | Destination | Client port | TID | Stored diff | Endpoint-local previous-request diff |
| --- | --- | --- | --- | --- | --- |
| 5000 | 185.175.0.4 | 34590 | 15044 | -27056 | first / unavailable |
| 5001 | 185.175.0.5 | 40926 | 42101 | 27057 | first / unavailable |
| 5002 | 185.175.0.4 | 45466 | 15045 | -27060 | +1 |
| 5003 | 185.175.0.5 | 40966 | 42106 | 27061 | +5 |

The -27060 difference implies a previous TID of 42105, while the immediately preceding retained row is 42101. Both stream interleaving and omitted source rows matter. Baseline frames 29381 onward similarly switch from server .4 TID 11178 to server .8 TID 1, creating -11177 on **normal** traffic.

The endpoint-only normal request diff has only one negative value in ten observed segments, versus 7,854 negatives in the stored baseline column. This does not make the endpoint rule a replay detector: endpoints can reset, wrap or restart legitimately, and the channel spans many TCP ports. Almost all true four-tuple proxies have only one observed request, so their previous-request TID is **missing**, not zero or one. A verified TCP-connection/session-local candidate cannot be computed: handshake continuity, `tcp.stream`, TCP sequence/ACK numbers and omitted messages are unavailable. Four-tuple comparison is explicitly only a proxy.

## Corrected semantics

New `session_tid_diff` and modulo delta use requests only within the same observed four-tuple/lifetime proxy. `endpoint_tid_diff` is a separately named cross-port endpoint/unit hypothesis. Histories reset at observed segment and partition boundaries, use only preceding requests, and are bounded by both 100 requests and 60 seconds. First history remains NaN with an availability indicator. A 65535 to 0 wrap gives signed -65535 and modulo +1; a decrease alone does not imply replay. No old CSV or stored delta was overwritten.

## Shortcut audit

Each row below gives TP / FP / TN / FN followed by precision, recall, F1, FPR and accuracy. These are descriptive diagnostics, not a detector selected on a test set. Fixed simple rules are frozen without tuning. In-sample per-field majority probes in the JSON are explicitly overfit artifact probes, not held-out scores. The unrestricted signature rule is a table-order diagnostic, not a bounded online duplicate rule or payload hash.

'''
    for name,values in A['diagnostics'].items():
        text+='\n\n### '+name+'\n\n'
        text+=table(['Rule','TP','FP','TN','FN','Precision','Recall','F1','FPR','Accuracy'],[[k]+[v[x] if x in ['TP','FP','TN','FN'] else f'{v[x]:.6f}' for x in ['TP','FP','TN','FN','precision','recall','F1','false_positive_rate','accuracy']] for k,v in values.items() if k!='single_field_in_sample_majority'])
    text+='\n\nFor the negative-diff rule, the positive support is unchanged across comparisons. Precision collapses when the larger normal population is admitted; the derivative composition is a major shortcut. The full-normal experiment deliberately contains only baseline normals plus derivative positives, exactly as requested; it does not invent new packet chronology or recompute cross-file history.\n'
    write('TID_AUDIT.md',text)


def requirements():
    claims=[
    ['Protocol-valid replay rather than malformed traffic (proposal p3, p13-16; TAF p4,p10)','Valid normal/replay signatures plus verified replay log','14 observed positive message signatures; every positive has a matching normal signature','PARTIAL','No raw byte or attack-log validation'],
    ['Main unit is transaction/context (proposal p15-16; FR-02)','Session-scoped request/response associations','Raw CSV is message rows; legacy and corrected pairing both present','CONDITIONAL','Pair scope is observed four-tuple, incomplete TCP/capture identity'],
    ['Transaction identifiers and changes (p3,p16; TAF p10)','Preceding requests in correct stream; wrap/reuse handling','Stored global diff flawed; new session proxy and endpoint variants separate','CONDITIONAL','Most proxies have no earlier request; true session identity absent'],
    ['Request/response timing (p16; FR-02/04)','Complete request/reply data; causal availability','78,620 pairs; missing reply is not a confirmed timeout','PARTIAL','Filtered omissions, capture truncation, configured search timeout'],
    ['Duplicate requests/repeated payloads (p3,p16; FR-03/04)','Recent command history and full bytes/hashes','Bounded observed-command fingerprint implemented','PARTIAL','Full ADU byte equality unsupported; read values zero/placeholder'],
    ['Session/sequence consistency (p14-16; TAF p10)','TCP stream and run identity; order','Segment/frame cuts and four-tuple proxies; endpoint history named explicitly','CONDITIONAL','No handshake/seq/ACK or verified replay capture identity'],
    ['Normal/replay binary XGBoost (p14,p16; FR-05)','Verified per-request target and classifier','Legacy XGBoost exists; corrected A/B/C runner implemented','YES for implementation','Packet labels not independently verified; request/response conflicts retained'],
    ['Conventional baseline vs transaction consistency (p16-18; FR-11)','Same target rows, groups, classifier; ablation','Legacy has only rule vs context model; new B/C runner uses common targets','NOT ESTABLISHED empirically','No independent manifest; no final experiment run'],
    ['False-positive rate and repetitive normals (p17; NFR-02)','Full difficult normal cases; confusion matrix','Full baseline shortcut tested; no normal cases removed','YES diagnostic','Independent generalization not established'],
    ['Latency measured, not assumed (p17-18; FR-07; NFR-01)','Decision availability plus parsing/feature/inference/wait times','Legacy batch inference/mean observed latency; corrected request arrival decision','PARTIAL','Batch amortization is not event/end-to-end latency; no live measurement'],
    ['Leakage-resistant scenario/session split (p18)','Verified campaign/run groups; train/val/test; no future context','Legacy dominant segment shared and row reallocation fallback; new manifest fails closed','CONDITIONAL new control','Independent current-data experiment UNSUPPORTED'],
    ['Reproducibility (FR-12; NFR-07)','Hashes, configuration, schema, runtime and model linkage','Old predictions/features reproduced; new hashed outputs/config/code and model metadata','YES for replayability','Original producer/version/provenance not recovered'],
    ['Confidence/evidence and fusion integration (FR-06/09; TAF p10)','Stable schema with label, probability, session, time/evidence','Historical dashboard; new batch inference schema and recurrence evidence','PARTIAL','No full four-component fusion/live integration validated'],
    ['Isolated controlled testbed (p16,p27; TAF p10)','Run logs with normal polling and multiple replay delays','No such verified captures/logs in this branch','NO','CIC supplement conditional in proposal; team TAF explicitly plans testbed'],
    ['Maintainability and bounded/streaming processing (NFR-06/08)','Separate modules and bounded state; batched ingestion','New simple modules; bounded recent history','PARTIAL','CSV preparation still batch in-memory; not a live streaming sensor'],
    ['PP1 proof of concept and risk mitigation (mark sheet p1)','Working demonstration and candid implementation/evidence gaps','Regression-tested preparation + review matrix + explicit blocked experiment','YES prototype evidence','PP1 is an assessment rubric, not permission to claim unsupported performance'],
    ]
    write('REQUIREMENTS_MATRIX.md','''# Requirements matrix

Read-only sources: the individual proposal (33 PDF pages), team TAF (12 PDF pages), and PP1 assessment criteria (1 page). PDF page markers are retained in `evidence/*.txt`. The proposal's title page says R26-CS-318 while the team form/repository use J26-CS-318; this clerical mismatch does not change Component 4 or student identity. Research claims below remain the intended methodology; the existing CSV does not redefine them. Historical prompts, where absent, are not invented; the reports and PDF are treated as evidence to audit.

'''+table(['Proposal/TAF claim','Evidence/data required','Current implementation','Verified?','Limitation'],claims))


def results():
    path=REVIEW/'evidence/retrospective_v1/diagnostics.json'
    if not path.exists(): return
    d=json.loads(path.read_text())
    saved=A['saved_results']
    rows=[]
    m=saved['saved_model_direct_metrics']
    rows.append(['Original saved model inference',m['TP'],m['FP'],m['TN'],m['FN'],m['precision'],m['recall'],m['F1'],m['false_positive_rate'],m['balanced_accuracy'],saved['ROC_AUC'],saved['PR_AUC_average_precision']])
    from audit_existing import metric
    prediction=pd.read_csv(ROOT/'artifacts/predictions/test_predictions.csv')
    rule=metric(prediction.target_is_attack,prediction.rule_pred)
    rows.append(['Original stored protocol rule']+[rule[x] for x in ['TP','FP','TN','FN','precision','recall','F1','false_positive_rate','balanced_accuracy']]+[None,None])
    helper=json.loads((path.parent/'original_helper_refit.json').read_text())['metrics']
    choices={'Original training helper refit':helper}
    choices.update({k:v['metrics'] for k,v in d['models'].items()})
    choices.update({k:v['metrics'] if 'metrics' in v else v for k,v in d['new_causal_diagnostics'].items() if isinstance(v,dict) and ('metrics' in v or 'TP' in v)})
    ablation=json.loads((path.parent/'feature_group_ablation.json').read_text())
    choices.update({k:v['metrics'] for k,v in ablation['variants'].items()})
    for k,m in choices.items():
        rows.append([k]+[m[x] for x in ['TP','FP','TN','FN','precision','recall','F1','false_positive_rate','balanced_accuracy','ROC_AUC','PR_AUC_average_precision']])
    for row in rows:
        for i in range(5,len(row)):
            if isinstance(row[i],float): row[i]=f'{row[i]:.6f}'
    text='''# Results and reproducibility

**Every score in this report uses the historical, scientifically conditional split. No score is an independent final result.** The saved manifest assigns part of inferred `replay_capture_2` to training and part to test, with 53 gap-excluded observations. No validation partition exists. We did not tune hyperparameters or threshold, select a detector from these scores, or save a final refitted model.

## Exact historical experiment

- Inputs: SHA256 `70d08fc730a8572d16a08d860be61536ae7565af048c7c7e283004e54fe55b01` (150,000 normal rows) and `714587f4511b12400a809f3ba6bd533e10167ff25f353414b4151f5d362918b1` (9,494 mixed replay derivative rows).
- Pairing: one-second search bound; normal filename scope and ten heuristic replay segments. 80,753 request observations, 78,620 pairs, 2,133 missing responses, 121 unpaired response rows, 1,047 label conflicts.
- Training: 54,777 requests (53,342 normal; 1,435 replay). Test: 25,923 (25,330 normal; 593 replay). Gap: 53 (7 normal; 46 replay). Request-label target, not packet-positive count.
- Features: the exact 21-field `src.feature_engineering.MODEL_FEATURE_COLUMNS`; see `FEATURE_AUDIT.md` and `feature_dictionary.json` for the saved definitions. Reconstructed request data and saved feature matrices reproduce to float serialization precision (largest per-column difference below 5e-13); discrete features reproduce exactly.
- Model: XGBoost 3.4.1; 100 estimators, depth 4, learning rate .1, subsample .8, column sample .8, seed 42, logloss, threshold .5; training-only median imputer; `scale_pos_weight=53342/1435=37.17212543554007`. No SMOTE/scaling/feature selection. The stored training-loss trace is training loss only, not validation evidence. Saved bundle timestamp: 2026-10-23T12:55:11.646630.
- Inference from the saved model reproduces 100% of stored binary predictions. Calling the original `train_xgboost_model` helper with all output paths unset reproduces the original confusion matrix and AUC/AP as well, in about one second of fit time. Nothing historical is overwritten.
- Explicit single-thread `hist` diagnostic refits yield four extra false positives relative to the original default-thread helper. This illustrates why runtime/thread settings must be recorded; it is not a failed reproduction of saved inference or the original helper. No environment-independent byte-identical model claim is made.

## Metrics (test support: 25,330 normal; 593 replay)

ROC-AUC and average precision use unrounded probabilities. `PR_AUC_AP` means average precision, not trapezoidal PR area. The saved prediction CSV rounds probabilities to four decimals and has slightly different AUC/AP (0.999504 / 0.983435), while unrounded saved-model inference gives the values below.

'''+table(['Model/diagnostic','TP','FP','TN','FN','Precision','Recall','F1','FPR','Balanced accuracy','ROC-AUC','PR_AUC_AP'],rows)
    text+='''

## What the diagnostic comparison does and does not establish

New A/B/C use exactly the same stored historical train/test **request targets**, cold-start histories per partition/segment, fixed classifier settings and threshold, and training-only class weight. B includes current-message fields, including raw TID, so C cannot claim advantage merely by seeing a field denied to B. These are diagnostic refits after the data audit, not the prohibited final model training.

C improves on B inside this split (F1 0.930421 vs 0.232040), but **current fields plus timing alone already reach 0.929669**. Removing TID-context features leaves F1 0.926672, while removing timing reduces F1 to 0.452860. The gain is therefore largely explained by timing/polling differences within a shared scenario. The simple bounded recurrence rule finds zero replay requests under the configured history. Absolute TID also contributes substantially. These results motivate controlled investigation; they do not establish unique replay sequence/payload consistency, unseen-session generalization, or XGBoost superiority.

The chronological embargo is useful for reducing immediate neighbor overlap. It cannot turn one replay recording/scenario into independent attack campaigns. Do not promote these diagnostic results to the final experiment. C remains conditional even though its features are causal and its within-split score is high.

## Importance and shortcuts

Saved gain importance: response latency 0.60043, flawed outstanding count 0.17889, timeout flag 0.08213 (together 86.145%); signed TID diff 0.05154. Gain importance alone is not causal evidence. One fixed-seed per-column permutation on saved test features gives the largest F1 drops for outstanding count (0.23034), register (0.12872), response latency (0.05607), and matched status (0.03261). Correlated features can mask a feature's effect; permutation is descriptive, not an independence test.

New causal C gain importance is dominated by endpoint request IAT (0.40264), time since observed command (0.21722) and absolute TID (0.17085). Actual session-local TID history is almost entirely unavailable. Precise parameters/importances/permutation deltas and all single-rule diagnostics are saved in `evidence/retrospective_v1/` and `evidence/audit_v1/audit.json`. No SHAP dependency was added.

## Detection latency

Historical stored 0.0004ms model inference and 0.0004ms preparation per row are batch-amortized timings; its 24.81ms operational number combines mean observed pair delay or a hardcoded one-second sentinel with batch computation. This is not a measured live end-to-end distribution, especially when unobserved replies may simply have been filtered out. It excludes capture, TCP reassembly, complete feature construction, buffering and scheduling.

New features become available when a complete request ADU has been observed, plus bounded prior history. There is no wait for its future reply, timeout, or later duplicate. A repeated-request feature can flag a later recurrence at that later arrival; it cannot retrospectively detect the first occurrence before the recurrence. Response latency is available only on an observed uniquely matched reply; absence-based consistency can be considered only after a timed search bound **and verified capture completeness**. Such outcomes are retained as audit metadata, not new request-arrival model inputs. Synthetic inference tests validate artifact wiring; no measured operational latency or detection-delay guarantee is claimed.
'''
    write('RESULTS.md',text)


def main():
    inventory(); datasets(); tids(); requirements(); results()
    print('Rendered inventory, dataset, TID, requirements and results reports')


if __name__=='__main__': main()
