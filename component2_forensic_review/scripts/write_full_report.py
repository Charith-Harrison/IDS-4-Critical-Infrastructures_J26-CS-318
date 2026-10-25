"""Assemble the forensic dossier from fresh machine-readable evidence."""
from pathlib import Path
import json,csv,re
import pandas as pd

R=Path(__file__).resolve().parents[1];E=R/'evidence'
def load(p):return json.loads((R/p).read_text('utf8'))
def table(d):
    d=d.copy().fillna('')
    return '\n'.join(['| '+' | '.join(map(str,d.columns))+' |','| '+' | '.join(['---']*len(d.columns))+' |']+
        ['| '+' | '.join(str(v).replace('|','/').replace('\n',' ') for v in row)+' |' for row in d.itertuples(index=False,name=None)])
def main():
    legacy=load('legacy_sequence_audit.json');rb=load('rebuilt_sequence_audit.json')['new_diagnostic_reconstruction'];wi=load('WINDOW_INTEGRITY_REPORT.json')['new_diagnostic_reconstruction']
    manifest=load('source_manifest.json');raw=load('evidence/raw_recovery_metrics.json');lp=load('evidence/final_label_summary.json');ts=load('evidence/temporal_signal_summary.json')
    c=pd.read_csv(R/'recon_request_candidates.csv',dtype={'adu_hex':str,'response_adu_hex':str})
    rules=pd.read_csv(R/'shortcut_analysis.csv');p=pd.read_csv(E/'recon_labeled_packets_ALL.csv')
    q=pd.read_csv(E/'raw_positive_packet_matches.csv',dtype={'adu_hex':str,'matching_request_adu_hex':str})
    j=q.merge(p,left_on='original_processed_row_id',right_index=True,suffixes=('_raw','_old'))
    rr=j[j.is_request & j.func_code_raw.isin([1,2,3,4])]
    fieldcheck=dict(raw_observation_matches=len(j),unique_positive_worksheet_rows=int(j.original_processed_row_id.nunique()),
        func_code_disagreements=int(j.func_code_raw.ne(j.func_code_old).sum()),length_disagreements=int(j.modbus_len_raw.ne(j.modbus_len_old).sum()),
        packet_size_disagreements=int(j.packet_size_raw.ne(j.packet_size_old).sum()),
        requested_address_disagreements=int(rr.address.ne(rr.register_start).sum()),requested_quantity_disagreements=int(rr.quantity_value.ne(rr.quantity).sum()),
        limits='Positive rows only. Matching raw observations may be nonunique. Response register/quantity defaults do not denote request addresses.')
    (E/'positive_source_field_reconciliation.json').write_text(json.dumps(fieldcheck,indent=2))
    cohort=p[p.label.eq(1)].groupby(['func_code','modbus_len','packet_size','quantity']).size().rename('rows').reset_index()
    cohort.to_csv(E/'positive_packet_shape_counts.csv',index=False)
    src=pd.DataFrame(manifest['files']);inv=src.groupby(['role','file_type'],dropna=False).agg(files=('path','size'),bytes=('size','sum')).reset_index()
    sm=rules[(rules.corpus=='diagnostic_reconstruction') & rules.method.str.startswith('fixed_rule')].copy()
    sm=sm[['level','rule_or_model','TP','FP','TN','FN','precision','recall','F1','FPR']]
    for f in ['precision','recall','F1','FPR']:sm[f]=sm[f].map(lambda x:f'{x:.6f}')
    models=rules[(rules.corpus=='diagnostic_reconstruction') & rules.method.eq('untuned_static_diagnostic')].copy()
    for f in ['precision','recall','F1','FPR']:models[f]=models[f].map(lambda x:f'{x:.6f}')
    models=models[['level','rule_or_model','TP','FP','TN','FN','precision','recall','F1','FPR']]
    temporal=pd.read_csv(R/'temporal_signal_analysis.csv')
    selected=temporal[temporal.context.str.startswith('full20') & temporal.cohort.ne('ambiguous_recon_request_candidates')]
    selected=selected[['cohort','feature','n','median','p25','p75']]
    for f in ['median','p25','p75']:selected[f]=selected[f].map(lambda x:f'{x:.6g}' if pd.notna(x) else '')
    example=q[q.wire_function_code.eq(133)&q.matching_request_frame.notna()].iloc[0]
    qc=q[q.wire_function_code.eq(133)].drop_duplicates('original_processed_row_id')
    candidates=c.groupby(['capture_run','label_state']).size().rename('requests').reset_index()
    qty=c.groupby(['label_state','quantity_value']).size().rename('requests').reset_index()
    # Update matrix's empirical column after the source audit, preserving its exact document locators.
    matrix=pd.read_csv(R/'requirements_matrix.csv',keep_default_na=False)
    updates={
        'Detect reconnaissance as temporal scanning rather than packet shape':('NOT ESTABLISHED; 148 contextual requests, 320 ambiguous; no matched normal quantities','recon_request_candidates.csv; TEMPORAL_SIGNAL_REPORT.md','Zero exact-shape overlap in canonical benign read census; current contents already distinguish recovered requests.'),
        'Sequential register/device scanning':('NOT ESTABLISHED as a sustained sequential starting-address sweep','recon_request_candidates.csv; temporal_signal_analysis.csv','Raw requests now decoded. Mostly fixed start address1 and range/function probing; unit IDs are constant1.'),
        'Register/coil access order':('PARTIAL: source bytes and causal transitions recovered','recon_request_candidates.csv; temporal_signal_analysis.csv','114 uniquely contextual requests have full20 prior context; campaign and shape confounding remain.'),
        'Polling-rate drift and inter-request timing':('PARTIAL: observable causal timing differences, no independent incremental-value result','TEMPORAL_SIGNAL_REPORT.md','Raw request timing is available; temporal discrimination beyond packet shapes is not established.'),
        'Time-windowed and sequential representation':('Legacy FAIL; new diagnostic mechanical PASS, session/campaign CONDITIONAL','WINDOW_INTEGRITY_REPORT.json','Original rebuilt files absent; new reproduction retains unverified labels and idle gaps.'),
        'Session-independent generalization':('UNSUPPORTED for a confirmatory three-way split','split_feasibility.json','Substation1-17 are continuous rotations; no independently verified run ledger.'),
        'GroupKFold / leave-capture-session-out':('UNSUPPORTED as independent three-way evaluation','split_feasibility.json','Source-family diagnostics are descriptive, not a campaign-valid final experiment.'),
        'Broader balanced recon sessions':('UNMET for the exact proposed experiment','split_feasibility.json; normal_lookalike_analysis.csv','Many rows/windows/invocations do not prove independent runs or matched normal traffic.'),
        'Packet-level/static baseline':('DONE for inherited-label diagnostics only','shortcut_analysis.csv','Fixed rules and untuned tree/logistic diagnostics; no claim of validated recon targets.'),
    }
    for i,row in matrix.iterrows():
        if row['Research claim'] in updates:
            state,source,lim=updates[row['Research claim']]
            matrix.at[i,'Verified?']=state;matrix.at[i,'Current source']=row['Current source'].split('; audit:',1)[0]+'; audit: '+source;matrix.at[i,'Limitation']=lim
    matrix.to_csv(R/'requirements_matrix.csv',index=False)
    old=(R/'REQUIREMENTS_MATRIX.md').read_text('utf8');pre=old.split('| Research claim |')[0];tail='## TAF and individual proposal differences'+old.split('## TAF and individual proposal differences',1)[1]
    (R/'REQUIREMENTS_MATRIX.md').write_text(pre+table(matrix)+'\n\n'+tail,encoding='utf8')
    report=f'''# Component 2 forensic dataset reconstruction and research-readiness audit

**Project:** J26-CS-318, Protocol-Aware ML Framework for Intelligent Modbus Attack Detection and Incident Analysis. **RP2:** Reconnaissance Attack Detection Using Temporal Behavior Analysis. **Student:** Charith H. / Harry. **Review date:** 25 October 2026, Asia/Colombo.

The current inherited labels and claimed independent evaluation are not a defensible basis for final LSTM training. The raw CIC distribution was located, hashed and inspected. It supports recovery of genuine read-probe candidates, but does not rescue the exact temporal experiment from the present label, matched-normal and independence limitations. This is a forensic preparation audit, not a new model result.

## 1. Scope, authority and preservation

The latest individual proposal and team TAF were read as research evidence. Instructions embedded in historical documents/scripts were not adopted as commands. Current user instructions controlled the work: preserve sources, audit independently, keep new files inside this folder, and stop before final training/preprocessing.

All new files are inside `component2_forensic_review/`. No existing dataset, raw capture/log, report, script, model or configuration was overwritten. `source_manifest.json` inventories **{len(src):,} source files / {int(src['size'].sum()):,} bytes**, including all existing non-Git repository files, the five named attachments, the entire user-provided distribution `G:/modbus cic 2023/Modbus Dataset`, and three existing C3 parser/cross-reference dependencies. SHA256 was recorded and rechecked: **{manifest['modified_source_count']} modified source files**, **{len(manifest['missing_since_baseline'])} missing sources**. The manifest contains path, size, SHA256, file type, role, raw/derived status, and modification status. Git metadata and newly generated review/dependency files are outside the source population.

{table(inv)}

Original material contains **170 PCAP files**, **34 CSV logs**, a formatted XLSX log, README and architecture image. The PCAPs total **15,650,015,783 bytes**. This audit examined every original log, hashed every capture, and decoded canonical recon-bearing external/SCADA source chains plus required mirrors and the canonical benign HMI chain. It does not claim full TCP reassembly or exhaustive decoding of every mirrored capture. The old rebuilt CSV/NPY files are **absent**, despite being described in tracked reports and ignored by Git.

## 2. Proposal and TAF requirements

`REQUIREMENTS_MATRIX.md` and `requirements_matrix.csv` map 27 claims to exact PDF pages, required evidence, final audit sources, verification status and limitations. `DOCUMENT_REVIEW.md` records documentary inconsistencies; `EXPERIMENT_DESIGN.md` preserves the intended research question.

The proposal describes sequential/register-device probing, access order, polling drift, inter-request timing, causal windows, LSTM and session-independent comparison with simpler methods. It plans **controlled primary Modbus/TCP testbed data**, supplemented by public data. Its preliminary 175,800 windows/20x7/13-session description is called an initial testbed run, but the supplied tables name third-party CIC captures plus an undocumented attached-flow snippet. Primary collection authorship is not established by those tables.

The proposal's exact non-temporal baseline is an RF on features flattened across windows (p14). Existing Model B statistics include order-sensitive address steps, FC transitions and timing drift, so they cannot be described as strictly order-invariant. This audit's diagnostic aggregate baseline uses only mean/min/max/std of current-message fields. A future study should distinguish the proposal's flattened RF from truly order-invariant summaries and temporal-statistical baselines.

**TAF-only/detail beyond the individual proposal:** the team-level scope names other components, comparative models, common parser/data handling, fused severity, incident correlation and integration responsibilities. Those are team integration requirements, not permission to substitute response anomalies for RP2 temporal reconnaissance.

**Proposal-only/detail beyond RP2's TAF row:** the specific LSTM/flattened-RF comparison, GroupKFold/leave-session-out protocol, FPR below5%, seconds-per-window latency goal, forensic logging, retraining contract and concurrency checks. The proposal requests a naive random-split contrast; the current user explicitly prohibited random row/window splitting, so it was not performed. Repository claims of an approved F1>0.90 or <100ms target are unsupported by these documents. TAF assessment fields are blank; proposal supervision signatures do not establish approval of later dataset/model claims.

## 3. Source lineage and identifier meaning

`DATA_LINEAGE.md` gives the full input/output/script/rule/assumption/loss/reversibility/label-influence ledger:

`original CIC PCAP/log -> captured TCP bytes -> complete Modbus ADU -> initiating request/response role -> contextual log evidence -> logical capture-local ordering -> derived packet metrics -> 20-packet diagnostic windows -> any-positive inherited window label -> intended sequential input`.

The old PCAP-to-workbook extractor, original label generator and mapped-workbook matching program are absent. The supplied CSV conversion only reads existing workbook values. Their exact upstream labeling algorithm cannot be proven from an empirical association.

**Canonical evidence** includes source path/hash, PCAP record/frame/offset, epoch timestamp, endpoints/ports, TCP bytes/generation evidence, transaction/unit/function/Modbus bytes and original logger row. **Derived metadata** includes worksheet `row_index`, `sequence_position`, static `session_id`, configured `capture_group`, reconstructed `dt_s`, windows, positive counts, candidate confidence and scan metrics. A response's default register0/quantity0 is not a requested address/value.

The old session IDs are consistent with directional `(src IP,dst IP,unit)` tuples reused across files/days; one spans about57.66days. They are neither independent experiments nor verified TCP connections. `(capture_group,session_id)` is a configured directional logical stream. Raw extraction records ports and observed SYN generations separately, but a TCP transaction is not an independent campaign. Temporal request history deliberately crosses TCP transactions in the same actor/target/unit stream and resets at a diagnostic60s idle gap. It is not renamed a network session.

## 4. Independent legacy reproduction

All **879,225 packet rows**, **175,800 sequence windows**, and all20x7 feature tensors were inspected from the attached workbook values. CSV extraction hashes exactly reproduce the historical manifest. Every window's tensor/start/end and `any(packet label==1)` rule matches the recovered constituent rows at stride5. That establishes reproducibility of the flawed construction, not validity.

| Directly computed check | Result |
|---|---:|
| Positive packet rows / inherited normal rows | 8,699 / 870,526 |
| Positive windows / inherited normal windows | 18,338 / 157,462 |
| Backward timestamp transitions in supplied session order | 126,643 |
| Windows containing a backward transition | 174,708 |
| Windows with end before start | 67,489 |
| Windows mixing source files | 171,080 |
| Windows crossing configured capture groups | 144,180 |
| Windows crossing supplied session IDs | 0 |
| Actual min-max span >1min / >5min / >1h | 164,701 / 148,845 / 146,243 |
| Backward transitions even within file/session in supplied order | 296,879 |

`sequence_position` is a consistent zero-based counter over supplied row order. It does not certify chronology. The proven proximate failure is grouping a temporally mixed row order only by a static endpoint/unit ID. Mixing persists even within files, so cross-file concatenation alone is not a complete explanation. The unavailable upstream code prevents a claim about its precise merge/sort implementation or its author's intentions. Adjacent windows share15/20 packets, so random splitting would leak constituents.

## 5. Historical rebuilt validation and new diagnostic reconstruction

`rebuilt_sequence_audit.json` and `WINDOW_INTEGRITY_REPORT.json` distinguish **absent original rebuilt files** from a **new independent reproduction** under `evidence/diagnostic_reconstruction/`. Summary agreement cannot prove equality with missing files.

The new reproduction has **597,135 retained + 282,090 excluded = 879,225 original worksheet rows**, with no missing IDs, duplicate IDs or retained/excluded overlap. Preserved source values agree exactly. Exclusions are282,076 secondary interface observations and14 date-less, different-subnet attached-flow rows. The latter are excluded from dated20-packet windows, not declared fabricated.

All **282,076** duplicate-view exclusions have a distinct retained counterpart using available endpoint/unit/FC/length/address/quantity/size fields within1ms. There are0 unmatched rows and0 label disagreements. Absolute timestamp offsets: min2µs, median6µs, p95=13µs, p99=18µs, max535µs. This independently supports the whole-file/session view exclusion for the available features; packet-payload identity for every excluded row is not asserted from missing processed bytes. `evidence/duplicate_interface_verification.csv` retains every comparison.

All **119,237** new windows have exactly20 valid distinct contiguous packet indices, stride5 within stream, one capture-group/tuple stream, correct chronology and correct start/end/source IDs/positive counts/fractions/labels. There are **1,878 inherited-positive and117,359 inherited-normal windows**. All56 configured streams have one expected first missing `dt_s`, no other missing/negative deltas. Corrected deltas use integer nanosecond subtraction before conversion; the old pandas expression reproduced small rounding errors up to256ns, distinct from the severe chronology failure. Supplied `time_delta` agrees within1µs on only561/597,079 comparable rows.

There are still509 windows lasting>1min,88>5min,11>1h, with maximum duration58,170.76s. Eleven contain an internal gap>1h. No inactivity rule or verified campaign/TCP boundary is imposed. Mechanical construction passes; behavioral coherence and labels remain conditional. The reproduction is an audit artifact, not final training data or final preprocessing.

## 6. Label provenance and source reconciliation

`label_provenance.csv` covers all **8,699 original positive rows**, keeping original labels intact. Final evidence states: **{lp['label_state_counts']}**. `attack_associated_response` here includes association with another attack family and does **not** mean verified reconnaissance.

Inherited cohorts are8,400 FC5 short replies,158 mapped-workbook associations,116 non-routine read-quantity rows,13 other short replies and12 positive rows from the date-less external snippet. Raw bytes were matched for **8,687/8,699** positive worksheet rows; the remaining12 are the unsupported snippet. There are8,731 raw ADU matches. The44 additional matches arise from exactly **two physical packet rows containing23 identical coalesced ADUs each at distinct payload offsets**. They are message expansion, not44 duplicate network packets or extra experiments. Both ambiguous packet-to-message correspondences remain explicit.

Another36 positive read rows with quantity20 have nearby original `Query flooding.Complete` logs (signed differences-823 to+721µs), rather than unique reconnaissance evidence. Their exact original references are retained in `evidence/unsupported_read_nearest_original_events.csv`. A non-routine quantity is not itself a reconnaissance label.

Positive-source field reconciliation gives0 normalized-FC, length or packet-size disagreements, and0 requested-address/quantity disagreements for matched read requests. That supports extraction of those particular fields, not their labels or every original negative row. The raw wire FC remains separate from normalized FC, preserving exception semantics.

All8 derivative log signatures occur in original sources, but the join expands158 mapped rows to263 original log-row correspondences because some source signatures repeat. **131/158 mapped packets have neither endpoint equal to the original logged TargetIP; only27 include it.** Variable packet/log differences range roughly-210 to+141.5minutes and cannot be justified by one clock shift. Completion TID1048575 is outside the16-bit wire range and cannot identify an exact Modbus transaction. Nearness, capture membership and endpoint identity alone are not attack labels. Exact causal event attribution remains conditional or ambiguous.

## 7. The length3/75-byte finding and actual mechanism

All **8,400 FC5+length3 positive packets** are raw server-to-client **wire FC0x85, exception code3 (Illegal Data Value)**. Their prior “FC5” representation had lost the exception high-bit distinction. They are neither truncated ordinary FC5 replies nor initiating read scans.

Representative immutable evidence:

- Source `{example.source_relative_path}`, frame{int(example.frame_identity)}, epochµs{int(example.timestamp_us)}, `{example.src_ip}:502 -> {example.dst_ip}:{int(example.dst_tcp_port)}`.
- Reply ADU `{example.adu_hex}`. Associated reversed-endpoint/TID/unit/FC request frame{int(example.matching_request_frame)} has ADU `{example.matching_request_adu_hex}`.
- Original nearest log `{example.nearest_nonrecon_log_reference}` says `{example.nearest_nonrecon_log_attack}`, with signed request/log difference{int(example.nearest_nonrecon_log_delta_us)}µs. Full response/request timing and pairing limits are retained in `evidence/len3_source_byte_examples.json` and `evidence/raw_positive_packet_matches.csv`.

All8,400 associated FC5 requests use values outside the normal ON0xff00/OFF0x0000 encodings. The example uses0xffff. These encodings and exception semantics are defined by the [Modbus specification, sections6.5 and7](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf). Original brute-force/specific-coil logs are within about0–1,020µs of the associated FC5 requests throughout the cohort. Those byte/log observations strongly support a **non-reconnaissance write-error mechanism**. Nearest log evidence is not promoted into a unique exact attack event without proving uniqueness. The13 read-function short replies are raw exceptions0x81–0x84/code2, which can be consequences of invalid read ranges; they are not the scan action itself.

**Answer:** these packets are PLC/IED exception responses, overwhelmingly associated with invalid coil-write activity in the source evidence. Calling them “mostly PLC responses caused by reconnaissance” would still overstate the evidence for the dominant8,400 cohort. They remain preserved, without automatic deletion or relabeling.

## 8. Static shortcut diagnostics

These metrics score **inherited labels**, not independently validated recon ground truth. Full legacy and reconstructed distributions by FC, length, frame size, address, quantity, endpoint direction and joint shape are in `evidence/*class_distributions.csv` and `*joint_packet_shapes.csv`.

For the reconstructed population,8,413/8,637 positives have length3 and packet size75, versus0/588,498 inherited normals. FC5+length3 accounts for8,400. At window level1,784/1,878 positives contain length3 (94.99%), versus0/117,359 inherited normals. Legacy mixing spreads the same shortcut to17,761/18,338 positive windows. The static signature explains labels without temporal context.

{table(sm)}

Untuned static tree/logistic diagnostics were fitted solely for the expressly requested shortcut audit. No final research estimator, LSTM, resampling, hyperparameter search or fitted preprocessing was exported. Train-only scaling was used for logistic regression. Conservative holdouts combine **all SCADA rotations/days**, **the external recording family**, and **benign/other recordings** into source-family units; no row/window random split was used. Window predictors are strictly order-invariant current-message mean/min/max/std. See `evidence/static_baseline_protocol.json` and per-fold results.

{table(models)}

The learned baselines transfer poorly when an entire attack source family is held out. This does not erase the fixed-rule confound: a rule can explain inherited labels almost perfectly while an estimator trained on a different source family has never seen that response mechanism. It demonstrates source/target shift and the weakness of calling configured chunks independent groups. Neither high historical scores nor these low source-family scores establish the temporal hypothesis.

Length, size, functions and responses were not blindly removed. They are legitimate observable deployment fields and diagnostically useful attack consequences. Their use for an initiating-request temporal-recon experiment requires a clearly frozen target. Ablation is reported as diagnosis, not as a way to manufacture LSTM novelty.

## 9. Actual reconnaissance request recovery

All original CSV/XLSX logs were scanned:1,453 recon-family logger rows and643 deduplicated start signatures. Completions and duplicate source rows are not counted as new campaigns. A bounded independent parser decoded complete ADUs in single captured TCP segments, retaining exact source/frame/record/ADU offsets, endpoints/ports, FC/address/quantity/unit/TID/bytes, response association and log references.

The finalized candidate table contains **{len(c)} master-to-slave read requests**, not the old short-response population:

{table(candidates)}

**148** have unique eligible contextual log-start correspondence. **320** have multiple equally eligible starts and remain `ambiguous`, excluded from positive target rows in the main temporal comparison. All468 retain evidence of recon-probe context; no `supported_exact` label is asserted because logger synchronization, repeated TIDs and unique causal correspondence are not globally proven. The25ms target/range join is an explicit diagnostic rule, with observed deltas and references retained. It is not permission to label a whole interval or endpoint.

There are **{int(c.response_frame_identity.notna().sum())}** associated response observations. Every saved response hex string was reread from the original PCAP frame after QA caught numeric CSV coercion; see `evidence/response_byte_reconciliation.json`. Unmatched requests remain unmatched. Single-segment extraction omits incomplete/unframed ADUs and does not claim full TCP reassembly or exhaustive campaign recovery. Exact bytes are strings; log IDs/confidence/state/frame paths are private audit metadata, not future predictors.

Quantities by evidence state:

{table(qty)}

Most recovered requests start at address1 and try bulk ranges or several read functions. Unit IDs are all1. This supports range/function probing and automated read collection in these sources. It does not establish a sustained sequential sweep of starting addresses or unit-ID enumeration. Temporal histories are built causally while streaming canonical captures, resetting on backward timestamps and inactivity; candidate positions are assigned only after the final chronological sort. Candidate-only row spacing is not the spacing of all network requests.

## 10. Temporal signal and normal lookalikes

The documented-benign canonical HMI chain supplies **2,042,925 read requests** across19 rotated captures. Current-message shape counts cover every extracted read request. Temporal distributions use20,428 deterministic every100th-request contexts, with20,427 having a full20-event history; additional shape exemplars are excluded from distribution sampling. All normal read quantities in this canonical view are1, length6, frame size78. Registers are5,8,13,14,15,25,35 depending on function. Normal polling already alternates functions/addresses and contains bursts of closely spaced requests.

Of the148 uniquely contextual recon requests,114 have full20-event prior context and34 have partial context, reported separately. **0/148** share FC+quantity+length+frame-size+unit shape with the full normal census. All468 candidates also use quantities>1. Matching only FC/length/frame-size would hide the quantity shortcut. Other benign device/network views are not automatically new experiments; claims of all possible legitimate shapes are not made.

Full20-context marginal statistics:

{table(selected)}

These observations show timing/access-pattern differences, including a much smaller immediate request gap in contextual probes, but the monotonic-increase median is the same (~0.2105) and source histories overlap ordinary polling behavior. Interval mean/CV describe rate and variability, not a dedicated rolling polling-rate drift test; that proposal dimension remains unestablished. Differences are confounded by quantity and source family. Since exact current-shape matched normal controls are absent, the audit cannot establish whether removing current-message shortcuts leaves a fair temporal detection task. It would be wrong to infer necessity of LSTM from these marginal differences.

`temporal_signal_analysis.csv`, `normal_lookalike_analysis.csv`, `evidence/matched_shape_temporal_analysis.csv`, and source-linked examples expose the comparison. Raw no-nearby-recon-log controls inside attack recordings remain **unlabeled**, never silently normal. Cross-target/actor-level enumeration and unit transitions are not established by per-target/unit histories. No hypothesis is answered through an LSTM score.

![Inherited static shortcut](figures/static_shortcut_coverage.png)

![Causal request histories](figures/temporal_context_distributions.png)

## 11. Campaign and experiment independence

Packets, initiating requests, responses, overlapping windows, log starts/completions, PCAP files, rotated chunks, mirrored NIC views, logical endpoint streams and independent acquisition campaigns are different counting units. `capture_campaign_summary.csv` reports source/group populations without converting them into independent runs.

Independent raw timestamp checking shows **substation1 through17 form a continuous rotation chain**:16 adjacent boundaries have gaps only16–19,971µs (maximum0.019971s). The old G04(sub1),G05(sub2),G06(sub4),G07(sub10),G08(sub14) therefore divide one acquisition into purported independent groups. Substation0 is temporally later, separated by about80,141s; filename suffix is not chronology. The new rotation evidence is in `evidence/rotation_continuity_independent_check.csv`.

Recovered recon appears in two source recording families, external February and compromised-SCADA March. The468 candidates reference **411 distinct original log rows**; the148 uniquely contextual requests reference91 distinct logger rows (59 SCADA,32 external). Rows are not independent experiments. These recording families are conservative dependency units, **not a verified count of independent attacks**. Repeated dates, logger events or TCP connections supply no acquisition/reset ledger. The independently verified campaign count remains **unknown/null**, not2 and not0. `evidence/recovered_request_campaign_summary.csv` separately tabulates these request/message counts, while `capture_campaign_summary.csv` accounts for all15 legacy source names and their inherited packet/window populations.

## 12. Split feasibility and exact eventual experiment

`split_feasibility.json`: **UNSUPPORTED** for a class-complete, independent train/validation/test experiment at present. No final partition assignment is manufactured. Rotations, mirrors, retransmissions, shared episodes and every overlapping context must remain in one partition. No future packets may enter a target's causal input. All normalization/imputation/encoding must be fitted only on training groups; tuning/thresholds belong to validation; final test access follows a frozen protocol.

The eventual comparison must use the **same request-ending target event IDs and same held-out run groups** for: A,current-packet static features; B,strictly order-invariant aggregate/statistical context; the proposal's flattened-window RF where applicable; and temporal LSTM. A simple causal scan rule is an optional diagnostic. Flattening can retain position; order-sensitive statistics must not be called non-temporal. The current inherited any-positive-window target is a different task and cannot be compared casually with current-request recognition. `EXPERIMENT_DESIGN.md` records this distinction.

## 13. CIC suitability and controlled supplement

**Category C for supporting the exact proposed confirmatory experiment with the evidence presently reconstructed.** This is a scoped judgment, not a claim that every remaining CIC byte has been exhausted or that CIC has no reconnaissance. Real contextual read probes have been recovered. However, inherited labels are dominated by another mechanism, matched normal request quantities are absent in the complete canonical benign census, sustained start-address scans/unit enumeration are not established, and independent three-way evaluation is unsupported. Additional recovery could refine the secondary benchmark; it cannot be counted as independent primary collection without evidence.

The proposal already plans controlled primary Modbus/TCP acquisition. `TESTBED_SUPPLEMENT_DESIGN.md` specifies real master/slave PCAP capture with a separate ground-truth ledger. Normal and attack scenarios must share current-message shapes, functions, quantities, unit IDs and address ranges wherever possible. Normal scenarios include regular/variable polling, valid multi-register reads, maintenance bursts and repeated reads. Recon scenarios include sequential/sparse/randomized/range scans, device/unit probing, function probing, slow/fast/jittered scans. Physical traffic and immutable captures are required; no fabricated CSV rows. Multiple independently initialized/acquired runs are needed, with their count justified by pilot variability and prespecified evaluation, not an invented magic run count.

## 14. Deliverables, reproducibility and limits

The required matrix, source manifest, lineage, legacy/rebuilt/window audits, per-positive provenance, raw request candidates, shortcuts, campaign summary, split feasibility and unresolved assumptions are present. `README.md` indexes them. `scripts/` contains the fresh extraction/audit/reconstruction/raw recovery/static/temporal/report code. `AUDIT_METHODS.md` records runtime/dependencies and reproduction order. `QUALITY_REVIEW.md` documents independent checks and corrected audit defects. Exact numerical source tables accompany the standalone figures.

The existing trained models/results were preserved as historical artifacts and not executed for final training. Only the expressly requested untuned static diagnostics were fitted, with train-only scaling and no exported estimator. There was no final LSTM fitting, scaling pipeline, class rebalance, SMOTE, tuning or final evaluation. All remaining evidence gaps are explicit in `UNRESOLVED_ASSUMPTIONS.md`.

## Final Verdict

**Raw-source provenance:** CONDITIONAL  
**Legacy sequence construction:** FAIL  
**Rebuilt sequence construction:** CONDITIONAL  
**Recon label provenance:** FAIL  
**Recon-request recovery:** PARTIAL  
**Static shortcut risk:** CRITICAL  
**Temporal reconnaissance signal:** NOT ESTABLISHED  
**Independent evaluation feasibility:** UNSUPPORTED  
**CIC suitability for Component 2:** INSUFFICIENT  
**Need for controlled-testbed supplement:** YES

“Rebuilt” is conditional because original rebuilt files were unavailable and the new reproduction passes mechanical checks while preserving unresolved session, gap, label and campaign issues. “Temporal signal not established” concerns the distinguishing temporal research claim beyond current-message shortcuts; observable request timing differences are documented. “CIC insufficient” is scoped to the exact confirmatory experiment supported by this reconstruction, not an assertion that further source work is impossible.

### Single best next action

Conduct a controlled Modbus/TCP testbed pilot with matched normal/recon request shapes and independently recorded run ground truth.
'''
    words='are|and|all|only|of|in|the|have|for|about|through|range|value|frame|code|length|rows|starts|address|unit|quantities|around|than|within|below|above|beyond|median|maximum|minimum|remaining|additional|containing|substation|sections|section|partitions|request|reply|stream|there|times|is|not|use|uses|diagnostic|stride|share|dated|exactly|still|min|max|containing'
    report=re.sub(r'\b('+words+r')(?=\d)',r'\1 ',report,flags=re.I)
    report=re.sub(r'(\d)(µs|ms|ns|days|seconds|minutes|min|s|h|requests|candidates|streams|rows|packets|windows|events|fields)\b',r'\1 \2',report)
    (R/'FULL_FINDINGS_REPORT.md').write_text(report,encoding='utf8')
    print('Full report written',len(report),'characters',flush=True)

if __name__=='__main__':main()
