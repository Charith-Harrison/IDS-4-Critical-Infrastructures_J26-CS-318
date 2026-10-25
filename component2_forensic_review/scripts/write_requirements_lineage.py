"""Reproduce document review outputs; reads immutable PDFs/code, writes only review outputs."""
import csv
from pathlib import Path

OUT = Path(__file__).resolve().parents[1]
ROWS = [
    ("Detect reconnaissance as temporal scanning rather than packet shape", "Source-supported initiating requests with order/timing different from legitimate polling; compare identical held-out targets", "Proposal pp3,11-14; TAF pp3-4,9", "Requirement confirmed; empirical claim not established by documents", "A classifier reproducing supplied labels or detecting response length cannot establish the hypothesis."),
    ("Sequential register/device scanning", "Ordered request addresses, endpoint/unit identifiers, unique frame and transaction references", "Proposal pp3,13-14,21; TAF p9", "Requirement confirmed; source reconstruction required", "Processed register_start on responses need not denote requested register; raw extraction missing."),
    ("Register/coil access order", "Decoded request function/address and causal address transitions within verified dependency units", "Proposal pp3,13,21; src/features.py", "Requirement confirmed; code implements arithmetic, not semantic source validation", "Source bytes and request/response distinction absent from supplied table."),
    ("Polling-rate drift and inter-request timing", "Reliable request timestamps and baseline polling, distributions across independent runs", "Proposal pp3,13-14,21; TAF pp4,9; src/features.py", "Requirement confirmed; recomputed directional packet gaps are only a proxy", "Existing req_rate counts packets including responses; drift may reflect consequences, capture sampling or labels."),
    ("Time-windowed and sequential representation", "Chronological windows without unrelated stream/capture mixing; explicit event target and label rule", "Proposal pp13-14,17,21; TAF p9; configs/default.yaml; src/rebuild_sequences.py", "Requirement confirmed; construction independently tested elsewhere in review", "L=20 is preliminary dataset shape, not proof that it is optimal or an approved immutable protocol."),
    ("LSTM proposed model", "Valid data and matched baseline experiment before final modelling", "Proposal pp3,13-14,17,21; TAF pp4,9", "Requirement confirmed; final fitting deferred by current user", "Existing artifacts do not validate dataset truth; do not rerun training pipeline."),
    ("Packet-level/static baseline", "Same target events and held-out dependency groups, current-message predictors only", "Proposal pp13-15; TAF p9; src/baselines.py", "Requirement confirmed", "Current labels mainly reward short responses; report shortcut diagnostics separately from temporal novelty."),
    ("Non-temporal Random Forest baseline", "RF on same protocol features flattened across windows, as written; also order-invariant summaries to isolate sequence benefit", "Proposal p14 section3.3; docs/C2_SPEC.md; src/features.py", "Requirement confirmed; implementation differs", "Existing Model B uses summaries including address steps, FC changes and timing drift, so it is not strictly non-temporal and is not the proposal's exact flattening."),
    ("Session-independent generalization", "Hold out verified capture campaigns/runs, with all mirrors and rotated chunks together", "Proposal pp3,13-15; src/splits.py; configs/default.yaml", "Requirement confirmed; independent campaigns unproven by config", "Static endpoint/unit session_id and named capture_group do not establish independence."),
    ("GroupKFold / leave-capture-session-out", "Disjoint packet, mirror, episode and campaign dependencies; class-complete training/validation/test", "Proposal p15 sections3.4-3.5; src/splits.py", "Requirement confirmed; feasibility depends on reconstructed campaigns", "Zero shared row indices is necessary but not sufficient for campaign independence."),
    ("Random-split leakage comparison", "Proposal requests reporting naive random split beside group results", "Proposal p15 sections3.4-3.5; docs/C2_EXPERIMENT_PROTOCOL.md", "Requirement text confirmed; not executed in this audit", "Current user explicitly prohibits random row/window splitting; that instruction overrides the proposal's experiment instruction."),
    ("Precision / recall / F1 beyond static analysis", "Identical target events and test groups; per-group and pooled metrics, uncertainty across campaigns", "Proposal pp13,15; TAF pp6,9", "Requirement confirmed; no new final-model result", "Proposal's outperform target is a hypothesis, not an outcome to manufacture."),
    ("False-positive rate below 5%", "Untouched group-held-out normal traffic with meaningful denominator", "Proposal pp15,18; TAF p6 general FPR metric", "Exact proposal target confirmed", "No proposal F1>0.90 target was found; repository claim ledger invents it."),
    ("ROC-AUC per fold", "Both classes where AUC is reported; undefined results remain undefined", "Proposal pp13,15; TAF p6", "Requirement confirmed", "Normal-only captures cannot supply per-fold positive-class AUC; pooling is not additional independent evidence."),
    ("Detection latency on order of seconds/window", "Measure buffering delay and inference pipeline under test load", "Proposal pp15,18; TAF p9 general latency", "Exact proposal wording confirmed", "Repo <100ms approved target is unsupported by supplied proposal/TAF; compute-only timing omits window acquisition."),
    ("Controlled primary Modbus/TCP testbed", "Real master/slave traffic, isolated capture PCAPs, separate experiment ledger", "Proposal pp3,13-14,18,21; TAF pp6-7", "Requirement confirmed; claimed preliminary provenance unproven", "Proposal p14 calls 175800 windows primary testbed data; their CIC origin needs explicit reconciliation."),
    ("Supplement/benchmark with public ICS datasets", "Dataset identity, version/license, PCAP/log lineage and scope limits", "Proposal p14; TAF pp6-7", "Requirement confirmed", "Public data is not the student's primary collection merely because processed locally."),
    ("Broader balanced recon sessions", "Independent captures with real supported scans across varied normal/recon conditions", "Proposal p14 final paragraph", "Requirement confirmed; unmet until source/campaign audit", "Thousands of overlapping windows are not thousands of sessions or experiments."),
    ("Class / confidence / contributing behavior output", "Standard output schema and honest explanation of predictors", "Proposal pp13,17-18 FR1-FR3,FR5; TAF p4", "Requirement confirmed; code/contract present", "Explanations of response length are not explanations of temporal reconnaissance."),
    ("Forensic event logging", "Timestamp, source-session reference, confidence and traceable capture/frame", "Proposal p18 FR4; src/contract.py", "Proposal-specific detailed requirement confirmed", "Existing source table omits canonical frame/transaction/TCP identity."),
    ("Retraining without changing shared schema", "Versioned input contract supporting newly captured/relabeled runs", "Proposal p18 FR6", "Proposal-specific detailed requirement confirmed", "No retraining occurs in this preparation audit."),
    ("Concurrent-session scalability", "Concurrent workload with accuracy and latency checked against per-session baseline", "Proposal p18 NFR4", "Proposal-specific detailed requirement confirmed", "A single inference timing result does not test concurrency."),
    ("Shared parser/repository and decision fusion", "Consistent protocol records and common split policy across modules", "Proposal pp16-17; TAF pp4,6", "Shared requirement confirmed", "C2 does not need to implement or train the other three modules to meet its individual research boundary."),
    ("Unified severity / incident correlation / XAI", "Team integration with explainable alerts and severity ranking", "Proposal pp16-17; TAF p4", "Shared requirement confirmed", "TAF describes team scope in more detail than RP2's p9 row; not a separate C2 classifier task."),
    ("Isolated capture, license compliance and no production ICS", "Controlled lab ledger, authorized public sources and source-license records", "Proposal pp14,18; TAF pp6-7", "Requirement confirmed; operational/source evidence required", "Local documentation is not evidence that testbed traffic was actually generated."),
    ("Preliminary 175800 windows /20x7 /13 sessions", "Verify counts and prove primary capture origin and session meaning separately", "Proposal p14; old workbooks; docs/C2_DATASET_AUDIT.md", "Numerical claim independently audited elsewhere; provenance claim conditional", "Shape/count does not prove temporal validity or 13 TCP sessions."),
    ("Supervisor approval claims", "Documented approval of the specific dataset/method claimed", "Proposal p2; TAF p11; docs/C2_SPEC.md; docs/C2_CLAIM_LEDGER.md", "Supervision declaration visible; dataset/method approval not established", "TAF assessment page is blank; signed proposal declaration is not approval of later generated metrics."),
]

def main():
    with (OUT/'requirements_matrix.csv').open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f); w.writerow(['Research claim','Required evidence','Current source','Verified?','Limitation']); w.writerows(ROWS)
    md='''# Component 2 research requirements matrix

Project J26-CS-318, RP2, Charith H. / Harry. Reviewed 25 October 2026.

The supplied individual proposal (September 2026, 26 PDF pages) is the latest statement of the individual research experiment. The TAF has 13 PDF pages. Page references below are one-based PDF pages, which agree with visible printed numbering. Requirements are documentary evidence, not instructions to execute: the current user request controls this audit, including the prohibition on final training and random splits. A confirmed requirement is not a verified scientific result.

| Research claim | Required evidence | Current source | Verified? | Limitation |
|---|---|---|---|---|
'''
    md+='\n'.join('| '+' | '.join(x.replace('|','/') for x in row)+' |' for row in ROWS)
    md+='''

## TAF and individual proposal differences

Both require RP2 temporal scanning detection, sequential register scanning/polling changes, time-windowed features, time-series/LSTM, comparison with packet-level analysis, detection performance and latency. Both describe a controlled testbed and public secondary data. No TAF-only empirical RP2 requirement conflicting with, or missing from, the latest individual proposal was identified.

The TAF additionally allocates the other members' model-specific work (pp8-10) and team duties: common protocol repository, multi-attack fusion, severity ranking and explainable incident analysis (p4). These are team context. The individual proposal also describes these shared duties (pp16-17), while deliberately excluding the internal modelling of RP1/RP3/RP4 from Harry's responsibility. They must not be silently turned into RP2 obligations. The TAF lists accuracy among general team evaluation metrics (p6); proposal p15 also mentions accuracy in general methodology prose but its RP2 success table prioritizes precision/recall/F1, FPR, AUC, latency and independent generalization.

The proposal adds explicit RP2 details absent from the TAF's RP2 row: register/coil order, request counts and inter-request timing (p13); controlled-primary versus secondary-public distinction and broader recon session coverage (p14); packet/static plus flattened-window RF baselines (p14); GroupKFold/leave-session-out, naive random-split comparison, per-fold ROC-AUC, FPR below 5% and latency of seconds per window (p15); class/confidence/contributing features and forensic event logging (pp17-18); retraining, concurrency and dashboard schema requirements (p18). These refine the TAF, rather than replacing its temporal hypothesis.

## Documentary corrections required before research claims

1. Proposal p14 attributes the preliminary 175800 windows to a primary testbed run. The available processed datasets refer to CIC 2023 sources and an unexplained attached-flow snippet. The primary-origin claim is not established. Numerical shape agreement cannot repair this provenance discrepancy.
2. Existing docs claim an approved <100 ms requirement and F1>0.90 target. The supplied proposal says seconds per window and outperform packet baselines; no such F1 threshold is supplied. These should be described as implementation choices if retained, not proposal mandates.
3. The proposal's RF baseline is flattened-window data. Existing Model B is a summary vector containing order-sensitive steps and timing drift. Use precise names and compare the proposal baseline explicitly in a later valid experiment.
4. Do not repeat blanket supervisor-approval labels. TAF p11 is blank on visual inspection. Proposal p2 contains signature images on a supervision declaration dated 15/09/2026; that does not document acceptance of later labels, scripts or results.
5. Proposal p18 says requirements were not elicited through direct stakeholder interviews and no human-subject data were collected. Appendix p25 visually contains charts labelled seven responses. Their origin, status and consent/ethics classification are not documented in the supplied PDF. This is an unresolved documentary inconsistency, not a finding of misconduct, and does not validate the network dataset.

## Experiment that the evidence must eventually support

Use the same evidence-supported target requests/windows and exactly the same held-out campaigns for current-message/static baseline A, proposal flattened-window RF and order-invariant aggregate baseline B, and ordered LSTM. A summary baseline may use temporal statistics, but must be named accordingly. Freeze target definition, dependency groups and analysis before fitting; fit encoders/scalers on training only. Reserve final LSTM fitting until data validity and independent evaluation feasibility are resolved. Existing training artifacts are historical claims only.
'''
    (OUT/'REQUIREMENTS_MATRIX.md').write_text(md,encoding='utf-8')

if __name__=='__main__': main()
