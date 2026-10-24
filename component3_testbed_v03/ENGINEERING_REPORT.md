# Component 3 v0.3 engineering qualification

**All 14 targeted engineering probes passed. Main collection remains disabled.**
User approval adopted engineering scope. Supervisor acceptance of the testbed-primary methodology
is not recorded; no academic approval is invented.

| Probe | Mode | Map/value/order/time | ADUs | Command | Response | Drops |
|---|---|---|---:|---:|---:|---:|
| EQ01 | mixed | M0/V0/O0/T0 | 2312 | 9 | 18 | 0 |
| EQ02 | mixed | M0/V0/O1/T1 | 2496 | 9 | 18 | 0 |
| EQ03 | mixed | M1/V0/O0/T1 | 2312 | 9 | 18 | 0 |
| EQ04 | mixed | M1/V0/O1/T0 | 2480 | 9 | 18 | 0 |
| EQ05 | mixed | M2/V0/O0/T0 | 2300 | 9 | 18 | 0 |
| EQ06 | mixed | M2/V0/O1/T1 | 2490 | 9 | 18 | 0 |
| EQ07 | mixed | M0/V0/O2/T0 | 2604 | 9 | 18 | 0 |
| EQ08 | mixed | M1/V0/O2/T1 | 2572 | 9 | 18 | 0 |
| EQ09 | mixed | M0/V0/O0/T2 | 2318 | 9 | 18 | 0 |
| EQ10 | mixed | M1/V0/O1/T2 | 2484 | 9 | 18 | 0 |
| EQ11 | mixed | M0/V1/O0/T0 | 2328 | 9 | 18 | 0 |
| EQ12 | mixed | M1/V1/O1/T1 | 2474 | 9 | 18 | 0 |
| EQ13 | normal_only | M0/V0/O0/T0 | 2292 | 0 | 0 | 0 |
| EQ14 | normal_only | M1/V0/O1/T1 | 2508 | 0 | 0 | 0 |

Totals: 33970 ADUs, 16985 complete transactions,
1260 episodes; 33646 normal, 108 command injections, 216 response injections.
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
Preservation checks passed for 299 earlier files, including CIC preparation,
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
