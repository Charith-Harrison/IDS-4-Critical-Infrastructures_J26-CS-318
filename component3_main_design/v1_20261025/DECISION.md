# Component 3 main-experiment proposal — 25 October 2026

**PROPOSED. Engineering: CONDITIONAL_GO. Academic acceptance: not recorded in the reviewed material.**
This package proposes a different, stronger main design than the earlier 48-run draft. Neither
design is adopted here. No collection, model preprocessing, training or actual partition
assignment was performed. All earlier qualification remains excluded from future model work.

## What works, and how this review checked it

Four successful captures contain **1,846 ADUs, 923 complete transactions and 80 episodes**:
**1,822 normal, eight command-injection and 16 response-injection messages**. Each recorder
reports zero kernel drops. **Only M0/V0/S1 has measured qualification evidence.**

This review reran the frozen validator with `write=False`, compared its results with the saved
reports, and separately decoded/reconciled the actual capture frames, streams and file offsets
for all messages. Separate review code replayed all 923 transactions against the private
intervention/state records. Every target has an earlier visible anchor and a same-run normal
control with the same object role and PDU. All eight genuine command ACKs remain normal.
The supplied coverage CSV and all 24 supplied examples reconcile to the annotations.
The preserved first failed attempt has zero observed ADUs and no accepted annotations; it is
excluded from every accepted total. There are **six normal families and two injection
mechanisms**, not eight attack mechanisms.

Two directly checked examples in Q01 (`Q01-20261024T180517Z-1a6f7c4b`) illustrate the contrast:

| Current observation | Earlier wire evidence | Interpretation |
|---|---|---|
| e66, frame 72, `050001ff00` | e65, frame 71, `03020000` | Direct injected ON while observed mode is 0 |
| e20, frame 26, identical `050001ff00` | e19, frame 25, `03020001` | Genuine permitted ON in mode 1 |
| e103, frame 109, `030200ac` | e101, frame 107, ACK `060001009d` | Forged 172 after acknowledged setpoint 157 |
| e43, frame 49, identical `030200ac` | e41, frame 47, ACK `06000100ac` | Genuine 172 after acknowledged setpoint 172 |

Exact bytes, IDs, source paths and byte offsets for these and six other representative
contrasts are in `evidence_checks.json`. Labels use the private intervention records as well
as wire evidence; a mode violation or readback difference alone is not generic proof of an
attacker in an unrestricted plant.

**Limits of verification:** the earlier 28 offline tests were inspected, not rerun. Their
successful execution is supported by the existing execution ledger, not a new test run.
No live Docker/isolation check, recapture, hardware attestation, PDF re-extraction or original
multi-GB CIC re-extraction/rehash occurred. This is an independent audit implementation over
the same internally generated evidence, not an external ground-truth certification.

## The narrow research question

Within this declared software process, how much does causal request-response/history
information add to current-message inspection for the two defined protocol-valid injections,
on fresh executions and predeclared conditions? How does contextual ML, if later feasible,
compare with simple causal rules?

Compare A: protocol validity; B: current-message information; C: simple causal permission and
consistency rules; D: the same learner as B with causal context. Use the same eligible
pump-ON/request and setpoint-readback/response tasks, and also report all-traffic coverage and
normal-only false alarms. Task eligibility may use audited pairing for every method; a
request-derived address must not become a current-response predictor. FC3 replies contain no
address. The public map and lab policy are supplied equally to comparable methods, including
the proposed held-out map. This tests portability with supplied roles, not discovering roles
from private metadata. Predeclare a companion current-wire/contextual-wire comparison that
also retains numeric TID and endpoint/port headers for both methods. Report it alongside the
semantic comparison; do not attribute a gain to context solely because current headers were
withheld. No baseline is fitted or scored on qualification here.

Decide a command at complete request arrival, before its ACK; decide a response at complete
reply arrival using earlier requests/ACKs only. Private state, future recovery reads,
scenario/step/episode/run/seed/file/partition identifiers are unavailable to detectors.
Missing/stale anchors, byte gaps or pairing ambiguity require abstention and visible coverage
reporting. Hidden writers, autonomous setpoint changes, forged anchors and policy-compliant
malicious intent are outside the identifiable core claim. No physical units or plant effects
are inferred. The rules fully express this process; **no added ML benefit is a valid result**.

## What qualification has not resolved

- All request TIDs increment sequentially within each run. The repeated-TID-5 case was an
  offline fixture. Matching PDUs does not generally match complete ADUs containing TIDs.
- Despite prefix polling, every actual attack anchor is only **zero or one intervening ADU**
  away. Longer useful history and alternative semantic ordering have not been qualified.
- Target transaction positions vary within small template bands: command 6–8, response 4–6
  (zero-based). Family-specific steps/lengths and visible setup ordering remain cues.
- The configured sleep is 8–15 ms, but measured client interexchange gaps include scheduler/IO
  effects: medians 16.7–27.9 ms across runs, with individual gaps up to 290.4 ms. Requested
  delays must not be presented as measured wire timings. All recordings are one short session.
- Endpoints/unit/port and M0 are fixed; there is one software environment. There are no
  normal-only captures or measured alternate map/value/order/timing conditions. Four distinct
  capture hashes and ordered PDU traces rule out exact copies here, not every possible shortcut.

The JSON specifies prospective audits of TIDs, timing, positions, lengths, values, maps,
scheduling, resets, missingness and copy lineage. No shortcut classifier or model was fitted.

## The proposed collection, before any collection

Every proposed run crosses three TID policies (sequential, literal 5, random) with three safe
anchor-gap levels: **nine value-pair blocks**, 90 episode slots. Mixed runs have nine direct
commands and 18 reciprocal forged replies by design, plus matched genuine controls. Normal-only
runs retain comparable template slots and nuisance distributions with no interventions.
Different rows/blocks are not independent executions.

Core conditions cross two public maps, two transaction orderings and two requested timing
ranges: eight cells. New maps, values, ordering and timing have separate final stress tests.

| Prospective role | Mixed | Normal-only | Whole executions |
|---|---:|---:|---:|
| Training: three mixed replications per core cell | 24 | 8 | 32 |
| Validation: one mixed replication per core cell | 8 | 8 | 16 |
| Primary final repeat test: two mixed replications per core cell | 16 | 8 | 24 |
| Final value-range test | 8 | 0 | 8 |
| Final supplied-map test | 8 | 0 | 8 |
| Final ordering test | 8 | 0 | 8 |
| Final timing test | 8 | 0 | 8 |
| **Total proposed main executions** | **80** | **24** | **104** |

These are coverage/replication choices, not a power analysis or row-count target. Validation
and stress-test cell replication is limited. Required precision and cost must be agreed before
adopting/freezing the main roster, with any revision made before final-test collection or
inspection. Single-axis tests remain separate; do not pool them to improve a headline result.

The replication unit is a whole fresh execution/connection and its related group, within one
simulator. Seeds do not create industrial campaigns. Keep shared-history twins, continuations,
mirrored observations and all derived copies together. Hash captures and ordered streams;
retain genuine repeated messages at different positions. The roster has **null actual recording
IDs and partition memberships**: no existing recording has been assigned anywhere.

Current v0.2 scripts reject these main roles and cannot implement all proposed controls.
A separate version must add the cross-balanced scheduler/TID/gap profiles, configurable delays,
normal-only mode, profile-aware independent validation and portable provenance. **Fourteen
fresh-seed engineering probes** address those specific additions and map/value/order/timing
interactions. They are unscored and excluded from all model work. They are not another round
of identical M0/V0/S1 qualification, nor the future scored test recordings.

Measured v0.2 run artifacts are 1.223–1.261 MB each; payload spans are 4.72–9.12 seconds and
launch-to-next-launch/end intervals are 8.03–14.64 seconds. Scaling to nine blocks, extra polls
and wider delays gives a rough budget for all 118 proposed executions: **0.83 GB and 2.46
hours**, with planning ranges **0.66–1.45 GB and 1.23–4.93 hours**. Reserve 4 GiB for working
data, a second copy and overhead. These are uncertain extrapolations from four runs, not
confidence intervals; they exclude implementation, manual review and unforeseen retries.
Remeasure after the new engineering probes. Exact assumptions/formulae are in the design JSON.

## Engineering and academic decisions

**CONDITIONAL_GO** means the proposed experiment could answer the narrow information/context
question after its controls and observability are qualified. It does not authorize main
collection. Conditions are the new version and targeted probes, per-cell normal/attack support,
complete byte/intervention/anchor reconciliation, no capture loss or unresolved pairing, and
prospective grouping/method/cohort/test-access decisions. Stop and revise if these fail or if
uncontrolled nuisance cues remain. Never fix the problem by tuning on final tests or oversampling.

The team TAF cached page 6 explicitly contemplates controlled primary data. The individual
proposal cached pages 21–22 specify CIC as primary and the testbed as optional. No actual
supervisor acceptance of changing that emphasis was found in the reviewed repository material;
an external agreement cannot be ruled out. The exact proposed methodology amendment is in
`proposed_main_design.json` under `academic_methodology_change.exact_proposed_text`. It makes
the testbed primary, preserves CIC separately, excludes other datasets, narrows generalization
and permits no ML benefit. Academic acceptance is separate from this engineering decision.

All **290** files in the six protected component-3 roots were unchanged. Portable relative-path
hashes include captures, annotations, private audits, code/configuration and execution records.
The actual collection transcript reports **DESKTOP-QT93GAU** on Windows, with Docker image
`sha256:c8c06ba2f25647e880bc5a7262436169be752d4d0d174c0afbfc72137cf74385`.
This is recorded machine identity, not independently attested hardware/operator identity.

**Exactly next:** review/adopt or amend this proposed claim and nuisance-control matrix, record
the academic methodology decision separately, then authorize only a separate v0.3 implementation
and its 14 targeted engineering probes. Do not start the 104 main runs or model preprocessing.

The four deliverables are in this directory: `DECISION.md`, `proposed_main_design.json`,
`proposed_run_roster.json` and `evidence_checks.json`. `_support/` contains reproducible audit/
design code and preservation hashes; the original evidence stays in its original locations.
