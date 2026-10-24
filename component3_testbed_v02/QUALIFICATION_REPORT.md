# Component 3 v0.2 qualification decision

**Four measured engineering qualification captures passed. Main collection remains disabled.**

| Run | Messages | Normal | Command | Response | Episodes | Drops |
|---|---:|---:|---:|---:|---:|---:|
| Q01 | 454 | 448 | 2 | 4 | 20 | 0 |
| Q02 | 466 | 460 | 2 | 4 | 20 | 0 |
| Q03 | 466 | 460 | 2 | 4 | 20 | 0 |
| Q04 | 460 | 454 | 2 | 4 | 20 | 0 |

Total: 1846 ADUs, 923 complete transactions,
80 episodes. The four fresh runs are replications of **one software testbed**,
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

Preserved failed collection attempts: 1. The initial Q01 implementation failure
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
