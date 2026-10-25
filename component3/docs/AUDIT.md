# Component 3 audit and decision — 25 October 2026

## Decision

The accepted testbed evidence and saved result counts are internally reproducible. The original experiment is preserved. Its defensible claim is that earlier observed mode and acknowledged-write context distinguish two deliberately controlled, valid-looking interventions from matched legitimate messages in this simulator. **Rules already solve this policy; ML superiority, industrial generalization and independent-campaign three-class generalization are not established.**

The proposal/implementation mismatch needs academic review. Do not present this as completion of the original CIC-primary, externally validated, broadly contextual experiment. See [traceability](TRACEABILITY.md) and the [draft amendment](METHODOLOGY_AMENDMENT.md).

## What was inspected and measured

Read all 52 pages of the individual proposal, all 13 TAF pages and the single-page PP1 rubric. Visually inspected image-only material: signed declaration, architecture, processing diagram, Gantt chart, seven-response survey and TAF diagram. Source hashes/page text are in `reports/document_extraction.json`; that record retains original pre-migration paths. The signed original proposal is **not** evidence of approval of the later testbed-primary amendment. No additional rubric was supplied; no other assessment criteria are assumed.

Inspected the entire four-file locked Python pipeline, both original test modules, frozen protocol/schema/roster, collector label validator/transport reader and generator state/scenario code, completion records and producer import manifest. Inspected legacy application references only to establish that they are separate; this is not an audit of other members' detectors or the entire legacy app.

Independent evidence code in [`tools/audit.py`](../tools/audit.py) does not import the generator's decoder, label replay or PCAP reader. It reads classic PCAP frames, TCP sequence positions, exact annotation byte spans, request/reply order, private intervention evidence and software state transitions. Private evidence is used **only for label audit**, never model inputs. It also reconstructs the original development features and checks fitted imputer medians against training rows. Final metrics are recounted from saved predictions, with eligibility/rule decisions independently checked against raw history. This is a retrospective integrity audit, not a new model test.

| Measured item | Result |
|---|---:|
| Indexed accepted attempts / all attempt folders | 104 / 107 |
| Accepted ADUs / complete transactions | 250,066 / 125,033 |
| Normal / command / response ADUs | 247,906 / 720 / 1,440 |
| Independently parsed PCAP frames | 313,208 |
| Exact ADU frame/file byte references checked | 250,066 |
| Sealed source/artifact hashes checked by admission | 1,597 |
| Reconstructed development ADUs matching saved export | 114,604 |
| Whole runs: train / validation / repeat / values / map / order / timing | 32 / 16 / 24 / 8 / 8 / 8 / 8 |
| Private episodes audited / episodes crossing roles | 9,360 / 0 |
| Independent testbed campaign identity | 1 |
| Repeated same-direction PDU occurrences within runs, retained | 243,127 |
| PDU patterns shared across evaluation roles | 787 |

The three unindexed failed attempts are MX086-20261025T063126Z-16600283, MX087-20261025T063952Z-1fa45191 and MX088-20261025T064936Z-55b059c6. They remain on disk and contribute no model rows. Whole ordered traces are unique under the original admission check. Identical payload patterns across genuine stream positions are expected, not observation leakage. Shared simulator templates remain a generalization limitation even with unique whole traces.

Every attack has a normal same-direction, same-PDU control in the same accepted run: 720/720 commands and 1,440/1,440 responses. Complete ADU controls, including TID, exist for 240 commands and 480 responses. These latter counts principally reflect the literal-TID-5 design; the other profiles alter headers. This is evidence against a trivial fixed-PDU attack signature, not proof against all generator shortcuts. See `audit_final_20261025/{representation.json,pattern_coverage.csv.gz,coverage.csv,runs.json}` for denominators.

## Independently recounted original results

All scores below are fixed-three-class macro F1 on the **same supported, public-task cohort**. They are not all-traffic accuracy. The final ADU total is 135,462; public tasks total 14,840, of which 10,376 have supported context and 4,464 abstain for C/D. Out-of-scope messages do not count as correct normal classifications.

| Original final role | All ADUs | Eligible | Supported | Context abstentions | B | C rules | D | B-wire | D-wire |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Repeat | 57,364 | 6,360 | 4,488 | 1,872 | .316479 | 1 | 1 | .316438 | 1 |
| Values | 19,136 | 2,120 | 1,496 | 624 | .307397 | 1 | 1 | .307397 | 1 |
| Supplied map | 19,150 | 2,120 | 1,496 | 624 | .307397 | 1 | 1 | .307397 | 1 |
| Ordering | 20,622 | 2,120 | 1,400 | 720 | .305470 | 1 | .998698 | .305470 | 1 |
| Timing | 19,190 | 2,120 | 1,496 | 624 | .307397 | 1 | 1 | .307397 | 1 |

The missed response is `MX069-20261025T060458Z-f13e4f3b:e1851`. Original D predicts normal; C and D-wire predict response injection. `original_order_error_lineage.json` preserves that ADU and preceding eight observations with exact frame/file byte references. It is a retrospective error example, not a tuning target or proven explanation of the RF's internal cause.

## Prioritized issues and actions

Paths below are relative to `component3/`; line numbers refer to unchanged original files or the new version at this audit.

| Priority | Finding and concrete evidence | Disposition |
|---|---|---|
| P0 academic | Proposal pp.21–24 makes CIC primary and MSU secondary; frozen `data/collection/_handover/source/collector/frozen/protocol.json:2` says approval NOT_RECORDED. Current records are simulator-primary. | Drafted amendment. Supervisor decision outstanding. MSU remains excluded. |
| P0 claims | C perfectly implements the declared lab policy; D has one additional error. `locked/v1_20261025/c3model/records.py:205` constructs the same comparison used in the rule. | Report no demonstrated ML advantage. Restrict inference to this testbed and its trusted anchors. |
| P1 deployment | `records.py:187` pairs using ledger `transaction_index`; `records.py:264` requires a complete verified-label file; `records.py:185` raises on gaps. This is a batch research adapter, not label-free operational inference. | Added separate v2 `runtime.py:24`: one pending request per connection, literal wire TID/unit/function/echo checks, no transaction ordinal/labels, explicit gap/pair/error statuses. All 114,604 development rows match v1 features, anchors, eligibility and rules. |
| P1 unsupported scope | `records.py:183` keys state by connection, not unit; decoder does not restrict unit 1 although the collection does. Multi-unit reuse could transfer anchors if this batch adapter were reused outside its scope. | No accepted-data impact (all accepted unit 1). v2 rejects other units and clears context. Multi-unit inference is not claimed. |
| P1 missing capability | Proposal pp.31,36–37 requires confidence/explanation, integration and graceful malformed/incomplete handling. Original exports are research tables, not a verified shared-service adapter. | v2 emits statuses, uncalibrated RF probability and observed anchor references for development demos. No live TCP adapter, agreed team schema or fusion receipt is claimed. |
| P1 metrics interpretation | `experiment.py:72` computes fixed-three-class macro F1 even for task/run subsets with an absent class. A perfect normal-only subset can have macro F1 1/3. Other methods' all-available cohorts differ in coverage. | Original results untouched. New audit names the fixed denominator and lists unsupported classes. Use task attack F1 and explicit support; compare methods on common rows. Never describe missing normal-only cohorts as zero FPR evidence. |
| P1 representation | `records.py:234` supplies current readback minus earlier acknowledged value. Nonzero residual directly expresses the forged-readback rule. Earlier mode similarly nearly specifies the command rule. | Explicitly documented. Saved impurity importances reported descriptively. No residual-removal ablation was conducted; such an experiment requires a new development version and prospective confirmation. |
| P1 validity | Single loopback writer, genuine anchors, no autonomous setpoint change, supplied maps, two hooks. A compromised writer sending a permitted operation, forged anchor or hidden legitimate update is not identifiable under this contract. | Threat boundary and prospective experiment requirements documented. No intent or physical-process inference. |
| P2 reproducibility | Original `__main__.py:16` defaults to a producer tree that is not the complete collection on this laptop. Historical RUN_ON_THIS_PC uses a different laptop's path. | Safe root `c3.py` uses canonical data/collection; original bytes unchanged. Source overrides accepted. |
| P2 preprocessing | Explicit feature allowlists and training-only imputer are sound within scope (`experiment.py:47,220,228`). Historical templates do not prove actual behavior. | Independently checked training medians, full development reconstruction, 4 saved model reloads and exact validation predictions. No new training. |
| P2 Git/storage | Earlier history already tracked some partial raw captures/ledgers. Many top-level C3 folders obscured current source selection. | Moved 16 intact roots into one layout; new raw/local/history-heavy files ignored; tracked old paths retired. Prior Git commits still contain previously committed bytes; no history rewrite performed. |
| P2 missing experiments | Proposal pp.26–29 specifies K=3/5/10, feature ablations, CV, ROC/PR-AUC and latency. Actual fixed six-ADU state budget and 4-candidate validation selection differ. | Traceability marks mismatch/missing. Warm prepared-event latency now measured on validation only. No claim that this supplies missing ablations, calibration or end-to-end capacity. |
| P2 uncertainty | Markers and hashes record a lock before final evaluation, but local records are not an independently timestamped proof that no human ever viewed final data. | Preserve identities; state this evidential limit. Reuse of final sets after this audit is exploratory. |

## Tests and engineering changes

Original 18 synthetic tests plus 14 new adapter tests passed. The first sandbox attempt hit Windows temporary-folder permissions; its log is retained as `reports/tests.txt`. The successful rerun outside that sandbox is `reports/tests_final.txt`. Synthetic test fixtures fit tiny forests to check training-only transformation behavior; **no research dataset was retrained**.

New tests cover literal TID reuse, separate identical observations, metadata independence, missing/zero/stale anchors, no current ACK backfill, concurrent requests, wrong TID/echo/unit, gaps, malformed bytes, public-map resets, new connections and abstention before imputation. Original tests additionally check future mutation, private-episode invariance, remapped address parity and train-only fit/reload. Actual-data admission verifies group containment and complete-trace uniqueness.

`reports/runtime_development_final.json` establishes v2 equivalence on 48 whole development runs (114,604 ADUs). Saved B/B-wire predictions match on 4,240 eligible validation rows; D/D-wire match on 2,992 supported rows. New runtime behavior outside the qualified input contract is engineering-tested, not a newly confirmed detector result. No v2 final-set predictions were generated.

Warm saved-D imputer+RF prediction, 30 repetitions per size on prepared validation rows: single-row median **50.01 ms**, p95 **54.15 ms**; 32-row batch median 49.28 ms; 128-row batch median 52.27 ms. Windows 11, Python 3.14.3, processor family/model recorded in the JSON. This meets the proposed 100-ms target only for this narrow prepared-event measurement. It excludes capture, assembly, feature construction, probability/explanation export, queueing and cold start. Sustained throughput, memory growth and live end-to-end latency remain unmeasured. A separate CIM hardware-name query was denied; processor identifier is available, full hardware inventory is not.

## Stop conditions and next action

Stop inference on unsupported map/unit/function, unresolved byte gaps, ambiguous outstanding requests or untrusted writer/anchor assumptions. Do not turn any of these into normal labels or imputed context. Do not load a different collection, merge old attempts, change frozen artifacts or remove the final-evaluation marker. Stop any proposed confirmatory claim if its design used already observed final outcomes.

**Established:** internally consistent accepted testbed evidence; correctly recounted original conditional results; preserved identities; development-equivalent label-free adapter.

**Recoverable with justified further work:** team-approved schema and transport adapter; stronger prospective data with independent implementations/operators, legitimate operational variation and documented uncertainty; predeclared representation ablations and end-to-end benchmarks.

**Not inferable here:** industrial effectiveness, physical harm, broad injection mechanisms, independence of seeds as campaigns, calibrated risk, malicious intent from policy-conforming traffic, or supervisor approval.

**Single best next action:** take the amendment and this evidence report to the supervisor and agree the narrow testbed research question before collecting or tuning another experiment.
