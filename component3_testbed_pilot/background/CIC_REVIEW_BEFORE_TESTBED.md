# Component 3: full progress and findings report

**Prepared:** 24 October 2026  
**Purpose:** Explain what was requested, what was done, what was found, what is still uncertain, and what should happen next.  
**Current status:** Original-CIC extraction and evidence reassessment have been completed for the documented selected scope. The supplied candidate split does not support the proposed independently evaluated supervised three-class model. No new model preprocessing or training has been performed in this authorized work.

## 1. The situation in ordinary language

A factory computer sends a machine instructions and receives answers. Modbus/TCP is one language used for that conversation. Component 3 is intended to identify fake instructions and fake answers, using the surrounding conversation to help decide whether a message is suspicious.

The project started with two exported CSV spreadsheets that looked like a ready-made dataset. Reviewing them revealed significant problems with their traceability, labels and extracted values. The work therefore moved back to the original CIC recordings and attack logs.

The newer extraction is a much better evidence foundation. However, extracting messages correctly is a different achievement from having enough varied, well-supported examples to train and fairly evaluate the proposed model. Under the current evidence policy, only 100 command-injection messages and 54 response-injection messages have accepted labels. Most of those are malformed and repetitive. Each class is concentrated in one related recording collection.

The subsequent reassessment checked whether useful examples had been missed through timing rules or limited recording coverage. It found a concrete broader-coverage option, but it did not justify accepting new labels or create a valid final split.

**The work has established real limitations rather than a trained detector. The preparation is useful; the original broad evaluation claim remains unsupported.**

## 2. What Component 3 originally proposed

The supplied team Topic Assessment Form and individual proposal describe command and response injection detection in Modbus/TCP using context-aware command analysis.

In practical terms, the intended research is to compare:

1. A model looking at the current message alone.
2. A comparable model also looking at information from the conversation, such as the request associated with a reply or relevant previous messages.

The individual proposal discusses a supervised three-class task: **normal**, **command injection**, and **response injection**. It proposes Random Forest comparisons, ordered command history, request-response relationships, per-class evaluation, and checks of what different context features contribute.

The important research question is whether context actually helps under a defensible evaluation. An impressive overall accuracy number alone cannot answer that question. Context might add little if nearly every accepted attack is already identifiable from an obvious error in the current message.

The documents were treated as material to assess. Their embedded instructions did not override the user's current restrictions. In particular, references to MSU in a proposal did not authorize using it.

## 3. Scope agreed during this work

The current work was restricted to **original CIC ModbusDataset2023** material. MSU and all other datasets were excluded. This records the user's project constraint; it is not a general conclusion that those datasets have no research value.

The old CSVs, pasted historical splitting prompt, README and proposal documents were diagnostic references. Their labels and derived values were not automatically accepted as truth for the new records.

The final Stage 1 handoff authorized inventory, protocol decoding, preservation of source identity and raw values, request-response auditing, evidence-supported labels, and candidate grouped memberships. It deliberately left later model preprocessing to the component owner so she can understand and demonstrate it in her viva.

Decoding a network recording into readable messages is already a data transformation in the ordinary sense. Here, the phrase **no model preprocessing** means that the authorized pipeline did not engineer model history/rate features, build model input matrices or sequence windows, impute missing values, encode categories, scale values, resample examples, fit normality profiles, or train/evaluate a detector. Those are separate later activities.

The original raw files were to remain unchanged. New derived outputs were kept separately. The independent reviews also left the supplied preparation and reassessment folders unchanged.

## 4. Stage-by-stage history

| Stage | Work performed | Main outcome |
|---|---|---|
| Initial scope review | Read the TAF/proposal and inspect both old CSVs | The proposed task needs evidence and context that the old exports did not reliably establish |
| Historical-method review | Examine the pasted previous prompt/README and reported approach | Narrated extraction rules and claimed model performance could not replace reproducible source evidence |
| Handoff revision | Move from the earlier Claude/Antigravity idea to a local Codex handoff | Final instructions became CIC-only extraction/annotation and candidate grouping, with model preprocessing deferred |
| Original-data inspection | Inspect the downloaded original CIC collection, original logs and example packet bytes | Original recordings contain information the exports lost; file order and log interpretation require care |
| Preparation execution on her machine | Produce `component3_preparation` with inventory, extraction, pairing, annotation and reports | Useful extracted records and accepted labels; independent three-class evaluation explicitly marked unsupported |
| Independent preparation review | Inspect downloaded code and Parquet outputs; rerun tests; compare accepted bytes with local original captures | Accepted bytes/limited parser findings reproduced; matching-policy and endpoint-coverage salvage leads identified |
| Reassessment on her machine | Produce `component3_reassessment/v1_20261024` with timing, identity, coverage and temporal diagnostics | No new accepted labels; no justified timing change; broader HMI coverage plan; narrower study remains conditional |
| Independent reassessment review | Check package hashes, rerun tests and reproduce phase counts from baseline Parquet data | Reported diagnostic counts agree; no new split or modelling success established |

The stage order is the order of work. It does not imply every original packet was independently reconstructed twice or that every reported result was independently remeasured.

## 5. Findings from the original CSV exports

### 5.1 The starting files

| Item | `normal_traffic_baseline.csv` | `command_response_injection_attacks.csv` |
|---|---:|---:|
| Data rows | 150,000 | 215,830 |
| Columns | 36 | 35 |
| Original capture provenance field `file_source` | Present | Missing |
| Time representation | Fractional epoch seconds | Whole epoch seconds |
| Explicit response-injection class demonstrated | No | No |

The attack derivative contained 110,415 normal-labelled rows, 105,391 `Coil_Brute_Force` rows and 24 `Length_Manipulation` rows. Its name did not mean every row was an attack.

### 5.2 Missing provenance

The missing `file_source` column mattered because a packet's frame number is normally local to its capture file. Frame 480 in one recording is not necessarily frame 480 in another. A row cannot be reliably traced to its original packet using frame number alone.

Adding an invented filename column would make the spreadsheet headers match without restoring the missing evidence. The name of an exported CSV is also not the identity of the original packet capture.

### 5.3 Contradictory labels

After allowing for the attack CSV's rounded timestamps, 96 exported observations matched across many identity and measurement fields. Of those matches, 48 had contradictory attack labels.

This is strong evidence of disagreement between exported records. Because the old CSVs lack raw packet bytes, it was not presented as byte-level proof that every matching row is the same original packet.

### 5.4 A simple rule explained the apparent attack labels

Every binary attack label in the attack derivative could be reproduced with a simple rule: classify a row as attack if its function code is 5 or 6, or its exported length-discrepancy field is nonzero.

Applied descriptively across both supplied CSVs, that rule produced about **99.828% accuracy** and **99.702% F1**, without training a model or using conversation context. It also flagged 630 normal-labelled baseline writes as attacks.

These numbers were a **shortcut diagnostic**, not legitimate detector-performance results. They showed that an apparently excellent score could follow an operation/length pattern in the labels. The absent historical implementation prevented proving exactly how the previous author generated those labels.

### 5.5 Exported values were unreliable for process analysis

Baseline read requests stored the requested quantity in `modbus_val`, while baseline and attack read responses stored zero in that field. That did not establish that the machines actually returned zero.

A later original-packet check found a benign read response returning raw register value 9. The export therefore failed to preserve useful returned-value information in that example. Such absent values cannot be recovered by simply filling the old column.

### 5.6 Historical results remained unverified

The pasted earlier conversation described a very high or perfect model result. The original historical extraction, labelling and split implementation was not available to reproduce it. Narrated outcomes were therefore retained as historical claims, not accepted validation.

**Initial conclusion:** The missing column was one symptom of a broader evidence problem. The old exports were unsuitable as the unquestioned foundation for the proposed three-class contextual experiment. They remained useful for diagnosing what went wrong.

## 6. Original CIC material became available

Initially the full original dataset was unavailable to the reviewer. The user subsequently downloaded it to:

`G:\modbus cic 2023\Modbus Dataset`

The component owner's repository used:

`C:\Users\ASUS\Desktop\Github_Kavisha_Harshangi\IDS-4-Critical-Infrastructures_J26-CS-318\data\raw\Modbus Dataset`

These are different machines' source locations. They must not be substituted for each other in runnable configuration. Earlier documents saying that the reviewer had not inspected the raw collection describe that earlier stage and are superseded by the subsequent inspection and reviews.

The recorded original inventory contains **207 files, 15,761,969,012 bytes**: 170 PCAP network recordings, 34 original CSV logs, one XLSX workbook, one README and one setup image. Source hashes were recorded by the preparation. File-count/size agreement and local hashes do not amount to a publisher-issued checksum certificate.

Original inspection also showed why assumptions about filenames and logs could fail. For example, one small file numbered `substation-0.pcap` belongs to a later observed time period than nearby numbered files. Concatenating files in numeric order would not give correct chronology. The original workbook could also preserve date/time information absent or damaged in some CSV representations.

## 7. What the preparation produced

The preparation selected four complete available observation chains. These are views of particular parts of the original traffic, not the entire collection.

| Selected view | Plain-language role | Capture chunks | Source bytes |
|---|---|---:|---:|
| `benign_ied1b` | Normal device traffic | 7 | 602,961,853 |
| `external_bridge` | External-attack scenario view | 2 | 146,790,882 |
| `scada_ied1a` | Command-side attack scenario view | 6 | 546,227,098 |
| `ied_ied1b` | Response-side attack scenario view | 6 | 519,956,231 |
| **Total** | | **21** | **1,815,936,064** |

The selected full chains retained surrounding traffic, not just individual suspected attack packets. Keeping surrounding messages matters because later context analysis needs the actual conversation.

The supplied completed extraction reports **3,768,287 retained records**: 3,767,894 complete Modbus application messages and 393 incomplete byte runs, reconciled from 20,923,685 observed network frames. A network frame is not necessarily one complete Modbus message: messages can be split across frames or share a frame.

The outputs preserve source/frame/byte lineage, raw message bytes, precise observed timestamps, values, decoding status, connection identity, and separate request-response relationships. TCP reconstruction and pairing have documented limitations, including gaps, ambiguous identity and unsupported reconstruction cases. Neither loss accounting nor passing tests proves universally perfect reconstruction.

### 7.1 Accepted labels

| Accepted class | Messages | Conservative class-bearing campaign groups |
|---|---:|---:|
| Normal | 1,404,306 | 1 |
| Command injection | 100 | 1 |
| Response injection | 54 | 1 |

The other 2,363,827 retained records do not have one of these accepted class labels. This includes unlabelled, ambiguous and out-of-scope observations and incomplete records; it does not mean they are all attacks or all normal.

An accepted label means the event met the documented evidence policy. It is not a guarantee of perfect ground truth or a complete count of attacks in the original dataset.

### 7.2 Why labels were limited

Command evidence required a supported relationship between original logs and observed requests, including the recording, target, transaction identifier, timing and logged coil behavior. Dense bursts could leave multiple plausible matches. Risky or ambiguous observations were withheld rather than guessed.

Response evidence used original false-data-injection logs and observed request/reply relationships. A legitimate acknowledgement associated with an injected command was not automatically labelled a forged response.

Normal labels came from the documented benign source and the applicable decoding/risk policy. Unlabelled traffic in attack recordings was not silently declared normal.

The accepted new counts and the old CSV attack-row counts use different source coverage, evidence policies and record populations. Subtracting one from the other would not measure how many real attacks were lost or recovered.

## 8. Why the candidate split was rejected for the proposed experiment

The preparation preserved entire related recording campaigns together to avoid presenting copies or highly related pieces as independent experiments. Its candidate memberships contain:

| Candidate partition | Normal | Command injection | Response injection |
|---|---:|---:|---:|
| Training | 1,404,306 | 100 | 0 |
| Validation/tuning | 0 | 0 | 0 |
| Test | 0 | 0 | 54 |

For the intended supervised three-class model, training has no response-injection class, validation has no accepted labelled targets, and test contains only response attacks. This is not a usable three-class train/tune/test experiment or a valid 70/15/15 result.

The code and reports explicitly mark it **`CANDIDATE_ONLY_UNSUPPORTED_INDEPENDENT_THREE_CLASS_EXPERIMENT`**. The presence of files named train, validation and test was not represented as proof of a successful experiment.

All accepted examples of each class belong to one conservative campaign group. Cutting a single related recording collection into more files or counting repeated days does not by itself establish more independent experiments. These conservative groups also do not prove that every possible narrower within-testbed study is impossible; that would be a different evaluation claim needing its own design.

## 9. Independent review of the preparation

The downloaded folder was reviewed locally at:

`D:\VSCode\GitHub\4th Year Cyber\C3\component3_preparation`

The independent review performed the following checks:

| Check | Result | Important limit |
|---|---|---|
| Existing offline tests rerun | 30 passed | Tests do not cover every possible real packet or reconstruction failure |
| Downloaded modules against recorded environment hashes | All 14 matched | Confirms consistency with the recorded modules, not publisher authenticity or scientific validity |
| Actual Parquet annotation/cohort counts | Reproduced | Does not independently prove every label correct |
| All 100 accepted command examples compared with original packets using an independent decoder | No disagreement in checked bytes/values/shape | Limited to the accepted command examples |
| All 154 accepted injection messages compared with original frame payloads using lineage | 154 matched, no mismatch | Byte identity does not independently prove maliciousness or campaign independence |

The review did not independently reconstruct all 3.7 million messages. It did not retrain a model, reassign labels or change the supplied project.

### 9.1 The malformed messages are present in the originals

| Accepted attacks | Malformed message | Structurally accepted by the decoder | Total |
|---|---:|---:|---:|
| Commands | 98 | 2 | 100 |
| Responses | 53 | 1 | 54 |

These shape findings were not explained by the old CSV value-export problem. The checked bytes agree with the original packets. This composition describes the accepted cohort, not the prevalence of malformed messages among every real attack in the entire source.

The 100 commands have only six distinct complete PDU patterns. Both structurally accepted command examples have the same pattern, `050001ff00`. All 54 accepted forged responses contain `ABCD` and have only three PDU patterns. The one structurally accepted response returns raw register word 43981.

**Consequence:** A detector could recognize broken message format, repeated bytes, endpoint identity, address or recording-period differences instead of learning the contextual behavior the proposal intends to investigate. A structurally accepted message is not automatically legitimate, physically plausible or authorized.

### 9.2 Injection attempts did not establish successful physical manipulation

Of the 100 accepted commands, 82 have observed exception replies and 18 lack an observed matched reply in the selected audit. Both structurally accepted commands lack a matched reply. This supports logged-attempt evidence and observed outcomes, not proof that the machine performed a harmful action. A missing reply proves neither success nor failure.

Of the 54 accepted response relations, 53 are inconsistent with the observed request/response expectations and one is matched without that inconsistency status. Most accepted responses are therefore challengeable with message or request-relative checks. No meaningful device-unit mapping, authorization policy or physical process model was established.

## 10. Salvage leads identified by the preparation review

### 10.1 Timing and uniqueness affect which commands receive labels

The selected command-side view contains **99,290 FC5 requests**, of which **46,297 are structurally accepted**. They are observed requests, not automatically established attacks.

Under unchanged candidate edges, clock offset and connection-risk filters, two-sided unique log/packet candidates varied with the allowed timing residual:

| Timing residual window | Unique diagnostic command candidates | Structurally accepted | Malformed |
|---|---:|---:|---:|
| Exact time | 82 | 34 | 48 |
| 1 millisecond | 400 | 63 | 337 |
| 5 milliseconds | 187 | 10 | 177 |
| 25 milliseconds: frozen policy | 100 | 2 | 98 |

The result is not contradictory: widening a window can introduce competing matches, removing uniqueness, while bringing different candidates into consideration. All 63 structurally accepted 1 ms candidates share the same command pattern. None was promoted to an accepted label.

The review identified a possible matching-policy bottleneck, not a licence to select whichever window produces more attacks. Timing precision, clock uncertainty, logger behavior and transaction identity still needed investigation.

### 10.2 The selected view did not cover all logged targets

The audit found **153,560 brute-force/specific-coil log signatures outside selected endpoint coverage**: 123,325 for target `.5` and 30,235 for `.8`. These are log signatures, not verified packet totals or independent attack counts.

A broader control-computer/HMI recording chain was therefore a concrete investigation option. Normal endpoint/function/address controls also needed attention because the current normal and attack cohorts use different endpoint combinations. Simply adding more attacks without comparable normal examples would not solve that shortcut.

## 11. What the reassessment investigated and found

The reassessment was produced on her machine and downloaded to:

`D:\VSCode\GitHub\4th Year Cyber\C3\component3_reassessment\v1_20261024`

It reproduced the earlier counts, reviewed timing and identity, checked accepted packet/log examples, examined bounded broader-view samples, proposed an expansion plan and tested hypothetical temporal blocks. It preserved the current labels and candidate memberships.

### 11.1 No new labels or timing-policy change

Accepted counts remained **1,404,306 / 100 / 54**. The proposed evidence-policy revision is explicitly not adopted. Its decision is **`NO_TIMING_TOLERANCE_CHANGE_JUSTIFIED_BY_AVAILABLE_CLOCK_AND_IDENTITY_EVIDENCE`**.

The reassessment reports that original CSVs serialize times up to milliseconds, while the PCAPs store microseconds. Storage resolution does not prove clock accuracy. No original attacker source/configuration was found to resolve logger call order and identity semantics. Selected successful-match residuals cannot establish a global clock model.

Literal wire transaction ID 5 is heavily reused: 96,200 FC5 requests use it in the selected command view. Matching that ID alone is not a strong identity guarantee, and it cannot be reinterpreted as a transaction range without evidence.

The 1 ms diagnostic set retains 97 of the frozen 100 commands and introduces 303 different candidates; exact-time candidates retain none of the frozen 100. These are materially different candidate sets. Their sizes do not justify replacing the existing policy.

### 11.2 A specific broader extraction option exists

| Proposed replacement canonical view | Capture files | Source bytes |
|---|---:|---:|
| Compromised SCADA/HMI | 17 | 1,664,745,012 |
| Benign HMI | 19 | 1,858,748,158 |
| **Total** | **36** | **3,523,493,170** |

The reported bounded pilot inspected 22,895 unique frames across boundary/time samples and 20 log windows. It found broader target coverage, compatible requests and cross-view observation copies. It did not complete full reconstruction of those chains or accept new labels. The independent reassessment review did not separately repeat this new raw pilot.

Broader benign samples included reads to all three targets, but observed normal FC5 controls remained at target `.5`, addresses 15/25. Comparable attack-address controls remain unresolved. Command expansion also does not establish additional response-injection variety or independent campaigns.

The proposed expansion replaces overlapping canonical views in a new version. It must not append simultaneous copies as extra independent observations. Complete-chain TCP continuity, loss and ambiguity still require validation. Resource figures in the plan are estimates, not measured guarantees for an expanded run.

### 11.3 Temporal subdivision was examined without creating a split

Global calendar blocks do not provide repeated class-complete periods in the frozen cohort: normal traffic is from January, accepted commands from March 15–21, and accepted responses from March 23–29.

As a narrower feasibility probe, the reassessment divided each campaign's duration into thirds and combined corresponding early/middle/late phases:

| Diagnostic phase, before purging | Normal | Commands | Responses | Structurally accepted commands | Structurally accepted responses |
|---|---:|---:|---:|---:|---:|
| Early | 465,934 | 57 | 13 | 2 | 0 |
| Middle | 468,838 | 34 | 18 | 0 | 0 |
| Late | 469,534 | 9 | 23 | 0 | 1 |

All classes appearing in these aggregates does not validate the experiment. The phases combine different calendar periods, reuse the same campaigns and retain repeated attack patterns. They are not a single globally forward-in-time deployment evaluation.

The two proposed response-campaign boundaries cross 66 and 11 connection generations. No observed matched pair or logged candidate-tool interval crossed those specific probes, but burst identity and later/missing replies remain uncertain. Boundaries still need verified dependency handling, quiet points or exclusions, and a declared future context horizon. No replacement memberships, purge, warm-up windows or model datasets were generated.

## 12. Independent review of the reassessment

The local review checked the supplied code and reports, reran the eight reassessment tests, verified recorded package hashes and independently recomputed phase counts from the preparation's actual Parquet annotations/events.

| Independent check | Result |
|---|---|
| Supplied reassessment tests | 8 passed |
| Recorded code/configuration/stage-output hash comparisons | 28 matched; no mismatch |
| Accepted totals from actual baseline data | 1,404,306 normal; 100 commands; 54 responses |
| Early/middle/late phase counts | All matched the report |

Some existing tests check recorded result fields rather than independently proving original-byte validity. Hash matches establish package consistency, not that every scientific conclusion is correct. The earlier independent preparation review supplied the direct original-byte checks for all accepted injection examples; this step did not independently re-run the complete new bounded raw pilot.

The reassessment reports its baseline files unchanged and raw sizes/modification times unchanged. It explicitly reuses original raw hashes rather than claiming a fresh exhaustive hash of every original PCAP. The local review did not change the supplied preparation or reassessment files.

## 13. What has been completed and what has not

| Activity | Status |
|---|---|
| Old CSV evidence/label/value review | Completed |
| Proposal and historical-method assessment | Completed |
| CIC-only Stage 1 handoff and later-preprocessing separation | Completed |
| Original source inventory and bounded original evidence inspection | Completed within documented scope |
| Selected-chain extraction and pair/evidence audit | Completed in supplied preparation |
| Conservative accepted labels and candidate memberships | Produced; limitations explicitly recorded |
| Independent preparation review | Completed with stated limits |
| Timing/identity/coverage/temporal reassessment | Completed as diagnostics |
| Independent reassessment package/count review | Completed with stated limits |
| Adoption of new timing labels | Not performed or justified |
| Full proposed HMI-chain expansion | Not performed |
| Defensible final three-class split | Not established |
| Context feature engineering and model preprocessing | Not performed in this authorized work |
| New model training, tuning, evaluation or deployment | Not performed |
| Demonstration that context improves detection | Not established |
| Independent-campaign three-class generalization | Unsupported by current accepted cohort |
| Successful physical process manipulation and authorization semantics | Not established |

## 14. What the findings mean for the project

The extraction has value and should not be discarded. It preserves information and auditability missing from the original derivatives. The remaining problem is the relationship between the available evidence and the research claims.

A model could technically be fitted to small, repetitive examples. The resulting score would not automatically establish useful contextual detection. Missing classes in training, weak controls, repeated payloads and recording/device shortcuts can invalidate a broader interpretation.

Recovering more evidence-supported commands could help a limited study. It cannot by itself repair response diversity, process meaning or independent-campaign scarcity. Similarly, more normal rows cannot substitute for varied attack examples or comparable normal controls.

Neither the 100/54 accepted counts nor the current failed split proves that the entire original CIC collection is useless or that every narrower experiment is impossible. Complete broader extraction remains unperformed, and the conservative grouping is designed for a particular independence claim. Any narrower claim must be explicit and tested on its own terms.

A valid research result need not show that context improves accuracy. With suitable design, a limited study could find that basic protocol checks already explain these accepted attacks. Whether that meets the original assessed ML component is an academic scope question; it cannot be settled by changing an experiment's description after seeing favourable scores.

## 15. Recommended next actions

1. **Discuss the objective using the decision report.** Ask whether a limited CIC within-testbed study comparing current-message detection against causal request-response/history context meets the component requirements. Explain the accepted cohort and the possibility of little contextual improvement.
2. **If the narrower objective is accepted, use the proposed broader HMI option in a separate version.** Validate a representative reassembly pilot, then perform the justified selected-chain expansion with source lineage and unchanged evidence rules. Recompute candidate identity and ambiguity; do not copy old labels onto replacement views.
3. **Reassess controls and labels before choosing a final evaluation.** Produce class/endpoint/function/address/pattern/shape counts and class support after dependency-aware boundary handling. Treat unknowns as unknowns. Confirm which cases could actually test added context.
4. **Proceed to her own preprocessing only if the task becomes defensible.** She should understand and demonstrate causal context construction and any training-only fitted transformations. No future reply may enter a request-time prediction, and original log-match/label metadata must not become model features.
5. **If the original independent-campaign claim remains mandatory, retain unsupported status.** Views, rows, days, oversampling and model choice do not establish the missing independent campaigns. The supervisor needs to resolve the evidence/requirement mismatch within the agreed data constraints.

Random row splitting, choosing tolerance for higher counts, declaring all writes malicious, treating unknown traffic as normal, using a fixed marker as proof of contextual intelligence, or importing MSU would not repair the present problem.

### Suggested message for the component owner to send herself

> The CIC-only preparation and reassessment are complete for the documented scope. The accepted cohort has 100 command-injection and 54 response-injection messages, each class concentrated in one campaign. Of those 154 attacks, 151 are malformed, and every accepted forged reply contains ABCD. The current candidate split cannot support the proposed supervised three-class evaluation. A broader HMI extraction option exists, but it will not create independent campaigns or guarantee diverse responses. Can we agree on a narrower within-testbed comparison of current-message checks versus request-response/history context, with explicit limitations and the possibility of no contextual improvement? If the original independent evaluation is mandatory, the currently established CIC evidence does not support it.

No message has been sent to anyone by this review.

## 16. Plain-language glossary

| Term | Meaning in this project |
|---|---|
| Modbus/TCP | A language machines and controllers use to communicate over a network |
| Command/request | An instruction or question sent to a machine |
| Response/reply | The machine's answer |
| Injection | An attacker inserting a message into the conversation |
| Context | Other relevant parts of the conversation that help interpret the current message |
| Dataset | The collected material used for analysis or learning |
| PCAP | A file recording observed network packets |
| Frame/packet | One observed network transmission unit; it is not always one complete application message |
| ADU | One complete Modbus application message, including its protocol header |
| PDU | The function/data portion inside that message |
| Label | An evidence-based class annotation, such as normal or response injection |
| Unknown/ambiguous | Evidence does not justify assigning a supported class |
| Parser/decoder | Software that reads message bytes and interprets their fields |
| Malformed | A message breaks the checked protocol structure/rules |
| Parser-ok | Structurally accepted by this decoder; not proof of safety, legitimacy or plausible process behavior |
| Provenance/lineage | Information tracing a derived record to its original source and bytes |
| Campaign | A conservative group of related recordings/views; not automatically an independent physical experiment |
| Canonical view | The chosen observation chain used instead of counting overlapping sensor copies separately |
| HMI | The operator/control-computer interface; its captures may observe several devices |
| Transaction ID/TID | A message identifier used in matching requests and replies; it can repeat |
| Training | Examples used to fit a model |
| Validation | Separate examples used for model/parameter selection |
| Test | Held-out examples used to assess the chosen model |
| Leakage | Information that gives the experiment an unfair answer or reveals future/test information |
| Shortcut | An easy incidental pattern a model can exploit instead of the behavior the research intends to measure |
| Purge/boundary exclusion | Keeping dependent observations near a partition boundary out of scoring so information does not cross unfairly |
| Preprocessing | Preparing model inputs; here this later work remains the component owner's task |
| Generalization | Working beyond the particular examples or recording setup used for learning |
| Hash | A digital fingerprint used to check whether file bytes match |

## 17. Evidence and deliverables index

| Evidence or deliverable | Location and purpose |
|---|---|
| Initial detailed guide | [COMPONENT_3_GUIDE.md](<D:/VSCode/GitHub/4th Year Cyber/output/component3_review/COMPONENT_3_GUIDE.md>): scope, old-CSV findings, methodological guidance and future-only preprocessing discussion |
| Old CSV diagnostics | [csv_audit_findings.md](<D:/VSCode/GitHub/4th Year Cyber/output/component3_review/csv_audit_findings.md>) and supporting JSON/scripts in that directory |
| Historical transcript assessment | [ORIGINAL_TRANSCRIPT_REVIEW.md](<D:/VSCode/GitHub/4th Year Cyber/output/component3_review/ORIGINAL_TRANSCRIPT_REVIEW.md>) |
| Original-data inspection | [RAW_INSPECTION_FINDINGS.md](<D:/VSCode/GitHub/4th Year Cyber/output/component3_execution/RAW_INSPECTION_FINDINGS.md>) and [LOG_EVIDENCE.md](<D:/VSCode/GitHub/4th Year Cyber/output/component3_execution/LOG_EVIDENCE.md>) |
| Preparation feasibility statement | [FEASIBILITY.md](<D:/VSCode/GitHub/4th Year Cyber/C3/component3_preparation/FEASIBILITY.md>) |
| Exact selected scope and grouping | [EXTRACTION_SCOPE_AND_GROUPING.md](<D:/VSCode/GitHub/4th Year Cyber/C3/component3_preparation/EXTRACTION_SCOPE_AND_GROUPING.md>) |
| Candidate split evidence | [split_manifest.json](<D:/VSCode/GitHub/4th Year Cyber/C3/component3_preparation/output/split_manifest.json>) |
| Independent preparation review | [COMPONENT3_PREPARATION_REVIEW.md](<D:/VSCode/GitHub/4th Year Cyber/output/component3_execution/review/COMPONENT3_PREPARATION_REVIEW.md>), with raw-byte/cohort/scope JSON and reproduction scripts nearby |
| Reassessment handoff | [FOLLOWUP_FOR_HER_CODEX.txt](<D:/VSCode/GitHub/4th Year Cyber/output/component3_execution/review/FOLLOWUP_FOR_HER_CODEX.txt>) |
| Reassessment decision | [DECISION_REPORT.md](<D:/VSCode/GitHub/4th Year Cyber/C3/component3_reassessment/v1_20261024/DECISION_REPORT.md>) |
| Unadopted timing policy | [PROPOSED_POLICY.md](<D:/VSCode/GitHub/4th Year Cyber/C3/component3_reassessment/v1_20261024/PROPOSED_POLICY.md>) |
| Proposed HMI expansion | [expanded_scope_plan.json](<D:/VSCode/GitHub/4th Year Cyber/C3/component3_reassessment/v1_20261024/output/expanded_scope_plan.json>) |
| Temporal feasibility and boundary warnings | [temporal_feasibility.json](<D:/VSCode/GitHub/4th Year Cyber/C3/component3_reassessment/v1_20261024/output/temporal_feasibility.json>) |
| Independent reassessment checks | [independent_checks.json](<D:/VSCode/GitHub/4th Year Cyber/output/component3_execution/reassessment_review/independent_checks.json>) |
| Decision brief and conditional continuation prompt | [NOW_WHAT.md](<D:/VSCode/GitHub/4th Year Cyber/output/component3_execution/reassessment_review/NOW_WHAT.md>) |

The historical handoff ZIP and independent-review ZIP are packaging for earlier stages. Their existence does not mean the data are ready for training. This consolidated report records the position after both supplied project folders were reviewed.

The appendix links refer to the reviewer's local copy. On another machine, use the matching repository-relative file names rather than the reviewer's drive letters.
