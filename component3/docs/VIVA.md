# Viva guide: what actually happened

## A simple explanation with the important details kept

Imagine a controller sending little notes to a machine. One note says “turn the pump on.” Another asks “what setpoint do you have?” Looking only at one note may not tell us whether it is allowed or truthful. We need some earlier notes.

Our software testbed has a public rule: mode0 forbids pump ON; mode1 permits ON. It also has a setpoint that changes only when the single controller writes it. A successful FC6 acknowledgement confirms the written raw word. A later FC3 readback should agree with that earlier acknowledgement. These are **declared toy-process rules**, not rules discovered for a real power/water plant.

The command intervention makes the compromised controller send a valid FC5 ON after mode0. The response intervention makes the compromised server return a different FC3 setpoint word. Those are two intervention mechanisms, not eight attack families. Six other scenario families provide legitimate traffic, including changed setpoints, repeats and mode transitions. A valid ON can be normal in one history and an injection in another. A value that appears in a forged reply also appears legitimately elsewhere.

## Why CIC did not become the primary model dataset

The original project planned CICModbusDataset2023 as primary. Conservative audit found 1,404,306 accepted normal, 100 command and54 response messages, but insufficient independent class-bearing campaigns. The candidate train/validation/test groups did not each support the three classes. Most accepted attack PDUs were malformed:98/100 commands and53/54 responses; the responses had only three ABCD-containing patterns. More rows or tighter timing windows did not establish independent campaigns or reliable broader labels.

That historical evidence remains under `history/component3_preparation` and `history/component3_reassessment`. It was not secretly relabelled or mixed with the new simulator. MSU and all other external datasets are excluded. The replacement is a **methodology amendment requiring supervisor review**, not proof that the original proposal was always followed. The original signed declaration is not approval of this later change.

## How the new evidence was generated and accepted

The simulator exchanged actual Modbus/TCP bytes on an isolated loopback connection. This is captured software traffic, not hand-written rows pretending to be measured traffic. It does not reproduce a physical industrial process. There is no physical effect or MITM claim; the response hook is inside the controlled server.

104 accepted whole executions were selected by `collection_complete.json` out of107 attempts. We did not select every folder. Three unsuccessful attempts remain preserved. Each accepted run has capture bytes, application observations, server/intervention audit evidence, a plan, validation report and a completion seal. Capture bytes and intervention evidence together establish labels. A folder name, FC, direction, missing reply or private scenario field alone is not a label.

The independent audit checks250,066 ADUs (247,906 normal,720 command,1,440 response),313,208 PCAP frames and all250,066 byte references. Every command has a normal same-PDU control in its run; every forged response does too. Literal-TID5 controls also match complete ADUs for240 command and480 response targets. Reused TID5 is not a unique transaction identity. Genuine repeated messages stay separate at different stream positions.

The collection has9,360 private episodes,104 executions and **one simulator campaign identity**. Episodes aid label auditing; they do not reset detector history. Seeds and repeated days are not independent industrial campaigns. The fixed collection order also leaves possible host/time drift confounding.

## What preprocessing was actually done

The original modelling work ran on the producer machine. The student must be able to demonstrate and explain it; this audit does not pretend she manually performed every earlier command. Update the AI-use declaration to reflect code/audit assistance and identify her own reviewed contributions.

1. **Admission:** read only the104 accepted index entries, check collection/frozen-source/receipt/artifact hashes and roster membership. Keep rejected attempts and pilots out.
2. **Decode:** convert exact MBAP/PDU bytes to protocol values. A complete Modbus ADU is the observation, not necessarily one network packet. Record missing fields faithfully.
3. **Replay everything:** process every normal/attack ADU in wire-consistent order before selecting scored tasks. Otherwise important normal mode reads and ACKs would disappear.
4. **Associate:** pair by connection and current pending request, checking literal TID/unit/function and exact write echo. The original batch adapter also used validated ledger ordinals; new v2 removes that dependence. Neither version treats TID as globally unique.
5. **Maintain causal state:** remember earlier genuine mode read and earlier successful setpoint ACK. No future ACK decides its own preceding command. A mode write invalidates the old read; an ACK of that write does not substitute for a new mode read. No private episode reset.
6. **Route:** public FC/map-defined pump-ON requests and paired setpoint-readback responses are eligible tasks. Lack of trustworthy recent context means abstain, not normal. The maximum is6 intervening ADUs. Other traffic is explicitly out of scope for this classifier.
7. **Separate tables:** retain raw/evidence rows, numeric candidate predictors, labels, routing/eligibility and memberships separately. Do not use “all columns except label” as X.
8. **Use whole-run roles:**32 train,16 validation,24finalrepeat and8 each values/map/order/timing. No row-random70/15/15 split; no pair/episode/mirrored copy crosses roles.
9. **Fit numeric missing-value handling on training only:** saved `SimpleImputer(strategy='median', add_indicator=True, keep_empty_features=True)` learns medians from the5,984 supported training targets. Structural missingness is preserved before that step. All-empty training columns remain in the schema; missing indicators are learned from training. Legitimate0 is a value, not missing context.
10. **Train/select:** Random Forests are fitted on training only and selected on2,992 supported validation targets. Their preprocessing travels inside the serialized pipeline. No scaler, normalization, SMOTE, balancing by duplicated observations, feature selection or fitted normal profile was used. Class weights were candidate settings, not extra rows.

Development preparation replayed114,604 ADUs;12,720 eligible tasks included8,976 supported tasks. Final score rows are a different, smaller subset of the full captured traffic. A table containing a label or run ID for audit is not itself leakage; passing that column to the estimator would be.

## Actual model-input dictionary

All features are cast to floating numeric columns before the saved imputer/RF. Public role codes are fixed constants, not a category encoder fitted on all data. Counts/addresses/words are unsigned protocol quantities; no physical units, signedness conventions or register-map meanings beyond the supplied laboratory map are invented.

| Feature | Source/type/unit | Missingness/transformation |
|---|---|---|
| current_function | Current PDU function, integer code | Decoded supported FC1/3/5/6; current byte semantics only |
| current_unit | Current MBAP unit, integer | Qualified collection unit1; v2 rejects others |
| current_is_request | Public direction, boolean0/1 | Transport direction, not attack label |
| current_pdu_length | Current PDU length, bytes | Exact length |
| current_wire_address | Address carried in current message, unsigned16-bit index | FC3 reply has no address: missing; write echo carries address |
| current_wire_word | Current value, unsigned word/coil encoding | Read requests have no returned word; FC5 uses0/65280 |
| current_wire_quantity | Current request quantity, objects | Missing on replies/writes; supported reads request one |
| current_byte_count | Current read-reply byte count, bytes | Missing where not present |
| current_request_object_role | Current request address + supplied map: mode1/setpoint2/pump3 | Missing for responses; never borrow the request's role into B |
| earlier_observed_mode | Most recent usable earlier mode-read reply,0/1 | Missing before anchor, after invalidation or when stale |
| earlier_acknowledged_setpoint | Most recent usable exact FC6 setpoint ACK, raw unsigned word | Missing if unobserved, pending update or stale |
| paired_request_object_role | Earlier matched request + public map, role code | Contextual information; missing for requests/unpaired replies |
| response_minus_acknowledged_setpoint | Current readback minus earlier ACK word, signed arithmetic difference of two raw unsigned words | Only supported response task; zero is real agreement, missing is different |
| context_available | Eligibility-specific trustworthy anchor flag, boolean | Used also as routing condition before imputation; not label-derived |
| current_numeric_tid | Current literal16-bit MBAP TID | Only B-wire/D-wire; never independent identity by itself |
| current_source_ip | Current source IP encoded as integer | Only wire companions; not a learned encoder |
| current_destination_ip | Current destination IP encoded as integer | Same; accepted testbed addresses are loopback |
| current_source_port | Current TCP source port, integer | Only wire companions; potential run/host shortcut |
| current_destination_port | Current TCP destination port, integer | Same; no private run ID substitution |

B has9current features, D adds5context features (14), B-wire has14, D-wire19. Imputer missingness indicators expand estimator input further; inspect the saved imputer rather than guessing the post-transform count.

Forbidden model inputs include label, true prior labels, scenario, step, episode, seed, block, intervention flags, private process state, run/event/file/group IDs, split membership and absolute capture time. No FC3 address exists on its current wire reply: associated request address may route the task or explain the affected object, but remains context.

## What the methods do

**A:** protocol format/available consistency checks. The interventions intentionally use valid syntax, so A predicts normal on the supported task cohort.

**B:** Random Forest with only current semantics/public map information. It cannot recover the missing history from identical current bytes. It mostly predicts normal here.

**C:** rules using the same public map, trust assumptions and history budget as D. For eligible ON, mode0 means command injection under this policy; mode1 means normal. For eligible setpoint reply, a difference from the earlier ACK means response injection. Missing/stale evidence abstains.

**D:** the same RF family with earlier context. It is learning a representation that already makes much of the rule easy. The residual feature literally subtracts expected from observed readback; zero versus nonzero almost specifies that part of the decision. Earlier mode similarly expresses command permission. This is useful engineering, but not evidence the model learned physical semantics or outperformed known rules.

B-wire/D-wire give both models numeric TID/IP/port access to check whether comparison depends on hiding current headers. Those fields can still carry environment/collection shortcuts. All methods receive the same legitimate public map/policy; the map holdout supplies M2 instead of asking a model to discover it.

All RFs use160 trees, random_state42, sqrt features per split and2 workers. Each has4 candidates: depth12/leaf2 or depth8/leaf5, crossed with balanced/None class weight. Validation common-cohort macroF1 selects the candidate; fixed order resolves ties. This is **not** the proposal's200/400/600-tree grid, grouped CV or K3/5/10-window study.

## How to explain the results honestly

MacroF1 gives each of the three classes equal weight. The main comparison scores identical context-supported task rows for all methods. Confusion matrices and class supports show what those averages mean. Per-task attack F1 avoids crediting a deliberately absent attack class. The original fixed-three-class per-run/task macro can be1/3 even for a perfect normal-only run; always state the denominator.

C rules classify all supported final cases correctly. D misses one of144 response injections in the ordering cohort. There is no demonstrated ML improvement over C. D's high score compared with B supports the usefulness of the chosen earlier information for these tasks, not broad intrusion-detection superiority.

10,376 final tasks are supported;4,464eligible tasks abstain. Out-of-scope traffic is not “correct normal.” Only the repeat cohort includes normal-only runs; other cohorts cannot establish a normal-only FPR. Zero false alarms among scored normals is different from monitoring every normal ADU successfully.

Whole-run bootstrap intervals describe simulator replication variability. They do not turn104 executions into104independent plants/campaigns. An observed final set cannot become fresh by changing a random seed or resampling it. Any model/feature changes after these results need a new version; testing again on these final rows is exploratory.

## Short demonstration sequence

1. Show `collection_complete.json`, the accepted MX001 receipt and `reports/audit_final_20261025/evidence_examples.json`.
2. In Wireshark, inspect a cited frame and compare the byte span to `adu_hex`. The source path, line and byte offsets are recorded; do not guess from a scenario name.
3. Show the original training examples in `locked/v1_20261025/VIVA_EXAMPLES.md`: identical ON ADU `00050000000601050001ff00` under modes1and0; identical readback `0005000000050103020039` after acknowledged words57and22.
4. Run `python c3.py check` then `python c3.py demo --run MX001`. Open the new JSONL output; explain complete, insufficient_context and out_of_scope counts.
5. Explain why the FC3 wire address is null while an affected address can come from an earlier request, and why the latter is not B's input.
6. Show lock/model hashes and `runtime_development_final.json`; explain that v2 validation equality is engineering evidence, not a second final experiment.
7. End with the amendment, the rule baseline's success and the missing integration/external evidence.

## Questions to be ready for

- **Why ML if rules are enough?** In this bounded policy, rules are enough and slightly better. The legitimate finding concerns representation and causal evidence. A stronger ML-value claim needs a justified harder problem, not artificial noise introduced to handicap rules.
- **Does the server ACK prove a safe physical action?** No. It confirms a protocol/software response under the declared testbed contract, not plant safety or physical truth.
- **Can an attacker forge the mode/ACK?** Yes in a broader threat model; this experiment assumes those anchors remain genuine. The existing result does not cover forged anchors, hidden writers or autonomous process changes.
- **Did preprocessing use final labels?** No in the inspected code/data path. Predictors have explicit allowlists, medians match training-only data, and final outputs came from saved frozen models. Local logs/hashes are provenance evidence, not an externally witnessed guarantee of every human's prior access.
- **Is confidence a probability that an attack is truly malicious?** No. The RF probabilities are uncalibrated votes/proportions under this dataset. Calibration and operational risk need separate study.
- **Is it real-time?** Causal decisions need no future ADU, but a production transport pipeline and live latency were not established. Warm model-only p95 is about54ms in the recorded final validation benchmark.
- **What did you personally verify?** Answer with your own performed byte walkthroughs, tests, interpretation and decisions; do not claim generated documentation proves your understanding.
