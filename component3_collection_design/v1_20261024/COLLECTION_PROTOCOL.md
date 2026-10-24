# Component 3 controlled Modbus/TCP collection protocol

Version: `c3-controlled-collection-v1-20261024`  
State: **proposed protocol; not a final dataset or an approved experimental result**.

## 1. Research question and present evidence

Under a declared software-process policy, how much useful information does causally observed command and request–response context add to current-message inspection when distinguishing normal traffic, unauthorized commands and deliberately altered replies?

The intended later comparison retains the same Random Forest family with and without context, and adds specification checks and simple contextual rules. A result showing no ML benefit is permissible. This study concerns one controlled testbed and explicitly held-out conditions within it; it cannot establish generalization to independent industrial plants or unseen attack techniques.

The local feasibility run `pilot-20261024T170840Z-d137ea97` contains 108 transactions and 216 messages: 208 normal, four command targets and four reply targets. Actual capture bytes, source hashes and labels were checked. All eight target role/PDU patterns also appear in normal controls. These observations establish collection feasibility; they are not the main experiment, development data or a hidden final test.

The frozen CIC extraction remains a separate case study. It has 100 accepted commands and 54 accepted responses in one campaign per attack class, with 151/154 accepted attacks malformed and all response targets sharing ABCD. More CIC rows or more repetitions of this pilot do not repair independent-campaign support. Old CSV derivatives, MSU, New Gas Pipeline and water-storage data supply no rows or labels to this collection.

## 2. Declared environment, policy and observation point

- Retain Docker `network_mode: none`, container loopback and port 15020; do not publish a host port or target another machine.
- Start with one controller, one software PLC, unit 1, FC1/3/5/6 and one outstanding request per connection. A new run starts fresh application state and a new capture. Preserve connection generations and genuine repetitions.
- Mode is a visible holding register. Mode 0 forbids pump ON; mode 1 permits it. Pump OFF is permitted in both modes. FC6 setpoint writes are permitted in both modes under `lab-policy-v1`.
- The server deliberately executes protocol-valid pump writes even when the lab operating policy forbids them. That separates syntax, authorization and simulated effect; it is not a safety-interlock model.
- Stored setpoint changes only after an acknowledged FC6 write. There are no hidden writers, autonomous setpoint changes or measurement noise in the core study. Any future relaxation needs its own process/observability contract and validator.
- The detector observes the complete local conversation and a declared public object-role map. It does not observe the private oracle or the generator's scenario schedule. Maps describe lab objects, not permissions learned from true labels.

All addresses are zero-based wire addresses. Setpoints are unsigned raw words, not degrees, voltage or another invented physical unit.

## 3. Scenario and normal-control matrix

These are planned families, not claims that the current launcher implements all of them.

| Family | Intended behavior | Evidence and control requirement |
|---|---|---|
| N_PERMITTED_ON | Observe mode 1, then pump ON | Same FC5 ON role/PDU as command targets, with different earlier permitted state |
| N_INHIBITED_IDLE | Observe mode 0, then lawful OFF/polling | Mode 0 and its surrounding traffic must also occur normally |
| N_AUTHORIZED_UPDATE | Visible setpoint write and genuine new readback | Normal changes must not be mistaken for forged values; retain write acknowledgement |
| N_REPEAT_WRITE | Repeated permitted ON/OFF and same-value writes | Preserve distinct stream occurrences; repetition is not automatically replay/injection |
| N_MODE_TRANSITION | Observable 0→1 and 1→0 changes followed by lawful actions | A previous mode cannot be treated as permanent; no unobserved mode change |
| N_GENUINE_READBACK | Readback equals last acknowledged write | Both values used in reciprocal forgeries also occur as genuine replies |
| C_BLOCKED_ON | Direct valid FC5 ON after observed mode 0 | Only that request is command_injection; genuine acknowledgement remains normal |
| R_CHANGED_READBACK | Replace the FC3 setpoint answer a→b or b→a | Only the changed reply is response_injection; preserve genuine expected reply privately |

Do not add a rule forbidding setpoint writes in mode 0: the existing pilot intentionally labels those setup writes normal. A different command policy needs a new version and cannot retroactively change v0.1 data.

For each attack family, require a normal example with the same current role and PDU pattern. Verify overlap on captured messages, not just planned parameters. Repeat this check within every qualification run and report main-collection coverage by run/configuration. Matching the current PDU does not certify that timing, headers or the schedule are free of shortcuts.

All families receive the same scheduling/timing treatment. Labels may not determine an endpoint, source port, TID rule, delay, message length, output file or special marker. Scenario, step, run and episode fields stay in the audit evidence and are excluded from future predictors.

## 4. Planned variation and held-out conditions

The machine-readable choices are in `collection_design.json`.

| Factor | Development conditions | Proposed held-out condition |
|---|---|---|
| Object map | M0: mode 0/setpoint 1/coil 1; M1: mode 10/setpoint 11/coil 7 | M2: mode 40/setpoint 41/coil 21 |
| Values | V0: distinct raw values in 20–180 | V1: 1000–1160, equally available in normal and forged roles |
| Ordering | S0 common template; S1 dependency-safe benign interleaving | S2 different legal ordering/polling mix under the same policy |

The public role map is available as deployment configuration to every applicable method; a map ID must not become a predictive shortcut. A value range is a collection condition, not a learned safety threshold. Separate test cohorts vary one factor at a time so changes can be interpreted. They do not represent independent environments.

The current generator fixes M0 and the original template. M1/M2, S1/S2 and several dedicated normal families require a new generator and corresponding independent validator. Keep v0.1 code and its original captures unchanged; implement the extension in a new version. Do not raise its `groups` limit to disguise missing scenario support.

Core qualification targets retain a visible causal anchor with at most six intervening ADUs. The original mode-to-ON interval already contains six intervening ADUs: inserting more exchanges there requires an explicit new mode observation closer to the target. Insert background exchanges before anchors or refresh anchors without changing their meaning. Position and benign interleaving vary across families. Longer-history stress conditions can be designed separately; do not silently make the declared history unavailable while claiming a detectable target.

## 5. Capture units, prospective roster and sample-size limits

A run is a fresh application execution with a complete capture and reset process state. An episode is a related scenario occurrence within it. A seed group is parameter generation, not an independent campaign. Repeated seeds, PCs, connections and runs do not create a new physical testbed or attack mechanism.

First implement and collect **four qualification runs**, seeds 60001–60004, M0/V0/S1, with all eight families and both reply-forgery directions. Require at least two direct command and two direct response targets per run, alongside all controls. These are engineering minimums, not a statistical sample-size justification. Qualification runs are excluded from model development and final scores.

The initial main-collection budget is a prospective factorial roster:

| Purpose | Conditions | Replications per condition cell | Planned captures |
|---|---|---:|---:|
| Development | M0/M1 × S0/S1 × V0 | 4 | 16 |
| Validation | Same condition cells, new executions/seeds | 2 | 8 |
| Test: repeat conditions | Same condition cells, sealed new executions | 2 | 8 |
| Test: value range | M0/M1 × S0/S1 × V1 | 2 | 8 |
| Test: object map | M2 × S0/S1 × V0 | 2 | 4 |
| Test: ordering | M0/M1 × S2 × V0 | 2 | 4 |
| **Draft main total** | | | **48** |

Every planned capture contains all core families and matched controls. These counts are an initial manageable replication budget, **not proof of statistical power or a required final dataset size**. Use qualification to measure yield, variability, runtime and capture reliability; revise this draft prospectively before main collection and test inspection. Do not choose a row count or regenerate seeds to obtain attractive model results.

The prospective roster contains no actual event assignments. It is not a 70/15/15 split or a model dataset. Keep whole related runs, all their episodes, response dependencies and any observation copies together. Never split rows from the same run across roles. If a run spans capture rotations, rotations retain one run identity and reconstruction state.

Reserve tests before collecting/inspecting them. Develop collection/validation code on engineering runs, then freeze code, policy, definitions and roster. A collector may inspect sealed tests for technical integrity using a frozen validator; model/feature decisions must not use their target patterns or scores. On a one-person project, record access and avoid claiming that already inspected data were untouched.

## 6. Ground truth, mechanism and outcome

Preserve the actual PCAP, recorder logs, application ledger, private server state/intervention audit, run configuration, source/image hashes and host execution metadata. Each accepted ADU needs endpoint tuple, connection generation, direction, TCP byte interval, full bytes and frame/file-byte references. Timestamps and TIDs are supporting identity fields, not sufficient occurrence identity.

Separate these dimensions:

1. **Intent/attempt:** the generator requested an intervention.
2. **Wire evidence:** the intended request/reply really appeared in the capture.
3. **Mechanism label:** a direct unauthorized command or altered reply is supported by both bytes and the declared experiment truth.
4. **Parser/pair result:** valid, malformed, exception, matched, missing or ambiguous.
5. **Simulated effect:** private before/after software state and any observed acknowledgement. This is not a measured physical-plant effect.

A genuine acknowledgement of an injected command is normal association. A response-injection event does not relabel its genuine request. An unsuccessful/no-op response mutation is not a forged-value example just because the hook was armed. Missing reply does not prove failure. An exception does not become an injection label. Preserve failed, incomplete and unverifiable runs; do not turn their unknowns into normal targets or change labels to pass validation.

The existing validator writes verified labels only for a completely accepted pilot. Keep that fail-closed behavior in the extension, including checks for policy state, reciprocal normal controls and new map/order support. A code-test PCAP or smoke run is not collected research data.

## 7. Qualification acceptance gates

All four engineering captures must meet all of the following:

- Runtime is isolated, capture readiness is recorded, reported drops are zero, and all expected messages reconcile with stream and byte lineage. Unassessed checksum/offload limits remain explicit.
- The independent decoder accepts supported target PDUs and map semantics. Every directly labelled target is manually inspectable against original capture bytes and the intervention audit.
- Every attack role/PDU has a genuine normal control. Both reciprocal reply-forgery directions occur, with normal returned values covering both values.
- Mode-0 lawful traffic, visible mode changes, legitimate updates and repeated lawful writes are present. No whole episode is blanket-labelled attack.
- At command arrival, a valid earlier mode observation is available; at reply arrival, its query and the relevant earlier acknowledged write are available. A future recovery read is not used to explain an earlier decision.
- Ground-truth, scenario, step, seed, schedule and run metadata are separated from detector-visible traffic. Failures and causal-history gaps are retained.
- The current pilot, collaborator handoff and frozen CIC folders are unchanged. New versions and runs have distinct paths and recorded hashes.

If any gate fails, repair and version the generator/validator and retain the failed evidence. More repetitions are not a repair. The qualification ledger must record failures, amendments and subsequent checks.

## 8. Later evaluation contract; no preprocessing now

Compare protocol checks, simple causal rules, isolated-event RF and the same RF with context/ablations on the same supported cohort. Predeclare a task-focused cohort for pump-ON requests and setpoint-readback responses using public protocol/object roles; never select it using private scenario flags. Also report all-traffic coverage and insufficient-context dispositions so trivial normal messages do not hide target failures.

A read response has no wire address. Request-derived address and expected-answer relations are contextual/audit information; they cannot enter the isolated-response baseline as if present in the current PDU. Declare request-arrival versus response-arrival decision time and any delayed decisions consistently.

Future preprocessing is the researcher's separate, inspectable implementation. It must preserve valid zeros and arrays, distinguish missing/inapplicable/unknown fields, use causal grouping, and fit any transformation on training only. No context features, windows, imputation, encoding, scaling, resampling, normal profiles, X/y matrices or models are produced by this design stage.

Later report per-class support/recall, macro metrics, false positives, confusion matrices, coverage and decision latency, with uncertainty summarized by run/condition rather than pretending packets are independent. If rules solve the toy policy, report that result; do not claim ML superiority from beating only the current-message baseline.

## 9. Academic decision and stop conditions

Using this testbed as the principal source changes the proposal's CIC-primary methodology, while retaining the TAF's context-aware command-analysis question. The proposed amendment is in `RESEARCH_ALIGNMENT.md`. Preparing this protocol does not assert supervisor approval.

Stop if timing/identity or ground truth cannot be reconciled, required normal controls are missing, the detector cannot observe the claimed context, unresolved capture gaps remain, source/template markers dominate without controls, tests have been used for tuning, or the work would enter unapproved larger collection/preprocessing. Independent-campaign three-class generalization remains unsupported by the audited CIC cohort; this testbed does not retroactively fix it.
