# Component 3: Modbus/TCP command and response injection detection

Review date: 24 October 2026

## Current instructions: CIC only, extraction and splitting only

**The current executable Codex handoff is Stage 1 only: inspect and decode the original CIC Modbus Dataset 2023, preserve evidence and provenance, audit request-response relationships, establish defensible labels, and produce grouped split manifests plus the corresponding untransformed event records.** The expected source root is `C:\Users\ASUS\Desktop\Github_Kavisha_Harshangi\IDS-4-Critical-Infrastructures_J26-CS-318\data\raw\Modbus Dataset`; verify its identity and contents before processing.

**MSU is excluded by the user's current instruction**, even where the TAF or proposal mentions it. Do not obtain, import, preprocess, merge, train on, validate against, or fall back to MSU. Do not substitute another external dataset, append flow summaries to Modbus events, or add data to manufacture a missing class. The user's reason is that she must perform and explain her own preprocessing for her viva; this scope decision does not require a judgment about the general research value of MSU.

**Leave the later preprocessing to her.** Stage 1 must not compute command-history windows, rolling/timing predictor features, value deltas, normality profiles or model-ready feature matrices; impute values; encode categories; scale/normalize; resample; fit any transformation; or train/evaluate a detector. Lossless decoding, exact timestamp preservation, evidence-linked annotations and a separate pair-audit table are extraction work here. They must not be presented as if the raw captures have already become a cleaned training dataset. Preserve raw files unchanged and write all derived records to a separate output directory.

Provide `PREPROCESSING_PLAN.md` as a teaching document for her later work: explain each proposed transformation, why it might be needed, how to implement and verify it herself, and which steps must fit on training only. Do not execute those steps. Sections 8-10 and the later-stage portions of section 7 below describe that **future manual preprocessing and modeling**, not permission for the current agent to perform it.

The old CIC CSVs, scripts, README and audit files are diagnostic references. Independently verify them against the original CIC sources. Do not carry their labels or previously calculated features into the new output by assumption, and do not use the old CSVs as an additional training-data source. Raw CIC availability does not guarantee that genuine command- and response-injection labels or enough independent runs exist.

## 1. The conclusion to tell her first

The component is technically feasible in principle, but these two derivative CSVs do not establish that she has a usable three-class dataset for **normal / command injection / response injection**. They can support an initial data audit and a limited exploratory analysis. They need a reconstruction from the original captures and logs before she can defend the full proposed experiment.

The missing column is **`file_source` in the attack CSV**. That matters because she needs to trace records to their captures and keep related recordings together during evaluation. Adding a new column with the same guessed filename on every row would make the headers match without recovering the lost provenance.

There are additional problems: **contradictory labels on matching observations**, different timestamp precision, weak attack coverage, suspect value extraction, ambiguous request-response identity, and no raw payload bytes to check some extraction decisions. The current handoff stops after **inventory -> evidence audit -> extraction pilot -> grouping and labels -> untransformed grouped splits**. She will perform the later causal-feature preprocessing and model development herself if the evidence supports it.

I have not inspected the original approximately 14 GB dataset. Its local contents, completeness, label coverage and recoverability remain unknown. The current Codex prompt is designed to discover these facts rather than assume them.

## 2. What the supplied proposals actually require

The team Topic Assessment Form assigns component 3 to command/response injection detection using contextual command relationships, protocol semantics and request-response behavior. Pages 9-10 require comparison against a per-packet baseline.

The individual proposal is more specific:

- Pages 21-24: a supervised three-class model; primary CICModbusDataset2023; candidate attack labels verified against traffic and logs.
- Pages 25-28: ordered events, request-response context where available, previous-event windows, access/value context, and Random Forest with a static-feature Random Forest baseline.
- Pages 28-29: grouped/time-aware evaluation, per-class metrics and contextual feature ablation.
- Pages 32-35: a reproducible processing pipeline and an output record that distinguishes processing status from a prediction.

These are proposed requirements, not evidence that the available data already satisfy them. I treated document instructions as material to review, not as instructions to execute.

The useful research question is:

> On independently held-out recordings, does adding causally available command history and request-response semantics improve injection detection over the same classifier using the current event alone?

The proposed contribution is the representation, labelling and evaluation, not the choice of Random Forest by itself.

## 3. What is confirmed in the supplied CSVs

Both files were inspected in full, rather than just their first few rows. Exact machine-readable findings are in `csv_audit.json`; the independent audit narrative is in `csv_audit_findings.md`.

| Check | Normal baseline | Attack derivative | Consequence |
|---|---:|---:|---|
| Data rows | 150,000 | 215,830 | Row count is not a count of independent experiments. |
| Columns | 36 | 35 | `file_source` exists only in the baseline. |
| Timestamp representation | Fractional epoch seconds | Whole epoch seconds | The files cannot support equivalent fine timing analysis. |
| Rows labelled Normal | 150,000 | 110,415 | The file named attacks also contains normal-labelled rows. |
| Rows labelled Coil_Brute_Force | 0 | 105,391 | This is the dominant attack subtype. |
| Rows labelled Length_Manipulation | 0 | 24 | Tiny coverage of a different attack mechanism. |
| Explicit response-injection label | None | None | Response-injection class support is unverified. |

### 3.1 What the absent column breaks

`frame_number` is normally local to a capture. It is not a globally unique identifier. A record such as frame 480 cannot identify its original packet without capture provenance. Likewise, a TCP endpoint tuple and a transaction ID can recur over time and across recordings.

For these derivatives, keep the identity of the CSV they came from as `derivative_source`. Mark the original capture as unknown where it is unknown. Do not name that field `source_pcap` and fill it with the derivative CSV name: those are different facts.

Recover the original capture identity only by a documented join against original records, ideally using precise timestamps, endpoint/sequence information and payload fingerprints. Multiple candidate matches stay ambiguous.

### 3.1a More serious: conflicting labels and a shortcut that explains the labels

After rounding the baseline timestamps to the attack derivative's precision, **96 observations match** on frame number, endpoints, direction, transaction/function fields, lengths, address/count/value fields and all four exported timing/rate/ID-difference features. **48 of those matches have contradictory `is_attack` labels.** Raw packet bytes are unavailable, so this is a very strong exported-record match rather than a byte-level proof of packet identity.

For example, physical CSV line 2880 in the baseline and line 215736 in the attack derivative both describe frame 14924, transaction 57951, FC5, from `185.175.0.3:35564` to `185.175.0.5:502`. Both have inter-arrival time `0.000978`. The baseline timestamp is `1674482417.866921`, the derivative timestamp `1674482418`. The former is labelled Normal; the latter Coil_Brute_Force. The matching response has the same label conflict.

Independently, this rule exactly reproduces every binary label in the attack derivative:

```python
predicted_attack = (function_code in {5, 6}) or (len_discrepancy != 0)
```

Applied descriptively to both supplied files together, it produces **99.828% accuracy and 99.702% F1**, without training a model or analysing context. Its 630 false positives are baseline-labelled normal writes. These are shortcut diagnostics, not detector performance claims. The pattern strongly suggests operation/length-based annotation, but the original extraction code was not supplied, so its implementation cannot be established.

Quarantine these annotation conflicts until original provenance and independent label evidence resolve them. Do not arbitrarily trust one side or let conflicting copies fall into separate splits.

### 3.1b The process-value column needs re-extraction

All 74,687 baseline read requests have `modbus_val` equal to requested quantity. All 74,683 baseline read responses have `modbus_val=0`. In the attack derivative, all 55,745 read responses also have `modbus_val=0`. This does not prove that the devices returned only zeros; it shows that the scalar export does not establish reliable process-value semantics.

The baseline contains six source files contributing exactly 25,000 rows each. The selection method is unknown. Its exported `inter_arrival_time` matches the previous capture-row delta on 149,992 of 149,999 transitions, rather than demonstrating per-device command timing. Her later preprocessing should recompute appropriately scoped history from originals instead of blindly inheriting these derived columns; Stage 1 preserves the necessary ordering and identities only.

### 3.2 What timestamp precision loss means

Whole-second timestamps cannot reconstruct original subsecond request-response delays. Many events share the same timestamp. Sorting equal timestamps by a capture-local frame number is defensible only after the capture and observation order are known.

Do not add random fractions, distribute events evenly within each second, or infer original timestamps from an existing rolling-rate column. Such operations manufacture data. Existing delay and inter-arrival columns also need their own provenance and calculation audit; a plausible-looking decimal does not prove correct pairing.

### 3.3 Why an attack-file name does not define every row's class

A capture containing an attack also contains background traffic, legitimate requests, responses, retransmissions and possibly traffic visible at several sensors. Neither the containing folder nor the attack CSV filename proves that every event is injected.

Keep original label fields as audit metadata. Verify how those labels were produced. `attack_sub_type`, `is_attack` and `attack_category` are targets/annotations and must never be predictor columns.

### 3.4 What these files cannot prove

The label `Coil_Brute_Force` is evidence of how the derivative was annotated. It does not by itself prove which requests were unauthorized, which writes succeeded, or whether an observed response was forged.

The lack of a response-injection label does not prove that no such behavior exists in the original dataset. It means that the supplied derivative does not demonstrate that class. The original PCAPs/logs must settle this before a three-class experiment is claimed.

## 4. What command injection, response injection and context mean

### 4.1 Command injection

An attacker inserts or changes a request that the controller should not have issued or the server should not accept. Examples include an unauthorized write, an inappropriate parameter change, or an operation outside an explicitly documented device/role policy.

A syntactically valid write can be malicious. A write is also a normal Modbus operation. Classifying every write as an attack would mostly teach the model the collection setup.

### 4.2 Response injection

An attacker forges, inserts or changes a response, for example falsifying the data reported to an HMI. The evidence concerns the response itself and its origin or manipulation.

**A real PLC's reply to a malicious command is not automatically response injection.** Nor is a legitimate later read response reporting the process state caused by that command. Those can be consequences of command injection. Preserve a relationship such as `associated_with_command_attack` separately from `response_injection`.

A delayed response is not automatically a forged response. A missing response can reflect capture loss, timeouts, overload or a closed connection. It is an observable anomaly with several possible causes.

### 4.3 Context

Context is the information available around an event: the corresponding request, recent commands to the same device, historical addresses and values, expected source role, supported device functions, and timing relative to prior activity.

Example: an HMI reads an input value, then legitimately writes a coil to close a breaker. The transition read -> write is allowed. Whether it is suspicious depends on the operational policy, requested object, requester and preceding conditions. The proposal's phrase 'unexpected write after read' needs this qualification.

Separate three types of evidence:

| Evidence | Example | Interpretation |
|---|---|---|
| Protocol constraint | A read response has an incompatible byte count. | A structural inconsistency; cause may still require investigation. |
| Configured policy | A client has no permission to write this coil. | A policy violation if the policy is correct and available at deployment. |
| Learned normality | A function transition was rare in training. | Unusual behavior; it does not prove unauthorized behavior. |

The detector can flag deviations. It cannot establish operator authorization solely from a valid packet when no authorization policy or trusted ground truth is available.

## 5. Protocol details the extractor must get right

Classic Modbus/TCP uses an MBAP header and a function-specific PDU. Transaction ID, protocol ID, length and unit ID belong to MBAP. TCP is a byte stream, so a network frame and a Modbus message are different units. Pairing must be connection scoped and aware of repeated transaction IDs. See the [official TCP/IP implementation guide](https://www.modbus.org/file/secure/messagingimplementationguide.pdf).

For implementation, distinguish these cases:

- One ADU spread across several TCP segments.
- Several ADUs within one TCP segment.
- Retransmitted bytes that do not represent a new application command.
- Truncated captures, missing bytes, resets and captures beginning mid-connection.
- The same communication observed by more than one capture interface.

The parser should emit **one record per reconstructed Modbus/TCP ADU (MBAP header + PDU)**, with links back to the relevant source frames and byte ranges. The PDU contains the function and function-specific data. Keep malformed/partial observations with a processing status. A `modbus` display filter alone must not become the entire evidence inventory, because malformed candidate traffic may fail dissection.

### 5.1 Function-specific interpretation

Common functions include 1/2 for bit reads, 3/4 for register reads, 5/6 for single writes and 15/16 for multiple writes. Read replies carry returned data rather than the request's starting address. A successful single-write reply echoes the write; a multiple-write reply acknowledges start/quantity. An exception uses the original function with bit 7 set. Registers are 16-bit quantities; engineering units require a device map. See the [official specifications index](https://www.modbus.org/modbus-specifications) and its [application protocol PDF](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf).

Practical consequences for this project:

- Associate a read reply with its request before assigning returned values to addresses.
- Store address zero as a valid value. Do not use it as a missing-address placeholder.
- Distinguish a request's requested quantity from a response's returned byte count.
- Preserve complete value arrays and raw bytes. A single scalar `modbus_val` is not an adequate general representation.
- For packed bit reads, preserve the requested bit count so padding bits are not treated as extra coils.
- For vendor-specific data, keep raw values until signedness, word order, scaling and object meaning are documented.
- A well-formed exception is not automatically an attack. It can be a normal device reply.
- A repeated transaction ID is not automatically replay. Transaction IDs can be reused; scope and outstanding state matter.
- An unsupported device function is different from an invalid protocol function. Device support needs documentation or an explicitly learned profile.
- Use raw PDU addresses plus an object-space field. A display reference such as 40012 must not silently replace the wire address.
- Classic Modbus/TCP does not carry the Modbus/RTU CRC field. An MSU `CRC rate` feature cannot simply be invented for CIC TCP records.

Check the installed dissector field registry before exporting. In Wireshark, the displayed `modbus.func_code` strips the exception bit; preserve the raw function byte and separate exception flag. Flattening repeated field arrays independently can also mix attributes from different PDUs in one frame. Validate per-PDU structure, not just column names. See the [official dissector source](https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-mbtcp.c).

### 5.2 Match requests and responses using state

Suggested matching identity:

```text
recording_run + observation_view + TCP connection instance + outstanding transaction generation
```

Resolve outstanding transactions using the transaction ID, then validate unit, direction and function relationships as evidence. Do not include unit or function so rigidly in the lookup key that a mismatched reply disappears instead of becoming an inconsistency. Preserve ambiguous candidates without forcing a pairing.

Maintain pending requests in observed order; handle wraparound, reuse and multiple outstanding requests. A port tuple needs a connection instance because the same tuple can be reused after reconnects. If a capture lacks the handshake, state that connection reconstruction is inferred. A `tcp.stream` value from one isolated file is not a global stream ID across all files.

Useful pair statuses include `matched`, `exception_response`, `pending`, `timeout`, `orphan_response`, `ambiguous`, `incomplete_capture` and `malformed`. Store consistency flags separately: function mismatch, unit mismatch, unexpected length and reply-content mismatch. A timed-out request should be reconsidered according to a documented late-response policy, rather than counted twice silently.

Do not match every identical transaction ID in an entire dataset to the first request with that ID. Do not force a match where two candidate requests remain plausible.

## 6. How to rebuild the dataset when she has the 14 GB source

### Stage A: Discover what actually exists

Inventory the supplied CIC root's archives, PCAP/PCAPNG, logs, README files and parsing scripts, and identify existing CIC-derived exports only for diagnosis. Record relative path, size, SHA-256 and detected format. For captures, record start/end time, interfaces, truncation indicators and available connection evidence. Do not assume 14 GB means raw PCAPs or a complete dataset. Verify that it is the intended CIC collection; a mismatch must be reported, not resolved by switching to MSU or another dataset.

The official CIC description documents separate device/bridge capture views, sequential capture chunks and timestamped attack logs. It also warns that logged attacks may not appear in captures. These facts make recording identity and log coverage essential; they do not establish what is present in her copy. See [CIC's dataset description](https://www.unb.ca/cic/datasets/modbus-2023.html).

There is a reason to inspect the compromised-IED recordings: the dataset authors' implementation paper discusses response-side manipulations as well as command-side attacks. That supports searching for response-attack evidence; it does not prove those recordings are in her local copy or justify bulk relabelling. See the authors' [implementation paper, sections 10.2.2-10.2.3](https://doi.org/10.3390/smartcities7010005).

Use the directory layout, capture intervals, file numbering and shared traffic to build a **recording-run manifest**. A numbered file is not automatically an independent experiment. Consecutive chunks from one recording and simultaneous views of it need a common parent identity.

### Stage B: Run a small, representative pilot

Select by recording/scenario coverage, not only the first few thousand rows. Include:

1. A benign recording.
2. A candidate command-attack recording.
3. A candidate response-manipulation recording if one exists.
4. At least one chunk boundary and multi-PDU/reassembly case if available.

Compare decoded PDUs and pairs manually against Wireshark. Check a successful read, successful write, exception and ambiguous case where present. Measure throughput, peak memory and output expansion. Estimate runtime and free disk from the pilot, without claiming that compressed source size predicts output size.

Use streaming extraction and partitioned Parquet where practical; bounded CSV chunks are acceptable if dependencies are unavailable. Do not read all 14 GB into pandas at once. Never modify or overwrite raw files. Save tool versions, commands and checkpoints, and verify that resuming does not append duplicate records.

### Stage C: Extract and preserve enough information

Recommended normalized layers:

| Layer | Minimum content |
|---|---|
| Source manifest | Source hashes, recording-run identity, sensor/interface, chunks, time range and tool versions. |
| ADU events | Stable event identity, source-frame linkage, first-byte/completion times, endpoints, connection instance, direction, MBAP, parsed PDU fields, raw ADU bytes and parse status. |
| Request-response relations | Request/response event IDs, match status, delay availability, mismatch reasons and related capture coverage. |
| Labels | Original annotations, component target, evidence reference, mapping rule, ambiguity and attack-episode identity. |
| Split manifest | Recording/duplicate group, split assignment, rationale, class support and exclusions. |
| Future preprocessing plan | Proposed predictors, decision-time rules, context scope and checks for her to implement later; no computed feature table in Stage 1. |

Keep provenance and labels in the extraction package. A later training pipeline must use an explicit predictor allowlist; Stage 1 only documents that proposed allowlist. Deleting every metadata column from the dataset would make auditing harder.

Represent unavailable fields as null plus a reason, rather than zero. This applies especially to response addresses, unmatched response time, engineering units, missing payload and unknown device permission. Preserve both raw and derived values when a derived interpretation is uncertain.

### Stage D: Align times using evidence

Extract epoch timestamps with their original precision. Keep an integer microsecond/nanosecond representation where supported, or seconds plus an exact fractional part. Record log time parsing, timezone assumptions and any measured offset.

**Do not blindly add three hours to `frame.time_epoch`.** Wireshark distinguishes stored timestamps from local display time. Inspect the actual encoding and validate against log matches. Preserve raw log text, normalize once, and compare target/transaction/time evidence for several events. If offset or clock drift is inferred, document the evidence and residual error. See [Wireshark time zones](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTimezones.html) and [timestamp precision](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTimestamps.html).

Do not silently widen the matching tolerance until every log has a match. Broad tolerances can attach unrelated reused transaction IDs to an attack. Report unmatched logs and packets, ambiguous matches and absent capture intervals.

### Stage E: Establish labels independently of the intended model

Use source logs and documented capture context to identify candidate events. Validate the event, direction, target, transaction identity, payload behavior and capture coverage. Keep the matching rule and evidence reference for each accepted label.

| Source evidence | Component treatment |
|---|---|
| Verified benign supported Modbus event | `normal` |
| Verified injected/modified request | `command_injection` |
| Verified forged/modified reply | `response_injection` |
| Attack name without sufficient event evidence | `unknown_or_ambiguous` |
| Relevant traffic lacking trustworthy annotation | `unlabelled` |
| Verified different attack mechanism | `out_of_scope` |
| Malformed/incomplete observation | Separate processing status; attack label only if independently supported. |

These statuses are not all classifier target classes. They are needed to avoid converting uncertain traffic into false normal or false attack labels.

The fact that a packet travels toward a server or client identifies its role, not its maliciousness. Do not define 'attack' using the same anomaly score the model is being trained to predict; that would mostly evaluate imitation of the labelling rule.

One attack log entry can correspond to multiple observations because of retransmission or several sensors. Resolve these as an evidence graph or canonical observation set before counting independent attack events.

### Stage F: Preserve the ordered source stream for later preprocessing

Maintain the ordered event stream, including necessary benign traffic surrounding attacks, with recording and connection identities. Attach evidence-based target eligibility separately. Do not build history features or windows now. The later manual preprocessing must build history only inside valid scopes and frozen partitions.

Do not extract only attack rows: later calculating 'previous command' on that selection would erase the communication between attacks. Similarly, do not silently remove other attacks and join the remaining events as though no time or behavior intervened. Retain these records with their annotation states and document how she should handle them in later windows; do not calculate those windows now.

If a scope limit is needed, select complete runs or contiguous episodes with an explicit surrounding-context policy. Preserve the prefix and its provenance for later warm-up handling. A row cap of 150,000 is not a scientific sampling plan.

## 7. How to split correctly

There are two different operations: selecting records relevant to component 3, and partitioning data for evaluation. Neither should be implemented as 'take some normal rows and some attack rows, shuffle and save'.

### 7.1 Recommended order

```text
immutable sources
  -> inventory and recording identity
  -> decoding, provenance, label evidence and duplicate/view relationships
  -> group-level train/validation/test assignment
  -> Stage 1 stops: untransformed event partitions + manifests + PREPROCESSING_PLAN.md

Later, performed by her:
  -> causal context construction separately within each frozen partition
  -> training-only fitting of preprocessing and normal profiles
  -> identical model experiments on frozen partitions
```

Deterministic decoding and label auditing can precede partitioning. They are the only data transformations authorized in this handoff, together with evidence annotations and auditable split assignment. Fitted transformations, learned normal profiles and context windows belong to her later preprocessing and must obey the frozen partition boundaries.

### 7.2 Group by the original experiment, not just a filename

Create a grouping graph. Connect observations that belong to the same physical/simulated recording, contiguous chunk series, simultaneous sensor views, request-response dependency or copied source content. Use the resulting parent groups for the main independent-recording evaluation.

Prefer a canonical capture viewpoint for each run when it provides the required visibility. Preserve other viewpoints for audit. If several views are retained, keep them in the same partition and avoid treating each copy as an independent event.

Start with a proposed 70/15/15 allocation of independent groups, but choose the actual assignment from available class-bearing groups. These are approximate proportions, not a requirement to cut groups apart. Report rows, events, attack episodes and independent groups for every class in every partition.

Group-aware splitters help keep related observations together; grouped and temporal evaluation answer different generalization questions. See [scikit-learn's cross-validation guidance](https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-iterators-for-grouped-data).

### 7.3 When the desired split is impossible

If there is one independently recorded response-injection episode, it cannot appear as an independent held-out example in all three partitions. Producing more rows, copying it, or sliding windows over it does not create independent experiments.

Options, reported honestly:

- Use leave-one-recording/episode-out validation when the number of groups permits it.
- Hold a genuinely separate run for final testing and use group-aware cross-validation inside training.
- Use a later contiguous time block from a recording as a separately labelled within-recording forecasting experiment, with purging and boundary handling.
- Reduce the claims and target classes to those supported by this local CIC copy. Do not fetch or substitute MSU or another dataset to fill the gap. Additional CIC recording work would require a separately authorized change of scope.

A later block from the same run estimates future behavior in a seen environment. It does not establish independence from that run or generalization to a new site.

For a temporal alternative, document the maximum planned event/time horizon and response-dependency policy before accepting a scored boundary. Audit pairs across candidate boundaries and keep dependent events together or explicitly exclude them; do not silently discard the cross-boundary evidence. Preserve boundary/warm-up flags and explain the later purge/cold-start rules without computing windows. If the later horizon is not yet fixed, label the temporal split provisional and require revalidation before she uses it for modeling. Independent parent-run groups are preferable when available.

### 7.4 Duplicates and repeated polling

Repeated legitimate polls may have identical semantic values. Do not delete all repeated function/address/value combinations. Distinguish:

- Exact copied sources.
- The same wire event observed at several interfaces.
- TCP retransmission.
- A legitimate new polling command with the same content.

Use source hashes and observation fingerprints with timing, endpoints, TCP identity/sequence and payload evidence. Group or canonicalize proven copies. Report semantic repetition separately from proven duplicated observations.

### 7.5 Acceptance checks for the Stage 1 split

Accept the split package only when its manifest accounts for every source/run/view and event, including unknown or excluded records; exact source hashes remain unchanged; and event identities trace back to the original CIC bytes. Reconcile parsing, label and output counts. Keep original evidence, contradictory labels, missingness and malformed observations visible rather than silently cleaning them away.

No parent recording, contiguous chunk family, simultaneous/copy viewpoint group, proven duplicate observation or request-response dependency may cross scored partitions. Show the grouping graph or equivalent mapping and the evidence for each relation. A different filename, capture interface or `tcp.stream` number is not proof of independence. If a canonical view is selected, justify its coverage and preserve the alternative-view relationship in metadata.

Report independent class-bearing parent groups and attack episodes per partition, alongside event counts. A large number of rows from one rare response-injection episode cannot support a claimed independent three-way evaluation. If the class or split is unsupported, return the supported subset and a precise gap report; do not manufacture labels, split one episode into shuffled rows, or import another dataset. No accuracy or classifier performance is produced in Stage 1.

## 8. Future manual preprocessing: define what is available when the detector decides

**Teaching material for her later work only.** Stage 1 may preserve the timestamps and pair relations needed for this design and describe the contract in `PREPROCESSING_PLAN.md`; it must not compute detector features.

This choice prevents a subtle but serious form of leakage.

**Request-time detector:** decide when the complete request ADU is observable. For a segmented request this is the arrival/reassembly of its final required bytes, not its first segment. Features may use this request and earlier history. Its future response, response delay and future window counts are unavailable.

**Response-time detector:** decide when the response ADU is complete. Its pending request and prior history are available. For a missing response, decide only after the timeout has elapsed and capture coverage supports that conclusion.

**Completed-transaction detector:** decide after response or timeout, with the same availability rule. Its label must describe the transaction explicitly, rather than pretending every reply in an attacked transaction is itself forged.

For the proposal's mixed command/response events, a practical design is one ADU-event target, previous-event context, and pair-derived features only when they are available at that event's decision time. A request has `response_delay = unavailable`; a corresponding response can have a measured delay. Alternatively, define transaction-level targets and change the labelling contract consistently.

Record first-byte time, ADU completion time, `decision_time`, and which events contributed to features. Specify whether latency starts at first byte, completed request, or independently logged attack onset. If retrospective pairing is used for an offline analysis, label the experiment retrospective. Do not describe its scores as request-time real-time detection.

An offline two-pass dissector can expose fields that depend on later packets. Those are useful for auditing and must be filtered by causal availability before training an online detector. See the [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html).

## 9. Future manual preprocessing: features she can implement

**Do not implement or compute these in the current handoff.** Explain them in `PREPROCESSING_PLAN.md` so she can implement, inspect and defend them herself after accepting Stage 1. Use the same target events and frozen splits for all later comparisons.

| Feature group | Examples | Conditions |
|---|---|---|
| Current event | Function, direction, object space, wire address, quantity, byte counts, parse/exception flags | Use function-specific interpretation; retain missingness. |
| Pair relation | Pair status, expected/actual function, reply-content compatibility, elapsed time | Only when observable at the decision time. |
| Command history | Previous K functions, recent write count, read/write transition, distinct recent addresses | Same valid context scope, previous events only. |
| Timing | Time since prior event/write, trailing-window rate, pending-request age | Correct clock precision and grouping; no centered/future windows. |
| Access | Role permission, allowed object range, unusual role behavior | Known policy or training-fitted profile, clearly distinguished. |
| Values | Per-object value delta, recent variation, verified engineering range flag | Compare the same device/unit/object; preserve value arrays and scaling provenance. |
| Quality | History length, incomplete capture, missing-field reason | Audit that these do not simply reveal the extraction source. |

For K = 3, 5 or 10, keep the context horizon a validation choice. Do not use true past attack labels as history features; a live detector does not know them. A recent-write feature is based on observed operations, not on 'previous row was labelled malicious'.

Fit statistical normality profiles only on the intended training subset. Do not automatically update the normal baseline with every attacked event during testing. Freeze the profile or specify a deployable, independently evaluated update policy.

Treat raw IP, absolute timestamp, filename, frame number, raw transaction-counter progression, capture/interface identity and dataset-origin flags as high-risk shortcuts. Keep identity for grouping and attribution. Prefer roles and meaningful relations as predictors. If an identity-based deployment model is evaluated, report it separately and compare against an identity-free model.

The individual proposal's `source-dataset flag` should remain audit metadata. This task uses CIC only; no cross-dataset predictor or validation experiment is authorized. Capture/source identity can still correlate with class and create shortcuts within CIC.

## 10. Future modeling and evaluation: after her preprocessing

**This section is a future research plan, not an instruction to train or evaluate a model now.** Stage 1 produces extraction and split-quality checks only.

### 10.1 Minimum experiments

1. Majority-class and simple protocol/policy baselines.
2. Random Forest using current-event fields only.
3. The same model family and comparable tuning budget using current-event plus context fields.
4. Remove sequence, pairing, timing, access and value-context groups one at a time.
5. Evaluate a version excluding raw IPs, absolute time, file identity and similar shortcuts.

For the isolated-ADU baseline, include only information contained in the current ADU and immediately observable transport metadata. A response's address recovered from its request, expected byte count, match status and response delay are **pair-derived context**, so exclude them from this baseline. An optional intermediate current-transaction model can include pairing but no earlier command history; comparing all three separates the benefit of pairing from the benefit of temporal context. All variants must use the same eligible target cohort or report coverage differences explicitly.

If writes alone separate labels in this derivative, a high Random Forest score would not establish that context helped. Include legitimate writes and difficult valid-looking attack cases in independently supported data. Report whether context improves beyond the strongest simple baseline.

Random Forest has no inherent sequence memory. Windows and pairing explicitly encode history. Use a moderate search suited to the machine, training-only class weights and reproducible seeds. Fit imputation and categorical encoders on training only. Do not resample validation/test data. Do not apply SMOTE to the full dataset or manufacture physically meaningful temporal sequences from synthetic feature rows.

### 10.2 Report these results

- Per-class support, precision, recall and F1; macro F1; full confusion matrix.
- Normal-traffic false-positive rate and false alerts per unit of valid monitored time.
- Precision-recall curves/AUC where both outcomes are supported; multiclass ROC-AUC only when each required class is present.
- Results by held-out recording/scenario, function, object range and attack episode.
- Attack-episode detection rate, misses and time to first supported detection where episode ground truth exists.
- Coverage: parsed, paired, unpaired, ambiguous, unknown and excluded events. A model evaluated on a tiny easy subset must expose that subset.
- End-to-end detection latency, including context/response waiting, separately from model prediction time; throughput and peak memory on stated hardware.
- Group/episode-based uncertainty intervals where there are enough independent groups. Thousands of adjacent packets are not thousands of independent experiments.

An absent class is 'unsupported/not evaluated', not proof of perfect recall. A rejected/ambiguous event is not silently normal. Class probabilities should be described as model probabilities; call them calibrated confidence only after calibration has been checked on appropriate held-out development data.

Review false positives and false negatives by their evidence. Feature importance or SHAP can show what influenced a model, but cannot independently prove an attack mechanism or operator intent.

## 11. Dead ends and how to avoid them

| Dead end | Why it fails | Useful alternative |
|---|---|---|
| Add a guessed `file_source` column | Repairs shape without recovering packet provenance. | Re-extract from originals or mark provenance unknown. |
| Randomly split packet rows | Related events and observations leak across partitions. | Split parent recordings/episodes before windows. |
| Treat each numbered capture as independent | Chunks can continue the same TCP traffic. | Reconstruct parent recording and chunk continuity. |
| Label every packet in attack folders as injected | Background traffic and legitimate replies inherit false labels. | Evidence-linked event labels with unknown states. |
| Map every FDI event to response injection | Attack names and direction do not prove reply forgery. | Verify mechanism and event-specific evidence. |
| Rename length manipulation as response injection | Changes taxonomy without evidence. | Preserve as separate out-of-scope mechanism. |
| Assume all writes/read-to-write transitions are attacks | Legitimate controllers write. | Use role/object/policy and historical context. |
| Pair on transaction ID alone | IDs recur and concurrent conversations collide. | Connection-scoped pending state plus validation. |
| Fill unavailable protocol fields with zero | Turns missingness into valid addresses/values. | Null with explicit applicability/reason. |
| Compare MBAP length directly with a whole TCP payload | Segmentation and coalescing change that relationship. | Validate each reassembled ADU. |
| Derive response delay from rounded timestamps | Original timing is lost. | Recover precise source timing or omit that feature. |
| Use an unmatched reply as proof of injection | Capture gaps and split boundaries can cause it. | Pair status with visibility and uncertainty. |
| Compute history after filtering all normal traffic | Artificially joins distant attacks. | Build context from the retained ordered stream. |
| Use future responses for request-time prediction | The information did not yet exist. | Explicit decision-time contracts. |
| Import MSU, flow summaries or another dataset to fill missing classes | Violates the current CIC-only scope and can introduce incompatible semantics and shortcuts. | Report unsupported classes and finish the supported CIC extraction. |
| Promise 99% accuracy or context improvement | Performance is not known in advance. | A falsifiable comparison with uncertainty. |
| Train first and investigate provenance later | Evaluation cannot validate a corrupted data construction. | Pass extraction, label and split checks first. |

## 12. Specific corrections to the individual proposal

The proposal already contains several sound safeguards: evidence-supported labels, exclusion of ambiguous matches, a static RF comparison, and grouped evaluation. Make the following changes so implementation cannot interpret them inconsistently:

1. **Resolve the primary-dataset contradiction.** The body names CIC as primary, while the appendices still refer to MSU categories as primary and state that primary data lack MBAP identity. The current task uses the original CIC collection only; MSU and all external fallbacks are excluded. Distinguish original CIC captures from the supplied incomplete CIC derivatives. Preserve the proposal PDF as historical reference and document this scope correction separately.
2. **Fix preprocessing order and ownership.** Page 22 lists feature creation before splitting, while page 26 prohibits cross-partition windows. Say explicitly: agent performs decode/audit -> parent recording and viewpoint grouping -> untransformed grouped splits; she later constructs partition-local features and fits transformations on training only. No current feature computation, imputation, encoding, scaling, resampling or normal-profile fitting is authorized.
3. **Define the event and decision time.** Choose ADU-event or transaction-event targets. Explain how request-side and response-side labels and response-dependent features follow that choice.
4. **Make response-injection availability a feasibility gate.** Identify evidence-supported independent episodes, not just an attack called false data injection. If absent, state the limitation and reduce the experiment to supported CIC classes. Do not import separate data or rename another mechanism to fill the class.
5. **Keep source identity as metadata.** Preserve the CIC capture/view/run identities for evidence and grouping, and exclude them from the proposed default predictor allowlist. No external dataset-origin feature is needed in this CIC-only study.
6. **Clarify permission and normality.** The parser cannot infer authorization from function codes. State whether permission comes from an operator policy, device map or training-fitted behavior.
7. **Remove external-validation commitments from this task.** No MSU or other external dataset is permitted for validation, transfer, comparison or fallback. Her later evaluation should state precisely which CIC parent runs/scenarios are held out and what that supports; within-CIC testing must not be described as cross-dataset validation.
8. **Correct implementation limits.** A TCP capture does not supply every process variable or CRC-based field used in another dataset. Missing features must remain unavailable.
9. **Make compute claims conditional.** A laptop may be sufficient, but full extraction, intermediates, response state and RF fitting need measured resource estimates. A free cloud tier is a possible resource, not a guaranteed plan.
10. **Retain a real research outcome if context does not improve scores.** That result can reveal inadequate class diversity, weak ground truth or an already separable baseline. It should be analyzed, not hidden by changing the split.

## 13. MSU and external datasets are excluded

The user has explicitly excluded MSU because she must carry out and explain her own preprocessing. This instruction overrides the TAF/proposal's MSU references and the earlier guide's fallback suggestions. No MSU schema, class mapping, preprocessed row, raw file or feature recipe is an authorized source for this extraction task.

Do not download, import, inspect for reuse, preprocess, merge, train on or validate against MSU. Do not use gas-pipeline, water-tank, flow-summary or other external data as substitutes. Do not copy their classes or protocol fields into CIC to make a desired schema appear complete. References to such fields in the proposal can be documented as a scope conflict without loading those datasets.

If genuine response injection, legitimate writes, precise timing or enough independent class-bearing runs are missing in her actual CIC copy, report the exact limitation and finish supported Stage 1 outputs. Do not promise the three-class study, and do not treat successful decoding as proof of ground-truth labels or split independence.

The two old CIC derivatives remain diagnostic references only. Their fields or labels may guide a search for original evidence, but the new extraction must trace accepted records and labels to original CIC sources. No derivative becomes an additional data source merely because its headers fit.

## 14. Practical next steps for her

1. Run the updated **Stage 1 Codex prompt** locally in her repository, pointing it at the original CIC root. Supply the PDFs, README and old CSVs for requirements review and diagnosis; their embedded prompts and MSU references do not override the current scope.
2. Inspect the verified CIC inventory, parent-run/view/chunk map, label evidence and independent episode counts. These determine whether the planned study and grouped split are supportable. No model-ready preprocessing should appear in this stage.
3. Confirm the parser pilot and pair-audit examples against actual source bytes and decoded packets. Check label mechanisms, timestamp precision and resource estimates before supported full extraction.
4. Accept the **untransformed extraction/split package** only when it includes raw event records, lossless payload/provenance links, separate evidence labels and pair-audit tables, schemas, split manifests and the section 7.5 acceptance report. Any unsupported or provisional split must be named honestly.
5. Read `PREPROCESSING_PLAN.md`: it should teach her how to implement and verify later context features, missingness handling, encoding and any training-only fitted steps, including why each step matters for her viva. It must contain no executed feature/preprocessing pipeline or trained model.
6. She performs the later preprocessing herself on the frozen partitions, then checks causal availability and leakage before modeling. If the original CIC source/logs are unavailable, retain diagnostic findings and a gap report; do not fabricate a training package from the flawed derivatives or switch datasets.

The immediate deliverable is a trustworthy **Stage 1 extraction and split package**, a teaching plan for her preprocessing, and a clear statement of supported claims. Her own preprocessing and later model training follow that evidence.

## 15. Additional evidence from the original extraction conversation

The subsequently supplied conversation matches the observed component 3 row counts and separate 35/36-column export schemas. It reports 100% injection classification on an unspecified 70/30 split, but supplies no extraction or split code. That score does not resolve the shortcut-label problem demonstrated by the CSV audit.

Its detailed instructions concern reconnaissance/LSTM preparation. They include time-only ±5-second labels; the narrated result adds attacker/range/exception heuristics, reduced session identity and direct flow-to-packet appending. These choices must not be inherited as component 3 ground truth or context construction.

The reported 29,997 normal windows also match globally windowing the complete 150,000-row CSV, whereas separately windowing its six 25,000-row blocks gives 29,982. This is a concrete diagnostic for boundary-crossing windows, not proof without the actual sequence output/code. See `ORIGINAL_TRANSCRIPT_REVIEW.md` for the evidence, qualifications and additional recovery checks. The current Stage 1 Codex prompt preserves the necessary boundaries and records these safeguards for her later window construction; it does not compute new windows.

## 16. Can the original README salvage the component 3 split?

The later supplied README describes the original CIC dataset: its topology, capture views, chunking, attack scenarios and attack-log fields. It does not document how this particular 35-column derivative was selected or labelled. It supplies no row-level mapping to command injection or response injection.

**README plus the two CSVs cannot establish a trustworthy normal/command-injection/response-injection ground truth. Partial reuse is possible.** The following tasks have different evidence requirements:

| Task | What is possible with the current evidence? |
|---|---|
| Divide rows by recorded request/response flag | Possible as a provisional direction partition; validate the flag when source evidence exists. |
| Assign device roles from the README IP map | Possible as documented testbed metadata, with scenario/compromise caveats. |
| Decide which requests were injected | Existing flags provide candidates, but contradictions and function-based shortcuts prevent trusting them wholesale. |
| Decide which replies were injected | Not established. Reply direction does not prove forgery/modification. |
| Restore precise timestamps, payloads or actual returned value arrays | Not from the README. Requires an authoritative retained export or source captures. |
| Repair original source identity | Sometimes possible using intermediate exports, row manifests or unique source matches; do not guess. |
| Recover dependable ordered context and independent groups | Only for subsets with enough recovered provenance, timing and continuity evidence. |

Do not create `command_injection` from `is_attack=1 AND is_request=1` and `response_injection` from `is_attack=1 AND is_request=0`. This only partitions the previous annotation by direction. A genuine acknowledgement to a malicious request would become a false response-injection example, and existing request labels already contain conflicts.

The documented external-attacker IP also does not identify every attack. The README explicitly includes compromised IED and HMI scenarios. Conversely, a response from a compromised device is not automatically malicious; scenario identity is useful evidence, not an every-row label.

### A proportionate salvage process

1. Preserve the old CSVs and labels unchanged, with hashes. Add annotation states rather than editing history.
2. Locate the old extraction code, execution logs, file/row manifests, checkpoints, intermediate exports and attack logs. A richer retained export may recover missing columns without decoding the whole source again.
3. Reconcile duplicate/conflicting records. Keep their label truth unresolved until independent evidence supports a decision. The 96 matches to the baseline can provide candidate linkage for that small subset; they do not restore provenance for the rest of the derivative.
4. Correlate surviving rows to documented attack events using scenario, target, transaction and time evidence. Rounded timestamps and missing capture identity mean some matches will remain ambiguous. Logs can support a subset of labels only if event identity and the attack mechanism are sufficiently established.
5. Find the relevant original capture chunks using that evidence. Re-extract the necessary recordings, adjacent chunks and preceding context. Include representative benign traffic and legitimate writes. The full 14 GB need not automatically be decoded again, but selecting only attack packets would destroy context and bias the experiment.
6. Publish the newly verified CIC extraction, diagnostic match relationships, exclusions, class/episode coverage and split groups. Do not append the old derivative rows or their calculated features to the new dataset. A match to an old malformed label is not independent confirmation of a new one.

If only the README and derivatives survive, retain a limited schema/parser prototype and exploratory operation analysis. A class named 'response records with the old attack flag' is an auditable description; naming it 'verified response injection' is unsupported. A supervised detector trained to reproduce the old flags would be a weak-label experiment and cannot validate the proposed ground-truth three-class study.

The README is therefore a navigation aid for recovery. The actual recovery depends on what logs, scripts, intermediate exports and source chunks still exist.

## Sources reviewed

User-provided material:

- `IT4010-TAF-2026 J26-CS-318 (1).pdf`, especially pages 9-10.
- `IT23150270_Rathnayaka K.H..pdf`, especially pages 21-29 and 50-51.
- `normal_traffic_baseline.csv`, all 150,000 data rows.
- `command_response_injection_attacks.csv`, all 215,830 data rows.
- The later supplied `Pasted text.txt`, reviewed as an extraction-conversation transcript; its narrated results are not treated as independently verified execution evidence.
- The subsequently supplied CIC README, used for its documented source structure and to assess whether derivative-specific recovery information is present.

Primary external references, accessed 24 October 2026, are linked at the relevant claims above. The analysis, proposed pipeline, checklist and feasibility rules are recommendations from this review. They are not claims that the unseen original dataset has already passed them.
