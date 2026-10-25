# Later model preprocessing: a learning and implementation plan

This stage has **not been executed**. The present package performs protocol extraction, evidence annotation, pairing audit and recording-group partitioning. It does not contain a trained detector, engineered command-history features, imputed or encoded model inputs, normalized values, resampled observations, sequence windows or X/y matrices. Decoding PCAPs is still data processing; the extracted tables are not untouched raw captures.

The researcher should implement, inspect and explain the later steps herself. These notes describe decisions and verification exercises; they do not claim she has already performed or understood them. Use only the original CIC sources represented in the frozen source manifest. Old CSVs remain diagnostic references. No external dataset is a fallback for missing class evidence.

## 1. Decide whether the experiment is supported before creating predictors

Read `FEASIBILITY.md`, `SPLIT_VALIDATION.md`, the label audit and the split manifest. Count independent recording groups containing each accepted target, rather than treating thousands of packets from one episode as independent repetitions. A three-class classifier requires evidence for normal, command_injection and response_injection. A class name in a log or proposal does not establish captured examples. A log-linked malformed reply may support one documented event; it does not demonstrate a broad class of valid-looking forgeries.

If any required class has too few independent groups for training, validation and testing, record the experiment as unsupported. A candidate group assignment preserves lineage without making it a valid class-complete experiment. Do not repair scarcity by random row splitting, inventing labels or copying observations into several partitions. Group cross-validation can be considered only when the held-out folds genuinely contain the classes being evaluated. A chronological split of one continuous run answers a narrower seen-run temporal question and must be named accordingly.

## 2. Freeze the unit of prediction and causal decision time

One extracted application event is one reconstructed Modbus/TCP ADU, containing an MBAP header and its PDU. It is not necessarily one captured Ethernet frame or TCP segment. A frame can contain several ADUs; one ADU can span several segments or capture chunks. Keep the current event identity throughout later transformations.

Choose and document a decision contract before selecting any feature:

| Decision | Information available | Information still unavailable |
|---|---|---|
| Completed request | Request bytes and strictly earlier permitted observations | Its later reply, eventual timeout, later log evidence and future commands |
| Completed response | Current reply and a causally observed matching earlier request | Future replies, commands and final offline connection outcome |
| Explicit timeout | Earlier request and elapsed time up to the configured audit/deployment deadline | Future late reply or final capture-end status |

Offline pair tables can contain later-derived conclusions. Treat them as audit metadata until each candidate field has an availability time. A request-derived read-response address, expected reply size or pair-consistency flag uses context. These are not isolated-current-response baseline fields. A pair marked unanswered at capture end is an offline observation, not a causal timeout predictor.

## 3. Keep genuine zero, missing, inapplicable and unknown distinct

| Case | Extraction meaning | Later handling to justify |
|---|---|---|
| Wire address `0` | Valid zero-based Modbus address | Preserve zero; never convert to missing |
| Register word `0` or coil OFF | Actual decoded data | Preserve the observed zero |
| Read-response address absent on wire | Inapplicable in this PDU | Leave the wire field absent; associated request address belongs in contextual metadata |
| Truncated value bytes | Missing observation | Preserve the parsing reason; do not fill with a fictional process value |
| Vendor word order or engineering unit unknown | Interpretation unknown | Keep unsigned raw register words; do not invent a physical unit or floating-point conversion |
| No matched request | Pairing unresolved or incomplete | Do not manufacture an address or call it response injection |

Concrete diagnostic example: the old baseline's second data row describes FC3 frame 5 in `veth5bbeaa2-normal-13.pcap` but stores `modbus_val=0`. The independently validated local pilot confirms response PDU `03 02 00 09`: function 3, byte count 2 and one raw register word `9`, with a separate TShark comparison. Requested quantity `1` is neither the returned value `9` nor an engineering measurement in an established unit.

Create a per-field applicability/missingness policy before deciding whether to impute. Missingness indicators can later distinguish these situations. For a numerical estimator that requires complete inputs, fit any imputation statistic on training data only, apply it unchanged to validation/test, and retain the indicator. Do not impute raw payload bytes, evidence labels, timestamps, transaction identities or ambiguous pair identities. Quarantining an unsupported observation can be more defensible than constructing a numerical substitute; retain its audit membership.

## 4. Define the isolated-event baseline explicitly

Create a reviewed predictor allowlist using fields available within the current ADU at its decision time. Function, operation/object space, current wire address where applicable, quantity and current decoded value structure are possible research choices. Decide how variable-length register/bit arrays can be represented without dropping values or confusing arrays with a scalar. Preserve the lossless extracted arrays alongside any later derived representation.

Remove targets, original attack names, evidence-match results, source folders, capture/view/run names, event/frame identifiers, split assignment, absolute experiment dates and other source shortcuts from predictor inputs. Transaction IDs and raw endpoint addresses are retained for attribution/pairing but can identify a collection artifact; do not automatically include them as predictive numerical variables. Device-role policy must come from documented deployment knowledge, not a label-derived allowlist.

The future baseline must not receive a request-derived response address, expected response length, pair outcome, inter-event timing or history summary. Those are contextual. Retain annotation and status metadata separately so failures remain inspectable without becoming target shortcuts.

## 5. Build context only after partitions are frozen

Possible later horizons are `K in {3,5,10}` previous events. Define whether a horizon means previous commands, all ADUs, device-pair events or a TCP conversation; each answers a different question. Order events by their causal availability with deterministic source/stream tie-breaking. Never join across recording groups, partitions, unrelated capture views, reconnect generations or declared gaps.

Candidate later experiments include prior function transitions, write counts, distinct-address counts, per-scope inter-arrival intervals and per-object value changes. These are research choices, not features already computed here. A register value change is meaningful only for the same object space, unit/device, address and documented representation. A previous-frame interval from an exported CSV is not automatically a previous-command interval within the intended scope.

State the maximum lookback, time horizon and label horizon in a versioned contract. Exclude or mark insufficient-context warm-up events at each valid boundary. Do not borrow training history as a prefix for validation/test. If temporal blocks are later introduced, include pair-dependency and horizon-aware purges; rerun split checks whenever the horizons change. Contiguous chunks of the same validated stream can share context, while simultaneous mirrored views must not become adjacent events.

Retain out-of-scope/unknown background communications in the ordered history under an explicit policy. Removing them and stitching remaining events together changes adjacency. Either retain them as unlabeled context where allowed or declare a boundary; never silently form windows across the removed interval. Never feed past true attack labels into a future predictor.

## 6. Fit transforms on training only

All data-learned choices must be trained inside the training partition or the training part of each cross-validation fold. This includes imputation, category vocabularies, clipping thresholds, normal-value profiles, feature selection, calibration and any learned permission approximation. Validation can select among predeclared candidates. Keep the final test untouched until the design and parameters are frozen.

Categorical representations should reflect semantics. Function codes are protocol categories; a larger code does not imply a larger operation. Preserve an unknown-category policy for held-out observations. Do not encode source filenames, evidence labels or attack mechanisms into a predictor vocabulary. Scaling is usually unnecessary for a Random Forest; do not add normalization by habit. If a later comparison uses an estimator that needs scaling, fit it only on training data and explain the reason.

Rebalancing is optional later work. First report the observed class and independent-group counts. Class weights or resampling, if scientifically justified, affect training only. Validation/test retain their observed distributions. Synthetic observations or duplicated rows cannot create independent class-bearing groups or repair unsupported labels.

## 7. Distinguish repeated behavior from duplicate observation

Repeated polling with identical PDU bytes can be normal industrial behavior. An identical write issued again later can be another genuine application action. Do not deduplicate by function/address/value or by payload alone.

A TCP retransmission of the same stream bytes is not a new command; extraction accounts for it under connection and byte offsets. Mirrored sensor packets require proved packet/view relationships. When a proven observation is present in more than one view, choose one canonical view or preserve its copy relationship and group containment. Conflicting labels remain quarantined until original evidence resolves them. Do not delete inconvenient disagreement or pick whichever label improves a score.

## 8. Compare representations on an identical eligible cohort

If class/group feasibility eventually passes, compare the same Random Forest family on the same frozen partitions and supported target cohort. Define eligibility before looking at model scores. A contextual warm-up exclusion must not quietly give the contextual model an easier test cohort than the baseline. Report a common eligible-cohort comparison and any broader coverage comparison separately.

Select hyperparameters through grouped/time-aware development validation. Later ablations can remove history, pairing, access and value groups to test their contribution. Report per-class support, confusion matrices, macro metrics, false-positive rate and decision latency. Metrics for an absent class are unavailable, not perfect. If the same test recordings have already been inspected or used for design, disclose that exposure. No accuracy promise follows from a successful parser or a historical perfect score.

## 9. Exercises for the researcher to run and explain

1. Trace a pilot ADU to its source path, frame references and lossless bytes. Explain why frame and application-event counts differ.
2. Demonstrate address zero, a genuine zero-valued register, an inapplicable response address and a truncated value. Explain why one fill value cannot represent all four.
3. Find one matched pair and one incomplete/ambiguous pair. State what is available at request time versus response completion.
4. Reproduce class-bearing group counts from the label/split manifests. Explain why class count and independent class-bearing group count differ.
5. Before creating a window, show its proposed lineage and prove one recording/view/context scope and partition. Explain warm-up and gap behavior.
6. Fit a proposed transformation on a training-only demonstration and verify that held-out rows cannot change its fitted parameters. This is a later exercise, not an executed step in this package.
7. Explain a legitimate repeated poll versus a proven retransmission or mirrored observation.
8. Explain why response direction, a write function, an exception, a malformed length and a log timestamp each need additional evidence before becoming an injection label.

Save the researcher's later implementation, reviewed field contract, transformation provenance and checks separately from this extraction package. Keep the original CIC files unchanged.
