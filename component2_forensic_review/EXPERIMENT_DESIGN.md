# Evidence required for a defensible Component 2 experiment

This is a proposed research design, not final preprocessing, training or a claim that a valid split already exists. The latest proposal remains the authority for the scientific question; the current user request controls execution. No random row/window split or final LSTM fitting is performed in this review.

## Exact question and target

The scientific question is whether preceding Modbus request context helps identify reconnaissance beyond the current request's protocol fields. The data must first establish reconnaissance initiating actions. Exceptions, short responses, log proximity and unusual quantities are separate evidence attributes. They are not interchangeable definitions of reconnaissance.

Keep two distinct evaluations separate. The historical-label diagnostic asks how easily the supplied target is reproduced, including its short-response signature. The eventual research experiment asks whether evidence-supported reconnaissance requests can be distinguished from legitimate polling with overlapping current-request shapes. Static rules on the historical target are forensic diagnostics and cannot validate the latter experiment.

For the eventual causal experiment, prespecify a target ending request `t` and a context of the last 20 ordered requests up to and including `t`, within a verified stream/run and inactivity policy. The target is the independently evidenced status of `t`. This permits a direct current-request versus preceding-context comparison without using future packets. If the final research protocol instead chooses an any-positive window target, use exactly that target and window set for every model, aggregate current-packet scores by maximum, and state that the task detects whether any initiating action occurred during the window. The preliminary any-positive implementation is not proof that this is the only valid scientific target. Choose and freeze one target before fitting; do not switch after seeing performance.

The report must distinguish initial attack time, first eligible context time, alert time and inference compute time. A seconds-per-window inference requirement does not erase the delay to accumulate a 20-request window.

## Evidence and dependency hierarchy

1. A capture frame is one recorded observation. A TCP segment may contain part of one message or several messages. TCP retransmissions and interface mirrors must not become additional target events.
2. A decoded request is an initiating message with bytes and frame/message identity. Its paired response is dependent on that request.
3. An original log row is an attack-tool assertion. Completion rows, duplicate spreadsheet copies and repeated status rows do not increase independent initiator counts. A `TransactionID` outside 0..65535 is not a wire transaction identifier.
4. Several requests can belong to one probing invocation or attack episode. Repeated requests, code probes and all responses from that episode stay together.
5. Sequential 100 MB PCAP chunks are pieces of a recording, according to the original CIC README. All rotations of a continuous recording stay together. NIC and Docker bridge views of the same traffic stay together.
6. A connection generation is derived from endpoints, ports, flags and sequence evidence. Starting a new TCP connection does not establish a new attack campaign.
7. A date, static endpoint/unit tuple, `capture_group` name or thousands of overlapping windows do not establish an independent run. Independent runs need acquisition/experiment evidence for separate orchestration, initialization and no shared traffic/episode dependency.

Use a dependency graph, with frame/message observations joined by mirror identity, retransmission, TCP generation, request/response pairing, overlapping windows, shared attack episode and capture-rotation continuity. Assign all connected dependencies to the same partition. Scenario families remain conservative grouping bounds until source evidence justifies finer independent units. An unknown relationship is not permission to split.

## Current raw reconstruction method and its limits

The new raw audit uses a single canonical external-attacker view and the complete selected substation-wide rotation family. A non-overlapping HMI prefix may recover earlier traffic not covered by the bridge; its overlap cutoff must remain explicit and it remains part of the same recording dependency. Other interface views are used to reconcile old positives; they must never add campaigns. All original CSV logs and available workbook log variants are inspected, with duplicate source references retained.

`recover_raw_requests.py` recovers complete Modbus ADUs already contained in a single captured TCP segment; it reports incomplete/unframed payloads and does not invent reassembled bytes. Log matching is contextual within a declared 25 ms candidate band, matching target where supplied and range/quantity where available. Logger timezone and clock contract remain unverified, so this rule must not silently promote associations to `supported_exact`. Report signed deltas and ambiguous match counts. Exact attribution would additionally require an independently corroborated clock and unique on-wire transaction correspondence. Request/response association requires reversed TCP endpoints, matching transaction/unit/base function, a nonnegative bounded delay and no unresolved reused-TID ambiguity. Observed SYN counts can start mid-connection and are not guaranteed globally complete generation IDs.

The source-log inventory contains 1453 recon rows across CSV/workbook variants and 643 deduplicated valid start signatures. Those are source assertions and tool-invocation signatures. Neither number is an independent-campaign count. Source evidence reviewed in this audit does not document separately initialized acquisitions for every day or invocation, so the independently verified campaign count is unknown, rather than zero or the number of scenario-family names.

The 25 ms band is a forensic candidate-recovery rule, not a supervised feature, class-expansion instruction or optimized threshold. Check narrower/wider bands as an uncertainty analysis before freezing targets. This must not be used to label every other packet in an attack recording normal: same-stream controls with no matching nearby recon start remain unlabeled lookalikes until independently supported by benign acquisition or a valid experiment ledger.

The counts and current split status are machine-readable in `split_feasibility.json`. `recon_request_candidates.csv` is a candidate evidence table, not an automatically final training set.

The completed recovery table contains 468 candidate requests: 148 `supported_contextual` and 320 `ambiguous`. Ambiguous rows are retained as evidence and are not positive training labels. There are 436 candidate rows in the compromised-SCADA recording family (including 12 in the non-overlapping HMI prefix) and 32 in the external recording family. These are candidate row counts, not 468 attacks or independent experiments. Exact logger-clock attribution remains unestablished.

An independent first/last-frame check finds 16 consecutive boundaries from `substation-1.pcap` through `substation-17.pcap` separated by only 16 to 19971 microseconds. The old G04/sub1, G05/sub2, G06/sub4, G07/sub10 and G08/sub14 groups therefore lie in one continuous capture rotation chain. This provides direct source evidence against their asserted independence. `substation-0.pcap` is later than substation17 in source time, after an 80141.384049-second gap, so filename order is not capture chronology. See `evidence/rotation_continuity_independent_check.csv`; neither the gap nor the date change alone proves a new initialized experiment.

## Split requirements

The desired experiment uses class-complete fit, validation and untouched test partitions at the highest defensible dependency unit. Each must contain supported reconnaissance targets and independently supported normal targets from separate campaigns, with sufficient variation to support the intended scope. Having three unit names is a necessary combinatorial condition, not an adequate sample-size argument.

- Freeze the campaign graph and a manifest of target events, excluded uncertain events and partition ownership before model fitting. Separate the rationale for independence from class balancing.
- Hold entire mirror/rotation/episode dependencies in one partition, then construct causal windows within their partition. No shared packet, retransmission, future context, normalization fit or episode may cross partitions.
- Distinct scenario families may permit an exploratory domain-held-out comparison if both labels are valid, but two positive recording families cannot provide three class-complete independent train/validation/test partitions. Do not call multiple days or chunks independent just to create more folds.
- Fit categorical vocabularies, imputation/scaling and any feature calibration on fit groups only. Select operating threshold/early stopping on validation only. Leave the test untouched until the prespecified comparison. Unknown categories and empty context have declared behavior.
- If campaign independence or normal target truth cannot be established, the confirmatory split is `UNSUPPORTED`. Candidate future partitions must not be emitted as an executable final split.
- Report campaign-level uncertainty and per-campaign results. Overlapping windows and repeated invocations are dependent observations; standard errors based on window count alone exaggerate certainty.

## Matched comparison after validity is resolved

| Representation | Information available | Role |
|---|---|---|
| A: static current request | Decoded current request function, address, quantity/value, unit, request direction and legitimate deployment length/size fields; exclude identity/ground-truth metadata | Tests whether the current message solves the same target |
| B1: proposal flattened RF | Same last-20 protocol features flattened by position, with no recurrent model | Exact proposal p14 comparison; retains positional information and must not be called order-invariant |
| B2: order-invariant summaries | Means/counts/ranges/fractions over the same requests, without address-step transitions or interval order | Separates a bag of requests from sequence modelling |
| B3: simple temporal statistics | Prespecified address progression/uniqueness, intervals/drift and rate statistics over the same causal context | Checks whether an LSTM adds value beyond simple behavioral engineering |
| Proposed LSTM | Same ordered 20-request context and feature availability, with causal timing if prespecified | Tests sequence representation after target/split validity |
| Optional deterministic scan rule | Prespecified address progression/coverage/rate rule on the same context | Interpretable mechanism diagnostic |

All representations predict the exact same ending events or frozen windows, use the same held-out campaigns and report TP/FP/TN/FN, precision, recall, F1, FPR and valid AUCs. Missing context must not silently remove only difficult attack examples from one model. A claimed LSTM advantage over a weak linear model while a small tree solves the task is not sufficient evidence of temporal necessity.

Do not delete length, size, function codes or response evidence because they are predictive. Retain all source evidence. Use primary deployable-feature results and a justified research ablation that asks whether preceding context still contributes beyond current-request shape. Response-only and request-plus-response experiments answer different latency and mechanism questions and must be explicitly named.

## Readiness gate

Before final fitting, require a source-backed target definition, audited request/response parsing, campaign ownership, verified normal lookalikes and sufficient independent unit coverage. A candidate-rich CIC reconstruction can be useful while this gate remains closed. No performance objective should be met by relabeling ambiguity, pretending rotations are runs, or adjusting controls after inspecting test outcomes.
