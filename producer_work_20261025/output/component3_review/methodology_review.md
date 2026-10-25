# Component 3 methodology review

This review treats the supplied proposal text as evidence to review, not instructions to execute. It does not assume access to the full 14 GB dataset. Proposal page numbers below refer to the extracted individual proposal unless stated otherwise.

## Overall judgment

The proposed research is feasible as a **conditional, evidence-driven study of context features for injection detection**. Its strongest element is the same-family Random Forest comparison with and without explicit context (pp. 26–29). Its biggest potential dead end is promising three verified classes from CIC before demonstrating that both malicious requests and forged responses actually exist with reliable labels. Dataset extraction and label verification must precede any commitment to that class formulation.

The defensible research question is: *Do causally available command, transaction and process-history features improve detection of evidence-supported Modbus injection events compared with current-event features, under independent capture/run tests?* Neither Random Forest nor an unusual write establishes malicious intent by itself.

## 1. Critical label gate: command injection is not the same as every response to an attack

The official [CIC dataset description](https://www.unb.ca/cic/datasets/modbus-2023.html) lists false data injection and brute-force write among its scenarios, but does not guarantee a separately labelled forged-response class. It documents captures and timestamped attack logs, not ready-made RP3 labels. Therefore the proposal's direction checks are necessary but insufficient.

- An attacker sends an unauthorized FC06/FC16 request: evidence of request-side command manipulation.
- A PLC sends a genuine acknowledgement to that injected request: the acknowledgement is not a forged response merely because it travels server-to-client during an attack.
- An attacker writes a false sensor/register value and the PLC later returns that value truthfully: corrupted process information is not automatically network response injection.
- A fabricated or modified server reply, supported by an attack log/script description and packet evidence, can support response-injection ground truth.

Store `attack_family_original`, `label_target`, `label_granularity`, `label_source`, `label_confidence`, and packet/log references separately. Labels need not all be present in every record. Use explicit unknown/ambiguous status; neither missing a log match nor being inside an attack capture proves normal/malicious.

**Stop condition:** if no verified response-injection examples are found, do not synthesize a third real-data class through direction heuristics or renaming delay-response attacks. Report the coverage gap. Options are a verified request-injection study with a scoped claim, a distinct MSU structured-data study, or independently labelled isolated testbed response scenarios. Synthetic/testbed records must remain distinguishable from public-dataset observations.

## 2. Define exactly what a model row means

The abstract and architecture refer to reconstructed request-response events, while the feature list sometimes says current command/response. These are different units. Choose and document one:

1. **PDU event:** one request or response, labelled on that PDU. A response may use its matched request as prior context.
2. **Transaction event:** a request plus its response/timeout, labelled by attack location within that transaction. If both sides can be malicious, a single exclusive command-versus-response label may be inadequate; preserve both side-specific flags.

A transaction that contains an injected command may be labelled a command-injection transaction, while its genuine response remains non-forged at PDU level. Mixing those conventions corrupts both training labels and performance interpretation.

Keep PDU and transaction tables and stable provenance IDs even if only one representation is used for training. This also prevents accidentally duplicating one malicious transaction as two independent positive examples.

## 3. Protocol context must be implemented rather than assumed

The [official TCP implementation guide](https://www.modbus.org/file/secure/messagingimplementationguide.pdf) associates a response with its request through transaction context and allows concurrent pending requests on one connection. Pairing by next row or transaction ID alone is unsafe. Use a connection identity including endpoint ports and connection generation, unit ID as relevant, transaction ID, compatible function and request/response direction. Retain ambiguous, orphan, duplicate and incomplete status explicitly.

Do not assume one TCP packet equals one Modbus message. Reassemble TCP payload, parse all ADUs, and preserve ADU position within frame/stream. Chunk boundaries can split a session and a pending request. A function-code field absent from a packet can mean reassembly state or incomplete parsing, not a legitimate zero-valued function.

Pair checks need function-specific semantics. A normal exception response changes the function code by setting its exception bit; literal function-code equality incorrectly flags it. Read responses often require the paired request to recover register addresses. Multi-register reads/writes require address-to-value mapping; a single flattened value cannot represent the entire operation reliably. Store raw 16-bit values and decode multi-register numeric types only when an authenticated schema/register map defines signedness, scaling, word order and meaning.

The [official Modbus specifications index](https://www.modbus.org/modbus-specifications) separates the application protocol from transport guidance. Use these sources for message validity. Operational authorization and process safety are additional plant-specific facts, not rules provided by the base Modbus protocol.

## 4. Remove false protocol rules and unverifiable policy claims

The team proposal's example of an unexpected write after read is only a possible learned anomaly. Modbus does not prohibit read→write ordering. Normal control cycles routinely read a value and then adjust a setpoint or actuator. Exception replies, retries, repeated polling, reused transaction IDs after completion, and multiple HMI clients can also be legitimate.

Replace universal `illegal_transition` claims with `transition_surprisal` or train-baseline transition counts, evaluated on held-out operation. Use separate configured policy flags only where an independently supplied permission map exists. A register absent from a benign training sample is **previously unseen**, not proven unauthorized. Likewise, an FC not observed during training may be supported maintenance behavior.

Role inference must not label the known dataset attacker IP as a forbidden actor and then claim broad behavioral learning. Keep endpoint identities as metadata in the core comparison, use policy information only when available at deployment, and test robustness when identifiers are removed or unseen endpoints appear.

Network traffic alone cannot always distinguish a legitimate command from a malicious command that has identical observable fields, timing and process context. A compromised authorized HMI can issue plausible actions. Scope the result to observable evidence; do not claim guaranteed detection of all valid-looking manipulation or proof of physical safety.

## 5. Causality and latency are part of the feature contract

For each feature record the earliest moment it is observable. A request-time alert cannot use its future response, later readback, the rest of the capture, future rolling values, or a final timeout outcome. A completed-transaction detector can use its response but its decision timestamp is then response arrival or timeout expiry.

Use strictly prior history for lag/window features. Compare values only for the same device, unit, object type and register (or correctly decoded process variable); a delta between unrelated rows is meaningless. Missing previous values are unknown, not zero. Define warm-up behavior, state reset rules, maximum state size, timeout policy, and state expiration after long gaps or reconnects.

Report parser/context/inference cost and end-to-end detection delay separately. A one-millisecond model call does not imply one-millisecond detection if the pipeline waits five seconds for a reply. If future outcomes are included for an offline analysis, label that experiment explicitly and exclude it from online performance claims.

## 6. Split whole independent runs before contextual windows

The narrative on p. 22 puts feature creation before splitting, while p. 26 promises no context across partitions. Rewrite the processing order unambiguously: inventory → identify independent capture/run groups and duplicated views → assign train/validation/test → construct causal history independently inside each partition → fit all learned transforms on training only.

The CIC documentation describes sequential 100 MB capture chunks and both device-interface and bridge observations. These are not automatically independent experiments. Group all chunks from the same continuous acquisition/run and all mirrored views of that run together; otherwise the same transaction or adjacent context can appear in train and test. Prefer one justified canonical vantage point where possible. Deduplication must distinguish mirrored observations and TCP retransmissions from legitimate repeated polling.

Do not shuffle individual rows or sample isolated records before sequence construction. Filtering to attack rows before context also destroys the normal commands surrounding attacks. Preserve the chronological event stream, attach labels, build context, and only then select an explicitly defined supervised cohort within each partition. If unrelated attack families remain in history, preserve their status and report their presence; do not quietly call them normal.

If a time split within one continuous run is the only option, disclose its weaker independence and enforce an appropriate boundary embargo/state reset so no example uses the other partition's feature history. Whole-run holdout remains the stronger primary result.

Before selecting 70/15/15 or another ratio, count **independent groups per class**. One response-injection run cannot populate three independent partitions. Group-stratified split software cannot fix that absence. Report infeasibility, use an honest leave-one-run-out design where supported, acquire additional runs, or narrow the claim. Never break groups to force class balance. Resampling is training only and cannot create independent experimental coverage.

## 7. Evaluate the claim fairly

Use identical eligible evaluation events and identical group partitions across experiments. Different missing-value drops or completion filters can make apparent context improvements a population change. Compare at the same decision time and make the baseline explicit:

- Current PDU/static RF.
- Current completed transaction RF, if pair features are included in the proposed representation.
- Current representation plus prior sequence/process/access context RF.

This distinguishes the value of request-response reconstruction from the value of prior temporal context. Use the same search budget and training-only grouped validation; the same fixed RF configuration is a useful controlled comparison, with separately tuned models as a sensitivity check. Fit imputers, categorical encoders, permission/normality profiles, thresholds and probability calibration within training folds.

Retain the planned feature-group ablations, including timing and identity/missingness groups. Keep `source_dataset` out of the core model: p. 26 proposes a dataset flag, which can become a shortcut whenever dataset and class coverage correlate. Missingness can similarly identify data provenance. If retained experimentally, document the intended deployment use and test its removal.

Report macro F1, per-class precision/recall/support, normal false-positive rate, attack false-negative rate, confusion matrices, and precision-recall AUC where supported. Add false alerts per hour and attack-episode detection delay using actual capture duration. Use independent-run bootstrap or per-run reporting rather than treating correlated sliding-window rows as independent confidence-interval samples. A missing test class makes its recall/AUC unmeasurable, not zero or successful detection.

Evaluate simple deterministic protocol/policy checks as a useful baseline alongside RF. Feature attribution describes model dependence, not verified attack root cause. RF vote proportions are not automatically calibrated probabilities; evaluate calibration and allow an `insufficient_evidence`/unsupported profile status in production integration.

## 8. MSU transfer is a separate compatibility test

The [maintainer's repository](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets) distinguishes older gas/water datasets from New Gas Pipeline and explicitly warns of unrealistic shortcuts in the older datasets. Record the exact downloaded version and schema; a legacy flaw warning should neither be ignored nor automatically attributed to every newer release.

MSU structured gas-pipeline variables are not automatically equivalent to CIC substation values. Verify whether an `address` is a slave/device address or register offset, whether `time` is elapsed/interarrival/absolute time, what its command-response flag means, and what values/CRC fields encode. Native Modbus/TCP has no serial RTU CRC field; manufacturing a TCP CRC equivalent would be invalid.

No-retraining cross-dataset evaluation requires both shared column names **and shared semantics/units/event granularity**, plus supported source/target classes. Define a frozen common-core model trained on the primary data, then test that exact representation externally. Separate this from independent within-MSU training/testing, which assesses a method in another dataset but is not transfer of the CIC model. If the common core is too weak or no meaningful mapping exists, say so and avoid a false generalization claim.

## 9. Concrete proposal corrections

1. p. 22: replace “create contextual features; and split” with partition-before-window generation.
2. pp. 4, 21–24: make the CIC three-class objective conditional on verified response-side coverage, with a defined coverage audit deliverable.
3. p. 26: move source-dataset identity to metadata and add feature availability/causality tables.
4. pp. 25–28: define PDU versus transaction row, exact baseline eligibility, pairing, timeout, response-exception handling, register-aware value deltas, and completion time.
5. p. 50 appendix: its “primary labels” are the MSU category names, while the body says CIC is primary. Rewrite as dataset-specific label maps.
6. p. 51 decision log: “Primary data lacks complete MBAP pairing fields” fits the MSU structured profile, not the stated CIC PCAP primary dataset. Reconcile and mark schema checks as verified only after inspection.
7. p. 15 contains drafting residue (“This version is enough…”). Remove it; it is not research content or an instruction to this reviewer.
8. Team proposal p. 6 commits to primary controlled testbed generation; individual p. 22 calls testbed gap-filling optional. Align commitments and make it mandatory if needed to support the promised class coverage.
9. Tighten novelty claims: “very few works” and prior studies' supposed omissions need a documented literature comparison. Claim an evaluated representation and reproducible experiment, not first-ever context-aware Modbus analysis.

## Go/no-go evidence before training

- Source inventory and provenance; verified dataset version and independent run grouping.
- Parser/schema coverage and manually traced request/response examples.
- Evidence-supported label mapping, ambiguous/unmatched counts, and independent groups per class.
- Explicit decision on whether response-injection ground truth exists.
- Saved split manifest with zero shared runs/duplicated observations between partitions.
- Feature dictionary including source, semantics, availability time, missingness and leakage restrictions.
- A small end-to-end extraction output reviewed before processing the full collection.

If any item fails, the output should be a concrete limitation/fix report. Training a high-scoring model on guessed labels or reordered fragments would hide the failure rather than solve it.
