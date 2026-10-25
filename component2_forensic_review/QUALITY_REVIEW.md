# Independent quality review

This review checks the new forensic analysis, not the inherited model claims. It does not certify final training readiness or independent campaigns. Source files were read only. No final LSTM or final preprocessing was fitted.

## Checks completed

| Area | Independent check | Result |
|---|---|---|
| Legacy sequences | All 175,800 original feature tensors and recovered memberships compared with the packet worksheet | Reproduced the failure; see `legacy_sequence_audit.json` |
| New diagnostic windows | All 119,237 windows, all original worksheet IDs, all duplicate-view exclusions | Mechanical checks pass; source labels, true TCP boundaries and campaign independence remain conditional |
| Static rules/models | Recomputed confusion-matrix totals and precision/recall/F1/FPR from all 56 output rows; reconciled all 24 fold rows with pooled outputs | No arithmetic/count errors; see `evidence/quality_shortcut_checks.json` |
| Grouped diagnostic protocol | Inspected source-family assignment, packet/window group assertions, feature indices and scaler placement | No random row/window split. Training-only diagnostic scaling. No estimator exports or tuning. `without_size_length` correctly removes length and size while preserving function indicators, address and quantity |
| Request-source evidence | Independently reread all 468 candidate request ADUs directly from original PCAP record offsets | Source bytes, timestamps, captured lengths, endpoints, TID/unit/function/address/quantity and TCP-sequence offsets match |
| Response-source evidence | Independently reread all 269 available paired response ADUs from original PCAP offsets after the byte repair below | Source bytes and candidate pair endpoint/TID/unit/base-function/delta fields match. Pair attribution uniqueness is not established |
| Raw candidate identity/order | Checked raw ADU keys, TCP-generation/sequence/payload keys, candidate IDs, chronological order and derived zero-based positions | No duplicates; ordering/position checks pass across four logical candidate streams |
| Log-reference/state consistency | Checked 788 original-log links with delimiter-aware row identities, destination/range and declared 25 ms bounds | All links satisfy the stated contextual rule. There are 411 distinct original row references. The table preserves 320 ambiguous candidates and 148 supported-contextual candidates; no exact clock claim |
| Causal temporal code | Reviewed histories, reset logic and sampling | Histories are updated after feature calculation. They contain preceding parsed read requests, not future events. Benign systematic sampling excludes extra shape exemplars from distribution estimates |
| Final benign/temporal outputs | Reconciled census/per-file totals, systematic sample ordinals, context bounds and all 60 distribution rows' counts/medians | All checks pass: 2,042,925 reads, 20,458 saved contexts, 20,428 systematic contexts, 20,427 full-20 systematic contexts |
| Bounded benign source-byte check | Independently reread one mid-record systematic request from each of the 19 canonical benign files | All 19 request ADUs, timestamps and read/quantity roles agree with original source bytes |
| Standalone figures | Visually inspected both exported figures | Titles, axes, labels, numerical coverage and source/confounding caveat are legible and consistent |

The bounded raw-source check is reproducible with `scripts/qa_recovered_evidence.py`; its exact candidate-file hash, counts and limitations are in `evidence/quality_raw_evidence_checks.json`. It validates record-offset bytes without recounting every frame ordinal or rescanning every preceding request.

## Defects found and fixes coordinated

1. **Exact response hex was coerced into numbers during a pandas round trip.** For example, leading-zero byte strings became numeric text. The raw-evidence agent restored all 269 response byte strings by rereading original source frames, added response record/payload offsets, and used explicit string dtypes. The independent source-byte check above passed after repair. Hex columns must always be read as strings; padding corrupted numeric text is not an acceptable repair.

2. **XLSX source-row locators contain internal semicolons.** A reference such as `...xlsx#sheet=To IED1A;row=2` cannot be split on every semicolon to count log events. The independent check separates only semicolons introducing another `attack/` path and obtains 411 distinct original row references. The raw-evidence writer now provides `attack_log_references_json`, and its summary reports 411. The split writer must consume that safe reference list or equivalent delimiter-aware parsing; an earlier value of 410 was flagged for correction.

3. **Some raw summary breakdowns were stale after merging the early HMI prefix.** The finalized table has 468 candidates and 269 response observations, with quantity 2,000 and quantity 125 each occurring 218 times, and address 1 occurring 459 times. Earlier summary values of 263 responses, 212 per main quantity and 447 address-1 observations describe the pre-merge table. The raw-evidence agent regenerated these breakdowns from the finalized table; the corrected summary now agrees.

4. **Epoch-nanosecond subtraction was rounded through floating point in the historical groupby-diff expression.** In this runtime, 579,064 gaps differ from integer subtraction by more than 1 ns, with maximum error about 256 ns. New diagnostic `dt_s` now subtracts int64 timestamps before conversion to seconds and passes a CSV-reload check with zero differences above 1 ns. This small numerical error does not explain the large legacy ordering failure.

5. **Temporal comparisons initially mixed full and partial histories.** The temporal writer was updated to separate full-20 and partial contexts and to keep ambiguous recon candidates outside the main supported-contextual comparison. This avoids interpreting unequal startup context lengths or ambiguous attribution as attack evidence.

## Important interpretation limits

- Diagnostic static models use inherited labels. A family-held-out model may fail to recognize a signature absent from its training family even when a fixed rule describes almost all positive rows in the complete population. Poor cross-family diagnostic scores do not establish that temporal context is necessary.
- Zero-denominator precision, recall and F1 use the script's zero convention. In particular, a benign-only held-out family has no attack recall to estimate. Pooled metrics and confusion counts must retain that context.
- Orderless window aggregates contain the whole 20-message window. Causal detection is anchored at its final message. Results cannot be presented as detecting an earlier attack message before the rest of that window arrived.
- Raw histories are keyed by actor, target and unit. They measure per-target address/timing context and do not by themselves test cross-target enumeration or unit transitions. A count of distinct targets is not evidence of temporal device scanning.
- Prior interval mean/CV characterize timing level/variability. They do not, by themselves, establish sustained polling-rate drift. That proposal dimension remains unestablished by the present descriptive evidence.
- `sequence_position_after_ordering` counts the recovered candidate subsequence. It is derived metadata, not the position of every network request, and is not a model predictor. Candidate-to-candidate gaps are not ordinary polling intervals.
- The global logger clock contract remains unverified. Target/range/time correspondence is contextual. A single eligible log row is not proof of a unique physical attack event or a one-to-one mapping from log rows to messages.
- A reverse-endpoint/TID/unit/function response match within five seconds is a candidate association. The current dictionary matching does not prove connection-generation uniqueness or exclude every repeated-TID ambiguity.
- The 8,731 raw positive-message observations map to 8,687 distinct legacy packet rows. Exactly two legacy rows, 678049 and 678050, each contain 23 identical ADUs at different TCP payload offsets. The extra 44 observations are packet-to-message expansion, not duplicated network packets or independent experiments.
- No raw/source/session/campaign independence claim follows from a valid byte match. The final scientific experiment still needs valid target labels, matched legitimate traffic, and defensible independent run boundaries.

## Final consistency review

The completed full benign census and temporal outputs pass the bounded checks in `evidence/quality_temporal_checks.json`, reproducible with `scripts/qa_temporal_outputs.py`. The final report's Category C judgment is explicitly scoped to the exact proposed confirmatory experiment supported by this reconstruction. It does not assert that all CIC bytes have been exhausted or that no additional reconnaissance exists. The conclusion that temporal novelty remains unestablished is consistent with the complete canonical benign read census having no matched current-message quantities for the 148 supported-contextual requests, and with unsupported independent train/validation/test construction.

No final training-readiness claim follows from these QA passes. The checks establish internal consistency and direct source correspondence within their stated bounds. The corrected split reference count and the documented ambiguity/session/campaign limitations must be retained in the final evidence package.
