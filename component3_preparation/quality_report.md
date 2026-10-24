# Stage1 quality results

All selected extraction frame/byte reconciliation and record-lineage invariants passed: **True**. Raw source SHA256 preservation passed: **True**. This confirms the measured extraction checks, not universal ground-truth correctness.

Decoded 3,767,894 ADUs plus 393 explicitly partial/nonframed candidates from 20,923,685 frames in21 selected original captures. Raw arrays, bytes, precise times and source offsets remain present. Original log rows: 1,536,126. Accepted targets: {'normal': 1404306, 'command_injection': 100, 'response_injection': 54}. See `output/quality_report.json` for every view's parse status, function/direction, class joints, null/wire-zero counts, non-Modbus/unsupported reasons, connection/retransmission/gap accounting, cross-chunk records and emitted-time reversals.

| Accepted target | Malformed PDU | Parser ok | Exception | Other parse outcomes |
|---|---:|---:|---:|---:|
| command_injection | 98 | 2 | 0 | 0 |
| response_injection | 53 | 1 | 0 | 0 |

These are current-PDU parser outcomes within the accepted evidence cohort, not independent attack repetitions. An `ok` PDU is structurally accepted under this decoder; it does not establish process plausibility, authorization or a correct request-relative value. A concentration of malformed targets creates a protocol-shape shortcut risk. This cohort does not support a broad claim that valid-looking injections require context-aware machine learning or that contextual features improve detection. Any later comparison must disclose this composition and the scarce structurally accepted injection examples.

`output/label_report.json`, per-view `log_matches.parquet` and global `log_signatures.parquet` preserve accepted/candidate/ambiguous/out-of-scope evidence and residuals; unsupported classes remain unavailable. `output/pair_report.json` preserves every relation status and sensitivity count. `output/duplicate_containment.json` distinguishes byte copies at coincident times from legitimate recurring content. Original sources and suppressed observations remain available; unsupported IP/format cases are counted, not declared successfully reconstructed.

Extraction source/config/parser contracts and output digests support deterministic resume. Event IDs and table publication are whole-chain replacements, never row appends. Offline fixtures cover parser, pairing, original-log version/clock ambiguity, boundary membership and checkpoint integrity. Actual test invocation/outcome is recorded in `output/execution_record.json`.

No engineered context/lag/rolling/value-delta/rate features, model windows/matrices, imputation, encoding, scaling, normalization, balancing, fitted normal profiles or classifier training were executed. `PREPROCESSING_PLAN.md` is a separate later learning guide.
