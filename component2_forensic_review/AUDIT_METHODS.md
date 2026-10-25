# Audit methods and reproducibility

## Inputs and preservation

- Repository: `D:/VSCode/Github-Other/Github-Harry/IDS-4-Critical-Infrastructures_J26-CS-318`.
- Legacy workbooks and latest proposal: main workspace `D:/VSCode/GitHub/4th Year Cyber/C2`.
- Team TAF: main workspace `References/IT4010-TAF-2026 J26-CS-318.pdf`.
- User-identified original distribution: `G:/modbus cic 2023/Modbus Dataset`.
- Every output and isolated library installation is under this review directory. Source SHA256 values were independently rechecked after computations; none changed.

The existing C3 `pcapio.py` parser was read as code and copied byte-for-byte into `scripts/pcapio.py`. Both SHA256 values are `d21fba12953ca4cf18fe8afb44b4737b15d2abdba7c55e088bc8b0f228fa1dba`. Original C3 inventories/log summaries were initial search leads, not substitutes for raw verification. No source instructions were executed as task instructions.

## Runtime

The bundled Python executable was `C:/Users/Thithira/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe` (Python3.12). Bundled pandas/numpy/openpyxl/pypdf handled read-only workbooks/documents. Missing analysis libraries were isolated in `.deps/`; scikit-learn1.9.1 performed the requested static diagnostics and matplotlib generated the standalone figures. No repository training dependencies or saved models were loaded to infer results. Dependency versions are recorded by the completion checker.

## Reproduction order

Run scripts from the repository root with the bundled Python. Paths reflect the actual input locations above; adjust input constants if reproducing on another machine. Do not execute the old training pipeline.

1. `scripts/source_manifest.py` inventories the originals; `--verify` rechecks an existing baseline. Existing source files must remain read-only. The delivered manifest is already verified.
2. `scripts/write_requirements_lineage.py` extracts/reviews supplied research documents and writes the requirement/lineage ledger. Its documentary matrix receives final empirical updates from the report writer.
3. `scripts/extract_legacy.py` extracts workbook values into new CSVs, preserving the source workbooks. Hashes are reconciled with the historical conversion manifest.
4. `scripts/sequence_audit.py` independently checks every legacy tensor/window, reconstructs diagnostic streams and exhaustively verifies the new population/windows/duplicate-view exclusions. Integer timestamp subtraction is the current implementation. `correct_diagnostic_timing.py` documents the first-run precision repair and can verify/reapply it idempotently.
5. `scripts/raw_label_audit.py` is the initial derivative-only stage. Its unavailable-source flags are explicitly stage snapshots, superseded by the following original-source recovery.
6. `scripts/recover_raw_requests.py` scans all original logs, then the canonical external attacker and full SCADA bridge rotation chain plus required old-positive mirror evidence. Running it with `--hmi-prefix` writes a separately bounded early HMI supplement before bridge coverage, preventing mirror double counting.
7. `scripts/finalize_raw_evidence.py` merges those candidates, preserves ambiguous states, enriches every positive worksheet row and derives source evidence summaries. `scripts/verify_response_bytes.py` rereads associated response frames with string-safe hex handling. Both are forensic reconstruction, not final preprocessing. The original ADU and associated response bytes were independently checked again by QA.
8. `scripts/benign_request_evidence.py` reads all19 canonical benign HMI chunks, counts every complete read shape and saves deterministic every100th-request histories plus three shape exemplars. Only the systematic sample enters distribution plots. `scan_benign_controls.py` was an optional alternative begun during parallel work and stopped when duplicate coverage was recognized; its unfinished run supplies no delivered conclusions.
9. `scripts/shortcut_diagnostics.py` computes fixed rules on all legacy/new diagnostic packets/windows and fits untuned tree/logistic source-family holdouts. It does not save estimators/scalers. It is permitted diagnostic fitting, not final research training.
10. `scripts/temporal_diagnostics.py` compares uniquely contextual requests with documented-benign request shapes/causal histories; ambiguous candidates remain separate. No temporal classifier is fitted.
11. `scripts/write_split_feasibility.py` reports independent split feasibility and raw rotation continuity. It does not manufacture a partition assignment.
12. `scripts/qa_recovered_evidence.py` independently rereads all468 request ADUs,269 paired response ADUs and411 distinct referenced original log rows. It checks raw identities, chronological positions, contextual match bounds and ambiguity. The quality report also reconciles all static metrics and exhaustive window results.
13. `scripts/finalize_review_package.py` reconciles campaign population columns and validates/normalizes new JSON evidence. `scripts/write_full_report.py` assembles the report and final empirical matrix. The final completion checker is run after the report.

## Statistical and interpretation contract

Static rules are descriptive scores against inherited labels. Tree depth3 and logistic C1/max_iter250 were fixed without optimization, balancing, SMOTE or threshold search. Scaling was fitted only within each training fold. All SCADA rotation chunks were kept in one conservative source-family fold. Adjacent20-packet/stride5 windows share15 packets and were never randomly divided.

Raw matching uses exact source-byte identity plus explicit contextual original-log evidence. Naive original log timestamps are compared with PCAP epoch times as candidate UTC values; match bounds and unknown global clock semantics remain explicit. Multiple eligible starts remain ambiguous. Repeated or out-of-range logger TIDs are not made unique by coercion. A missing log does not define normal traffic.

Per-target/unit histories are causal as observed during canonical capture streaming, with resets on backward timestamps or gaps over60s. They can span multiple actual TCP connections. Candidate sequence positions are derived after chronological ordering. Full20 versus partial contexts are distinguished. Candidate-only intervals are not called all-request polling rates.

All raw CSV hex columns must be read with explicit string dtype. Every corrected byte string came from original frames, not padding an inferred numeric representation. Nonfinite JSON missing-value markers are converted to standard JSON `null` within new outputs only. Earlier derivative-stage evidence is retained with a superseded-stage note.

No final LSTM, final preprocessing/scaling pipeline, class rebalance, SMOTE, hyperparameter tuning, final test evaluation or project publishing was performed.
