# Component 2 forensic review

Start with [FULL_FINDINGS_REPORT.md](FULL_FINDINGS_REPORT.md). The current inherited labels and evaluation groups are not ready for final LSTM training. The report ends with the requested verdict and one next action.

## Research and interpretation

| File | Purpose |
| --- | --- |
| REQUIREMENTS_MATRIX.md / requirements_matrix.csv | Proposal/TAF requirements, exact page locators and audit evidence |
| DATA_LINEAGE.md | Canonical evidence versus derived metadata and transformation ledger |
| DOCUMENT_REVIEW.md | Unsupported historical claims and documentary differences |
| LABEL_FORENSICS.md / RAW_SOURCE_EVIDENCE.md | Original PCAP/log reconstruction, label states and actual mechanisms |
| TEMPORAL_SIGNAL_REPORT.md | Request histories, observable differences and normal lookalike limitations |
| SESSION_IDENTIFIER_REPORT.md / SEQUENCE_FINDINGS.md | Identifier semantics and independent sequence findings |
| EXPERIMENT_DESIGN.md | Same-target/same-group static, aggregate and eventual LSTM comparison |
| TESTBED_SUPPLEMENT_DESIGN.md | Controlled primary testbed design justified by the final findings |
| UNRESOLVED_ASSUMPTIONS.md | What remains unknown and what evidence could resolve it |
| AUDIT_METHODS.md / QUALITY_REVIEW.md | Reproduction, computation limits and independent QA |

## Machine-readable evidence

| File | Population |
| --- | --- |
| source_manifest.json | 313 original source/dependency files with before/after SHA256 verification |
| legacy_sequence_audit.json | 879,225 supplied packet rows and all 175,800 legacy windows |
| rebuilt_sequence_audit.json | Missing historical rebuilt files distinguished from new reproduction |
| WINDOW_INTEGRITY_REPORT.json | Exhaustive checks of all 119,237 new diagnostic windows |
| label_provenance.csv | All 8,699 inherited positive packet rows; original labels preserved |
| recon_request_candidates.csv | 468 raw request candidates: 148 contextual, 320 ambiguous |
| shortcut_analysis.csv | Fixed rules and untuned diagnostic baselines against inherited labels |
| capture_campaign_summary.csv | Original file, retained/excluded, window and provenance populations |
| split_feasibility.json | UNSUPPORTED independent three-way experiment; no manufactured split |
| temporal_signal_analysis.csv / normal_lookalike_analysis.csv | Temporal distributions and exact current-message overlap |
| audit_completion_checks.json | Final package reconciliation and output validity checks |
| review_output_manifest.json | Hashes for review outputs, excluding isolated dependency packages |

`evidence/` contains source-linked tables and extraction metadata. `evidence/diagnostic_reconstruction/` is a new, independently generated diagnostic reproduction. It preserves unresolved inherited labels and is not final training data. It does not validate the missing historical rebuilt files.

`figures/` contains standalone plots backed by CSV tables. `scripts/` contains reproducible audit code and a SHA256-identical copy of the existing read-only PCAP parser. `.deps/` contains isolated audit dependencies, not project models.

All original files, raw PCAPs/logs, previous scripts/reports and models were preserved. No final LSTM, final preprocessing pipeline, class balancing, SMOTE, tuning or final evaluation was performed.
