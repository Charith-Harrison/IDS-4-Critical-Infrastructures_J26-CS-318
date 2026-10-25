# CIC-only evidence reassessment v1

Start with [DECISION_REPORT.md](DECISION_REPORT.md). The frozen baseline is `../../component3_preparation`; this package never writes there. `config.json` fixes diagnostic windows and bounded sampling limits.

Reproduce from the repository root:

```powershell
./.venv/Scripts/python.exe -B component3_reassessment/v1_20261024/run.py
```

The runner checks baseline preservation, reads existing extracted evidence/logs, performs bounded original-PCAP inspection and records code/config/input hashes and exact commands in `output/execution_manifest.json`. It does not run the original extraction/annotation pipeline or create model datasets. Ordinary reruns verify existing outputs and reuse completed stages when code/config/input/output hashes agree. `--refresh` recomputes these bounded diagnostics only.

Key outputs: `review_reproduction.json`, `cohort_diagnostics.json`, the accepted-cohort joint-count CSV, `diagnostic_candidates.json`, `original_log_timing_and_coverage.json`, `identity_byte_log_examples.json`, `identity_and_clock_audit.json`, `mechanism_parse_pair_impact.json`, `bounded_raw_evidence.json`, `view_overlap_samples.json`, `expanded_scope_plan.json`, `temporal_feasibility.json`, `shortcut_risks.json`, and `proposed_policy_v2_not_adopted.json`.

All row lists are evidence/candidate diagnostics, not accepted-label replacements or model matrices. The CSV contains aggregate counts, not predictor rows. Exact raw frame numbers are retained when known; mid-file pilot records use actual PCAP byte offsets and explicitly unknown global frame numbers. Source signatures are not packet counts or independent episodes. Original naive times and workbook serials remain available; no clock accuracy is assumed from their printed precision.

`PRESERVATION_VERIFICATION` is in `output/preservation_verification.json`: all baseline files are rehashed; raw file size/mtime are compared, original stored source hashes reused, original log hashes checked and sampled raw packet bytes verified. This is not an unnecessary exhaustive rehash of all raw PCAPs.

No new labels, replacement partitions, full expanded extraction, fitted transformations or models are produced. The proposed temporal claim needs academic-objective agreement; independent-campaign three-class evaluation remains unsupported.
