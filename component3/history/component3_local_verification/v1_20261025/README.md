# Verify the imported Component 3 collection and saved models

The actual imported raw source is `component3_raw/collection`. The processed data and
models are `component3_model_pipeline/v1_20261025/artifacts`. The producer's absolute paths
and the pipeline's historical default source are not used by this verification.

`/component3_raw/` was added to the root `.gitignore`. No raw files were already tracked;
`git check-ignore -v component3_raw/collection/collection_complete.json` confirms the rule.
No git index removal, pipeline code/default change or lock regeneration was performed.

From the repository root, repeat the read-only verification/model-load check with:

```powershell
.\.venv\Scripts\python.exe -B .\component3_local_verification\v1_20261025\verify_saved.py --source component3_raw/collection --artifacts component3_model_pipeline/v1_20261025/artifacts
```

This writes only a new timestamped report under this verification folder. It does not call
prepare, train, freeze, evaluate-final, predict or fit; does not build features or rewrite
existing artifacts; and does not require Docker. Loaded model objects exist in the checker
process for inspection, then are released when it exits. It does not install a running
prediction service or change the old application.

Verified on 25 October 2026:

- Collection `40ae7a846cce48fc8e3c52ebfca7e2cd`: all 104 accepted planned IDs and frozen
  roles/groups match the model lock. All 104 accepted capture logs report zero kernel drops.
- 1,597 frozen/source artifact hashes checked by the existing collection verifier; accepted
  counts are 247,906 normal, 720 command injections, 1,440 response injections: 250,066 ADUs.
  Failed attempts outside the accepted index remain excluded and are listed in the report.
- The saved development ADU, candidate-feature and routing Parquet metadata each reports
  114,604 rows. The label CSV counts and candidate column order match the saved preparation
  report; all 104 actual memberships match the frozen source. No data was reprocessed.
- Code, selected model files, locked development artifacts, collection identity and final
  lock references agree. Archived report copies match the supplied artifacts.
- B, D, B-wire and D-wire deserialize as fitted imputer/Random Forest pipelines. Input counts
  are 9, 14, 14 and 19 respectively; saved feature names, classes, 160 fitted trees and selected
  classifier parameters agree with the lock/selection. No predictions or scores were computed.
- All imported pipeline/code/artifact file hashes and the raw collection's header hashes
  match before/after verification. The experiment lock remains
  `f59f8e8922de62afd28f610a2521d9c45c0ebc46cec35b587210f4da0c6181c9`.

The report is `reports/verification-20261025T093000Z-cabe4fdc.json`. It includes exact commands,
input identities, model hashes, environment comparison, load warnings and preservation checks.
Local scikit-learn 1.8.0 matches the producer. Local Python/NumPy/pandas/joblib differ from
the producer environment; successful loading is not a numerical-equivalence or score test.
No package installation or dependency upgrade was needed.

To use only the existing official dataset verifier in a future PowerShell session:

```powershell
$env:PYTHONPATH = (Resolve-Path .\component3_model_pipeline\v1_20261025).Path
.\.venv\Scripts\python.exe -B -m c3model verify --source component3_raw/collection
```

That command verifies hashes/seals and prints admission, without rerunning model stages.
Its CLI ensures the existing artifacts directory exists; it does not replace locked files.
Keep the explicit `--source` argument on this PC. Do not use the old producer path or invoke
prepare/train/freeze/evaluate-final on the locked artifacts.

Scope: source verification checks hashes, receipts, groups and saved reports; it does not
independently reconstruct all TCP/PCAP bytes or certify clocks/industrial generalization.
Parquet companion checks use metadata and saved development labels, not a fresh row-by-row
reconstruction. Raw final ADU/label rows are not decoded; saved final predictions are not
loaded/scored. Final reports are read/hash-compared as existing results only. The earlier
scientific limitations of one testbed and two interventions remain unchanged.
