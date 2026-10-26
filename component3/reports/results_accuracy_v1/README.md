# Results-page accuracy

Subsequent update: the source-lock mismatch described below was repaired by restoring the exact original source bytes. See [inference recovery](../locked_source_recovery_v1/README.md). The original test logs below remain a record of the state during the accuracy task.

The Results page now adds derived accuracy to every saved final method/condition, preserving the existing layout and Macro F1 values. All percentages displayed in the page use two decimal places. The numeric download retains precision.

Changed frontend: `component3/frontend.py`. Reporting backend: `component3/demo_results.py`. This local Streamlit application calls the reporting module directly; no separate API server is involved.

## Existing files

[FILE_LOCATIONS.md](FILE_LOCATIONS.md) lists every discovered path, with [file_inventory.json](file_inventory.json) as the machine-readable inventory. The files named `validation_report.json` under individual collection/pilot folders validate captures; they are not classification validation metrics. The older `results/metrics/` reports belong to the separate older application and are not mixed into this page.

Canonical experiment files are under `component3/locked/v1_20261025/artifacts/`:

- `validation_report.json`: validation confusion matrices, per-class precision/recall/F1, Macro F1, support, coverage and abstentions.
- `selection.json`: selected RF configurations, validation selection results, feature names and provenance.
- `validation_predictions.parquet`: saved per-message validation labels, predictions and eligibility/context flags. It does not store probabilities.
- `final_summary.json`: compact final results by condition and method; not the detailed source for confusion matrices.
- `final/final_test_{repeat,values,map,order,timing}_report.json`: detailed final metrics and denominators, each from its own condition.
- `final/final_test_{repeat,values,map,order,timing}_predictions.parquet`: saved per-message final predictions and truth for checking those matrices.

The page already reads the sealed copies in `component3/locked/v1_20261025/reports/locked_results/`; that source remains unchanged. The tests compare derived numbers with the canonical saved final prediction files, without calling a model or rerunning final evaluation. Validation reports are inventoried but are not presented as final-test metrics.

## Denominators

Accuracy (%) = `100 × sum(diagonal cells) / common_cohort.support`.

This is the same common supported cohort used by the displayed Macro F1. In all current saved reports every common-cohort decision is scored, so it is labelled scored-only. It is not accuracy across all captured messages. If a matrix omits decisions within that cohort, the reporting helper keeps the original support denominator rather than silently removing them.

Prediction coverage (%) = `100 × method.scored / task_eligible`.

Coverage describes all publicly eligible tasks, not only the common cohort. Each method's abstentions are shown separately. A/B/B-wire can classify eligible rows without context; C/D/D-wire abstain where an earlier trustworthy anchor is unavailable. Other traffic remains out of scope and is never credited as correctly classified normal traffic. The existing false-alarm rate uses supported-normal decisions only.

The page keeps packet-only/context-aware RF together, rules separately, and protocol/wire comparisons in the existing expander. Per-class precision and recall remain available with the confusion matrix. The download now includes accuracy, cohort support, per-method coverage/abstentions and exact final condition for all 30 combinations. [derived_final_metrics.csv](derived_final_metrics.csv) is a new reporting export; no original metric file was overwritten.

## Verification and limitation

See [verification.json](verification.json), [accuracy_tests.txt](accuracy_tests.txt) and [browser_check.json](browser_check.json). Screenshot: `component3/local/results_accuracy_v1/results_ordering.png`.

Five new tests cover all method/condition matrices, agreement with saved predictions, unchanged Macro F1, coverage, missing values, unrepresented decisions, download identity and frontend formatting. Browser checks cover condition selection, six methods, CSV download, and 1366/1280-wide laptop layouts.

The full active suite is **not green**: 29 methods ran (28 passed, one PCAP UI test failed), and two class-setup failures prevented 14 additional tests. All three error events stem from the pre-existing frozen-source/lock mismatch documented in the prior type-check proposal. `experiment.py` and `records.py` already differ from their original locked hashes. No loader check was weakened, and no frozen source or lock was repaired as part of this Results task. Read-only Results loading and the new accuracy tests pass independently.

All 1,821 protected files retain their task-start hashes, including the dataset, models, labels, original reports, lock and current frozen source files. No training or model inference was executed for this reporting change.

Restart an already-running dashboard once so Python reloads the changed reporting module:

```powershell
.\.venv\Scripts\python.exe -m streamlit run component3/frontend.py --server.address 127.0.0.1 --server.port 8503
```
