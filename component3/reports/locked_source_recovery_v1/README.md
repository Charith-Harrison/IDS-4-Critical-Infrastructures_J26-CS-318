# PCAP and CSV inference recovery

The error `Locked decoder/model code changed` came from a source-integrity mismatch, not from the accuracy calculation. The production loader correctly refused source bytes that differed from `experiment_lock.json`.

The exact original `experiment.py` and `records.py` were recovered from Git revision `9a1811ab398a964965eb3417f0613ecaea27891d`. Both recovered files match the SHA-256 values already recorded in the original experiment lock. Their syntax trees also match the edited versions, so no decoding, pairing, feature, rule or training logic was changed by this recovery.

Before restoration, the edited versions were saved intact under:

```text
component3/development/locked_source_recovery_v1/preserved_current/c3model/experiment.py
component3/development/locked_source_recovery_v1/preserved_current/c3model/records.py
```

The separate type-checking proposal is also retained. Use development copies for comments, typing or other source improvements. Files inside `component3/locked/` must retain their original bytes; do not reformat or add comments there.

The lock, saved models, raw collection, labels, official reports, feature definitions and accuracy-page code were not changed. The model loader's integrity checks remain enabled.

One stale frontend test assertion was updated from recall `1.0000` to the requested display format `100.00%`. The CSV browser checker now uses isolated sessions for its three fixtures instead of depending on version-specific uploader delete controls.

See [restoration.json](restoration.json) for source revisions, preserved-copy paths and before/after hashes, and [verification.json](verification.json) for regression, browser and preservation checks. Earlier type-check/accuracy reports describe the state before this subsequent recovery; their failure records have not been erased.

If an existing browser tab still shows the old error, click detection again. If necessary, stop the dashboard terminal with Ctrl+C and restart from the repository root:

```powershell
.\.venv\Scripts\python.exe -m streamlit run component3/frontend.py --server.address 127.0.0.1 --server.port 8503
```

Then refresh the browser and run **Recorded PCAP** or upload the existing `component3/local/csv_demo/labelled_observations.csv` again. This is saved-model inference only; no retraining is needed.
