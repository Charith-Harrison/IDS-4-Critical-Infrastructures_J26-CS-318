# Repeated frozen-source edit recovered

CSV inference was blocked again because a new `#Hyperparameters` comment was saved inside the locked `c3model/experiment.py`. Even a comment changes the byte hash checked by the original experiment lock. The dataset, CSV schema and accuracy calculation were not the cause.

The commented file was preserved at `component3/development/locked_source_recovery_v2/preserved_current/c3model/experiment.py`. The original was then recovered from Git revision `9a1811ab398a964965eb3417f0613ecaea27891d` and verified against the existing lock. The edited and original files have identical Python syntax trees.

VS Code workspace settings now include:

```json
"files.readonlyInclude": {
  "**/component3/locked/**": true
}
```

This setting is supported by the installed VS Code version. It protects the locked folder in the editor; it does not change filesystem permissions or relax any model-integrity check. Make comments and proposed code changes in development copies, not under `component3/locked/`.

No model was retrained, no lock was updated, and no dataset, official result or accuracy calculation was changed. See [restoration.json](restoration.json) for exact source hashes and [verification.json](verification.json) for the tests and CSV browser check.

Refresh the dashboard and run detection again. If an old session still shows the error, restart the Streamlit terminal and reload the page. No preprocessing or training command is needed.
