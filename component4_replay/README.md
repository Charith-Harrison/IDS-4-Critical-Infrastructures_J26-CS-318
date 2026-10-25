# Component 4: Replay Attack Detection Using Transaction Consistency Analysis

Ilankoon I. M. D. S. - IT23284616

Start with `../component4_review/FULL_COMPONENT_AUDIT.md`. The current extracts support a useful prototype, but **do not establish independent replay campaigns or the proposed improvement over a current-message classifier**. Do not present the old 99.76% accuracy as proof of the research contribution.

## Folder guide

| Folder | Purpose |
|---|---|
| `src/` | Strict CSV loading, pairing, causal request features, manifest validation, training, metrics and batch inference |
| `configs/baseline.json` | Fixed feature/history/timeout/model settings |
| `tests/` | Scientific regression tests; standard-library unittest |
| `data/processed/<new-run>/` | New compressed transaction/features tables and checksummed metadata |
| `artifacts/<new-run>/` | Future validated experiments only; none trained as a final model in this audit |
| `../component4_review/` | Requirements, inventories, audit evidence, limitations and results |
| `../data/raw/` | Canonical historical CSV references; preserved byte for byte |
| `../src/`, `../artifacts/`, `../app/` | Original implementation and saved artifacts retained in place as historical evidence |

No large CSVs were moved or duplicated into `data/raw_reference/`. There are no raw PCAPs on this branch. `data/interim/` is unnecessary. The original dashboard permits viewing/downloads; its write actions and the original end-to-end CLI are disabled. Original module functions are retained for read-only retrospective reproduction and are not the supported research pipeline.

## Run from the repository root (PowerShell)

The existing `.venv` worked during this audit. No additional framework is needed.

```powershell
# Recompute the audit in a NEW directory (original pipeline is read in memory only).
& .\.venv\Scripts\python.exe component4_review/audit_existing.py --out component4_review/evidence/my_audit

# Prepare the complete existing canonical CSVs, without training or assigning splits.
& .\.venv\Scripts\python.exe -m component4_replay.src.prepare --out component4_replay/data/processed/my_run

# Regression tests (do not run legacy dashboard integration tests against preserved artifacts).
& .\.venv\Scripts\python.exe -m unittest discover -s component4_replay/tests -v
```

Every output directory must be new. A repeated command refuses to replace it. Dataset paths in the JSON config resolve from the repository root even when invoked elsewhere; pass an absolute `--config` path if necessary. Outputs resolve from the shell's working directory. Labels are accepted as -1/0/1 only; missing labels stay unknown. No source filename is invented. Original row order and row identities (input SHA256 + zero-based CSV row) survive preparation.

For a fresh environment, install `component4_replay/requirements-lock.txt` with Python 3.13. The lock records the existing tested scientific stack. The dashboard-viewer regression tests also need the root requirements: use `python -m pip install -r requirements.txt -r component4_replay/requirements-lock.txt`. Binary model reproducibility can still depend on platform/library versions, which are saved with each experiment.

## What preparation produces

`transactions.csv.gz` contains one **request observation**, optionally linked to one uniquely matching observed response. It is not a count of independent attacks. Replies with no unique request remain in `unpaired_responses.csv.gz`. `request_features.csv.gz` contains metadata plus the explicitly allowed features. Labels and provenance are metadata only. `observed_segments.csv` lists discontinuities, **not verified captures/campaigns**. `metadata.json` records input/output hashes, configuration, runtime and counts.

Matching uses observed segment, canonical bidirectional IP/port tuple, observed TCP lifetime indicators, TID, unit and base function. It accepts a normal or exception reply within the configured interval. Concurrent different TIDs work. Reused outstanding TIDs remain ambiguous; no greedy match is fabricated. Late/duplicate/orphan replies remain distinguishable as unresolved candidates. The CSV lacks TCP sequence numbers and full handshake/stream history, so four-tuple scopes remain proxies. Right-censoring is recorded at segment ends. Timeout is a pairing search bound, **not proof of server silence**.

Request-arrival features use only the current request and bounded preceding requests. True previous-within-proxy TID difference is separate from endpoint history across ports. The latter is explicitly an endpoint-channel hypothesis, not a TCP session. Missing history stays NaN with an availability indicator; it is never replaced with a normal increment. TID wrap is represented by both signed difference and modulo-65536 delta. A decrease or repeated command is not itself an attack.

The command fingerprint uses observed unit/function/register/count/scalar fields. It does not assert byte equality. Read-response process values, raw payload hashes and full payload duplicate detection are unavailable. New request-arrival inputs exclude current response latency, timeout outcome, label conflicts, raw IPs, ports, filenames, absolute timestamps and frame IDs.

## Training is conditional on evidence

Training requires a manually prepared CSV with these columns:

```csv
segment_id,independence_group,partition,evidence
```

Use the exact segment IDs from preparation. `partition` must be `train`, `validation`, or `test`; `independence_group` must unite all related recordings, interface views and replay episodes; `evidence` must reference the recording/run log that establishes the relationship. Each segment has exactly one assignment. All three partitions must contain verified normal and replay request labels. Never type arbitrary group names to bypass the check. **No such verified manifest can currently be derived from this repository.** We deliberately provide no fabricated example assignment for these data.

Once independent groups have actually been established:

```powershell
& .\.venv\Scripts\python.exe -m component4_replay.src.train --prepared component4_replay/data/processed/my_run --manifest verified_independence.csv --out component4_replay/artifacts/my_experiment
& .\.venv\Scripts\python.exe -m component4_replay.src.infer --prepared component4_replay/data/processed/new_batch --artifacts component4_replay/artifacts/my_experiment --out component4_replay/artifacts/new_batch_predictions
```

The comparison holds request targets, split, classifier settings, threshold and class weights constant:

- A: bounded observed-command + TID recurrence rule.
- B: XGBoost using current request fields, including absolute TID to expose that potential shortcut.
- C: the same XGBoost with B plus transaction-history features.

No SMOTE, row shuffling, label-based row moves, pre-split learned preprocessing or test tuning occurs. XGBoost handles missing values natively; class weight uses training labels only. Validation and test metrics include confusion matrix, precision, recall, F1, FPR, balanced accuracy, ROC-AUC and average precision. The validation set is reported separately; the default design uses fixed hyperparameters and threshold rather than tuning on the final test set.

Batch inference requires preparation with the same schema/config; history starts cold for each input batch/segment. It is not a live stateful TCP sensor. The output includes probability, decision point, session proxy and simple recurrence evidence. Measured batch inference time is amortized computation, not an end-to-end replay latency measurement.

## Student's next experiment

Capture and label independent isolated testbed runs of normal repetitive polling and replay of valid requests, retaining source/run IDs, complete ADUs, TCP stream identity and replay delay logs. Then lock campaign groups before comparing A/B/C. See the audit for the specific evidence gaps and a limited source-check alternative; rebuilding all public PCAPs is not a prerequisite for continuing this component.
