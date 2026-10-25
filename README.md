> **Component 3: start at [component3/README.md](component3/README.md).** It contains the audited testbed study, safe root commands, viva guide and methodology gaps. The original experiment is preserved under `component3/locked/v1_20261025`; canonical raw evidence is `component3/data/collection`. The binary CSV workflow below is historical and is not the new experiment's training/evaluation pipeline.

# Command and Response Injection Detection in Modbus/TCP Using Context-Aware Command Analysis

**J26-CS-318 — Preliminary Binary Injection Detection Model (approximately 70% implementation).**

The research contribution is contextual protocol feature engineering, evaluated
by comparing an isolated-event Random Forest with a context-aware Random Forest
on identical partitions and candidate settings. Random Forest was selected
because it is suitable for structured contextual features; performance is
evaluated experimentally.

**The current dataset combines command and response injection under one attack
label. Separate command-injection and response-injection classification will be
enabled when the verified three-class dataset is integrated.**

Current classes are exactly `Normal` and `Command_Response_Injection`. Request
direction never determines a target. The old reconstructed Command Injection
labels and models are no longer used.

## Installation

The rebuild was verified with Python 3.14 on Windows (Python 3.12+ is required by
the pinned dependencies). Use a fresh virtual
environment when copying the repository to another machine. Exact package
versions are in requirements.txt and model metadata; the pinned scientific
packages require a compatible recent Python release.

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

With the virtual environment activated, the workflow is:

```powershell
python scripts/inspect_dataset.py
python scripts/prepare_data.py
python scripts/train_models.py
python scripts/evaluate_models.py
python scripts/run_demo.py
streamlit run app/dashboard.py
pytest
```

For an integration check of all five pages with both saved models, run
`python scripts/verify_dashboard.py`. This needs local loopback sockets for
Streamlit's test runner; it does not start a persistent web server.

Without activation, replace `python` with `.\.venv\Scripts\python.exe` and use
`.\.venv\Scripts\python.exe -m streamlit run app/dashboard.py` or
`.\.venv\Scripts\python.exe -m pytest`. These commands use project-relative paths.
The first four scripts accept `--config path/to/config.yaml` for explicit experiments.
The dashboard uses the primary `config/config.yaml`.

## Dataset placement and inspection

Place these original files in `data/raw/`:

- `normal_traffic_baseline.csv`
- `command_response_injection_attacks.csv`

The current files contain 150,000 and 192,920 records respectively. Their combined
labels are 247,960 Normal and 94,960 Command_Response_Injection. The inspection
script records schemas, missingness, duplicates, labels, constant fields and
suspicious identifiers under `results/metrics/dataset_audit.json` and `.md`.
Raw files are read-only inputs and their checksums are recorded.

## Architecture and outputs

```text
app/dashboard.py          Streamlit entry point and five modular pages
config/config.yaml        modes, dataset, features, split and RF settings
src/                      ingestion → validation → labels → events → features
                          → training/evaluation → inference/explanations
scripts/                  reproducible CLI commands
tests/                    small synthetic software fixtures
data/raw/                 unchanged original data (ignored by Git)
data/processed/           events.parquet, quarantine.parquet (ignored by Git)
data/manifests/           source hashes, exclusions, grouping, split provenance
models/baseline/           isolated-event pipeline and metadata
models/contextual/         proposed pipeline and metadata
results/metrics/          audit, validation and holdout comparison
results/predictions/      API demo and measured predictions
results/figures/          confusion-matrix figure
docs/                    audit record, feature contract, limitations
legacy_backup/           preserved pre-rebuild project (ignored by Git)
experiments/             automatic archives on dataset/configuration changes
```

`src/label_mapper.py` centralizes both modes. `src/leakage_guard.py` enforces an
exact feature whitelist, including order and numeric types. `src/event_builder.py`
uses session/capture boundaries and causal partial pairing. The baseline contains
current-event features only; the contextual RF adds enabled sequence, pairing,
access, timing and value groups. Each feature has a missingness indicator.
`src/feature_profiles.py` fits training-only reference quantiles for explanation.

## Preprocessing and evaluation

Preprocessing normalizes schemas, preserves original row IDs, quarantines invalid
records, checks duplicates/conflicting labels, and writes a manifest. The current
data retains all 342,920 rows. Six supplied normal capture IDs and six inferred
attack reset segments are kept disjoint across train, validation and test.

Train: 156,376 rows; validation: 70,984; test: 115,560. Group fractions need not
equal row fractions. Validation has only 98 attack-labelled rows; this limits
selection reliability. If reliable groups cannot be formed, the code can use
chronological blocks, resetting context at boundaries; it refuses unsupported
random row splitting and partitions that lack configured classes.

Both RFs use 200 trees and the same two reduced candidates. Median imputation is
fitted on training rows only. Selection uses validation macro F1, never test
scores; the selected model remains fitted on train only. Configurable class
weighting avoids test resampling. There is no oversampling.

Run evaluation once after training. Inspect `results/metrics/comparison.md`,
`comparison.csv`, and `comparison.json` for measured accuracy, macro/weighted
metrics, attack recall, false-positive rate, binary or multiclass AUC, confusion
matrices and latency. PR-AUC is average precision; latency excludes feature
construction. Repeated evaluation of the same hashes returns the saved report.
Retraining the identical evaluated experiment is blocked. When input checksums
or configuration change, inspection/preprocessing automatically archives the old
models, generated data, results and configuration under `experiments/` before
starting a new experiment. Original raw data, source and research docs stay in place.

The legacy project already evaluated these source data. This is **preliminary
internal evaluation, not an untouched final research holdout**. High scores can
reflect scenario/function-code artifacts even with the feature whitelist. Do
not claim contextual improvement unless the measured comparison supports it.

## Dashboard and inference

The five pages are Security Overview, Detection Events, Event Investigation,
Model Performance and System Health. The default view predicts the first 3,000
validation events, labelled as a demo. Upload a CSV to analyze an ordered batch;
each batch resets context and all invalid rows remain visible. The UI does not
train or evaluate models. It displays the preliminary limitation prominently.

Programmatic inference:

```python
import pandas as pd
from src.inference import load_model, predict_csv, prediction_records
from src.utils import load_config

model = load_model('contextual', load_config())
predictions, health = predict_csv(pd.read_csv('data/raw/my_batch.csv'), model)
records = prediction_records(predictions)
```

Records include event_id, timestamp, prediction, confidence, function_code,
address_or_register, evidence, model_version, model_mode, processing_status and
invalid_reason. Confidence is an uncalibrated RF vote fraction. Explanations
show observed feature evidence and global importance, not causal local attribution.
Only locally trained trusted joblib artifacts are loaded; uploads are CSV only.

## Ablation support

Set `features.sequence`, `pairing`, `access`, `timing` or `value` to false to
exclude that group. Set `features.windows` to `[3]`, `[5]`, `[10]`, or a combination.
Reprocess and retrain to keep feature/model schemas consistent. Use development
validation for ablations; do not tune against the already evaluated holdout.
The full scientific ablation study remains pending.

## Transition to Final Three-Class Dataset

1. Place the properly labelled new CSV(s) in `data/raw/`; never overwrite originals.
2. Update `config/config.yaml`: set `model_mode: final_three_class`, replace
   `dataset.files`, set `dataset.label_column`, set `verified_labels: true`, and
   provide `label_evidence` referencing the verified source/mapping documentation.
3. For canonical targets use `label_scheme: canonical` with exactly `Normal`,
   `Command_Injection`, `Response_Injection`. For verified original MSU categories,
   use `label_scheme: msu_numeric`: 0→Normal; 1/2→Response_Injection;
   3/4/5→Command_Injection; 6/7→explicitly excluded and recorded. This planned
   mapping must be checked against the actual supplied dataset documentation.
4. Configure `column_map` for actual raw-to-canonical protocol names,
   `timestamp_unit`, and preferably a verified `group_column`. Disable inferred
   reset grouping when verified capture/session identifiers are available.
5. Run inspect, prepare, train, evaluate, demo and tests using the commands above.
   The changed configuration automatically archives the current experiment under
   `experiments/`; no manual deletion or application redesign is required.
   Inspect label counts, exclusions, class-complete partitions and source evidence
   before accepting results. The saved class schema automatically drives the UI.

CIC targets require external, verified packet/log preprocessing with original
attack information, direction, request/response relationships and supporting
evidence. This application does not manufacture that ground truth. Missing
protocol fields become explicit missing features; complete PCAP reconstruction
still requires a dedicated ingestion step.

## Tests and current limitations

Tests exercise schema/range checks, label mapping, leakage protection, chronological
order, causal windows, session/partition separation, partial pairing, missingness,
model reload, valid predictions/confidence, deterministic inference and a synthetic
three-class software path. Synthetic fixtures are not used in research metrics.

See `docs/research_limitations.md` for pairing, exporter semantics, grouping,
prior test exposure and probability limitations, and `docs/rebuild_audit.md` for
the preserved old project. Final verified labels/data, full CIC reconstruction,
external MSU validation, full ablation/hyperparameter experiments, integration
with other components and final research conclusions remain pending.
