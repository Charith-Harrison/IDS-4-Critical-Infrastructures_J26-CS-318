# Command and Response Injection Detection in Modbus/TCP

IT4010, J26-CS-318 (RP3). Progress version, roughly 70% of the planned work.

This component classifies Modbus/TCP request events using the surrounding command context (what came before, whether the register was seen in normal traffic, timing, request/response pairing).

**Current status.** The progress model supports Normal and Command Injection only. Verified response-injection training examples are unavailable in the supplied datasets, so final three-class implementation remains pending. Held-out evaluation, ablation, full explainability and fusion-layer integration are also still to do.

## Layout

```
app/          Streamlit dashboard
src/          data loading, pairing, features, training, inference
tests/        pytest suite
data/raw/     the two source CSVs (unchanged)
data/splits/  80/20 split by capture; test.parquet is kept for the final stage
models/       saved baseline and contextual Random Forests plus their metadata
results/      audit reports, feature audit, validation metrics, progress notes
docs/         data dictionary, model card, limitations
```

## Setup and run (Windows)

```
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app\dashboard.py
```

The dashboard opens at http://localhost:8501.

Open **Preliminary Model Performance** to compare the baseline and contextual
models using saved grouped out-of-fold predictions. It shows accuracy,
balanced accuracy, macro and per-class precision/recall/F1, false-positive and
false-negative rates, ROC-AUC, PR-AUC, confusion matrices, ROC and
precision-recall curves, fold stability, feature counts, training time and
inference latency. These are development-validation results, not final
held-out test scores; the final test partition remains untouched.

Rebuild everything from the raw CSVs (a few minutes):

```
.\.venv\Scripts\python.exe run_pipeline.py all
```

Single steps: `prep`, `train`, `verify`, `audit`, `compare`. Checks:

```
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m black --check app src tests run_pipeline.py
.\.venv\Scripts\python.exe -m ruff check app src tests run_pipeline.py
```

Run the model diagnostics after training:

```
.\.venv\Scripts\python.exe run_pipeline.py evaluate
```

This reuses saved capture-grouped out-of-fold predictions for validation,
checks train/test capture separation, reports function-code label rates and
per-code performance, ranks fitted Random Forest feature importances, runs
contextual feature-group ablations, and evaluates the saved models on the
capture-grouped held-out test partition. It also reports in-sample training
scores and an FC5-only diagnostic. Outputs are written to
`results\evaluation_diagnostics\`.

The held-out test partition was evaluated once on 2026-10-23 at the user's
request. Do not use its results for feature selection, threshold/model tuning,
or repeated model selection; obtain new independent data for further
experiments. The FC5 test subset has very few Normal examples, and labels are
not independently verified, so even perfect scores are not evidence of
deployment readiness. Diagnostics additionally include class-wise summaries
for all seven baseline features and single-feature grouped OOF tests.

## Candidate-model comparison

The comparison uses only the existing capture-grouped development file
(`data/splits/train.parquet`) and the split manifest. It does not open the
protected final 20% test partition. The existing event feature builder and
capture grouping are reused. Candidate pipelines fit median imputation (and,
for Logistic Regression and LinearSVC, scaling) within each validation fold.
Label-informed normal-access and value-range profile features are excluded
from the candidate feature set because they can reproduce the current
function/register-based label rule.

Run the documented preprocessing step if the saved split files need to be
rebuilt:

```
.\.venv\Scripts\python.exe run_pipeline.py prep
```

Run candidate-model comparison (Experiment A algorithm selection and separate
Experiment B isolated-versus-contextual Random Forest comparison):

```
.\.venv\Scripts\python.exe -m scripts.compare_models
```

Alternatively, after preprocessing, run:

```
.\.venv\Scripts\python.exe run_pipeline.py compare
```

Inspect Experiment A's summary and table:

```
Get-Content reports\model_comparison_summary.md
Import-Csv reports\model_comparison.csv | Format-Table
```

The separate Experiment B results are in
`reports\context_feature_experiment_summary.md`,
`reports\context_feature_experiment.csv`, and
`reports\context_feature_experiment.json`. Experiment A's JSON table and three
plots are `reports\model_comparison.json`,
`reports\model_comparison_macro_f1.png`,
`reports\model_comparison_attack_recall.png`, and
`reports\model_comparison_false_positive_rate.png`.

Load the selected fitted pipeline and its feature schema/metadata:

```
.\.venv\Scripts\python.exe -c "from scripts.compare_models import load_selected_candidate; artifact = load_selected_candidate(); print(artifact['metadata'])"
```

The fitted pipeline and sidecars are saved under `models\` as
`selected_candidate_model.joblib`, `selected_candidate_feature_names.json`,
and `selected_candidate_model.json`. Model selection prioritizes macro F1,
then Command Injection recall, false-positive rate, fold stability and
latency; models over the 100 ms/event target are not operationally acceptable.

## Data

Put these in `data/raw/` if they are missing:

- `normal_traffic_baseline.csv`
- `command_response_injection_attacks.csv`

Use only authorized public research data or authorized laboratory traffic.

## Things to know before presenting

- The labels are reconstructed from the dataset, not independently verified. Command Injection means an attack-labelled write to a function/register combination that never appears as a write in the normal file.
- Because of that, the cross-validation scores are close to perfect and a simple rule gives the same result. Read them as preliminary. Details are in `docs/limitations.md`.
- The final 20% test partition has not been used for anything. Code that reads data goes through a guard that blocks it.
