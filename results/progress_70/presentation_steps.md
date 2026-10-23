# Presentation steps

Start the dashboard from the project root (Windows):

```
.\.venv\Scripts\python.exe -m streamlit run app\dashboard.py
```
Open http://localhost:8501. Pages are selected from the left panel.

## Function 1 — Modbus/TCP preprocessing and contextual feature generation
1. Open **Preprocessing & Features**, pick a development capture (for example `atk-4`), keep 1000 packets and press **Generate features**.
2. Show the generated feature table (function name, pair status, previous-event, timing, access and value features), the feature derivation table, the unavailable-feature list, and the processing time.
Explain: the dashboard calls the same modules used for training (`src/data`, `src/features`).

Command-line equivalent: `.\.venv\Scripts\python.exe run_pipeline.py prep`

## Function 2 — Saved model loading and validation prediction
1. Open **Validation Detection Results**. Show the out-of-fold actual-vs-predicted table (saved during grouped CV).
2. Press **Load model and predict one event** to load `contextual_rf.joblib`, verify checksum/feature schema and predict one event with probabilities.
Command-line equivalent: `.\.venv\Scripts\python.exe run_pipeline.py verify`

## Function 3 — Preliminary Normal / Command Injection detection
1. Open **Attack Detection**, choose "Validation records", pick `atk-4`, press **Validate Data**, then **Run Attack Detection**.
2. Show the summary values, the results table (actual vs predicted shown separately, with out-of-fold columns), and the exports.
3. Open **Event Investigation** to show previous-event, timing, access-profile and value evidence with "supporting contextual observations".
4. To test a CSV: choose "Authorized CSV upload" and upload a CSV with the same 28 required columns (labels optional). Unlabelled input shows Actual Class: Unavailable.

Say clearly: only Normal and Command Injection are supported; results are preliminary cross-validation results; the 20% test partition is untouched; scores partly restate the label rule.
