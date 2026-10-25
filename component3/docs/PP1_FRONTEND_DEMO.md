# Component 3 frontend

Start from the repository root:

```powershell
.\.venv\Scripts\python.exe -m streamlit run component3/frontend.py --server.address 127.0.0.1 --server.port 8503 --server.headless true --browser.gatherUsageStats false
```

Open **http://127.0.0.1:8503**. Ctrl+C in its terminal stops the page. Restart the server after changing imported Python modules so an older loader is not retained in memory.

For another laptop, follow SETUP.md for the canonical evidence/artifacts and install the optional packages with:

```powershell
.\.venv-c3\Scripts\python.exe -m pip install -r component3/requirements-frontend.txt
```

## Sections

- **Demo:** identical current messages, with earlier context hidden or shown. The command pair uses mode1 versus mode0. The response pair reports30 after acknowledged values30 and118.
- **How it works:** the traffic-to-Random-Forest flow and the actual feature groups. Missing context is a diagnostic that requires abstention.
- **Results:** saved final metrics by experimental condition, using readable model names and the same supported cohort. Causal-rule results and wire-header comparisons are labelled separately.
- **Evidence:** exact run/event/ledger/PCAP references, ground-truth annotation, model inputs and integrity checks. The original four training examples remain selectable.
- **Dataset & scope:** recorded collection counts, whole-run separation, label provenance and the bounded testbed assumptions.

## Where displayed values come from

The main paired examples are from accepted validation run MX025-20261025T052550Z-e356f7ee:

| Example | Event | Complete current ADU |
|---|---|---|
| Normal command | e36 | 00050000000601050001ff00 |
| Injected command | e1060 | 00050000000601050001ff00 |
| Normal response | e33 | 000500000005010302001e |
| Injected response | e2101 | 000500000005010302001e |

These are explanatory examples selected by matching bytes and verified classes. They do not change partitions, training, scores or labels.

Packet-only/context-aware predictions are read from the existing **validation_predictions.parquet**, joined by exact event ID. This file contains predictions but no probabilities, so the page displays **Not saved** for confidence. It does not generate replacement probabilities. If that output is absent, the original examples remain available and the page states that the model comparison is unavailable.

Complete accepted streams are replayed before selecting the displayed events. That reconstruction uses an explicit public-observation allowlist; labels are opened separately after features exist. Ground truth selects/identifies explanatory cases and is never a predictor.

Final metrics come from the unchanged report mirrors in **locked/v1_20261025/reports/locked_results/**. False-alarm rate is the saved confusion matrix's normal-to-attack count divided by its supported-normal count. No new final predictions, pooled scores or model fitting are performed.

## Verification

The loader checks the original lock, collection index, selected run receipts/artifacts, public protocol, prepared development data, saved validation predictions and report hashes. Existing exact frame/file byte references remain available. Use **Recheck evidence and reload** after replacing local evidence files.

The tests check saved-output identity, absence of private fields in detector observations, preservation of original examples and source byte spans, metric denominators, context reveal, condition selection, missing-output fallback and reload. The browser check covers all five sections at normal laptop resolutions.

Relevant code: frontend.py and frontend.css (presentation), demo_data.py (existing evidence loader plus saved-output mode), demo_results.py (read-only result views). The frontend never modifies captures, annotations, saved models or experiment results.

## Run actual detection on captured traffic

Under **Demo**, scroll to **Analyze traffic** and choose **Recorded PCAP**:

1. Select **MX025 · validation** and press **Run detection**.
2. The page reads capture.pcap, reconstructs its TCP byte streams and complete Modbus messages, rebuilds causal context and calls the original saved RF models.
3. This recording produces 2,272 replayed messages and 27 contextual-RF alerts: 9 command injections and 18 response injections. There are 90 abstentions and 2,007 out-of-scope messages. Counts come from the inference output, not constants in the UI.
4. Inspect the packet-only versus context-aware decisions, freshly computed confidence and PCAP frame references. Turn on **Show normal and abstained decisions** to inspect supported non-alert traffic too.
5. Download the decisions CSV, or open a cited frame in Wireshark. Select the normal-only recording **MX084 · train** for a contrast: it replays 2,486 messages with zero predicted injection alerts and 66 abstentions.

The PCAP replay accepts only the 48 indexed training/validation recordings. It is an offline demonstration on existing development data, not a new final evaluation or a live network attack. Arbitrary PCAP uploads are not supported. The additional **CSV** route accepts the strict ordered-observation schema described in [CSV_INFERENCE.md](CSV_INFERENCE.md).

**How this differs from the example cards:** the cards load selected ground-truth cases and their stored validation predictions. The PCAP button runs detection now, without reading the application ledger, labels, simulator state or intervention logs. Its probabilities are real, freshly calculated, uncalibrated RF outputs. The historical example cards continue to say **Not saved** for confidence because those original probabilities were not recorded.

**PCAP or CSV?** PCAP is the strongest demonstration here: it shows the path from captured wire bytes through reconstruction and features to a prediction. A CSV needs the correct protocol schema, ordering, connections and earlier context; a standalone row or label column is insufficient. The downloadable replay CSV contains model decisions and packet references, not new ground truth.

For CSV input, download **observations (CSV input)** after a PCAP replay, then select **CSV** and upload that file. This public-observation export is separate from the prediction report. Both input routes share the causal context builder, saved preprocessing and saved models. Uploading a CSV does not train the model. Optional uploaded labels are scored only after predictions exist; training and validation metrics are not independent test evidence.

## Evaluation metrics in the frontend

**Results** already contains the saved Macro F1, injection recall, normal precision, false-alarm rate, run support and abstention counts. **Per-class metrics and confusion matrix** adds precision, recall, F1 and support for each class and a true-class-versus-predicted-class matrix. Choose the model and experimental condition. **Download saved evaluation metrics (CSV)** exports the existing metrics table.

These saved evaluation metrics remain separate from the fresh development-PCAP replay. No model is fitted and no final test is rerun. Replay implementation: capture_replay.py; it reuses the qualified, hash-checked TCP reader from the original collection bundle.
