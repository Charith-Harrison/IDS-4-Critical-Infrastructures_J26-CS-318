# C2 / RP2 — Modbus/TCP Reconnaissance Attack Detection Using Temporal Behavior Analysis

**Overall Project:** Protocol-Aware ML Framework for Intelligent Modbus Attack Detection and Incident Analysis  
**Project ID:** `J26-CS-318`  
**Component:** `C2 / RP2` — Reconnaissance Attack Detection Using Temporal Behavior Analysis  
**Author:** Charith H. (`IT23269002`) — B.Sc. (Hons) Information Technology (Cyber Security)

---

## 1. Overview & Research Questions

This repository implements, audits, evaluates, and documents the **C2 / RP2** research component investigating whether temporal sequence modelling of protocol-aware Modbus/TCP traffic improves reconnaissance/scanning attack detection compared with packet-level and non-temporal windowed baselines under strict capture-independent evaluation.

- **Primary Research Question (RQ1):** *Does temporal modelling of protocol-aware Modbus/TCP request sequences improve reconnaissance detection compared with packet-level and non-temporal baselines under session-independent evaluation?*
- **Secondary Research Question (RQ2):** *Does explicit timing information provide useful predictive information beyond the ordered Modbus/TCP request features themselves?*

---

## 2. Key Empirical Findings

1. **Hostile Dataset Audit & Chronological Sequence Reconstruction (`docs/C2_DATASET_AUDIT.md`):**
   - The supplied packet table (`recon_labeled_packets_ALL.csv.xlsx`, `879,225` rows, `8,699` positives) spans `15` `.pcap` files and `17` directional sessions.
   - The supplied pre-built sequence table (`recon_sequences_ALL.csv.xlsx`, `175,800` windows of `20x7`) is severely corrupted: **`99.38%` (`174,708 / 175,800`) of windows contain backward (negative) timestamp jumps**, **`97.32%` (`171,080 / 175,800`) cross `.pcap` file boundaries**, and `67.70%` of `time_delta` values are clamped to `0.0` because packets were sorted by `(session_id, func_code, reg)` before window slicing.
   - Five `2023-02-01` `veth*` `.pcap` files are simultaneous virtual-interface captures of the same network traffic (`282,076` duplicate secondary-view rows, including `50` duplicated positive rows in `veth665f3cf-0.pcap`).
   - Our deterministic rebuild pipeline (`src/rebuild_sequences.py`) removes the `282,076` multi-interface duplicate rows and `14` non-Modbus/malformed rows, sorts packets strictly chronologically within each `(capture_group_id, session_id)`, and constructs **`119,237` verified `20`-packet windows (`stride = 5`; `1,878` positive, `117,359` negative)** across **`10` independent capture groups (`G01`..`G10`)** with `0` backward timestamps and `0` cross-capture windows.

2. **Discovery of the `modbus_len == 3` Protocol Shortcut (`docs/C2_LEAKAGE_AUDIT.md`):**
   - `100.0%` of packets with `modbus_len == 3` (`8,401` rebuilt packets, all `packet_size == 75`, `func_code == 5` in `185.175.0.5_185.175.0.3_u1_s0004`) are labelled positive (`0` false positives across `588,498` negative packets), covering **`94.99%` (`1,784 / 1,878`)** of all positive rebuilt windows (**Category 1**).
   - The remaining `94` positive windows split into **`23` Category 2 windows** (`quantity > 1` multi-register/coil scans) and **`71` Category 3 windows** (`event_mapped` intervals with normal protocol fields `func_code in {1, 5}, quantity == 1, modbus_len == 6` resulting from a `~4h 57m` clock offset in `attack_events_mapped.xlsx`).

3. **Model Comparison (`RQ1` & `RQ2` — `docs/C2_RESULTS.md`):**

| Model | Features (Dims) | LOCGO-10 Pooled F1 (`@0.5`) | LOCGO-10 Pooled F1 (`@val_thr`) | LOCGO-10 Precision (`@val_thr`) | LOCGO-10 Recall (`@val_thr`) | LOCGO-10 FPR (`@val_thr`) | LOCGO-10 ROC-AUC | LOCGO-10 PR-AUC | SGKF-5 Pooled F1 (`@val_thr`) | Single-Window Latency `p99` (ms) |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Static Rule (`any(modbus_len == 3)`)** | `modbus_len` (`1`) | 0.9743 | 0.9743 | 1.0000 | 0.9499 | 0.00000 | N/A | N/A | 0.9743 | `< 0.1` |
| **`Model_A_Packet_LogReg`** | Packet -> Max (`5`) | 0.9455 | 0.9399 | 0.9306 | 0.9494 | 0.00113 | 0.9718 | 0.8353 | 0.9482 | 0.85 (inf) |
| **`Model_A_Packet_DT`** | Packet -> Max (`5`) | 0.9481 | **0.9717** | 0.9933 | 0.9510 | 0.00010 | 0.9776 | 0.9600 | **0.9746** | 0.49 (inf) |
| **`Model_B_Window_RF`** | Window + Timing (`29`) | **0.9738** | 0.9706 | 0.9928 | 0.9494 | 0.00011 | **0.9859** | **0.9644** | 0.9682 | 84.11 (E2E) |
| **`Model_B_Window_LogReg`** | Window + Timing (`29`) | 0.9159 | 0.9511 | 0.9604 | 0.9420 | 0.00062 | 0.9803 | 0.9428 | 0.9560 | — |
| **`Model_C_LSTM_Full` (Primary)** | Sequence + Timing (`20x19`) | 0.9458 | 0.9401 | 0.9437 | 0.9366 | 0.00089 | 0.9796 | 0.9467 | 0.9154 | **34.51 (E2E)** |
| **`Model_D_LSTM_NoTiming` (RQ2)** | Sequence No-Timing (`20x17`) | 0.9585 | 0.9540 | 0.9820 | 0.9276 | 0.00027 | 0.9791 | 0.9421 | 0.9548 | 4.38 (inf) |
| **`NoShortcut_Model_A_Packet_DT`** | Packet No-Shortcut (`3`) | 0.2131 | 0.2131 | 0.1193 | 0.9510 | 0.11232 | 0.9333 | 0.0975 | 0.2089 | — |
| **`NoShortcut_Model_B_Window_RF`** | Window No-Shortcut (`24`) | 0.6251 | **0.6210** | 0.5052 | 0.7726 | 0.01211 | **0.9562** | **0.4326** | **0.6624** | — |
| **`NoShortcut_Model_B_RF_NoTiming`** | Window No-Shortcut No-Time (`16`) | 0.1404 | 0.1379 | 0.0750 | 0.8504 | 0.16775 | 0.8195 | 0.0530 | 0.1379 | — |
| **`NoShortcut_Model_C_LSTM_Full`** | Seq No-Shortcut + Timing (`16`) | 0.1510 | 0.2171 | 0.1329 | 0.5921 | 0.06178 | 0.8617 | 0.0725 | 0.1656 | — |

---

## 3. Repository Structure

```text
C2_Reconnaissance_Detection/
├── configs/
│   └── default.yaml                 # Central configuration (paths, seed=42, hyperparams)
├── data/
│   ├── raw/                         # Read-only CSV conversions + SHA-256 manifest
│   ├── rebuilt_sequences/           # Chronologically rebuilt packets (597,135) & windows (119,237)
│   └── samples/                     # Sample JSON payloads for contract & API testing
├── src/
│   ├── common.py                    # Hashing, JSON serialization, seed & config utilities
│   ├── io_data.py                   # Safe loaders for original Dataset/ files
│   ├── convert_raw.py               # Stage 1: Convert Excel/CSV sources + verify SHA-256
│   ├── inspect_data.py              # Stage 2: Dataset profiling (dataset_profile.json)
│   ├── audit_sequences.py           # Stage 3: Audit corrupted recon_sequences_ALL (sequence_audit.json)
│   ├── audit_labels.py              # Stage 4: Audit attack_events_mapped & modbus_len==3 (label_audit.json)
│   ├── rebuild_sequences.py         # Stage 5: Deduplicate veth & rebuild chronological windows
│   ├── features.py                  # Stage 6: Packet (5), Sequence (19/17), & Window (29/21) features
│   ├── audit_leakage.py             # Stage 7: Quantify split overlap & shortcut leakage
│   ├── splits.py                    # Stage 8: Generate LOCGO-10 & SGKF-5 splits (folds.json)
│   ├── evaluate.py                  # Inner-val threshold selection & single-class-safe metrics
│   ├── baselines.py                 # Stage 9: Train & evaluate Models A1, A2, B1, B2
│   ├── train_lstm.py                # Stage 10: Train & evaluate PyTorch LSTM Models C & D
│   ├── ablations.py                 # Stage 11: Shortcut-removed, timing, leakage, & L=10/20/40 ablations
│   ├── latency.py                   # Stage 12: Single-window & batch latency benchmarks
│   ├── contract.py                  # C2InferenceEngine & shared JSON alert contract
│   ├── explain.py                   # Stage 13: Saliency attributions, metrics.json, & 6 plots
│   └── run_all.py                   # Master end-to-end execution script
├── backend/
│   └── app.py                       # FastAPI C2 service (/health, /model-info, /predict-window, etc.)
├── tests/
│   └── test_c2_pipeline.py          # 15-test automated verification suite (100% passing)
├── artifacts/                       # All JSON/CSV outputs, trained models, scalers, and plots
├── docs/                            # Comprehensive research & methodology documentation
├── requirements.txt
└── README.md
```

---

## 4. Reproducible Execution Instructions

### 4.1 Environment Setup (Windows PowerShell)
```powershell
cd d:\Github\IDS-4-Critical-Infrastructures_J26-CS-318\C2_Reconnaissance_Detection
python -m venv .venv
.\.venv\Scripts\pip.exe install -r requirements.txt
```

### 4.2 Run the Complete Research Pipeline End-to-End
```powershell
.\.venv\Scripts\python.exe -u src\run_all.py
```
To re-run only the post-processing, explainability, and plot generation without re-converting the raw `.xlsx` files:
```powershell
.\.venv\Scripts\python.exe -u src\explain.py
```

### 4.3 Run Automated Verification Tests (`pytest`)
```powershell
.\.venv\Scripts\pytest.exe -v tests\test_c2_pipeline.py
```

### 4.4 Launch the C2 FastAPI Integration Service
```powershell
.\.venv\Scripts\uvicorn.exe backend.app:app --host 127.0.0.1 --port 8002
```
Endpoints:
- `GET /health` — Service and model readiness check
- `GET /model-info` — Model metadata, feature schema, thresholds, and latency summary
- `GET /Metrics` — Summary of LOCGO-10 and SGKF-5 evaluation metrics
- `GET /sample-alert` — Example C2 reconnaissance alert contract
- `POST /predict-window` — Score a `20`-packet Modbus/TCP window (`model_family`: `"lstm"`, `"rf"`, or `"ensemble"`) and return behavioural indicators + top-attributed features and time steps

---

## 5. Documentation Index (`docs/`)

- [`docs/C2_SPEC.md`](docs/C2_SPEC.md) — Approved scope, research questions, and TAF/proposal alignment
- [`docs/C2_IMPLEMENTATION_PLAN.md`](docs/C2_IMPLEMENTATION_PLAN.md) — Architecture, module responsibilities, and execution workflow
- [`docs/C2_DATASET_AUDIT.md`](docs/C2_DATASET_AUDIT.md) — Hostile audit of raw packets, sequence corruption root cause, and label provenance
- [`docs/C2_LEAKAGE_AUDIT.md`](docs/C2_LEAKAGE_AUDIT.md) — Multi-interface duplication, stride overlap, identifier exclusion, and `modbus_len == 3` shortcut analysis
- [`docs/C2_EXPERIMENT_PROTOCOL.md`](docs/C2_EXPERIMENT_PROTOCOL.md) — `LOCGO-10` and `SGKF-5` cross-validation design, inner-validation thresholding, and single-class fold handling
- [`docs/C2_DECISIONS.md`](docs/C2_DECISIONS.md) — Methodological decision log (`D-01`..`D-10`)
- [`docs/C2_LITERATURE_MATRIX.md`](docs/C2_LITERATURE_MATRIX.md) — Grounded literature comparison matrix
- [`docs/C2_RESULTS.md`](docs/C2_RESULTS.md) — Full experimental results, RQ1 & RQ2 answers, ablations, latency, and sequence attributions
- [`docs/C2_CLAIM_LEDGER.md`](docs/C2_CLAIM_LEDGER.md) — Epistemic claim ledger (`Prior literature`, `Approved proposal / TAF`, `Implemented method`, `Observed result`, `Interpretation`, `Limitation`)
- [`docs/C2_LIMITATIONS.md`](docs/C2_LIMITATIONS.md) — Dataset, labelling, modelling, and operational limitations
