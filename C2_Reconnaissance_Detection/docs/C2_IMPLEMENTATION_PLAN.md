# C2 / RP2 — End-to-End Implementation & Execution Plan

## 1. Execution Phases

The C2 research component is engineered and executed in nine sequential, artifact-verified phases:

| Phase | Script / Module | Primary Outputs | Status |
| :--- | :--- | :--- | :--- |
| **Phase 0: Raw Data Protection & Conversion** | `src/convert_raw.py` | `data/raw/*.csv`, `data/raw/raw_manifest.json` | Completed & Verified |
| **Phase 1: Hostile Dataset & Sequence Audit** | `src/inspect_data.py`, `src/audit_sequences.py` | `artifacts/dataset_profile.json`, `artifacts/sequence_audit.json`, `artifacts/tables/*.csv` | Completed & Verified |
| **Phase 2: Ground-Truth Label Audit** | `src/audit_labels.py` | `artifacts/label_audit.json`, `artifacts/tables/positive_categories_by_file.csv` | Completed & Verified |
| **Phase 3: Chronological Sequence Reconstruction** | `src/rebuild_sequences.py` | `data/rebuilt_sequences/packets_rebuilt.csv`, `windows.csv`, `window_index.npy`, `artifacts/rebuild_report.json` | Completed & Verified |
| **Phase 4: Leakage Audit & Split Freeze** | `src/audit_leakage.py`, `src/splits.py`, `src/features.py` | `artifacts/leakage_audit.json`, `artifacts/folds.json`, `artifacts/feature_schema.json` | Completed & Verified |
| **Phase 5: Baseline Modelling (Models A & B)** | `src/baselines.py` | `artifacts/baseline_metrics.json`, `artifacts/baseline_oof_predictions.csv`, `artifacts/models/*.joblib` | Completed & Verified |
| **Phase 6: Temporal Sequence Modelling (Models C & D)** | `src/train_lstm.py` | `artifacts/lstm_metrics.json`, `artifacts/training_history.json`, `artifacts/lstm_oof_predictions.csv`, `artifacts/models/*.pt` | Executed |
| **Phase 7: Ablations, Latency & Explainability** | `src/ablations.py`, `src/latency.py`, `src/explain.py` | `artifacts/ablation_results.json`, `artifacts/latency.json`, `artifacts/metrics.json`, `artifacts/confusion.json`, `artifacts/curves.json`, `artifacts/example_sequences.json`, `artifacts/plots/*.png` | Executed |
| **Phase 8: Integration API & Automated Tests** | `src/contract.py`, `backend/app.py`, `tests/test_c2_pipeline.py` | FastAPI endpoints (`/health`, `/metrics`, `/examples`, `/predict`) + 16-category `pytest` suite | Executed |

---

## 2. Repository Architecture

```text
C2_Reconnaissance_Detection/
├── configs/
│   └── default.yaml                  # Frozen experiment configuration & capture group definitions
├── data/
│   ├── raw/                          # Streamed CSV working copies + SHA-256 manifest
│   ├── rebuilt_sequences/            # Deduplicated chronological packets (597,135) & windows (119,237)
│   └── samples/                      # Real extracted recon & normal 20-packet JSON windows for API testing
├── src/
│   ├── common.py                     # Path resolution, deterministic seeding, NaN-safe JSON serialization
│   ├── io_data.py                    # Read-only streaming OOXML (.xlsx) reader
│   ├── convert_raw.py                # One-time .xlsx -> .csv converter with checksum verification
│   ├── inspect_data.py               # Packet, sequence, and attack-event profiler
│   ├── audit_sequences.py            # Forensic audit of as-provided 175,800 sequences
│   ├── audit_labels.py               # Ground-truth alignment & positive signature categorizer
│   ├── rebuild_sequences.py          # Multi-interface deduplication & chronological window builder
│   ├── features.py                   # Causal per-packet, sequence (20x19), and window (29) feature extractors
│   ├── audit_leakage.py              # Overlap, identifier, and protocol-shortcut leakage quantifier
│   ├── splits.py                     # Zero-packet-overlap LOCGO-10, SGKF-5, Session-5, and Random-5 splits
│   ├── evaluate.py                   # Inner-val threshold selector, single-class safe metrics, ECE/Brier
│   ├── baselines.py                  # Model A (Packet LogReg/DT) & Model B (Window RF/LogReg)
│   ├── train_lstm.py                 # Model C (PyTorch LSTM Full) & Model D (PyTorch LSTM No-Timing)
│   ├── ablations.py                  # Shortcut-removal, timing, split-leakage, and window-length ablations
│   ├── latency.py                    # Warmup-controlled preprocessing, inference, and batch benchmarks
│   ├── contract.py                   # Standardized C2 JSON output contract & gradient attribution engine
│   ├── explain.py                    # Master artifact consolidator, occlusion analyser, and figure generator
│   └── run_all.py                    # Reproducible end-to-end pipeline runner
├── artifacts/
│   ├── models/                       # Saved PyTorch (.pt) and scikit-learn (.joblib) models
│   ├── preprocessing/                # Training-fitted SequenceScaler (.json) and StandardScaler (.joblib)
│   ├── plots/                        # 6 publication-quality Matplotlib figures (.png)
│   ├── tables/                       # Detailed CSV audit breakdowns
│   └── *.json / *.csv                # All machine-readable audit, fold, metric, curve, and latency artifacts
├── docs/                             # Comprehensive research & methodological documentation
├── backend/
│   └── app.py                        # Minimal FastAPI service (/health, /metrics, /examples, /predict)
├── tests/
│   └── test_c2_pipeline.py           # 16-category automated pytest suite
├── requirements.txt
└── README.md
```
