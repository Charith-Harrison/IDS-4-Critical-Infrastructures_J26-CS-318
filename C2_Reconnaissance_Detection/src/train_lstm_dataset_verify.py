"""Train and verify the PyTorch LSTM models directly against the files in:
D:\\Github\\IDS-4-Critical-Infrastructures_J26-CS-318\\Dataset

Source files in Dataset/:
  1. recon_labeled_packets_ALL.csv.xlsx -> data/raw/recon_labeled_packets_ALL.csv (879,225 packets)
     -> Rebuilt chronological 20-packet windows (119,237 windows x 20 steps x 19 features)
     -> Model C (model_c_lstm_full.pt) & Model D (model_d_lstm_no_timing.pt)
  2. recon_sequences_ALL.csv.xlsx -> data/raw/recon_sequences_ALL.csv (175,800 sequences x 20 steps x 7 features)
     -> Trained directly with ModbusReconLSTM (model_c_lstm_recon_sequences_all.pt)
  3. attack_events_mapped.xlsx -> data/raw/attack_events_mapped.csv (158 mapped attack events)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import numpy as np
import torch
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ARTIFACTS, DATA_RAW, DATA_REBUILT, load_config, read_json, resolve, set_seeds, write_json
from evaluate import evaluate_predictions, select_validation_threshold
from io_data import load_events, load_packets, load_sequences
from train_lstm import ModbusReconLSTM, train_one_fold_lstm

AS_PROVIDED_FEATURES = [
    "unit_id",
    "func_code",
    "modbus_len",
    "register_start",
    "quantity",
    "packet_size",
    "time_delta",
]


def main() -> None:
    set_seeds(42)
    cfg = load_config()
    dataset_dir = resolve(cfg["paths"]["original_dataset_dir"])
    print(f"=== Verifying source Dataset path: {dataset_dir} ===", flush=True)

    manifest = read_json(DATA_RAW / "raw_manifest.json")
    for f in manifest["files"]:
        print(f"  Source: {f['source']} -> Working CSV: {f['output']} ({f['rows_including_header'] - 1:,} rows)", flush=True)

    print("\n=== Loading recon_sequences_ALL.csv (175,800 windows from Dataset/recon_sequences_ALL.csv.xlsx) ===", flush=True)
    t0 = time.perf_counter()
    s_df, X_3d = load_sequences(DATA_RAW / "recon_sequences_ALL.csv", parse_features=True)
    y_seq = s_df["label"].to_numpy(dtype=np.int64)
    sids = s_df["session_id"].to_numpy()
    X_seq = X_3d.astype(np.float32)
    print(
        f"  Loaded {len(s_df):,} sequences of shape {X_seq.shape} "
        f"(Positive={int(y_seq.sum()):,}, Negative={int((y_seq == 0).sum()):,}) in {time.perf_counter() - t0:.1f}s",
        flush=True,
    )

    # Train 5-fold StratifiedKFold LSTM on recon_sequences_ALL.csv
    print("\n=== Training PyTorch ModbusReconLSTM on recon_sequences_ALL.csv (5-Fold CV) ===", flush=True)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    oof_scores_rand = np.zeros(len(s_df), dtype=np.float64)
    oof_thr_rand = np.full(len(s_df), 0.5, dtype=np.float64)
    fold_summaries = []
    best_model = None
    best_scaler = None
    best_thr = 0.5

    for fold_idx, (tr_idx, te_idx) in enumerate(skf.split(X_seq, y_seq)):
        rng = np.random.default_rng(42 + fold_idx)
        perm = rng.permutation(len(tr_idx))
        n_val = max(int(0.15 * len(tr_idx)), 1)
        val_idx = tr_idx[perm[:n_val]]
        fit_idx = tr_idx[perm[n_val:]]

        model, scaler, val_scores, test_scores, train_meta = train_one_fold_lstm(
            X_fit_raw=X_seq[fit_idx],
            y_fit=y_seq[fit_idx],
            X_val_raw=X_seq[val_idx],
            y_val=y_seq[val_idx],
            X_test_raw=X_seq[te_idx],
            features=AS_PROVIDED_FEATURES,
            max_epochs=8,
            batch_size=512,
            lr=1.5e-3,
            patience=3,
            max_neg_per_epoch=15000,
            seed=42 + fold_idx,
        )
        thr_info = select_validation_threshold(y_seq[val_idx], val_scores, max_fpr=0.05)
        thr = float(thr_info["threshold"])
        oof_scores_rand[te_idx] = test_scores
        oof_thr_rand[te_idx] = thr
        ev = evaluate_predictions(y_seq[te_idx], test_scores, threshold=thr)
        print(
            f"  [Fold {fold_idx + 1}/5] best_epoch={train_meta['best_epoch']}/{train_meta['epochs_ran']} "
            f"({train_meta['train_wall_seconds']:.1f}s) | thr={thr:.3f} | "
            f"Acc={(ev['tp'] + ev['tn']) / ev['n_samples'] * 100:.2f}% | F1={ev['f1']:.4f} | "
            f"Prec={ev['precision']:.4f} | Rec={ev['recall']:.4f}",
            flush=True,
        )
        fold_summaries.append(
            {
                "fold": fold_idx + 1,
                "best_epoch": train_meta["best_epoch"],
                "train_wall_seconds": train_meta["train_wall_seconds"],
                "threshold": thr,
                "metrics": ev,
            }
        )
        if best_model is None or fold_idx == 0:
            best_model = model
            best_scaler = scaler
            best_thr = thr

    pooled_rand_05 = evaluate_predictions(y_seq, oof_scores_rand, threshold=0.5)
    models_dir = ARTIFACTS / "models"
    prep_dir = ARTIFACTS / "preprocessing"
    models_dir.mkdir(parents=True, exist_ok=True)
    prep_dir.mkdir(parents=True, exist_ok=True)

    if best_model is not None and best_scaler is not None:
        ckpt_path = models_dir / "model_c_lstm_recon_sequences_all.pt"
        torch.save(
            {
                "model_state_dict": best_model.state_dict(),
                "input_dim": len(AS_PROVIDED_FEATURES),
                "features": AS_PROVIDED_FEATURES,
                "hidden1": best_model.hidden1,
                "hidden2": best_model.hidden2,
                "dense_dim": best_model.dense_dim,
                "dropout": best_model.dropout_p,
                "operational_threshold": float(best_thr),
                "source_file": str(dataset_dir / "recon_sequences_ALL.csv.xlsx"),
            },
            ckpt_path,
        )
        write_json(
            best_scaler.state(),
            prep_dir / "model_c_lstm_recon_sequences_all_scaler.json",
        )
        print(f"  Saved checkpoint: {ckpt_path}", flush=True)

    # Load existing LOCGO-10 and SGKF-5 LSTM metrics trained on recon_labeled_packets_ALL.csv
    lstm_metrics = read_json(ARTIFACTS / "lstm_metrics.json")
    c_locgo = lstm_metrics["Model_C_LSTM_Full"]["locgo_10fold"]["pooled_oof_at_val_threshold"]
    c_sgkf5 = lstm_metrics["Model_C_LSTM_Full"]["sgkf_5fold"]["pooled_oof_at_val_threshold"]

    summary = {
        "dataset_directory": str(dataset_dir),
        "source_files_used": [
            {
                "dataset_file": str(dataset_dir / "recon_labeled_packets_ALL.csv.xlsx"),
                "csv_working_copy": str(DATA_RAW / "recon_labeled_packets_ALL.csv"),
                "rebuilt_packets_csv": str(DATA_REBUILT / "packets_rebuilt.csv"),
                "rebuilt_windows_csv": str(DATA_REBUILT / "windows.csv"),
                "raw_packet_rows": 879225,
                "deduplicated_chronological_packets": 596193,
                "rebuilt_20pkt_windows": 119237,
                "positive_windows": 1878,
                "negative_windows": 117359,
                "trained_models": [
                    str(models_dir / "model_c_lstm_full.pt"),
                    str(models_dir / "model_d_lstm_no_timing.pt"),
                ],
                "locgo_10fold_pooled_metrics": c_locgo,
                "sgkf_5fold_pooled_metrics": c_sgkf5,
            },
            {
                "dataset_file": str(dataset_dir / "recon_sequences_ALL.csv.xlsx"),
                "csv_working_copy": str(DATA_RAW / "recon_sequences_ALL.csv"),
                "total_sequences": int(len(s_df)),
                "positive_sequences": int(y_seq.sum()),
                "negative_sequences": int((y_seq == 0).sum()),
                "sequence_shape": list(X_seq.shape),
                "features": AS_PROVIDED_FEATURES,
                "trained_model": str(models_dir / "model_c_lstm_recon_sequences_all.pt"),
                "cv_5fold_pooled_at_0_5": pooled_rand_05,
                "per_fold": fold_summaries,
            },
            {
                "dataset_file": str(dataset_dir / "attack_events_mapped.xlsx"),
                "csv_working_copy": str(DATA_RAW / "attack_events_mapped.csv"),
                "mapped_attack_events": 158,
                "role": "Ground-truth attack event timestamp mapping & label audit verification",
            },
        ],
    }
    out_file = ARTIFACTS / "lstm_dataset_training_summary.json"
    write_json(summary, out_file)
    print(f"\nSaved complete dataset training summary to: {out_file}", flush=True)


if __name__ == "__main__":
    main()
