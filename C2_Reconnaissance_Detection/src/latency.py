"""Latency and operational throughput benchmarking for C2 (Section 21).

Measures after warmup (`n_warmup = 50`, `n_trials = 500` single windows):
1. Single-window feature extraction + scaling latency (ms)
2. Single-window model inference latency (ms) for Models A1, A2, B1, C, D
3. Single-window end-to-end latency (raw 20-packet table -> scaled tensor -> model score -> alert contract)
4. Batch inference latency and throughput across batch sizes {1, 32, 256, 1024}
5. Explicit verification against the < 100 ms per-sequence proposal target.
"""
from __future__ import annotations

import platform
import time
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch

from common import ARTIFACTS, DATA_REBUILT, read_json, write_json
from features import (
    PACKET_FEATURES,
    SEQ_FEATURES,
    SEQ_FEATURES_NO_TIMING,
    WINDOW_FEATURES,
    SequenceScaler,
    extract_single_window_from_packets,
    packet_level_columns,
    packet_matrix,
    sequence_tensor,
    window_aggregates,
)
from train_lstm import ModbusReconLSTM


def _stats_ms(times_ms: list[float] | np.ndarray) -> dict[str, float]:
    arr = np.asarray(times_ms, dtype=np.float64)
    return {
        "n_runs": int(len(arr)),
        "mean_ms": float(arr.mean()),
        "std_ms": float(arr.std(ddof=0)),
        "median_ms": float(np.median(arr)),
        "p95_ms": float(np.percentile(arr, 95)),
        "p99_ms": float(np.percentile(arr, 99)),
        "min_ms": float(arr.min()),
        "max_ms": float(arr.max()),
        "meets_100ms_target_p99": bool(np.percentile(arr, 99) < 100.0),
    }


def load_saved_lstm(prefix: str) -> tuple[ModbusReconLSTM, SequenceScaler, float]:
    ckpt = torch.load(ARTIFACTS / "models" / f"{prefix}.pt", map_location="cpu", weights_only=False)
    model = ModbusReconLSTM(
        input_dim=ckpt["input_dim"],
        hidden1=ckpt["hidden1"],
        hidden2=ckpt["hidden2"],
        dense_dim=ckpt["dense_dim"],
        dropout=ckpt["dropout"],
    )
    model.load_state_dict(ckpt["model_state_dict"])
    model.eval()
    scaler_st = read_json(ARTIFACTS / "preprocessing" / f"{prefix}_scaler.json")
    scaler = SequenceScaler.from_state(scaler_st)
    return model, scaler, float(ckpt.get("operational_threshold", 0.5))


def main() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")

    # Load saved models
    clf_a_lr = joblib.load(ARTIFACTS / "models" / "model_a_packet_logreg.joblib")
    sc_a_lr = joblib.load(ARTIFACTS / "preprocessing" / "model_a_packet_logreg_scaler.joblib")
    clf_a_dt = joblib.load(ARTIFACTS / "models" / "model_a_packet_dt.joblib")
    sc_a_dt = joblib.load(ARTIFACTS / "preprocessing" / "model_a_packet_dt_scaler.joblib")
    clf_b_rf = joblib.load(ARTIFACTS / "models" / "model_b_window_rf.joblib")
    clf_b_rf.n_jobs = 1
    sc_b_rf = joblib.load(ARTIFACTS / "preprocessing" / "model_b_window_rf_scaler.joblib")

    lstm_c, sc_c, thr_c = load_saved_lstm("model_c_lstm_full")
    lstm_d, sc_d, thr_d = load_saved_lstm("model_d_lstm_no_timing")

    # Select 550 representative 20-packet windows (50 warmup + 500 timed)
    rng = np.random.default_rng(42)
    sample_win_ids = rng.choice(len(idx_mat), size=550, replace=False)
    raw_cols = ["timestamp", "ts_ns", "dt_s", "func_code", "modbus_len", "register_start", "quantity", "packet_size"]
    sample_packet_dfs = [r.iloc[idx_mat[w]][raw_cols].copy() for w in sample_win_ids]

    n_warmup = 50
    # Warmup
    for i in range(n_warmup):
        X_seq, X_win, X_pkt = extract_single_window_from_packets(sample_packet_dfs[i])
        Z_c = sc_c.transform(X_seq)
        with torch.no_grad():
            _ = torch.sigmoid(lstm_c.forward_logits(torch.from_numpy(Z_c))).item()
        _ = clf_b_rf.predict_proba(sc_b_rf.transform(X_win.to_numpy(dtype=np.float32)))

    prep_seq_ms = []
    prep_win_ms = []
    inf_a_lr_ms = []
    inf_a_dt_ms = []
    inf_b_rf_ms = []
    inf_c_lstm_ms = []
    inf_d_lstm_ms = []
    e2e_b_rf_ms = []
    e2e_c_lstm_ms = []

    for i in range(n_warmup, len(sample_packet_dfs)):
        pkt_df = sample_packet_dfs[i]

        # Measure feature extraction + scaling
        t0 = time.perf_counter()
        X_seq_c, X_win, X_pkt = extract_single_window_from_packets(pkt_df, seq_features=SEQ_FEATURES)
        Z_c = sc_c.transform(X_seq_c)
        t1 = time.perf_counter()
        prep_ms = (t1 - t0) * 1000.0
        prep_seq_ms.append(prep_ms)

        t_w0 = time.perf_counter()
        Z_win = sc_b_rf.transform(X_win[WINDOW_FEATURES].to_numpy(dtype=np.float32))
        t_w1 = time.perf_counter()
        prep_win_ms.append(prep_ms + (t_w1 - t_w0) * 1000.0)

        # Model C LSTM inference
        t_c0 = time.perf_counter()
        with torch.no_grad():
            score_c = float(torch.sigmoid(lstm_c.forward_logits(torch.from_numpy(Z_c))).item())
        t_c1 = time.perf_counter()
        c_ms = (t_c1 - t_c0) * 1000.0
        inf_c_lstm_ms.append(c_ms)
        e2e_c_lstm_ms.append(prep_ms + c_ms)

        # Model D LSTM No-Timing inference
        X_seq_d = X_seq_c[:, :, [SEQ_FEATURES.index(f) for f in SEQ_FEATURES_NO_TIMING]]
        Z_d = sc_d.transform(X_seq_d)
        t_d0 = time.perf_counter()
        with torch.no_grad():
            _ = float(torch.sigmoid(lstm_d.forward_logits(torch.from_numpy(Z_d))).item())
        t_d1 = time.perf_counter()
        inf_d_lstm_ms.append((t_d1 - t_d0) * 1000.0)

        # Model B RF inference
        t_b0 = time.perf_counter()
        _ = float(clf_b_rf.predict_proba(Z_win)[0, 1])
        t_b1 = time.perf_counter()
        b_ms = (t_b1 - t_b0) * 1000.0
        inf_b_rf_ms.append(b_ms)
        e2e_b_rf_ms.append(prep_win_ms[-1] + b_ms)

        # Model A1 Packet LogReg inference
        Z_pkt_lr = sc_a_lr.transform(X_pkt)
        t_alr0 = time.perf_counter()
        _ = float(clf_a_lr.predict_proba(Z_pkt_lr)[:, 1].max())
        t_alr1 = time.perf_counter()
        inf_a_lr_ms.append((t_alr1 - t_alr0) * 1000.0)

        # Model A2 Packet DT inference
        Z_pkt_dt = sc_a_dt.transform(X_pkt)
        t_adt0 = time.perf_counter()
        _ = float(clf_a_dt.predict_proba(Z_pkt_dt)[:, 1].max())
        t_adt1 = time.perf_counter()
        inf_a_dt_ms.append((t_adt1 - t_adt0) * 1000.0)

    # Batch throughput benchmark on pre-extracted tensors
    r_cols = packet_level_columns(r)
    X_seq_all = sc_c.transform(sequence_tensor(r_cols, idx_mat[:4096], features=SEQ_FEATURES))
    X_win_all = sc_b_rf.transform(
        window_aggregates(r_cols, idx_mat[:4096])[WINDOW_FEATURES].to_numpy(dtype=np.float32)
    )

    batch_benchmarks = {}
    for bsz in [1, 32, 256, 1024]:
        bx_seq = torch.from_numpy(X_seq_all[:bsz])
        bx_win = X_win_all[:bsz]
        # Warmup
        for _ in range(5):
            with torch.no_grad():
                _ = torch.sigmoid(lstm_c.forward_logits(bx_seq))
            _ = clf_b_rf.predict_proba(bx_win)

        lstm_b_times = []
        rf_b_times = []
        for _ in range(30):
            t0 = time.perf_counter()
            with torch.no_grad():
                _ = torch.sigmoid(lstm_c.forward_logits(bx_seq)).numpy()
            lstm_b_times.append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            _ = clf_b_rf.predict_proba(bx_win)
            rf_b_times.append((time.perf_counter() - t0) * 1000.0)

        mean_lstm_b = float(np.mean(lstm_b_times))
        mean_rf_b = float(np.mean(rf_b_times))
        batch_benchmarks[f"batch_{bsz}"] = {
            "batch_size": bsz,
            "Model_C_LSTM_batch_mean_ms": mean_lstm_b,
            "Model_C_LSTM_per_window_ms": mean_lstm_b / bsz,
            "Model_C_LSTM_throughput_windows_per_sec": float(bsz / (mean_lstm_b / 1000.0)),
            "Model_B_RF_batch_mean_ms": mean_rf_b,
            "Model_B_RF_per_window_ms": mean_rf_b / bsz,
            "Model_B_RF_throughput_windows_per_sec": float(bsz / (mean_rf_b / 1000.0)),
        }

    latency_report = {
        "hardware_and_environment": {
            "os": platform.platform(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "torch_version": torch.__version__,
            "device": "cpu",
            "n_warmup_windows": n_warmup,
            "n_timed_windows": len(sample_packet_dfs) - n_warmup,
        },
        "proposal_target_ms": 100.0,
        "single_window_preprocessing_ms": {
            "sequence_feature_extraction_and_scaling": _stats_ms(prep_seq_ms),
            "window_aggregate_extraction_and_scaling": _stats_ms(prep_win_ms),
        },
        "single_window_inference_only_ms": {
            "Model_A_Packet_LogReg": _stats_ms(inf_a_lr_ms),
            "Model_A_Packet_DT": _stats_ms(inf_a_dt_ms),
            "Model_B_Window_RF": _stats_ms(inf_b_rf_ms),
            "Model_C_LSTM_Full": _stats_ms(inf_c_lstm_ms),
            "Model_D_LSTM_NoTiming": _stats_ms(inf_d_lstm_ms),
        },
        "single_window_end_to_end_ms": {
            "Model_B_Window_RF": _stats_ms(e2e_b_rf_ms),
            "Model_C_LSTM_Full": _stats_ms(e2e_c_lstm_ms),
        },
        "batch_inference_benchmarks": batch_benchmarks,
    }

    write_json(latency_report, ARTIFACTS / "latency.json")
    print("Saved artifacts/latency.json")
    print(
        "Single-window End-to-End LSTM (ms):",
        latency_report["single_window_end_to_end_ms"]["Model_C_LSTM_Full"],
    )
    print(
        "Single-window End-to-End RF (ms):",
        latency_report["single_window_end_to_end_ms"]["Model_B_Window_RF"],
    )


if __name__ == "__main__":
    main()
