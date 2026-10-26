"""Frozen Component 2 inference pipeline for the offline demo (no PyTorch, no Docker).

request table (CSV/Parquet) -> schema validation -> run + client/target stream -> chronological order
-> frozen per-step features (component2_testbed/c2tb/model_data.py) -> causal last-20 contexts
-> frozen B3 history statistics (c2tb/diagnostics.build_contexts) -> frozen representations/scaling
(c2tb/representations.py) -> frozen models (RF joblib files; LSTM forward pass in NumPy with the exported
frozen weights) -> per-request recon scores and alerts at the frozen thresholds.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "component2_testbed"))

from c2tb import model_data  # noqa: E402  (frozen feature engineering)
from c2tb.diagnostics import build_contexts  # noqa: E402  (frozen B3 statistics)
from c2tb.representations import rep, scale, seq  # noqa: E402  (frozen representations)

BUNDLE = REPO / "C2_Reconnaissance_Detection" / "demo_bundle"
MODELS = ["A", "B1", "B2", "B3", "L"]
REQUIRED = ["src_ip", "dst_ip", "unit", "wire_fc", "address", "quantity", "mbap_len", "frame_len"]
INT_COLS = ["unit", "wire_fc", "address", "quantity", "mbap_len", "frame_len"]


class SchemaError(ValueError):
    pass


def validate(df: pd.DataFrame) -> pd.DataFrame:
    missing = [c for c in REQUIRED if c not in df]
    if "ts_corr_ns" not in df and "ts_ns" not in df:
        missing.append("ts_corr_ns (or ts_ns)")
    if missing:
        raise SchemaError(f"missing columns: {', '.join(missing)}")
    df = df.copy()
    if "ts_corr_ns" not in df:
        df["ts_corr_ns"] = df["ts_ns"]
    df["run_id"] = df["run_id"].astype(str) if "run_id" in df else "upload"
    if "frame_number" not in df:
        df["frame_number"] = np.arange(1, len(df) + 1)
    if "adu_id" not in df:
        df["adu_id"] = df.run_id + ":" + df.frame_number.astype(str)
    for c in INT_COLS + ["frame_number", "ts_corr_ns"]:
        try:
            df[c] = pd.to_numeric(df[c], errors="raise").astype("int64")
        except (ValueError, TypeError) as e:
            raise SchemaError(f"column {c} must be integer: {e}") from e
    if not df.wire_fc.isin([1, 2, 3, 4]).all():
        raise SchemaError("wire_fc must be a Modbus read function 1-4 (requests only)")
    if (df.quantity <= 0).any():
        raise SchemaError("quantity must be > 0")
    if df.adu_id.duplicated().any():
        raise SchemaError("adu_id must be unique")
    df["src_ip"], df["dst_ip"] = df.src_ip.astype(str), df.dst_ip.astype(str)
    return df


def lstm_forward(S: np.ndarray, w: dict) -> np.ndarray:
    """Single-layer LSTM (PyTorch gate order i, f, g, o), last step -> linear head -> sigmoid. Dropout is inactive
    at inference, exactly as in torch eval mode."""
    n, T, _ = S.shape
    H = int(w["hidden"])
    h = np.zeros((n, H), np.float32)
    c = np.zeros((n, H), np.float32)
    sig = lambda z: 1.0 / (1.0 + np.exp(-z))
    for t in range(T):
        g = S[:, t] @ w["w_ih"].T + w["b_ih"] + h @ w["w_hh"].T + w["b_hh"]
        i, f, gg, o = np.split(g, 4, axis=1)
        c = sig(f) * c + sig(i) * np.tanh(gg)
        h = sig(o) * np.tanh(c)
    z = h @ w["head_w"].T + w["head_b"]
    return sig(z[:, 0]).astype(np.float64)


class FrozenPipeline:
    def __init__(self, bundle: Path = BUNDLE):
        self.bundle = bundle
        d = bundle / "models"
        self.rf = {m: joblib.load(d / f"model_{m}.joblib") for m in ["A", "B1", "B2", "B3"]}
        z = np.load(d / "model_L_weights.npz")
        self.lstm = {k: z[k].astype(np.float32) if k != "hidden" else int(z[k]) for k in z.files}
        self.thresholds = json.loads((d / "thresholds.json").read_text())

    def score(self, raw: pd.DataFrame) -> pd.DataFrame:
        df = validate(raw)
        df = df.sort_values(["run_id", "src_ip", "dst_ip", "ts_corr_ns", "frame_number"]).reset_index(drop=True)
        X, segment = model_data.step_features(df)
        W = model_data.windows(segment)
        parts = []
        for _, g in df.groupby("run_id", sort=False):
            h, _ = build_contexts(g.reset_index(drop=True))
            parts.append(h[["adu_id"] + [c for c in h if c.startswith("h_")]])
        b3 = df[["adu_id"]].merge(pd.concat(parts), on="adu_id", how="left")
        B3 = b3.drop(columns="adu_id").to_numpy(np.float32)
        rows = np.arange(len(df))
        out = df[["run_id", "adu_id", "src_ip", "dst_ip", "ts_corr_ns", "frame_number"]].copy()
        for m in ["A", "B1", "B2", "B3"]:
            out[m] = np.concatenate([self.rf[m].predict_proba(rep(m, X, W, B3, rows[i:i + 20000]))[:, 1]
                                     for i in range(0, len(rows), 20000)])
        mu, sd = self.lstm["mu"], self.lstm["sd"]
        out["L"] = np.concatenate([lstm_forward(scale(seq(X, W, rows[i:i + 20000]), mu, sd), self.lstm)
                                   for i in range(0, len(rows), 20000)])
        for m in MODELS:
            out[f"alert_{m}"] = out[m] > self.thresholds[m]
        out["full_context"] = (W >= 0).all(axis=1)
        for c in b3.columns[1:]:
            out[c] = b3[c].to_numpy()
        return out
