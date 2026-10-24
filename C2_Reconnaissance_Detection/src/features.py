"""Feature engineering for C2 (all features derived only from verified packet fields).

Three representations, all computed from the rebuilt packet table (stream-ordered):
  A. per-packet static protocol features      -> packet-level baseline (Model A)
  B. window-level aggregate features          -> non-temporal baseline (Model B)
  C. per-timestep sequence features (20 x F)   -> LSTM (Model C) / timing ablation (Model D)

Excluded on purpose (leakage / non-informative): src_ip, dst_ip, session_id, file_source,
capture_group, absolute timestamp, row_index, sequence_position, supplied time_delta (unreliable,
see rebuild_report.json), unit_id (constant = 1 in every packet).

Every 20-packet window is strictly self-contained: per-timestep transition features at t=0
(the first packet of the window) do not reference packet i_0 - 1 outside the window, ensuring
100% mathematical parity between batch training tensors and standalone 20-packet runtime inference.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

FC_CODES = [1, 2, 3, 4, 5, 6]
WRITE_FCS = {5, 6, 15, 16}
EPS_DT = 1e-6  # seconds; floor for log10 of inter-packet time

PACKET_FEATURES = ["func_code", "modbus_len", "register_start", "log_quantity", "packet_size"]

SEQ_FEATURES = (
    [f"fc_{c}" for c in FC_CODES]
    + ["fc_other"]
    + ["modbus_len", "register_start", "log_quantity", "packet_size"]
    + ["d_reg", "log_abs_d_reg", "seq_step", "back_step", "fc_change", "is_write"]
    + ["log_dt", "d_log_dt"]
)
SEQ_TIMING = ["log_dt", "d_log_dt"]
SEQ_FEATURES_NO_TIMING = [f for f in SEQ_FEATURES if f not in SEQ_TIMING]

WINDOW_FEATURES = (
    ["duration_s", "req_rate", "dt_mean", "dt_std", "dt_min", "dt_max", "dt_cv", "polling_drift"]
    + [
        "n_unique_fc",
        "n_unique_reg",
        "reg_range",
        "seq_step_ratio",
        "mean_abs_d_reg",
        "back_step_ratio",
        "fc_change_ratio",
        "log_qty_mean",
        "log_qty_max",
        "write_ratio",
        "modbus_len_mean",
        "modbus_len_min",
        "modbus_len_max",
        "packet_size_mean",
        "packet_size_max",
    ]
    + [f"fc_frac_{c}" for c in FC_CODES]
)
WINDOW_TIMING = [
    "duration_s",
    "req_rate",
    "dt_mean",
    "dt_std",
    "dt_min",
    "dt_max",
    "dt_cv",
    "polling_drift",
]
WINDOW_FEATURES_NO_TIMING = [f for f in WINDOW_FEATURES if f not in WINDOW_TIMING]

# Size / length shortcut ablation subsets (removing modbus_len and packet_size)
SHORTCUT_COLS_PACKET = ["modbus_len", "packet_size"]
SHORTCUT_COLS_SEQ = ["modbus_len", "packet_size"]
SHORTCUT_COLS_WINDOW = [
    "modbus_len_mean",
    "modbus_len_min",
    "modbus_len_max",
    "packet_size_mean",
    "packet_size_max",
]

PACKET_FEATURES_NO_SHORTCUT = [f for f in PACKET_FEATURES if f not in SHORTCUT_COLS_PACKET]
SEQ_FEATURES_NO_SHORTCUT = [f for f in SEQ_FEATURES if f not in SHORTCUT_COLS_SEQ]
SEQ_FEATURES_NO_SHORTCUT_NO_TIMING = [
    f for f in SEQ_FEATURES_NO_SHORTCUT if f not in SEQ_TIMING
]
WINDOW_FEATURES_NO_SHORTCUT = [f for f in WINDOW_FEATURES if f not in SHORTCUT_COLS_WINDOW]
WINDOW_FEATURES_NO_SHORTCUT_NO_TIMING = [
    f for f in WINDOW_FEATURES_NO_SHORTCUT if f not in WINDOW_TIMING
]

# As-provided 7-feature raw schema (excluding constant unit_id -> 6 active or all 7 as-provided)
AS_PROVIDED_7_FEATURES = [
    "unit_id",
    "func_code",
    "modbus_len",
    "register_start",
    "quantity",
    "packet_size",
    "time_delta",
]

FEATURE_DESCRIPTIONS = {
    "fc_k": "one-hot Modbus function code k (k in 1..6); fc_other for any other code",
    "modbus_len": "Modbus length field as parsed (verified column modbus_len)",
    "register_start": "starting register/coil address field (verified column register_start)",
    "log_quantity": "log1p(quantity field)",
    "packet_size": "frame size in bytes (verified column packet_size)",
    "d_reg": "register_start minus register_start of previous packet in the window (0 at t=0)",
    "log_abs_d_reg": "log1p(|d_reg|) (0 at t=0)",
    "seq_step": "1 if d_reg == +1 (sequential forward address step) else 0 (0 at t=0)",
    "back_step": "1 if d_reg < 0 (backward address step) else 0 (0 at t=0)",
    "fc_change": "1 if func_code differs from previous packet in the window else 0 (0 at t=0)",
    "is_write": "1 if func_code in {5,6,15,16} else 0",
    "log_dt": "log10(max(dt_s, 1e-6)); dt_s = recomputed inter-packet time (s) within window; "
    "NaN at t=0 (imputed to training mean 0.0 after standardisation)",
    "d_log_dt": "log_dt[t] minus log_dt[t-1] within window (NaN at t=0,1; imputed to 0.0 after standardisation)",
    "duration_s": "window end timestamp minus start timestamp (s)",
    "req_rate": "(L-1)/max(duration_s, 1e-6) packets per second",
    "dt_mean/std/min/max/cv": "statistics of the L-1 within-window inter-packet intervals; cv=std/mean",
    "polling_drift": "mean log_dt of second half of within-window intervals minus first half",
    "n_unique_fc/n_unique_reg": "distinct function codes / register addresses in window",
    "reg_range": "max(register_start)-min(register_start) in window",
    "seq_step_ratio/back_step_ratio/fc_change_ratio": "fraction of within-window steps (L-1) with that indicator",
    "mean_abs_d_reg": "mean |register step| over within-window steps (L-1)",
    "log_qty_mean/max": "mean/max of log1p(quantity) across the L packets",
    "write_ratio": "fraction of write function codes across the L packets",
    "modbus_len_mean/min/max, packet_size_mean/max": "window statistics of those fields",
    "fc_frac_k": "fraction of packets in window with function code k",
}


def packet_level_columns(r: pd.DataFrame) -> pd.DataFrame:
    """Add causal derived per-packet columns to the stream-ordered rebuilt packet table."""
    r = r.copy()
    g = r.groupby(["capture_group", "session_id"], sort=False)
    r["log_quantity"] = np.log1p(r.quantity.astype(float))
    prev_reg = g.register_start.shift()
    r["d_reg"] = (r.register_start - prev_reg).fillna(0.0)
    r["log_abs_d_reg"] = np.log1p(r.d_reg.abs())
    r["seq_step"] = (r.d_reg == 1).astype(float)
    r["back_step"] = (r.d_reg < 0).astype(float)
    prev_fc = g.func_code.shift()
    r["fc_change"] = ((r.func_code != prev_fc) & prev_fc.notna()).astype(float)
    r["is_write"] = r.func_code.isin(WRITE_FCS).astype(float)
    r["log_dt"] = np.log10(np.maximum(r.dt_s.astype(float), EPS_DT))  # NaN preserved for first packet
    r["d_log_dt"] = r.log_dt - r.groupby(["capture_group", "session_id"], sort=False).log_dt.shift()
    for c in FC_CODES:
        r[f"fc_{c}"] = (r.func_code == c).astype(float)
    r["fc_other"] = (~r.func_code.isin(FC_CODES)).astype(float)
    return r


def packet_matrix(r: pd.DataFrame, features: list[str] = PACKET_FEATURES) -> np.ndarray:
    if "log_quantity" not in r.columns:
        r = r.copy()
        r["log_quantity"] = np.log1p(r["quantity"].astype(float))
    return r[list(features)].to_numpy(dtype=np.float32)


def sequence_tensor(
    r: pd.DataFrame, I: np.ndarray, features: list[str] = SEQ_FEATURES
) -> np.ndarray:
    """Build (n_windows, L, F) sequence tensor with self-contained window boundary at t=0."""
    if "fc_1" not in r.columns:
        r = packet_level_columns(r)
    feat_list = list(features)
    M = r[feat_list].to_numpy(dtype=np.float32)
    X = M[I].copy()  # (n_windows, L, F)
    # Enforce window self-containment at t=0 (and t=1 for d_log_dt)
    zero_at_t0 = {"d_reg", "log_abs_d_reg", "seq_step", "back_step", "fc_change"}
    nan_at_t0 = {"log_dt", "d_log_dt"}
    for j, fname in enumerate(feat_list):
        if fname in zero_at_t0:
            X[:, 0, j] = 0.0
        elif fname in nan_at_t0:
            X[:, 0, j] = np.nan
            if fname == "d_log_dt" and X.shape[1] > 1:
                X[:, 1, j] = np.nan
    return X


def window_aggregates(r: pd.DataFrame, I: np.ndarray) -> pd.DataFrame:
    if "log_quantity" not in r.columns:
        r = r.copy()
        r["log_quantity"] = np.log1p(r["quantity"].astype(float))
    L = I.shape[1]
    ts = r.ts_ns.to_numpy(dtype=np.int64)[I]
    dts = np.diff(ts, axis=1) / 1e9  # (n, L-1) within-window intervals
    fc = r.func_code.to_numpy()[I]
    reg = r.register_start.to_numpy(dtype=float)[I]
    lq = r.log_quantity.to_numpy(dtype=float)[I]
    ml = r.modbus_len.to_numpy(dtype=float)[I]
    ps = r.packet_size.to_numpy(dtype=float)[I]
    dreg = np.diff(reg, axis=1)
    dur = (ts[:, -1] - ts[:, 0]) / 1e9
    ldt = np.log10(np.maximum(dts, EPS_DT))
    h = ldt.shape[1] // 2
    dmean = dts.mean(1)
    out = {
        "duration_s": dur,
        "req_rate": (L - 1) / np.maximum(dur, EPS_DT),
        "dt_mean": dmean,
        "dt_std": dts.std(1),
        "dt_min": dts.min(1),
        "dt_max": dts.max(1),
        "dt_cv": np.where(dmean > 0, dts.std(1) / np.maximum(dmean, 1e-12), 0.0),
        "polling_drift": ldt[:, h:].mean(1) - ldt[:, :h].mean(1),
        "n_unique_fc": (np.diff(np.sort(fc, axis=1), axis=1) != 0).sum(axis=1) + 1,
        "n_unique_reg": (np.diff(np.sort(reg, axis=1), axis=1) != 0).sum(axis=1) + 1,
        "reg_range": reg.max(1) - reg.min(1),
        "seq_step_ratio": (dreg == 1).mean(1),
        "mean_abs_d_reg": np.abs(dreg).mean(1),
        "back_step_ratio": (dreg < 0).mean(1),
        "fc_change_ratio": (np.diff(fc, axis=1) != 0).mean(1),
        "log_qty_mean": lq.mean(1),
        "log_qty_max": lq.max(1),
        "write_ratio": np.isin(fc, list(WRITE_FCS)).mean(1),
        "modbus_len_mean": ml.mean(1),
        "modbus_len_min": ml.min(1),
        "modbus_len_max": ml.max(1),
        "packet_size_mean": ps.mean(1),
        "packet_size_max": ps.max(1),
    }
    for c in FC_CODES:
        out[f"fc_frac_{c}"] = (fc == c).mean(1)
    df = pd.DataFrame(out)
    return df[WINDOW_FEATURES]


def extract_single_window_from_packets(
    packets: pd.DataFrame,
    seq_features: list[str] = SEQ_FEATURES,
) -> tuple[np.ndarray, pd.DataFrame, np.ndarray]:
    """Compute (1, L, F_seq), (1, F_win), and (L, F_pkt) directly from an L-row packet DataFrame.

    Expects columns: `func_code`, `modbus_len`, `register_start`, `quantity`, `packet_size`,
    and either `ts_ns` or `timestamp` (or `dt_s`).
    """
    df = packets.copy().reset_index(drop=True)
    if "ts_ns" not in df.columns or df["ts_ns"].isna().any():
        if "timestamp" in df.columns and df["timestamp"].notna().all():
            ts_parsed = pd.to_datetime(df["timestamp"], format="ISO8601", utc=True).dt.as_unit("ns")
            df["ts_ns"] = ts_parsed.astype("int64")
        elif "dt_s" in df.columns and df["dt_s"].iloc[1:].notna().all():
            dts = df["dt_s"].fillna(0.0).to_numpy(dtype=np.float64)
            df["ts_ns"] = np.cumsum(np.r_[0.0, dts[1:]] * 1e9).astype(np.int64)
        else:
            raise ValueError("Packet sequence requires 'ts_ns', 'timestamp', or 'dt_s'.")
    else:
        df["ts_ns"] = df["ts_ns"].astype("int64")

    if "dt_s" not in df.columns or df["dt_s"].iloc[1:].isna().any():
        ts = df["ts_ns"].to_numpy(dtype=np.int64)
        dt_s = np.empty(len(df), dtype=np.float64)
        dt_s[0] = np.nan
        dt_s[1:] = np.diff(ts) / 1e9
        df["dt_s"] = dt_s
    else:
        df["dt_s"] = df["dt_s"].astype(float)
    if "capture_group" not in df.columns:
        df["capture_group"] = "runtime"
    if "session_id" not in df.columns:
        df["session_id"] = "runtime"

    df_cols = packet_level_columns(df)
    I = np.arange(len(df), dtype=np.int64).reshape(1, -1)
    X_seq = sequence_tensor(df_cols, I, features=seq_features)
    X_win = window_aggregates(df_cols, I)
    X_pkt = packet_matrix(df_cols, features=PACKET_FEATURES)
    return X_seq, X_win, X_pkt


class SequenceScaler:
    """Per-feature standardisation fitted on TRAINING windows only; NaN -> 0 (= training mean)."""

    def __init__(self, features):
        self.features = list(features)
        self.mean_ = None
        self.std_ = None

    def fit(self, X: np.ndarray):
        flat = X.reshape(-1, X.shape[-1]).astype(np.float64)
        self.mean_ = np.nanmean(flat, axis=0)
        std = np.nanstd(flat, axis=0)
        self.std_ = np.where(std > 1e-12, std, 1.0)
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        Z = (X - self.mean_.astype(np.float32)) / self.std_.astype(np.float32)
        return np.nan_to_num(Z, nan=0.0).astype(np.float32)

    def state(self) -> dict:
        return {
            "features": self.features,
            "mean": self.mean_.tolist(),
            "std": self.std_.tolist(),
        }

    @classmethod
    def from_state(cls, st: dict):
        s = cls(st["features"])
        s.mean_ = np.array(st["mean"])
        s.std_ = np.array(st["std"])
        return s


def get_feature_schema() -> dict[str, Any]:
    return {
        "packet_features": {
            "count": len(PACKET_FEATURES),
            "names": PACKET_FEATURES,
            "no_shortcut_names": PACKET_FEATURES_NO_SHORTCUT,
        },
        "sequence_features": {
            "count": len(SEQ_FEATURES),
            "names": SEQ_FEATURES,
            "timing_features": SEQ_TIMING,
            "no_timing_names": SEQ_FEATURES_NO_TIMING,
            "no_shortcut_names": SEQ_FEATURES_NO_SHORTCUT,
            "no_shortcut_no_timing_names": SEQ_FEATURES_NO_SHORTCUT_NO_TIMING,
        },
        "window_aggregate_features": {
            "count": len(WINDOW_FEATURES),
            "names": WINDOW_FEATURES,
            "timing_features": WINDOW_TIMING,
            "no_timing_names": WINDOW_FEATURES_NO_TIMING,
            "no_shortcut_names": WINDOW_FEATURES_NO_SHORTCUT,
            "no_shortcut_no_timing_names": WINDOW_FEATURES_NO_SHORTCUT_NO_TIMING,
        },
        "as_provided_7_features": AS_PROVIDED_7_FEATURES,
        "excluded_columns": [
            "row_index",
            "timestamp",
            "ts_ns",
            "src_ip",
            "dst_ip",
            "session_id",
            "sequence_position",
            "file_source",
            "capture_group",
            "unit_id",
            "time_delta (as-provided broken column; replaced by causal stream dt_s -> log_dt)",
        ],
        "feature_descriptions": FEATURE_DESCRIPTIONS,
    }
