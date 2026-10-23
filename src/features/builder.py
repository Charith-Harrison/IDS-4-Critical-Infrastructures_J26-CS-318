"""Stat-free feature construction (isolated, protocol, pair, context).

Everything here uses only the CURRENT event plus PAST events of the same
stream (capture, source, destination). Nothing is fitted, so it can be run on
any partition without leaking statistics. Features that need training-derived
values (normal-access profile, value ranges, clipping) live in profile.py.

Encoding note: -1 means "not applicable / unavailable" for flag-like and
duration-like values (documented in docs/data_dictionary.md).
"""

from __future__ import annotations

import warnings

import numpy as np
import pandas as pd

from src.utils.config import COIL_FUNCTIONS

K_WINDOW = 5  # number of previous events in short context windows
KNOWN_FC = {1, 2, 3, 4, 5, 6, 15, 16}
STREAM = ["capture_id", "src_ip", "dst_ip"]  # context never crosses a stream

# Feature groups (configurable). BASELINE+PROTOCOL = current-event only.
FEATURE_GROUPS: dict[str, list[str]] = {
    "BASELINE": [
        "func_code",
        "ref_num",
        "word_cnt",
        "bit_cnt",
        "write_value",
        "frame_len",
        "payload_len",
        "mbtcp_len",
        "unit_id",
        "tcp_syn",
        "tcp_ack",
        "tcp_fin",
        "tcp_rst",
        "tcp_psh",
    ],
    "PROTOCOL": [
        "is_write",
        "is_coil_op",
        "is_known_fc",
        "proto_id_valid",
        "length_consistent",
        "len_discrepancy",
        "has_stacked_frames",
    ],
    "PAIR": [
        "pair_found",
        "pair_status_code",
        "response_missing",
        "unit_id_match",
        "function_code_match",
        "address_match",
        "quantity_match",
        "value_echo_match",
        "response_delay",
        "response_exception",
        "response_length_valid",
    ],
    "SEQUENCE": [
        "first_in_stream",
        "prev_fc",
        "prev_is_write",
        "prev_ref",
        "read_to_write",
        "write_to_write",
        "same_ref_as_prev",
        "writes_prev_k",
        "reads_prev_k",
        "distinct_fc_prev_k",
        "distinct_ref_prev_k",
        "same_ref_writes_prev_k",
    ],
    "ACCESS": [
        "access_combo_unseen",
        "access_combo_normal_count_log",
        "access_write_unseen",
    ],
    "VALUE": [
        "prev_value_same_ref",
        "value_delta",
        "value_changed",
        "value_rate",
        "value_outside_normal_range",
    ],
    "RATE": [
        "iat",
        "iat_mean_prev_k",
        "iat_min_prev_k",
        "events_last_1s",
        "events_last_10s",
        "writes_last_1s",
        "time_since_last_write",
        "time_since_last_read",
    ],
}
ISOLATED_GROUPS = ["BASELINE", "PROTOCOL"]
CONTEXT_GROUPS = ISOLATED_GROUPS + ["PAIR", "SEQUENCE", "ACCESS", "VALUE", "RATE"]
# Context features that need fold-fitted statistics (profile.py).
# Features constant by construction of the pairing key (excluded, documented).


def group_features(groups: list[str]) -> list[str]:
    """Flatten feature names for the requested groups, preserving order."""
    return [f for g in groups for f in FEATURE_GROUPS[g]]


def _shift(a: np.ndarray, k: int, fill: float = np.nan) -> np.ndarray:
    """Shift array down by k (past values), padding with *fill*."""
    out = np.full(a.shape, fill, dtype="float64")
    if k < len(a):
        out[k:] = a[:-k] if k else a
    return out


def _distinct(stack: np.ndarray) -> np.ndarray:
    """Count distinct non-NaN values per row of a 2-D array."""
    s = np.sort(stack, axis=1)  # NaN sorts to the end
    valid = ~np.isnan(s)
    diff = np.diff(s, axis=1)
    changes = ((diff != 0) & ~np.isnan(diff)).sum(axis=1)
    return valid[:, 0].astype(int) + changes


def _stream_features(g: pd.DataFrame) -> pd.DataFrame:
    """Past-only context features for ONE chronologically sorted stream."""
    n = len(g)
    ts = g["timestamp"].to_numpy(float)
    fc = g["modbus_func_code"].to_numpy(float)
    ref = g["modbus_ref_num"].to_numpy(float)
    isw = g["is_write"].to_numpy(float)
    isr = 1.0 - isw
    idx = np.arange(n)
    f: dict[str, np.ndarray] = {}
    f["first_in_stream"] = (idx == 0).astype(int)
    f["prev_fc"] = _shift(fc, 1, -1)
    f["prev_is_write"] = _shift(isw, 1, -1)
    f["prev_ref"] = _shift(ref, 1, -1)
    pw = f["prev_is_write"]
    f["read_to_write"] = ((pw == 0) & (isw == 1)).astype(int)
    f["write_to_write"] = ((pw == 1) & (isw == 1)).astype(int)
    f["same_ref_as_prev"] = ((f["prev_ref"] == ref) & (idx > 0)).astype(int)
    shifts_w = np.stack([_shift(isw, k) for k in range(1, K_WINDOW + 1)])
    shifts_ref = np.stack([_shift(ref, k) for k in range(1, K_WINDOW + 1)])
    shifts_fc = np.stack([_shift(fc, k) for k in range(1, K_WINDOW + 1)])
    f["writes_prev_k"] = np.nansum(shifts_w, axis=0)
    f["reads_prev_k"] = np.nansum(np.where(np.isnan(shifts_w), np.nan, 1 - shifts_w), axis=0)
    f["distinct_fc_prev_k"] = _distinct(shifts_fc.T)
    f["distinct_ref_prev_k"] = _distinct(shifts_ref.T)
    same = (shifts_ref == ref[None, :]) & (shifts_w == 1)
    f["same_ref_writes_prev_k"] = same.sum(axis=0)
    # Timing (past only): gaps to earlier events in the same stream.
    iat = np.diff(ts, prepend=np.nan)
    f["iat"] = np.where(idx == 0, np.nan, iat)
    iats = np.stack([_shift(f["iat"], k) for k in range(1, K_WINDOW + 1)])
    # All-NaN columns (first events of a stream) legitimately give NaN.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        f["iat_mean_prev_k"] = np.nanmean(iats, axis=0)
        f["iat_min_prev_k"] = np.nanmin(iats, axis=0)
    cw = np.concatenate([[0.0], np.cumsum(isw)])  # writes before position i
    for name, win in (("events_last_1s", 1.0), ("events_last_10s", 10.0)):
        start = np.searchsorted(ts, ts - win, side="left")
        f[name] = np.maximum(idx - start, 0)
    start1 = np.searchsorted(ts, ts - 1.0, side="left")
    f["writes_last_1s"] = np.maximum(cw[idx] - cw[np.minimum(start1, idx)], 0)
    last_w = np.maximum.accumulate(np.where(isw == 1, ts, -np.inf))
    last_r = np.maximum.accumulate(np.where(isr == 1, ts, -np.inf))
    for name, arr in (("time_since_last_write", last_w), ("time_since_last_read", last_r)):
        prev = _shift(arr, 1, -np.inf)  # strictly earlier events only
        f[name] = np.where(np.isinf(prev), np.nan, ts - prev)
    return pd.DataFrame(f, index=g.index)


def build_stat_free_features(events: pd.DataFrame) -> pd.DataFrame:
    """Build all features that need no fitted statistics.

    *events* = paired request events (pair_events output) plus label columns.
    Returns a copy with feature columns appended; row order is preserved.
    """
    ev = events.sort_values(STREAM + ["timestamp", "frame_number"], kind="mergesort").copy()
    out = pd.DataFrame(index=ev.index)
    fc = ev["modbus_func_code"]
    out["func_code"] = fc
    out["ref_num"] = ev["modbus_ref_num"]
    out["word_cnt"] = ev["modbus_word_cnt"]
    out["bit_cnt"] = ev["modbus_bit_cnt"]
    out["write_value"] = np.where(ev["is_write"] == 1, ev["modbus_val"], -1)
    out["frame_len"] = ev["frame_len"]
    out["payload_len"] = ev["payload_len"]
    out["mbtcp_len"] = ev["mbtcp_len"]
    out["unit_id"] = ev["mbtcp_unit_id"]
    for flag in ("syn", "ack", "fin", "rst", "psh"):
        out[f"tcp_{flag}"] = ev[f"tcp_flags_{flag}"]
    out["is_write"] = ev["is_write"]
    out["is_coil_op"] = fc.isin(COIL_FUNCTIONS).astype(int)
    out["is_known_fc"] = fc.isin(KNOWN_FC).astype(int)
    out["proto_id_valid"] = (ev["mbtcp_proto_id"] == 0).astype(int)
    # MBAP length counts unit id + PDU; payload = 6-byte MBAP prefix + length.
    out["length_consistent"] = (ev["payload_len"] == ev["mbtcp_len"] + 6).astype(int)
    out["len_discrepancy"] = ev["len_discrepancy"]
    out["has_stacked_frames"] = ev["has_stacked_frames"]
    code = ev["pair_status"].map({"matched": 0, "exception": 1, "missing": 2, "out_of_order": 3})
    out["pair_status_code"] = code
    for c in ("pair_found", "response_missing"):
        out[c] = ev[c]
    for c in (
        "unit_id_match",
        "function_code_match",
        "address_match",
        "quantity_match",
        "value_echo_match",
        "response_exception",
        "response_length_valid",
    ):
        out[c] = ev[c].fillna(-1)
    out["response_delay"] = ev["response_delay"].fillna(-1)
    # Past-only stream context.
    tmp = ev[STREAM + ["timestamp", "modbus_func_code", "modbus_ref_num", "is_write"]]
    parts = [_stream_features(g) for _, g in tmp.groupby(STREAM, sort=False)]
    ctx = pd.concat(parts).loc[ev.index]
    out = out.join(ctx)
    # Value features (writes only): previous value for the same register.
    wmask = ev["is_write"] == 1
    w = ev.loc[wmask, STREAM + ["modbus_ref_num", "modbus_val", "timestamp"]]
    grp = w.groupby(STREAM + ["modbus_ref_num"], sort=False)
    pv = grp["modbus_val"].shift(1)
    pt = grp["timestamp"].shift(1)
    out["prev_value_same_ref"] = -1.0
    out["value_delta"] = -1.0
    out["value_changed"] = -1
    out["value_rate"] = -1.0
    has_prev = pv.notna()
    wi = w.index
    out.loc[wi[has_prev.to_numpy()], "prev_value_same_ref"] = pv[has_prev]
    delta = (w["modbus_val"] - pv).abs()
    out.loc[wi[has_prev.to_numpy()], "value_delta"] = delta[has_prev]
    out.loc[wi[has_prev.to_numpy()], "value_changed"] = (delta[has_prev] > 0).astype(int)
    dt = (w["timestamp"] - pt).clip(lower=1e-6)
    out.loc[wi[has_prev.to_numpy()], "value_rate"] = (delta / dt)[has_prev]
    keep_meta = [
        "event_id",
        "capture_id",
        "source_row",
        "timestamp",
        "src_ip",
        "dst_ip",
        "modbus_func_code",
        "function_name",
        "modbus_ref_num",
        "pair_status",
        "response_delay",
        "class_id",
        "label_status",
        "attack_sub_type",
    ]
    meta = ev[[c for c in keep_meta if c in ev.columns and c != "response_delay"]]
    return meta.join(out)
