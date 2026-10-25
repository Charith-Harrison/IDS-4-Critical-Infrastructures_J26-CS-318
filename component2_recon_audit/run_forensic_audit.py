"""
Independent Forensic Dataset Audit Script for Component 2 (J26-CS-318)
Strictly READ-ONLY on all existing repository files.
Writes all audit outputs to: d:/Github/IDS-4-Critical-Infrastructures_J26-CS-318/component2_recon_audit/
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

REPO_ROOT = Path(r"d:\Github\IDS-4-Critical-Infrastructures_J26-CS-318")
REBUILT_DIR = REPO_ROOT / "Pre-processed" / "rebuilt_sequences"
RAW_CSV_DIR = REPO_ROOT / "C2_Reconnaissance_Detection" / "data" / "raw"
AUDIT_OUT_DIR = REPO_ROOT / "component2_recon_audit"


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict[str, Any]:
    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred = np.asarray(y_pred, dtype=np.int64)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))
    prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = float(2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) > 0 else 0.0
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    spec = float(tn / (fp + tn)) if (fp + tn) > 0 else 0.0
    acc = float((tp + tn) / len(y_true)) if len(y_true) > 0 else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": round(prec, 6),
        "recall": round(rec, 6),
        "f1": round(f1, 6),
        "fpr": round(fpr, 6),
        "specificity": round(spec, 6),
        "accuracy": round(acc, 6),
    }


def main() -> None:
    AUDIT_OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[Audit] Loading rebuilt files from {REBUILT_DIR} ...")

    packets_path = REBUILT_DIR / "packets_rebuilt.csv"
    exclusions_path = REBUILT_DIR / "packet_exclusions.csv"
    windows_path = REBUILT_DIR / "windows.csv"
    win_idx_path = REBUILT_DIR / "window_index.npy"

    raw_packets_path = RAW_CSV_DIR / "recon_labeled_packets_ALL.csv"
    raw_seqs_path = RAW_CSV_DIR / "recon_sequences_ALL.csv"
    raw_events_path = RAW_CSV_DIR / "attack_events_mapped.csv"

    df_pkt = pd.read_csv(packets_path)
    df_exc = pd.read_csv(exclusions_path)
    df_win = pd.read_csv(windows_path)
    win_idx = np.load(win_idx_path)

    df_raw_pkt = pd.read_csv(raw_packets_path)
    df_raw_seq = pd.read_csv(
        raw_seqs_path,
        usecols=["session_id", "label", "window_start_time", "window_end_time"],
    )
    df_events = pd.read_csv(raw_events_path)

    print("[Audit] Loaded all datasets successfully.")

    # =========================================================================
    # SECTION 5A: packets_rebuilt.csv ACCOUNTING
    # =========================================================================
    pkt_row_count = int(len(df_pkt))
    pkt_class_counts = {str(k): int(v) for k, v in df_pkt["label"].value_counts().sort_index().items()}
    pkt_columns = list(df_pkt.columns)
    pkt_null_counts = {col: int(df_pkt[col].isna().sum()) for col in df_pkt.columns}

    n_capture_groups = int(df_pkt["capture_group"].nunique())
    n_distinct_session_ids = int(df_pkt["session_id"].nunique())
    n_distinct_streams = int(df_pkt.groupby(["capture_group", "session_id"]).ngroups)
    n_distinct_source_files = int(df_pkt["file_source"].nunique())

    # First/last timestamp per capture group
    cg_time_summary = []
    for cg, grp in df_pkt.groupby("capture_group", sort=True):
        idx_min = grp["ts_ns"].idxmin()
        idx_max = grp["ts_ns"].idxmax()
        cg_time_summary.append({
            "capture_group": str(cg),
            "packets": int(len(grp)),
            "pos_packets": int((grp["label"] == 1).sum()),
            "neg_packets": int((grp["label"] == 0).sum()),
            "distinct_sessions": int(grp["session_id"].nunique()),
            "distinct_source_files": int(grp["file_source"].nunique()),
            "source_files": sorted(grp["file_source"].unique().tolist()),
            "first_timestamp": str(grp.loc[idx_min, "timestamp"]),
            "last_timestamp": str(grp.loc[idx_max, "timestamp"]),
            "first_ts_ns": int(grp["ts_ns"].min()),
            "last_ts_ns": int(grp["ts_ns"].max()),
            "duration_s": round(float((grp["ts_ns"].max() - grp["ts_ns"].min()) / 1e9), 6),
        })

    # First/last timestamp per session_id (globally across capture groups)
    sess_time_summary = []
    for sid, grp in df_pkt.groupby("session_id", sort=True):
        ts_min_ns = int(grp["ts_ns"].min())
        ts_max_ns = int(grp["ts_ns"].max())
        idx_min = grp["ts_ns"].idxmin()
        idx_max = grp["ts_ns"].idxmax()
        sess_time_summary.append({
            "session_id": str(sid),
            "packets": int(len(grp)),
            "pos_packets": int((grp["label"] == 1).sum()),
            "capture_groups": int(grp["capture_group"].nunique()),
            "source_files": int(grp["file_source"].nunique()),
            "first_timestamp": str(grp.loc[idx_min, "timestamp"]),
            "last_timestamp": str(grp.loc[idx_max, "timestamp"]),
            "span_days": round(float((ts_max_ns - ts_min_ns) / (1e9 * 86400)), 3),
        })

    # Stream chronology checks: within each (capture_group, session_id) in file order
    stream_reversals = 0
    streams_with_multiple_source_files = 0
    first_pkt_na_matches = 0
    non_first_pkt_na_count = 0
    negative_dt_s_count = int((df_pkt["dt_s"].dropna() < 0).sum())
    zero_dt_s_count = int((df_pkt["dt_s"].dropna() == 0).sum())

    stream_details = []
    for (cg, sid), grp in df_pkt.groupby(["capture_group", "session_id"], sort=False):
        ts_vals = grp["ts_ns"].to_numpy(dtype=np.int64)
        diffs = np.diff(ts_vals)
        n_rev = int(np.sum(diffs < 0))
        stream_reversals += n_rev
        dt_vals = grp["dt_s"].to_numpy(dtype=np.float64)
        if np.isnan(dt_vals[0]):
            first_pkt_na_matches += 1
        non_first_na = int(np.sum(np.isnan(dt_vals[1:])))
        non_first_pkt_na_count += non_first_na

        files_in_stream = sorted(grp["file_source"].unique().tolist())
        if len(files_in_stream) > 1:
            streams_with_multiple_source_files += 1

        stream_details.append({
            "capture_group": str(cg),
            "session_id": str(sid),
            "packets": int(len(grp)),
            "pos_packets": int((grp["label"] == 1).sum()),
            "first_timestamp": str(grp["timestamp"].iloc[0]),
            "last_timestamp": str(grp["timestamp"].iloc[-1]),
            "reversals": n_rev,
            "first_dt_is_na": bool(np.isnan(dt_vals[0])),
            "non_first_dt_na": non_first_na,
            "source_files": files_in_stream,
        })

    session_only_crossings = sum(1 for s in sess_time_summary if s["capture_groups"] > 1)

    # =========================================================================
    # SECTION 5B: packet_exclusions.csv ACCOUNTING & INDEPENDENT VERIFICATION
    # =========================================================================
    exc_row_count = int(len(df_exc))
    exc_reason_counts = {str(k): int(v) for k, v in df_exc["reason"].value_counts().items()}

    raw_total_rows = int(len(df_raw_pkt))
    retained_ids = df_pkt["row_index"].to_numpy(dtype=np.int64)
    excluded_ids = df_exc["row_index"].to_numpy(dtype=np.int64)

    n_dup_retained = int(len(retained_ids) - len(np.unique(retained_ids)))
    n_dup_excluded = int(len(excluded_ids) - len(np.unique(excluded_ids)))
    overlap_ret_exc = int(len(np.intersect1d(retained_ids, excluded_ids)))

    combined_ids = np.concatenate([retained_ids, excluded_ids])
    combined_sorted = np.sort(combined_ids)
    expected_ids = np.arange(raw_total_rows, dtype=np.int64)
    exact_partition_match = bool(
        len(combined_sorted) == raw_total_rows and np.array_equal(combined_sorted, expected_ids)
    )
    missing_orig_ids = int(len(np.setdiff1d(expected_ids, combined_sorted)))

    # Verify the 14 attached_recon_flows rows
    attached_rows_raw = df_raw_pkt[df_raw_pkt["file_source"] == "attached_recon_flows.csv"].copy()
    attached_raw_indices = attached_rows_raw.index.to_numpy(dtype=np.int64)
    attached_exc = df_exc[df_exc["row_index"].isin(attached_raw_indices)]
    attached_in_rebuilt = int((df_pkt["file_source"] == "attached_recon_flows.csv").sum())

    # Independently verify duplicate_interface_view exclusions!
    print("[Audit] Independently verifying duplicate_interface_view exclusions against retained packets...")
    dup_exc_ids = df_exc[df_exc["reason"] == "duplicate_interface_view"]["row_index"].to_numpy(dtype=np.int64)
    dup_exc_df = df_raw_pkt.iloc[dup_exc_ids].copy()
    dup_exc_df["ts_ns"] = pd.to_datetime(dup_exc_df["timestamp"], utc=True, format="ISO8601").dt.as_unit("ns").astype("int64")

    # All 282,076 duplicate_interface_view packets belong to G03_0201_veth (simultaneous veth captures on 2023-02-01)
    sig_cols = [
        "session_id",
        "src_ip",
        "dst_ip",
        "unit_id",
        "func_code",
        "register_start",
        "quantity",
        "modbus_len",
        "packet_size",
        "label",
    ]
    ret_g03 = df_pkt[df_pkt["capture_group"] == "G03_0201_veth"]
    ret_grouped = {
        k: np.sort(v["ts_ns"].to_numpy(dtype=np.int64))
        for k, v in ret_g03.groupby(sig_cols, sort=False)
    }

    dup_deltas_ns = []
    unmatched_dup_exclusions = 0
    for sig, grp in dup_exc_df.groupby(sig_cols, sort=False):
        if sig not in ret_grouped:
            unmatched_dup_exclusions += len(grp)
            continue
        ret_ts = ret_grouped[sig]
        exc_ts = grp["ts_ns"].to_numpy(dtype=np.int64)
        idx = np.searchsorted(ret_ts, exc_ts)
        idx_left = np.clip(idx - 1, 0, len(ret_ts) - 1)
        idx_right = np.clip(idx, 0, len(ret_ts) - 1)
        dist = np.minimum(np.abs(exc_ts - ret_ts[idx_left]), np.abs(ret_ts[idx_right] - exc_ts))
        dup_deltas_ns.extend(dist.tolist())
        unmatched_dup_exclusions += int(np.sum(dist > 1_000_000))

    dup_deltas_arr = np.asarray(dup_deltas_ns, dtype=np.int64)
    dup_verification = {
        "total_duplicate_interface_view_excluded": int(len(dup_exc_df)),
        "excluded_files_in_duplicate_view": {str(k): int(v) for k, v in dup_exc_df["file_source"].value_counts().items()},
        "matched_within_1ms_of_retained_identical_packet": int(len(dup_exc_df) - unmatched_dup_exclusions),
        "matched_within_1ms_pct": round(float(100.0 * (len(dup_exc_df) - unmatched_dup_exclusions) / len(dup_exc_df)), 4),
        "unmatched_over_1ms": int(unmatched_dup_exclusions),
        "exact_0ns_delta_count": int(np.sum(dup_deltas_arr == 0)),
        "delta_le_50us_count": int(np.sum(dup_deltas_arr <= 50_000)),
        "delta_le_100us_count": int(np.sum(dup_deltas_arr <= 100_000)),
        "delta_le_500us_count": int(np.sum(dup_deltas_arr <= 500_000)),
        "delta_le_1ms_count": int(np.sum(dup_deltas_arr <= 1_000_000)),
        "median_delta_us": round(float(np.median(dup_deltas_arr) / 1e3), 3),
        "p95_delta_us": round(float(np.percentile(dup_deltas_arr, 95) / 1e3), 3),
        "max_delta_us": round(float(np.max(dup_deltas_arr) / 1e3), 3),
        "positive_packets_excluded_as_duplicate": int((dup_exc_df["label"] == 1).sum()),
        "normal_packets_excluded_as_duplicate": int((dup_exc_df["label"] == 0).sum()),
    }

    # =========================================================================
    # SECTION 5C: window_index.npy + windows.csv 100% FULL VALIDATION
    # =========================================================================
    print("[Audit] Validating all 119,237 windows in window_index.npy + windows.csv...")
    n_windows = int(len(df_win))
    win_shape = list(win_idx.shape)
    all_indices_valid = bool((win_idx.min() >= 0) and (win_idx.max() < pkt_row_count))

    diffs_within_win = np.diff(win_idx, axis=1)
    all_contiguous_step1 = bool(np.all(diffs_within_win == 1))
    windows_with_dup_indices = int(
        np.sum([len(np.unique(row)) != 20 for row in win_idx]) if not all_contiguous_step1 else 0
    )

    cg_codes = pd.Categorical(df_pkt["capture_group"]).codes
    sid_codes = pd.Categorical(df_pkt["session_id"]).codes
    win_cg_matrix = cg_codes[win_idx]
    win_sid_matrix = sid_codes[win_idx]

    same_cg_all = bool(np.all(win_cg_matrix == win_cg_matrix[:, [0]]))
    same_sid_all = bool(np.all(win_sid_matrix == win_sid_matrix[:, [0]]))

    # Check stride within each (capture_group, session_id) stream
    first_pos_indices = win_idx[:, 0]
    last_pos_indices = win_idx[:, -1]
    win_stream_same_as_prev = (
        (df_win["capture_group"].values[1:] == df_win["capture_group"].values[:-1])
        & (df_win["session_id"].values[1:] == df_win["session_id"].values[:-1])
    )
    intra_stream_FirstIdx_diffs = (
        first_pos_indices[1:][win_stream_same_as_prev] - first_pos_indices[:-1][win_stream_same_as_prev]
    )
    all_intra_stream_stride_5 = bool(np.all(intra_stream_FirstIdx_diffs == 5))

    # Timestamps inside every window
    pkt_ts_ns = df_pkt["ts_ns"].to_numpy(dtype=np.int64)
    pkt_orig_row_idx = df_pkt["row_index"].to_numpy(dtype=np.int64)
    win_ts_matrix = pkt_ts_ns[win_idx]
    win_ts_diffs = np.diff(win_ts_matrix, axis=1)
    non_decreasing_ts_all = bool(np.all(win_ts_diffs >= 0))
    windows_with_ts_reversal = int(np.sum(np.any(win_ts_diffs < 0, axis=1)))

    # Match metadata in windows.csv against packet arrays
    # Note: first_row_index and last_row_index in windows.csv store the original packet row_index!
    first_row_match = bool(
        np.array_equal(df_win["first_row_index"].to_numpy(dtype=np.int64), pkt_orig_row_idx[first_pos_indices])
    )
    last_row_match = bool(
        np.array_equal(df_win["last_row_index"].to_numpy(dtype=np.int64), pkt_orig_row_idx[last_pos_indices])
    )
    start_ns_match = bool(np.array_equal(df_win["start_ns"].to_numpy(dtype=np.int64), win_ts_matrix[:, 0]))
    end_ns_match = bool(np.array_equal(df_win["end_ns"].to_numpy(dtype=np.int64), win_ts_matrix[:, -1]))

    pkt_labels = df_pkt["label"].to_numpy(dtype=np.int64)
    win_label_matrix = pkt_labels[win_idx]
    calc_n_pos = win_label_matrix.sum(axis=1)
    n_pos_match = bool(np.array_equal(df_win["n_pos_packets"].to_numpy(dtype=np.int64), calc_n_pos))
    pos_frac_match = bool(np.allclose(df_win["pos_packet_fraction"].to_numpy(dtype=np.float64), calc_n_pos / 20.0))
    win_label_rule_any_pos_match = bool(
        np.array_equal(df_win["label"].to_numpy(dtype=np.int64), (calc_n_pos >= 1).astype(np.int64))
    )

    pkt_fc5_len3 = ((df_pkt["func_code"] == 5) & (df_pkt["modbus_len"] == 3)).to_numpy(dtype=np.int64)
    pkt_is_fc5_col_match = bool(
        np.array_equal(df_pkt["is_fc5_len3"].astype(np.int64).to_numpy(), pkt_fc5_len3)
    )
    calc_n_fc5_len3 = pkt_fc5_len3[win_idx].sum(axis=1)
    n_fc5_len3_match = bool(np.array_equal(df_win["n_fc5_len3_packets"].to_numpy(dtype=np.int64), calc_n_fc5_len3))

    # Window duration statistics
    win_durations_s = (win_ts_matrix[:, -1] - win_ts_matrix[:, 0]) / 1e9
    max_step_gap_s = np.max(win_ts_diffs, axis=1) / 1e9

    long_gap_windows_df = df_win.copy()
    long_gap_windows_df["calc_duration_s"] = win_durations_s
    long_gap_windows_df["max_inter_packet_gap_s"] = max_step_gap_s

    flagged_gt_60s = long_gap_windows_df[long_gap_windows_df["calc_duration_s"] > 60.0].sort_values(
        "calc_duration_s", ascending=False
    )

    window_integrity_report = {
        "n_windows": n_windows,
        "window_index_shape": win_shape,
        "packets_per_window_exact_20": bool(win_shape[1] == 20),
        "intra_stream_stride_exact_5": all_intra_stream_stride_5,
        "all_indices_valid": all_indices_valid,
        "all_windows_contiguous_20_packets": all_contiguous_step1,
        "windows_with_duplicate_indices": windows_with_dup_indices,
        "all_packets_same_capture_group": same_cg_all,
        "all_packets_same_session_id": same_sid_all,
        "timestamps_non_decreasing_in_all_windows": non_decreasing_ts_all,
        "windows_with_timestamp_reversal": windows_with_ts_reversal,
        "start_ns_matches_first_packet": start_ns_match,
        "end_ns_matches_last_packet": end_ns_match,
        "first_row_index_matches_orig_row_index": first_row_match,
        "last_row_index_matches_orig_row_index": last_row_match,
        "n_pos_packets_matches": n_pos_match,
        "pos_packet_fraction_matches": pos_frac_match,
        "window_label_matches_any_positive_rule": win_label_rule_any_pos_match,
        "packet_is_fc5_len3_matches_formula": pkt_is_fc5_col_match,
        "n_fc5_len3_packets_matches": n_fc5_len3_match,
        "window_class_counts": {
            "normal_0": int((df_win["label"] == 0).sum()),
            "recon_1": int((df_win["label"] == 1).sum()),
        },
        "window_duration_s_stats": {
            "min": round(float(np.min(win_durations_s)), 6),
            "p05": round(float(np.percentile(win_durations_s, 5)), 6),
            "p25": round(float(np.percentile(win_durations_s, 25)), 6),
            "median": round(float(np.median(win_durations_s)), 6),
            "mean": round(float(np.mean(win_durations_s)), 6),
            "p75": round(float(np.percentile(win_durations_s, 75)), 6),
            "p95": round(float(np.percentile(win_durations_s, 95)), 6),
            "p99": round(float(np.percentile(win_durations_s, 99)), 6),
            "max": round(float(np.max(win_durations_s)), 6),
            "count_gt_1s": int(np.sum(win_durations_s > 1.0)),
            "count_gt_5s": int(np.sum(win_durations_s > 5.0)),
            "count_gt_1m": int(np.sum(win_durations_s > 60.0)),
            "count_gt_5m": int(np.sum(win_durations_s > 300.0)),
            "count_gt_1h": int(np.sum(win_durations_s > 3600.0)),
        },
        "max_intra_window_inter_packet_gap_s_stats": {
            "min": round(float(np.min(max_step_gap_s)), 6),
            "median": round(float(np.median(max_step_gap_s)), 6),
            "p95": round(float(np.percentile(max_step_gap_s, 95)), 6),
            "p99": round(float(np.percentile(max_step_gap_s, 99)), 6),
            "max": round(float(np.max(max_step_gap_s)), 6),
            "count_gap_gt_1s": int(np.sum(max_step_gap_s > 1.0)),
            "count_gap_gt_5s": int(np.sum(max_step_gap_s > 5.0)),
            "count_gap_gt_60s": int(np.sum(max_step_gap_s > 60.0)),
            "count_gap_gt_300s": int(np.sum(max_step_gap_s > 300.0)),
            "count_gap_gt_3600s": int(np.sum(max_step_gap_s > 3600.0)),
        },
        "inactivity_gap_breakdown_by_capture_group_and_session": [
            {
                "capture_group": str(cg),
                "session_id": str(sid),
                "total_windows": int(len(grp)),
                "windows_gt_1s": int((grp["calc_duration_s"] > 1.0).sum()),
                "windows_gt_5s": int((grp["calc_duration_s"] > 5.0).sum()),
                "windows_gt_60s": int((grp["calc_duration_s"] > 60.0).sum()),
                "windows_gt_300s": int((grp["calc_duration_s"] > 300.0).sum()),
                "windows_gt_3600s": int((grp["calc_duration_s"] > 3600.0).sum()),
                "max_duration_s": round(float(grp["calc_duration_s"].max()), 3),
                "max_single_gap_s": round(float(grp["max_inter_packet_gap_s"].max()), 3),
            }
            for (cg, sid), grp in long_gap_windows_df.groupby(["capture_group", "session_id"], sort=True)
            if (grp["calc_duration_s"] > 60.0).any()
        ],
        "top_25_longest_duration_windows": [
            {
                "window_id": str(r["window_id"]),
                "capture_group": str(r["capture_group"]),
                "session_id": str(r["session_id"]),
                "label": int(r["label"]),
                "window_start_utc": str(r["window_start_utc"]),
                "window_end_utc": str(r["window_end_utc"]),
                "duration_s": round(float(r["calc_duration_s"]), 3),
                "max_inter_packet_gap_s": round(float(r["max_inter_packet_gap_s"]), 3),
            }
            for _, r in flagged_gt_60s.head(25).iterrows()
        ],
    }

    with open(AUDIT_OUT_DIR / "window_integrity_report.json", "w", encoding="utf-8") as f:
        json.dump(window_integrity_report, f, indent=2)
    print("[Audit] Wrote window_integrity_report.json")

    # =========================================================================
    # SECTION 6: DETERMINE WHAT session_id ACTUALLY MEANS
    # =========================================================================
    session_mapping_table = []
    for (src, dst, uid, sid), grp in df_pkt.groupby(["src_ip", "dst_ip", "unit_id", "session_id"], sort=True):
        expected_str = f"{src}_{dst}_u{uid}_s"
        session_mapping_table.append({
            "session_id": str(sid),
            "src_ip": str(src),
            "dst_ip": str(dst),
            "unit_id": int(uid),
            "matches_formula_src_dst_unit": bool(str(sid).startswith(expected_str)),
            "packets": int(len(grp)),
            "pos_packets": int((grp["label"] == 1).sum()),
            "distinct_capture_groups": int(grp["capture_group"].nunique()),
            "distinct_source_files": int(grp["file_source"].nunique()),
        })

    n_unique_endpoint_unit_triples = int(df_pkt.groupby(["src_ip", "dst_ip", "unit_id"]).ngroups)
    session_id_is_exact_bijection_with_endpoint_unit = bool(
        n_unique_endpoint_unit_triples == n_distinct_session_ids == len(session_mapping_table)
    )

    # =========================================================================
    # SECTION 7 & 8: RECON LABEL PROVENANCE & FC5 + MODBUS_LEN=3 INVESTIGATION
    # =========================================================================
    print("[Audit] Analyzing FC5 + modbus_len == 3 and positive label provenance...")
    event_keys = set(zip(df_events["packet_timestamp"], df_events["src_ip"], df_events["dst_ip"]))
    df_pkt["is_event_mapped"] = [
        (ts, s, d) in event_keys
        for ts, s, d in zip(df_pkt["timestamp"], df_pkt["src_ip"], df_pkt["dst_ip"])
    ]

    df_pos = df_pkt[df_pkt["label"] == 1].copy()
    df_neg = df_pkt[df_pkt["label"] == 0].copy()

    def dist_dict(series: pd.Series) -> dict[str, int]:
        return {str(k): int(v) for k, v in series.value_counts().sort_index().items()}

    def top_dist_dict(series: pd.Series, top_n: int = 20) -> dict[str, int]:
        return {str(k): int(v) for k, v in series.value_counts().head(top_n).items()}

    joint_pos_fc_len = {
        f"FC{fc}_len{ml}": int(cnt)
        for (fc, ml), cnt in df_pos.groupby(["func_code", "modbus_len"]).size().items()
    }
    joint_neg_fc_len = {
        f"FC{fc}_len{ml}": int(cnt)
        for (fc, ml), cnt in df_neg.groupby(["func_code", "modbus_len"]).size().items()
    }

    joint_pos_full = {
        f"FC{fc}_len{ml}_pkt{ps}_qty{q}": int(cnt)
        for (fc, ml, ps, q), cnt in df_pos.groupby(["func_code", "modbus_len", "packet_size", "quantity"]).size().items()
    }
    joint_neg_full = {
        f"FC{fc}_len{ml}_pkt{ps}_qty{q}": int(cnt)
        for (fc, ml, ps, q), cnt in df_neg.groupby(["func_code", "modbus_len", "packet_size", "quantity"]).size().items()
    }

    # Categorize every retained positive packet into mutually exclusive forensic categories
    pos_cat = np.select(
        [
            (df_pkt["func_code"] == 5) & (df_pkt["modbus_len"] == 3),
            df_pkt["is_event_mapped"],
            df_pkt["quantity"] > 1,
            df_pkt["modbus_len"] == 3,
        ],
        [
            "cat1_fc5_len3_75b_response",
            "cat3_event_mapped_substation2_substation10",
            "cat2_nonroutine_quantity_gt1_read",
            "cat1b_fc1to4_len3_75b_response",
        ],
        default="other_positive",
    )
    df_pkt["forensic_pos_category"] = np.where(df_pkt["label"] == 1, pos_cat, "normal")

    pos_category_counts = {
        str(k): int(v)
        for k, v in df_pkt[df_pkt["label"] == 1]["forensic_pos_category"].value_counts().items()
    }

    # Window-level positive breakdown
    win_has_fc5_len3 = df_win["n_fc5_len3_packets"] >= 1
    win_has_any_len3 = (df_pkt["modbus_len"].to_numpy()[win_idx] == 3).any(axis=1)
    win_has_qty_gt1 = (df_pkt["quantity"].to_numpy()[win_idx] > 1).any(axis=1)
    win_has_event_mapped = df_pkt["is_event_mapped"].to_numpy()[win_idx].any(axis=1)

    pos_win_mask = df_win["label"].to_numpy() == 1
    neg_win_mask = df_win["label"].to_numpy() == 0

    fc5_len3_summary = {
        "pos_packets_total": int(len(df_pos)),
        "neg_packets_total": int(len(df_neg)),
        "pos_packets_fc5_len3": int(((df_pos["func_code"] == 5) & (df_pos["modbus_len"] == 3)).sum()),
        "pos_packets_fc5_len3_pct": round(
            float(100.0 * ((df_pos["func_code"] == 5) & (df_pos["modbus_len"] == 3)).sum() / len(df_pos)), 4
        ),
        "neg_packets_fc5_len3": int(((df_neg["func_code"] == 5) & (df_neg["modbus_len"] == 3)).sum()),
        "pos_packets_any_len3": int((df_pos["modbus_len"] == 3).sum()),
        "pos_packets_any_len3_pct": round(float(100.0 * (df_pos["modbus_len"] == 3).sum() / len(df_pos)), 4),
        "neg_packets_any_len3": int((df_neg["modbus_len"] == 3).sum()),
        "pos_windows_total": int(pos_win_mask.sum()),
        "neg_windows_total": int(neg_win_mask.sum()),
        "pos_windows_with_fc5_len3": int((pos_win_mask & win_has_fc5_len3.to_numpy()).sum()),
        "pos_windows_with_fc5_len3_pct": round(
            float(100.0 * (pos_win_mask & win_has_fc5_len3.to_numpy()).sum() / pos_win_mask.sum()), 4
        ),
        "neg_windows_with_fc5_len3": int((neg_win_mask & win_has_fc5_len3.to_numpy()).sum()),
        "pos_windows_with_any_len3": int((pos_win_mask & win_has_any_len3).sum()),
        "pos_windows_with_any_len3_pct": round(
            float(100.0 * (pos_win_mask & win_has_any_len3).sum() / pos_win_mask.sum()), 4
        ),
        "pos_windows_without_len3_total": int((pos_win_mask & (~win_has_any_len3)).sum()),
        "pos_windows_only_qty_gt1_no_len3": int((pos_win_mask & (~win_has_any_len3) & win_has_qty_gt1).sum()),
        "pos_windows_only_routine_event_mapped_no_len3_no_qty_gt1": int(
            (pos_win_mask & (~win_has_any_len3) & (~win_has_qty_gt1)).sum()
        ),
    }

    # Inspect neighboring packets in the substation captures around FC5 + len3 packets!
    fc5_neighbor_analysis = {}
    for cg in ["G04_0315_sub1", "G05_0315_sub2", "G06_0316_sub4", "G07_0319_sub10", "G08_0320_sub14"]:
        sub_cg = df_pkt[df_pkt["capture_group"] == cg].sort_values(["ts_ns", "row_index"]).reset_index(drop=True)
        fc5_resp = sub_cg[(sub_cg["func_code"] == 5) & (sub_cg["modbus_len"] == 3)]
        fc5_req = sub_cg[(sub_cg["func_code"] == 5) & (sub_cg["modbus_len"] == 6)]

        resp_indices = fc5_resp.index.to_numpy()
        prev_indices = np.clip(resp_indices - 1, 0, len(sub_cg) - 1)
        prev_pkts = sub_cg.iloc[prev_indices]
        dt_from_prev_ms = (
            sub_cg.iloc[resp_indices]["ts_ns"].to_numpy() - prev_pkts["ts_ns"].to_numpy()
        ) / 1e6

        prev_is_fc5_req = (
            (prev_pkts["src_ip"] == "185.175.0.3")
            & (prev_pkts["func_code"] == 5)
            & (prev_pkts["modbus_len"] == 6)
        )

        # Also extract 5 sample request->response pairs to show in AUDIT_REPORT.md
        sample_pairs = []
        for r_idx in resp_indices[:3]:
            if r_idx > 0:
                req_row = sub_cg.iloc[r_idx - 1]
                resp_row = sub_cg.iloc[r_idx]
                sample_pairs.append({
                    "req_orig_row_index": int(req_row["row_index"]),
                    "req_ts": str(req_row["timestamp"]),
                    "req_src_dst": f"{req_row['src_ip']}->{req_row['dst_ip']}",
                    "req_fc_len_reg_qty_size": f"FC={req_row['func_code']} len={req_row['modbus_len']} reg={req_row['register_start']} qty={req_row['quantity']} size={req_row['packet_size']}B",
                    "req_label": int(req_row["label"]),
                    "resp_orig_row_index": int(resp_row["row_index"]),
                    "resp_ts": str(resp_row["timestamp"]),
                    "resp_src_dst": f"{resp_row['src_ip']}->{resp_row['dst_ip']}",
                    "resp_fc_len_reg_qty_size": f"FC={resp_row['func_code']} len={resp_row['modbus_len']} reg={resp_row['register_start']} qty={resp_row['quantity']} size={resp_row['packet_size']}B",
                    "resp_label": int(resp_row["label"]),
                    "delay_ms": round(float((resp_row["ts_ns"] - req_row["ts_ns"]) / 1e6), 3),
                })

        fc5_neighbor_analysis[cg] = {
            "source_file": str(sub_cg["file_source"].iloc[0]),
            "total_packets_in_capture": int(len(sub_cg)),
            "fc5_len3_slave_to_master_count": int(len(fc5_resp)),
            "fc5_len3_labelled_1_count": int((fc5_resp["label"] == 1).sum()),
            "fc5_len6_master_to_slave_count": int(len(fc5_req)),
            "fc5_len6_labelled_1_count": int((fc5_req["label"] == 1).sum()),
            "fc5_len6_labelled_0_count": int((fc5_req["label"] == 0).sum()),
            "fc5_len6_unique_register_targets": int(fc5_req["register_start"].nunique()),
            "fc5_len6_register_min": int(fc5_req["register_start"].min()) if len(fc5_req) > 0 else None,
            "fc5_len6_register_max": int(fc5_req["register_start"].max()) if len(fc5_req) > 0 else None,
            "fc5_len3_immediately_preceded_by_fc5_len6_req_count": int(prev_is_fc5_req.sum()),
            "median_response_delay_ms": round(float(np.median(dt_from_prev_ms)), 3) if len(dt_from_prev_ms) > 0 else None,
            "sample_request_response_pairs": sample_pairs,
        }

    # Alignment of attack_events_mapped.csv with packets_rebuilt.csv
    df_events["packet_ts_ns"] = pd.to_datetime(df_events["packet_timestamp"], utc=True, format="ISO8601").dt.as_unit("ns").astype("int64")
    df_events["log_ts_ns"] = pd.to_datetime(df_events["log_timestamp"], format="ISO8601").dt.as_unit("ns").astype("int64")
    df_events["offset_utc_minus_log_min"] = (df_events["packet_ts_ns"] - df_events["log_ts_ns"]) / (60.0 * 1e9)

    event_alignment_summary = []
    for (fsrc, latk, lts, lfile), grp in df_events.groupby(["file_source", "log_attack", "log_timestamp", "log_file"], sort=True):
        event_alignment_summary.append({
            "file_source": str(fsrc),
            "log_attack": str(latk),
            "log_timestamp": str(lts),
            "log_file": str(lfile),
            "mapped_packet_rows": int(len(grp)),
            "first_packet_timestamp": str(grp["packet_timestamp"].min()),
            "last_packet_timestamp": str(grp["packet_timestamp"].max()),
            "offset_utc_minus_log_min_min": round(float(grp["offset_utc_minus_log_min"].min()), 3),
            "offset_utc_minus_log_min_max": round(float(grp["offset_utc_minus_log_min"].max()), 3),
            "func_codes": sorted(grp["func_code"].unique().tolist()),
            "quantities": sorted(grp["quantity"].unique().tolist()),
        })

    # =========================================================================
    # GENERATE capture_group_summary.csv AND positive_lineage.csv
    # =========================================================================
    print("[Audit] Generating capture_group_summary.csv and positive_lineage.csv...")
    raw_f2g = {}
    for cg, grp in df_pkt.groupby("capture_group"):
        for f in grp["file_source"].unique():
            raw_f2g[f] = cg

    df_raw_pkt["capture_group_mapped"] = df_raw_pkt["file_source"].map(raw_f2g).fillna("EXCLUDED_attached_recon_flows")
    df_exc_with_src = df_exc.merge(
        df_raw_pkt[["file_source", "capture_group_mapped", "label"]],
        left_on="row_index",
        right_index=True,
        how="left",
    )

    cg_rows = []
    for cg, grp in df_pkt.groupby("capture_group", sort=True):
        win_cg = df_win[df_win["capture_group"] == cg]
        exc_cg = df_exc_with_src[df_exc_with_src["capture_group_mapped"] == cg]
        files_cg = sorted(grp["file_source"].unique().tolist())
        ev_cg = df_events[df_events["file_source"].isin(files_cg)]
        pos_cg = grp[grp["label"] == 1]

        cat1_cnt = int((pos_cg["forensic_pos_category"] == "cat1_fc5_len3_75b_response").sum())
        cat1b_cnt = int((pos_cg["forensic_pos_category"] == "cat1b_fc1to4_len3_75b_response").sum())
        cat2_cnt = int((pos_cg["forensic_pos_category"] == "cat2_nonroutine_quantity_gt1_read").sum())
        cat3_cnt = int((pos_cg["forensic_pos_category"] == "cat3_event_mapped_substation2_substation10").sum())

        if "normal" in cg:
            scenario = "CICModbus2023 Benign Baseline Capture (0 positives)"
        elif cg == "G03_0201_veth":
            scenario = "CICModbus2023 Simultaneous 5-Interface Docker veth Capture (50 retained nonroutine qty=204 read packets in 185.175.0.7->185.175.0.4; 50 duplicate view packets excluded)"
        elif "sub" in cg:
            scenario = "CICModbus2023 Compromised-SCADA Substation Capture (Master 185.175.0.3 <-> IEDs 185.175.0.4, 0.5, 0.8)"
        else:
            scenario = "CICModbus2023 veth3efd353 Capture (Master 185.175.0.2 <-> IEDs 185.175.0.4, 0.5, 0.8; 0 positives)"

        idx_min = grp["ts_ns"].idxmin()
        idx_max = grp["ts_ns"].idxmax()

        cg_rows.append({
            "capture_group": str(cg),
            "scenario_campaign": scenario,
            "retained_packets": int(len(grp)),
            "excluded_packets": int(len(exc_cg)),
            "excluded_positive_packets": int((exc_cg["label"] == 1).sum()),
            "positive_packets": int(len(pos_cg)),
            "positive_packet_pct": round(float(100.0 * len(pos_cg) / len(grp)), 4),
            "cat1_fc5_len3_packets": cat1_cnt,
            "cat1b_fc1to4_len3_packets": cat1b_cnt,
            "cat2_nonroutine_qty_gt1_packets": cat2_cnt,
            "cat3_event_mapped_packets": cat3_cnt,
            "distinct_streams": int(grp["session_id"].nunique()),
            "positive_streams": int(pos_cg["session_id"].nunique()),
            "total_windows": int(len(win_cg)),
            "positive_windows": int((win_cg["label"] == 1).sum()),
            "positive_windows_with_fc5_len3": int((win_cg["n_fc5_len3_packets"] >= 1).sum()),
            "positive_windows_without_fc5_len3": int(((win_cg["label"] == 1) & (win_cg["n_fc5_len3_packets"] == 0)).sum()),
            "first_timestamp_utc": str(grp.loc[idx_min, "timestamp"]),
            "last_timestamp_utc": str(grp.loc[idx_max, "timestamp"]),
            "duration_seconds": round(float((grp["ts_ns"].max() - grp["ts_ns"].min()) / 1e9), 3),
            "n_source_files_retained": int(grp["file_source"].nunique()),
            "source_files_retained": ";".join(files_cg),
            "mapped_attack_log_rows": int(len(ev_cg)),
        })

    df_cg_summary = pd.DataFrame(cg_rows)
    df_cg_summary.to_csv(AUDIT_OUT_DIR / "capture_group_summary.csv", index=False)

    # Build positive_lineage.csv
    lineage_rows = []
    df_pkt_with_pos = df_pkt.copy()
    df_pkt_with_pos["rebuilt_pos_idx"] = np.arange(len(df_pkt))

    for (cg, sid, fsrc, fcat), grp in df_pkt_with_pos[df_pkt_with_pos["label"] == 1].groupby(
        ["capture_group", "session_id", "file_source", "forensic_pos_category"], sort=True
    ):
        ev_cg = df_events[(df_events["file_source"] == fsrc) & (df_events["src_ip"] == grp["src_ip"].iloc[0])]
        if fcat == "cat1_fc5_len3_75b_response":
            rule_str = "Rule A1: Static signature rule (func_code == 5 AND modbus_len == 3, 75B slave->master response)"
            conf_str = "CRITICAL SHORTCUT / QUESTIONABLE SEMANTICS (Slave->Master 3-byte exception/truncated response to FC5 coil write; preceding FC5 requests from 185.175.0.3 are labelled 0)"
            ev_str = (
                f"No direct row match in attack_events_mapped.xlsx for FC5+len3 ({len(ev_cg)} event rows for this stream); "
                f"labelled by static signature across {fsrc}"
            )
        elif fcat == "cat1b_fc1to4_len3_75b_response":
            rule_str = "Rule A2: Static signature rule (func_code in {1,2,3,4} AND modbus_len == 3, 75B slave->master response)"
            conf_str = "HIGH SHORTCUT RISK (Slave->Master 3-byte exception/truncated response during substation scan)"
            ev_str = f"No direct row match in attack_events_mapped.xlsx; 3-byte slave response in {fsrc}"
        elif fcat == "cat2_nonroutine_quantity_gt1_read":
            rule_str = "Rule B: Non-routine multi-register read signature (func_code in {1..4} AND quantity > 1 AND modbus_len == 6)"
            conf_str = "MODERATE-HIGH (Master->Slave multi-register read requests with quantity in {27, 45, 75, 92, 95, 204, ...}, but static quantity > 1 separates them from routine quantity == 1 polling)"
            ev_str = f"Non-routine bulk read requests in {fsrc}; 0 rows in attack_events_mapped.xlsx for G03_0201_veth"
        else:
            rule_str = "Rule C: Direct timestamp+endpoint lookup from attack_events_mapped.xlsx (158 rows in substation-2 & substation-10)"
            conf_str = "LOW-MODERATE (Matched to attack_events_mapped.xlsx 'Recon. Complete' / 'Recon. Range: 2000', but packet-minus-log clock offsets vary from -210 min to +141.5 min and 147/158 packets have routine qty <= 1 shape)"
            ev_str = (
                f"Matched to {len(ev_cg)} rows in attack_events_mapped.xlsx "
                f"(log_file: {ev_cg['log_file'].iloc[0] if len(ev_cg) else 'substation log'})"
            )

        sample_positions = sorted({0, len(grp) // 2, len(grp) - 1})
        for pos_i in sample_positions:
            row = grp.iloc[pos_i]
            lineage_rows.append({
                "Rebuilt positive row": int(row["rebuilt_pos_idx"]),
                "Original raw row ID": int(row["row_index"]),
                "Cohort packet count": int(len(grp)),
                "Cohort sample role": "first" if pos_i == 0 else ("last" if pos_i == len(grp) - 1 else "middle"),
                "Capture group": str(cg),
                "Source PCAP": str(fsrc),
                "Frame / packet identity": (
                    f"session={sid} | {row['src_ip']}->{row['dst_ip']} | u={row['unit_id']} | "
                    f"ts={row['timestamp']} | FC={row['func_code']} reg={row['register_start']} "
                    f"qty={row['quantity']} len={row['modbus_len']} size={row['packet_size']}B"
                ),
                "Forensic category": str(fcat),
                "Original log evidence": ev_str,
                "Label rule": rule_str,
                "Confidence": conf_str,
            })

    # Also append the 12 positive rows in excluded attached_recon_flows.csv and 50 duplicate_interface_view positives
    for idx_r, row in attached_rows_raw[attached_rows_raw["label"] == 1].iterrows():
        lineage_rows.append({
            "Rebuilt positive row": -1,
            "Original raw row ID": int(idx_r),
            "Cohort packet count": int((attached_rows_raw["label"] == 1).sum()),
            "Cohort sample role": "excluded_attached_recon_flows",
            "Capture group": "EXCLUDED (attached_recon_flows.csv)",
            "Source PCAP": "attached_recon_flows.csv",
            "Frame / packet identity": (
                f"session={row['session_id']} | {row['src_ip']}->{row['dst_ip']} | u={row['unit_id']} | "
                f"ts={row['timestamp']} | FC={row['func_code']} reg={row['register_start']} "
                f"qty={row['quantity']} len={row['modbus_len']} size={row['packet_size']}B"
            ),
            "Forensic category": "excluded_external_attached_flow_no_date",
            "Original log evidence": "None in attack_events_mapped.xlsx; time-of-day-only timestamps (00:31:xx) on 192.168.10.x subnet",
            "Label rule": "External small lab snippet (12 positive rows out of 14 total rows; excluded in rebuild)",
            "Confidence": "EXCLUDED (Non-CIC 192.168.10.x subnet, unparseable date, 2-4 packets per stream < 20-packet window length)",
        })

    df_lineage = pd.DataFrame(lineage_rows)
    df_lineage.to_csv(AUDIT_OUT_DIR / "positive_lineage.csv", index=False)

    # =========================================================================
    # SECTION 9: MEASURE STATIC-SHORTCUT BASELINES (PACKET & WINDOW LEVEL)
    # =========================================================================
    print("[Audit] Evaluating static shortcut rules and non-temporal baselines...")
    y_pkt = df_pkt["label"].to_numpy(dtype=np.int64)
    y_win = df_win["label"].to_numpy(dtype=np.int64)

    fc_arr = df_pkt["func_code"].to_numpy()
    len_arr = df_pkt["modbus_len"].to_numpy()
    ps_arr = df_pkt["packet_size"].to_numpy()
    reg_arr = df_pkt["register_start"].to_numpy()
    qty_arr = df_pkt["quantity"].to_numpy()

    pkt_rules = {
        "Rule 1: func_code == 5": (fc_arr == 5),
        "Rule 2: modbus_len == 3": (len_arr == 3),
        "Rule 3: func_code == 5 AND modbus_len == 3": (fc_arr == 5) & (len_arr == 3),
        "Rule 4: packet_size == 75": (ps_arr == 75),
        "Rule 5a: register_start == 0 AND quantity == 0": (reg_arr == 0) & (qty_arr == 0),
        "Rule 5b: func_code == 5 AND register_start == 0 AND quantity == 0": (fc_arr == 5) & (reg_arr == 0) & (qty_arr == 0),
        "Rule 6a: quantity > 1": (qty_arr > 1),
        "Rule 6b: (func_code == 5 AND modbus_len == 3) OR (quantity > 1)": ((fc_arr == 5) & (len_arr == 3)) | (qty_arr > 1),
        "Rule 6c: (modbus_len == 3) OR (quantity > 1)": (len_arr == 3) | (qty_arr > 1),
    }

    shortcut_rows = []
    for rname, mask in pkt_rules.items():
        m_pkt = compute_binary_metrics(y_pkt, mask.astype(np.int64))
        shortcut_rows.append({
            "evaluation_level": "packet_level",
            "evaluation_protocol": "deterministic_static_rule (no training)",
            "model_or_rule": rname,
            "window_aggregation_rule": "N/A (single current packet)",
            "features_used": rname.split(": ", 1)[1],
            **m_pkt,
        })

        win_mask = mask[win_idx].any(axis=1)
        m_win = compute_binary_metrics(y_win, win_mask.astype(np.int64))
        shortcut_rows.append({
            "evaluation_level": "window_level",
            "evaluation_protocol": "deterministic_static_rule (no training)",
            "model_or_rule": rname,
            "window_aggregation_rule": "any_packet_in_window_matches (>=1 of 20 packets)",
            "features_used": rname.split(": ", 1)[1],
            **m_win,
        })

    # Simple static non-temporal ML baselines under Leave-One-Capture-Group-Out (LOCGO) across all 10 capture groups
    cgs = df_pkt["capture_group"].to_numpy()
    unique_cgs = np.unique(cgs)

    X_pkt_full = df_pkt[["func_code", "register_start", "quantity", "modbus_len", "packet_size", "unit_id"]].to_numpy(dtype=np.float64)
    X_pkt_nolen = df_pkt[["func_code", "register_start", "quantity", "unit_id"]].to_numpy(dtype=np.float64)

    for feat_label, X_mat, feat_desc in [
        ("with_len_size", X_pkt_full, "func_code, register_start, quantity, modbus_len, packet_size, unit_id"),
        ("without_len_size", X_pkt_nolen, "func_code, register_start, quantity, unit_id (NO modbus_len/packet_size)"),
    ]:
        oof_dt3 = np.zeros(len(y_pkt), dtype=np.int64)
        oof_lr = np.zeros(len(y_pkt), dtype=np.int64)
        for held_cg in unique_cgs:
            tr = cgs != held_cg
            te = ~tr
            if np.sum(y_pkt[tr]) == 0:
                continue
            dt3 = DecisionTreeClassifier(max_depth=3, random_state=42)
            dt3.fit(X_mat[tr], y_pkt[tr])
            oof_dt3[te] = dt3.predict(X_mat[te])

            scaler = StandardScaler()
            X_tr_s = scaler.fit_transform(X_mat[tr])
            X_te_s = scaler.transform(X_mat[te])
            lr = LogisticRegression(max_iter=200, random_state=42)
            lr.fit(X_tr_s, y_pkt[tr])
            oof_lr[te] = lr.predict(X_te_s)

        m_dt3 = compute_binary_metrics(y_pkt, oof_dt3)
        shortcut_rows.append({
            "evaluation_level": "packet_level",
            "evaluation_protocol": "LOCGO_cross_validation (10 capture groups)",
            "model_or_rule": f"Static DecisionTree (max_depth=3, {feat_label})",
            "window_aggregation_rule": "N/A (single current packet)",
            "features_used": feat_desc,
            **m_dt3,
        })
        m_lr = compute_binary_metrics(y_pkt, oof_lr)
        shortcut_rows.append({
            "evaluation_level": "packet_level",
            "evaluation_protocol": "LOCGO_cross_validation (10 capture groups)",
            "model_or_rule": f"Static LogisticRegression ({feat_label})",
            "window_aggregation_rule": "N/A (single current packet)",
            "features_used": feat_desc,
            **m_lr,
        })

    # Window-level non-sequential aggregated static features
    win_cgs = df_win["capture_group"].to_numpy()
    for feat_label, X_pkt_base, feat_desc in [
        ("with_len_size", X_pkt_full, "Non-sequential window min/max/mean/std of [func_code, register_start, quantity, modbus_len, packet_size, unit_id]"),
        ("without_len_size", X_pkt_nolen, "Non-sequential window min/max/mean/std of [func_code, register_start, quantity, unit_id] (NO modbus_len/packet_size)"),
    ]:
        W_3d = X_pkt_base[win_idx]
        X_win_agg = np.concatenate(
            [W_3d.min(axis=1), W_3d.max(axis=1), W_3d.mean(axis=1), W_3d.std(axis=1)],
            axis=1,
        )
        oof_w_dt3 = np.zeros(len(y_win), dtype=np.int64)
        oof_w_rf = np.zeros(len(y_win), dtype=np.int64)
        oof_w_lr = np.zeros(len(y_win), dtype=np.int64)

        for held_cg in unique_cgs:
            tr = win_cgs != held_cg
            te = ~tr
            if np.sum(y_win[tr]) == 0:
                continue
            dt3 = DecisionTreeClassifier(max_depth=3, random_state=42)
            dt3.fit(X_win_agg[tr], y_win[tr])
            oof_w_dt3[te] = dt3.predict(X_win_agg[te])

            rf = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42, n_jobs=-1)
            rf.fit(X_win_agg[tr], y_win[tr])
            oof_w_rf[te] = rf.predict(X_win_agg[te])

            scaler = StandardScaler()
            X_tr_s = scaler.fit_transform(X_win_agg[tr])
            X_te_s = scaler.transform(X_win_agg[te])
            lr = LogisticRegression(max_iter=200, random_state=42)
            lr.fit(X_tr_s, y_win[tr])
            oof_w_lr[te] = lr.predict(X_te_s)

        for mname, preds in [
            (f"Window Static Aggregated DecisionTree (max_depth=3, {feat_label})", oof_w_dt3),
            (f"Window Static Aggregated RandomForest (max_depth=6, {feat_label})", oof_w_rf),
            (f"Window Static Aggregated LogisticRegression ({feat_label})", oof_w_lr),
        ]:
            mw = compute_binary_metrics(y_win, preds)
            shortcut_rows.append({
                "evaluation_level": "window_level",
                "evaluation_protocol": "LOCGO_cross_validation (10 capture groups)",
                "model_or_rule": mname,
                "window_aggregation_rule": "bag_of_packets_summary_stats (order-invariant, no timing)",
                "features_used": feat_desc,
                **mw,
            })

    df_shortcut = pd.DataFrame(shortcut_rows)
    df_shortcut.to_csv(AUDIT_OUT_DIR / "shortcut_analysis.csv", index=False)
    print("[Audit] Wrote shortcut_analysis.csv")

    # =========================================================================
    # SECTION 10: TEMPORAL SIGNAL ANALYSIS BEYOND THE STATIC SHORTCUT
    # =========================================================================
    print("[Audit] Computing Section 10 temporal reconnaissance diagnostics across all 119,237 windows...")
    W_reg = reg_arr[win_idx].astype(np.float64)
    W_fc = fc_arr[win_idx]
    W_dt = win_ts_diffs / 1e9

    reg_diffs = np.diff(W_reg, axis=1)
    feat_address_delta = np.mean(reg_diffs, axis=1)
    feat_abs_address_delta = np.mean(np.abs(reg_diffs), axis=1)

    W_reg_sorted = np.sort(W_reg, axis=1)
    feat_unique_addresses = 1 + np.sum(W_reg_sorted[:, 1:] != W_reg_sorted[:, :-1], axis=1)
    feat_register_span = W_reg_sorted[:, -1] - W_reg_sorted[:, 0]

    feat_monotonic_pos_frac = np.mean(reg_diffs > 0, axis=1)
    feat_unit_step_frac = np.mean(reg_diffs == 1, axis=1)
    feat_function_transition = np.mean(W_fc[:, 1:] != W_fc[:, :-1], axis=1)
    feat_read_request_rate = np.mean(np.isin(W_fc, [1, 2, 3, 4]), axis=1)
    feat_requests_per_sec = 20.0 / np.maximum(win_durations_s, 1e-6)
    feat_median_interarrival = np.median(W_dt, axis=1)
    dt_mean = np.mean(W_dt, axis=1)
    dt_std = np.std(W_dt, axis=1)
    feat_polling_drift_cv = dt_std / np.maximum(dt_mean, 1e-9)
    feat_same_address_repeats = np.sum(reg_diffs == 0, axis=1)

    W_uid = df_pkt["unit_id"].to_numpy()[win_idx]
    W_uid_sorted = np.sort(W_uid, axis=1)
    feat_unique_unit_ids = 1 + np.sum(W_uid_sorted[:, 1:] != W_uid_sorted[:, :-1], axis=1)

    win_has_fc5_req = ((W_fc == 5) & (len_arr[win_idx] == 6)).any(axis=1)

    cohort1_mask = pos_win_mask & win_has_any_len3
    cohort2_mask = pos_win_mask & (~win_has_any_len3) & win_has_qty_gt1
    cohort3_mask = pos_win_mask & (~win_has_any_len3) & (~win_has_qty_gt1)

    cohort_masks = {
        f"normal_all (n={int(neg_win_mask.sum())})": neg_win_mask,
        f"recon_all (n={int(pos_win_mask.sum())})": pos_win_mask,
        f"recon_cohort1_len3_shortcut (n={int(cohort1_mask.sum())})": cohort1_mask,
        f"recon_cohort2_qty_gt1_no_len3 (n={int(cohort2_mask.sum())})": cohort2_mask,
        f"recon_cohort3_event_mapped_routine_no_len3_no_qty_gt1 (n={int(cohort3_mask.sum())})": cohort3_mask,
        f"unlabelled_master_fc5_request_windows_in_s0003 (n={int((neg_win_mask & win_has_fc5_req).sum())})": neg_win_mask & win_has_fc5_req,
    }

    diag_features = {
        "address_delta": feat_address_delta,
        "abs_address_delta": feat_abs_address_delta,
        "unique_addresses_last_20": feat_unique_addresses,
        "register_span_last_20": feat_register_span,
        "monotonic_scan_fraction (reg_t > reg_t-1)": feat_monotonic_pos_frac,
        "exact_step1_scan_fraction (reg_t - reg_t-1 == 1)": feat_unit_step_frac,
        "function_transition_rate": feat_function_transition,
        "read_request_rate (FC1-4)": feat_read_request_rate,
        "requests_per_second": feat_requests_per_sec,
        "median_interarrival_s": feat_median_interarrival,
        "polling_interval_drift_cv": feat_polling_drift_cv,
        "same_address_repeat_steps (out of 19)": feat_same_address_repeats,
        "unique_unit_ids_last_20": feat_unique_unit_ids,
    }

    temporal_diagnostics_summary = {}
    for cname, cmask in cohort_masks.items():
        c_dict = {"window_count": int(np.sum(cmask))}
        for fname, farr in diag_features.items():
            sub = farr[cmask]
            if len(sub) == 0:
                c_dict[fname] = None
            else:
                c_dict[fname] = {
                    "mean": round(float(np.mean(sub)), 4),
                    "median": round(float(np.median(sub)), 4),
                    "p25": round(float(np.percentile(sub, 25)), 4),
                    "p75": round(float(np.percentile(sub, 75)), 4),
                    "p95": round(float(np.percentile(sub, 95)), 4),
                }
        temporal_diagnostics_summary[cname] = c_dict

    # Evaluate a classifier trained strictly on the 12 temporal/sequence-dynamics features
    # (NO static func_code=5 identity, NO modbus_len, NO packet_size, NO quantity):
    X_win_temporal_only = np.column_stack([
        feat_address_delta,
        feat_abs_address_delta,
        feat_unique_addresses,
        feat_register_span,
        feat_monotonic_pos_frac,
        feat_unit_step_frac,
        feat_function_transition,
        feat_read_request_rate,
        np.clip(feat_requests_per_sec, 0, 1e4),
        np.clip(feat_median_interarrival, 0, 1e4),
        np.clip(feat_polling_drift_cv, 0, 1e4),
        feat_same_address_repeats,
    ])

    oof_temp_rf = np.zeros(len(y_win), dtype=np.int64)
    oof_temp_lr = np.zeros(len(y_win), dtype=np.int64)
    for held_cg in unique_cgs:
        tr = win_cgs != held_cg
        te = ~tr
        if np.sum(y_win[tr]) == 0:
            continue
        rf = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=42, n_jobs=-1)
        rf.fit(X_win_temporal_only[tr], y_win[tr])
        oof_temp_rf[te] = rf.predict(X_win_temporal_only[te])

        scaler = StandardScaler()
        X_tr_s = scaler.fit_transform(X_win_temporal_only[tr])
        X_te_s = scaler.transform(X_win_temporal_only[te])
        lr = LogisticRegression(max_iter=200, random_state=42)
        lr.fit(X_tr_s, y_win[tr])
        oof_temp_lr[te] = lr.predict(X_te_s)

    temporal_only_locgo_rf = compute_binary_metrics(y_win, oof_temp_rf)
    temporal_only_locgo_lr = compute_binary_metrics(y_win, oof_temp_lr)

    temporal_only_recall_by_cohort = {
        "rf_locgo_overall": temporal_only_locgo_rf,
        "lr_locgo_overall": temporal_only_locgo_lr,
        "rf_recall_on_cohort1_len3_windows": round(float(np.mean(oof_temp_rf[cohort1_mask] == 1)), 4) if cohort1_mask.any() else None,
        "rf_recall_on_cohort2_qty_gt1_windows": round(float(np.mean(oof_temp_rf[cohort2_mask] == 1)), 4) if cohort2_mask.any() else None,
        "rf_recall_on_cohort3_event_mapped_windows": round(float(np.mean(oof_temp_rf[cohort3_mask] == 1)), 4) if cohort3_mask.any() else None,
    }

    # =========================================================================
    # SECTION 11: ATTACK INDEPENDENCE AND CLASS DISTRIBUTION
    # =========================================================================
    contiguous_pos_bursts = 0
    for (cg, sid), grp in df_pkt.groupby(["capture_group", "session_id"], sort=False):
        lbl = grp["label"].to_numpy()
        if np.sum(lbl) == 0:
            continue
        starts = np.sum((lbl[1:] == 1) & (lbl[:-1] == 0)) + (1 if lbl[0] == 1 else 0)
        contiguous_pos_bursts += int(starts)

    pos_by_cg = df_pkt[df_pkt["label"] == 1]["capture_group"].value_counts()
    pos_by_sid = df_pkt[df_pkt["label"] == 1]["session_id"].value_counts()
    pos_win_by_cg = df_win[df_win["label"] == 1]["capture_group"].value_counts()
    pos_win_by_sid = df_win[df_win["label"] == 1]["session_id"].value_counts()

    independence_summary = {
        "hierarchy_of_counts": {
            "1_raw_packet_count_before_dedup": raw_total_rows,
            "1b_raw_positive_packet_count_before_dedup": int((df_raw_pkt["label"] == 1).sum()),
            "1c_rebuilt_retained_packet_count": pkt_row_count,
            "1d_rebuilt_positive_packet_count": int(len(df_pos)),
            "2_rebuilt_total_window_count": n_windows,
            "2b_rebuilt_positive_window_count": int(pos_win_mask.sum()),
            "2c_rebuilt_non_len3_positive_window_count": int((pos_win_mask & (~win_has_any_len3)).sum()),
            "3_mapped_attack_event_rows_in_xlsx": int(len(df_events)),
            "3b_distinct_log_timestamps_in_attack_events_mapped": int(df_events["log_timestamp"].nunique()),
            "3c_contiguous_positive_packet_bursts_in_rebuilt_streams": contiguous_pos_bursts,
            "4_distinct_source_pcap_files_in_raw": int(df_raw_pkt["file_source"].nunique()),
            "4b_distinct_source_pcap_files_retained": n_distinct_source_files,
            "4c_distinct_capture_groups_retained": n_capture_groups,
            "4d_positive_capture_groups_retained": int((pos_by_cg > 0).sum()),
            "5_independent_reconnaissance_campaigns": 2,
            "5_campaign_breakdown": [
                {
                    "campaign_id": 1,
                    "name": "Feb 2023 Docker veth Multi-Interface Capture (G03_0201_veth)",
                    "capture_groups": ["G03_0201_veth"],
                    "positive_packets": int(df_pos[df_pos["capture_group"] == "G03_0201_veth"].shape[0]),
                    "positive_windows": int(df_win[(df_win["label"] == 1) & (df_win["capture_group"] == "G03_0201_veth")].shape[0]),
                    "dominant_artifact": "50 retained packets (10 windows) in 185.175.0.7->185.175.0.4 with FC=1, quantity=204, register_start=114 (repeated identical probe, plus 50 duplicate view packets dropped from veth665f3cf-0.pcap)",
                },
                {
                    "campaign_id": 2,
                    "name": "Mar 15-20 2023 Compromised-SCADA Substation Captures (G04_0315_sub1, G05_0315_sub2, G06_0316_sub4, G07_0319_sub10, G08_0320_sub14)",
                    "capture_groups": ["G04_0315_sub1", "G05_0315_sub2", "G06_0316_sub4", "G07_0319_sub10", "G08_0320_sub14"],
                    "positive_packets": int(df_pos[df_pos["capture_group"].str.contains("_sub")].shape[0]),
                    "positive_windows": int(df_win[(df_win["label"] == 1) & (df_win["capture_group"].str.contains("_sub"))].shape[0]),
                    "dominant_artifact": "8,400 FC5+len3 slave responses (97.82% of substation positives) + 13 FC1-4+len3 responses + 16 non-routine qty>1 reads + 158 event_mapped rows",
                },
            ],
        },
        "concentration_metrics": {
            "largest_positive_capture_group": str(pos_by_cg.index[0]),
            "largest_positive_capture_group_packets": int(pos_by_cg.iloc[0]),
            "largest_positive_capture_group_packet_pct": round(float(100.0 * pos_by_cg.iloc[0] / len(df_pos)), 2),
            "substation_campaign_packet_pct": round(
                float(100.0 * df_pos[df_pos["capture_group"].str.contains("_sub")].shape[0] / len(df_pos)), 2
            ),
            "largest_positive_session_id": str(pos_by_sid.index[0]),
            "largest_positive_session_id_packets": int(pos_by_sid.iloc[0]),
            "largest_positive_session_id_packet_pct": round(float(100.0 * pos_by_sid.iloc[0] / len(df_pos)), 2),
            "largest_positive_session_id_windows": int(pos_win_by_sid.iloc[0]),
            "largest_positive_session_id_window_pct": round(
                float(100.0 * pos_win_by_sid.iloc[0] / pos_win_mask.sum()), 2
            ),
            "positive_packets_by_capture_group": {str(k): int(v) for k, v in pos_by_cg.items()},
            "positive_windows_by_capture_group": {str(k): int(v) for k, v in pos_win_by_cg.items()},
            "positive_packets_by_session_id": {str(k): int(v) for k, v in pos_by_sid.items()},
            "positive_windows_by_session_id": {str(k): int(v) for k, v in pos_win_by_sid.items()},
        },
    }

    # =========================================================================
    # OLD SEQUENCE FILE COMPARISON (recon_sequences_ALL.csv)
    # =========================================================================
    old_start_ns = pd.to_datetime(df_raw_seq["window_start_time"], utc=True, format="ISO8601").dt.as_unit("ns").astype("int64").to_numpy()
    old_end_ns = pd.to_datetime(df_raw_seq["window_end_time"], utc=True, format="ISO8601").dt.as_unit("ns").astype("int64").to_numpy()
    raw_pkt_ts_ns = pd.to_datetime(df_raw_pkt["timestamp"], utc=True, format="ISO8601", errors="coerce").dt.as_unit("ns").astype("int64").to_numpy()
    raw_pkt_fsrc = df_raw_pkt["file_source"].to_numpy()

    old_backward_wins = 0
    old_multi_file_wins = 0
    for sid, idx in df_raw_seq.groupby("session_id").indices.items():
        p_mask = (df_raw_pkt["session_id"] == sid).to_numpy()
        tns_s = raw_pkt_ts_ns[p_mask]
        fs_s = raw_pkt_fsrc[p_mask]
        for k in range(len(idx)):
            a = k * 5
            w_tns = tns_s[a : a + 20]
            w_fs = fs_s[a : a + 20]
            if np.any(np.diff(w_tns) < 0):
                old_backward_wins += 1
            if len(set(w_fs)) > 1:
                old_multi_file_wins += 1

    old_seq_summary = {
        "rows": int(len(df_raw_seq)),
        "distinct_session_ids": int(df_raw_seq["session_id"].nunique()),
        "positive_windows": int((df_raw_seq["label"] == 1).sum()),
        "negative_windows": int((df_raw_seq["label"] == 0).sum()),
        "windows_with_start_after_end": int(np.sum(old_start_ns > old_end_ns)),
        "windows_with_any_backward_time_step": int(old_backward_wins),
        "windows_spanning_multiple_file_sources": int(old_multi_file_wins),
    }

    # =========================================================================
    # WRITE MASTER audit_metrics.json
    # =========================================================================
    audit_metrics = {
        "project_id": "J26-CS-318",
        "component": "Component 2 (RP2) - Reconnaissance Attack Detection Using Temporal Behavior Analysis",
        "student": "Charith H. / Harry (IT23269002)",
        "section_5_rebuilt_dataset_accounting": {
            "packets_rebuilt": {
                "row_count": pkt_row_count,
                "class_counts": pkt_class_counts,
                "positive_rate_pct": round(float(100.0 * pkt_class_counts.get("1", 0) / pkt_row_count), 4),
                "columns": pkt_columns,
                "null_counts": pkt_null_counts,
                "distinct_capture_groups": n_capture_groups,
                "distinct_session_ids": n_distinct_session_ids,
                "distinct_capture_session_streams": n_distinct_streams,
                "distinct_source_files": n_distinct_source_files,
                "timestamps_reverse_within_any_stream": bool(stream_reversals > 0),
                "total_stream_timestamp_reversals": stream_reversals,
                "dt_s_negative_count": negative_dt_s_count,
                "dt_s_zero_count": zero_dt_s_count,
                "dt_s_null_count": pkt_null_counts["dt_s"],
                "first_packet_of_stream_accounts_for_all_missing_dt_s": bool(
                    first_pkt_na_matches == n_distinct_streams
                    and non_first_pkt_na_count == 0
                    and pkt_null_counts["dt_s"] == n_distinct_streams
                ),
                "any_stream_has_multiple_retained_source_files": bool(streams_with_multiple_source_files > 0),
                "session_ids_spanning_multiple_capture_groups_if_not_grouped_by_capture": session_only_crossings,
                "capture_group_timestamps": cg_time_summary,
                "session_id_timestamps": sess_time_summary,
            },
            "packet_exclusions": {
                "row_count": exc_row_count,
                "exclusion_reasons_and_counts": exc_reason_counts,
                "raw_packet_population_total": raw_total_rows,
                "retained_plus_excluded_total": int(pkt_row_count + exc_row_count),
                "exact_reproduction_of_original_packet_population": exact_partition_match,
                "duplicate_retained_orig_row_ids": n_dup_retained,
                "duplicate_excluded_orig_row_ids": n_dup_excluded,
                "overlap_between_retained_and_excluded_ids": overlap_ret_exc,
                "missing_original_row_ids": missing_orig_ids,
                "attached_recon_flows_14_rows_intentionally_excluded": bool(
                    len(attached_rows_raw) == 14 and len(attached_exc) == 14 and attached_in_rebuilt == 0
                ),
                "duplicate_interface_view_independent_verification": dup_verification,
            },
            "old_sequences_comparison": old_seq_summary,
        },
        "section_6_session_id_forensics": {
            "distinct_session_ids_retained": n_distinct_session_ids,
            "distinct_session_ids_raw_including_excluded": int(df_raw_pkt["session_id"].nunique()),
            "distinct_src_dst_unit_triples_retained": n_unique_endpoint_unit_triples,
            "is_exact_1to1_bijection_with_src_ip_dst_ip_unit_id": session_id_is_exact_bijection_with_endpoint_unit,
            "pattern_formula": "<src_ip>_<dst_ip>_u<unit_id>_s<4-digit-index>",
            "tcp_ports_present_in_dataset": False,
            "represents_actual_tcp_connection": False,
            "represents_capture_local_stream_by_itself": False,
            "precise_meaning": "Global directed (src_ip, dst_ip, unit_id) logical endpoint+unit tuple reused across all captures and months; only (capture_group, session_id) is capture-local",
            "session_mapping_table": session_mapping_table,
        },
        "section_7_and_8_label_provenance_and_fc5_len3": {
            "forensic_positive_categories": pos_category_counts,
            "fc5_len3_summary": fc5_len3_summary,
            "normal_distributions": {
                "func_code": dist_dict(df_neg["func_code"]),
                "modbus_len": dist_dict(df_neg["modbus_len"]),
                "packet_size": dist_dict(df_neg["packet_size"]),
                "quantity": dist_dict(df_neg["quantity"]),
                "register_start_top20": top_dist_dict(df_neg["register_start"], 20),
                "joint_func_code_modbus_len": joint_neg_fc_len,
                "joint_full_signature": joint_neg_full,
            },
            "recon_distributions": {
                "func_code": dist_dict(df_pos["func_code"]),
                "modbus_len": dist_dict(df_pos["modbus_len"]),
                "packet_size": dist_dict(df_pos["packet_size"]),
                "quantity": dist_dict(df_pos["quantity"]),
                "register_start_top20": top_dist_dict(df_pos["register_start"], 20),
                "joint_func_code_modbus_len": joint_pos_fc_len,
                "joint_full_signature": joint_pos_full,
            },
            "fc5_neighbor_request_response_pairing": fc5_neighbor_analysis,
            "attack_events_mapped_alignment": event_alignment_summary,
        },
        "section_9_static_shortcut_summary": shortcut_rows,
        "section_10_temporal_signal_diagnostics": {
            "cohort_feature_distributions": temporal_diagnostics_summary,
            "temporal_only_locgo_classifier_evaluation": temporal_only_recall_by_cohort,
        },
        "section_11_attack_independence": independence_summary,
    }

    with open(AUDIT_OUT_DIR / "audit_metrics.json", "w", encoding="utf-8") as f:
        json.dump(audit_metrics, f, indent=2)
    print("[Audit] Wrote audit_metrics.json")
    print("[Audit] All forensic computations completed successfully.")


if __name__ == "__main__":
    main()
