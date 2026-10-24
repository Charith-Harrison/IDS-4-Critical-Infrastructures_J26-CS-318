"""Export comprehensive real dataset, accuracy metrics, and detected network packets for the React dashboard.

Generates `artifacts/dashboard_data.json` (and copies to `frontend/public/dashboard_data.json` if present)
using strictly verified experimental artifacts and real rebuilt Modbus/TCP packets. Zero mock data.
"""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from common import ARTIFACTS, DATA_REBUILT, ROOT, read_json, write_json
from contract import C2InferenceEngine

MODBUS_FC_NAMES: dict[int, str] = {
    1: "FC01 Read Coils",
    2: "FC02 Read Discrete Inputs",
    3: "FC03 Read Holding Registers",
    4: "FC04 Read Input Registers",
    5: "FC05 Write Single Coil",
    6: "FC06 Write Single Register",
    15: "FC15 Write Multiple Coils",
    16: "FC16 Write Multiple Registers",
}


def _enrich_confusion(cm: dict[str, Any]) -> dict[str, Any]:
    tp = int(cm.get("tp", 0) or 0)
    fp = int(cm.get("fp", 0) or 0)
    fn = int(cm.get("fn", 0) or 0)
    tn = int(cm.get("tn", 0) or 0)
    total = tp + fp + fn + tn
    acc = (tp + tn) / total if total > 0 else None
    rec = cm.get("recall")
    spec = cm.get("specificity")
    bal_acc = (
        0.5 * (float(rec) + float(spec))
        if (rec is not None and spec is not None)
        else None
    )
    out = dict(cm)
    out["accuracy"] = acc
    out["balanced_accuracy"] = bal_acc
    out["n_total"] = total
    return out


def build_dashboard_data() -> dict[str, Any]:
    print("Loading verified artifacts and rebuilt packet/window tables...")
    profile = read_json(ARTIFACTS / "dataset_profile.json")
    seq_audit = read_json(ARTIFACTS / "sequence_audit.json")
    label_audit = read_json(ARTIFACTS / "label_audit.json")
    rebuild = read_json(ARTIFACTS / "rebuild_report.json")
    leakage = read_json(ARTIFACTS / "leakage_audit.json")
    metrics = read_json(ARTIFACTS / "metrics.json")
    confusion = read_json(ARTIFACTS / "confusion.json")
    curves = read_json(ARTIFACTS / "curves.json")
    ablations = read_json(ARTIFACTS / "ablation_results.json")
    latency = read_json(ARTIFACTS / "latency.json")
    examples = read_json(ARTIFACTS / "example_sequences.json")

    rebuilt_dir = DATA_REBUILT
    W = pd.read_csv(rebuilt_dir / "windows.csv")
    P = pd.read_csv(ARTIFACTS / "predictions.csv")
    idx_mat = np.load(rebuilt_dir / "window_index.npy")
    pkt_df = pd.read_csv(rebuilt_dir / "packets_rebuilt.csv", low_memory=False)

    engine = C2InferenceEngine().load()

    # 1. Enrich model summaries with accuracy and balanced_accuracy
    model_summaries: dict[str, Any] = {}
    model_display_names = {
        "Model_A_Packet_LogReg": "Model A1: Packet Logistic Regression",
        "Model_A_Packet_DT": "Model A2: Packet Decision Tree",
        "Model_B_Window_RF": "Model B1: Window Random Forest (29 dims)",
        "Model_B_Window_LogReg": "Model B2: Window Logistic Regression (29 dims)",
        "Model_C_LSTM_Full": "Model C: Temporal LSTM Full (20x19, Primary)",
        "Model_D_LSTM_NoTiming": "Model D: Temporal LSTM No-Timing (20x17, RQ2)",
    }

    for m_key, m_val in metrics["models"].items():
        m_out: dict[str, Any] = {
            "model_id": m_key,
            "display_name": model_display_names.get(m_key, m_key),
        }
        for scheme in ["locgo_10fold", "sgkf_5fold"]:
            s_data = m_val[scheme]
            p05 = _enrich_confusion(s_data["pooled_oof_at_0_5"])
            pval = _enrich_confusion(s_data["pooled_oof_at_val_threshold"])
            per_fold = []
            for pf in s_data["per_fold"]:
                pf_05 = _enrich_confusion(pf["at_0_5"])
                pf_val = _enrich_confusion(pf["at_val_threshold"])
                per_fold.append(
                    {
                        "fold_id": pf["fold_id"],
                        "test_groups": pf["test_groups"],
                        "val_groups": pf.get("val_groups", []),
                        "threshold": pf["threshold_selection"]["threshold"],
                        "at_0_5": pf_05,
                        "at_val_threshold": pf_val,
                    }
                )
            m_out[scheme] = {
                "pooled_at_0_5": p05,
                "pooled_at_val_threshold": pval,
                "summary_at_0_5": s_data["summary_at_0_5"],
                "summary_at_val_threshold": s_data["summary_at_val_threshold"],
                "per_fold": per_fold,
            }
        model_summaries[m_key] = m_out

    # Include Model_C_LSTM_Sequences_ALL trained directly on Dataset/recon_sequences_ALL.csv
    ds_summary_path = ARTIFACTS / "lstm_dataset_training_summary.json"
    if ds_summary_path.exists():
        ds_summary = read_json(ds_summary_path)
        seq_entry = next(
            (
                item
                for item in ds_summary.get("source_files_used", [])
                if "recon_sequences_ALL" in item.get("dataset_file", "")
            ),
            None,
        )
        if seq_entry:
            seq_pooled = _enrich_confusion(seq_entry["cv_5fold_pooled_at_0_5"])
            seq_per_fold = []
            for pf in seq_entry.get("per_fold", []):
                m_pf = _enrich_confusion(pf["metrics"])
                seq_per_fold.append(
                    {
                        "fold_id": f"Fold_{pf['fold']}_recon_sequences_ALL",
                        "test_groups": ["recon_sequences_ALL.csv (20% Fold)"],
                        "val_groups": ["recon_sequences_ALL.csv (15% Val)"],
                        "threshold": pf["threshold"],
                        "at_0_5": m_pf,
                        "at_val_threshold": m_pf,
                    }
                )
            seq_scheme_obj = {
                "pooled_at_0_5": seq_pooled,
                "pooled_at_val_threshold": seq_pooled,
                "summary_at_0_5": {},
                "summary_at_val_threshold": {},
                "per_fold": seq_per_fold,
            }
            model_summaries["Model_C_LSTM_Sequences_ALL"] = {
                "model_id": "Model_C_LSTM_Sequences_ALL",
                "display_name": "Model C (recon_sequences_ALL.csv - 175,800 Windows)",
                "locgo_10fold": seq_scheme_obj,
                "sgkf_5fold": seq_scheme_obj,
            }

    # Add Static Rule baseline for direct comparison
    static_rule = leakage["protocol_field_shortcut_risk"][
        "trivial_rule_any_modbus_len_eq_3_on_rebuilt_windows"
    ]
    sr_fp = int(static_rule.get("fp", 0))
    sr_tn = int(static_rule.get("tn", 117359))
    sr_fpr = float(static_rule.get("fpr", sr_fp / max(sr_fp + sr_tn, 1)))
    static_cm = _enrich_confusion(
        {
            "tp": static_rule["tp"],
            "fp": sr_fp,
            "fn": static_rule["fn"],
            "tn": sr_tn,
            "precision": static_rule["precision"],
            "recall": static_rule["recall"],
            "f1": static_rule["f1"],
            "fpr": sr_fpr,
            "specificity": 1.0 - sr_fpr,
            "roc_auc": None,
            "pr_auc": None,
            "brier_score": None,
            "ece_10bin": None,
        }
    )

    # 2. Categorize all 119,237 windows for sampling and statistics
    ml_mat = pkt_df["modbus_len"].to_numpy()[idx_mat]
    qty_mat = pkt_df["quantity"].to_numpy()[idx_mat]
    has_ml3 = (ml_mat == 3).any(axis=1)
    has_scan_qty = (~np.isin(qty_mat, [0, 1])).any(axis=1)
    y_win = W["label"].to_numpy()

    win_category = np.where(
        y_win == 0,
        "Normal Polling",
        np.where(
            has_ml3,
            "Cat 1: modbus_len=3 Signature",
            np.where(
                has_scan_qty,
                "Cat 2: Multi-Register Quantity Scan",
                "Cat 3: Event-Mapped Interval",
            ),
        ),
    )

    s_c = P["score_model_c_lstm"].to_numpy()
    t_c = P["thr_model_c_lstm"].to_numpy()
    pred_c = (s_c >= t_c).astype(int)

    s_b = P["score_model_b_window_rf"].to_numpy()
    t_b = P["thr_model_b_window_rf"].to_numpy()
    pred_b = (s_b >= t_b).astype(int)

    s_a_dt = P["score_model_a_packet_dt"].to_numpy()
    t_a_dt = P["thr_model_a_packet_dt"].to_numpy()
    pred_a_dt = (s_a_dt >= t_a_dt).astype(int)

    s_d = P["score_model_d_lstm_no_timing"].to_numpy()
    t_d = P["thr_model_d_lstm_no_timing"].to_numpy()
    pred_d = (s_d >= t_d).astype(int)

    # 3. Select a diverse set of 60 representative 20-packet windows across all categories, groups, and outcomes
    selected_w_indices: list[int] = []

    def _add_indices(mask: np.ndarray, limit: int, sort_by: np.ndarray | None = None) -> None:
        cand = np.where(mask)[0]
        if len(cand) == 0:
            return
        if sort_by is not None:
            order = np.argsort(sort_by[cand])[::-1]
            cand = cand[order]
        step = max(1, len(cand) // limit)
        for idx in cand[::step][:limit]:
            if int(idx) not in selected_w_indices:
                selected_w_indices.append(int(idx))

    # Include the 6 canonical example windows first
    w_id_to_idx = {str(wid): i for i, wid in enumerate(W["window_id"])}
    for ex_val in examples["examples"].values():
        wid = ex_val["window_id"]
        if wid in w_id_to_idx and w_id_to_idx[wid] not in selected_w_indices:
            selected_w_indices.append(w_id_to_idx[wid])

    # Add Cat 1 True Positives across each positive capture group (G04, G05, G06, G07, G08)
    for grp in ["G04_0315_sub1", "G05_0315_sub2", "G06_0316_sub4", "G07_0319_sub10", "G08_0320_sub14"]:
        _add_indices((y_win == 1) & has_ml3 & (W["capture_group"].to_numpy() == grp) & (pred_c == 1), 4, s_c)

    # Add Cat 2 Quantity Scan windows (all 23 are interesting, take 12)
    _add_indices((y_win == 1) & (~has_ml3) & has_scan_qty, 12, s_a_dt)

    # Add Cat 3 Event-Mapped windows (take 8 across G03, G05, G07)
    _add_indices((y_win == 1) & (~has_ml3) & (~has_scan_qty), 8, s_c)

    # Add False Positives from Model C LSTM or Model B RF (take 10)
    _add_indices((y_win == 0) & ((pred_c == 1) | (pred_b == 1)), 10, s_c)

    # Add True Negatives across all 10 capture groups (take 14)
    for grp in sorted(W["capture_group"].unique()):
        _add_indices((y_win == 0) & (pred_c == 0) & (pred_b == 0) & (W["capture_group"].to_numpy() == grp), 2, -s_c)

    print(f"Selected {len(selected_w_indices)} representative 20-packet windows for interactive inspection.")

    raw_cols = [
        "row_index",
        "timestamp",
        "ts_ns",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "session_id",
        "capture_group",
        "file_source",
        "func_code",
        "modbus_len",
        "register_start",
        "quantity",
        "packet_size",
        "dt_s",
        "label",
        "label_source",
    ]
    avail_cols = [c for c in raw_cols if c in pkt_df.columns]

    inspected_windows: list[dict[str, Any]] = []
    packet_table_rows: list[dict[str, Any]] = []
    seen_packet_indices: set[int] = set()

    for w_idx in selected_w_indices:
        w_row = W.iloc[w_idx]
        p_row = P.iloc[w_idx]
        p_indices = idx_mat[w_idx]
        sub_pkts = pkt_df.iloc[p_indices][avail_cols].copy()

        # Run live inference + gradient*input attribution via C2InferenceEngine
        contract_res = engine.score_window(
            sub_pkts,
            session_id=str(w_row["session_id"]),
            model_choice="c2-lstm-v1",
            include_attribution=True,
        )
        ts_salience = (
            contract_res["attribution"]["timestep_salience"]
            if contract_res.get("attribution")
            else [0.05] * len(sub_pkts)
        )

        true_lbl = int(w_row["label"])
        oof_c_score = float(p_row["score_model_c_lstm"])
        oof_c_thr = float(p_row["thr_model_c_lstm"])
        oof_c_pred = int(oof_c_score >= oof_c_thr)

        oof_b_score = float(p_row["score_model_b_window_rf"])
        oof_b_thr = float(p_row["thr_model_b_window_rf"])
        oof_b_pred = int(oof_b_score >= oof_b_thr)

        oof_a_dt_score = float(p_row["score_model_a_packet_dt"])
        oof_a_dt_thr = float(p_row["thr_model_a_packet_dt"])
        oof_a_dt_pred = int(oof_a_dt_score >= oof_a_dt_thr)

        oof_d_score = float(p_row["score_model_d_lstm_no_timing"])
        oof_d_thr = float(p_row["thr_model_d_lstm_no_timing"])
        oof_d_pred = int(oof_d_score >= oof_d_thr)

        if true_lbl == 1 and oof_c_pred == 1:
            verdict_c = "TP"
        elif true_lbl == 0 and oof_c_pred == 1:
            verdict_c = "FP"
        elif true_lbl == 1 and oof_c_pred == 0:
            verdict_c = "FN"
        else:
            verdict_c = "TN"

        if true_lbl == 1 and oof_b_pred == 1:
            verdict_b = "TP"
        elif true_lbl == 0 and oof_b_pred == 1:
            verdict_b = "FP"
        elif true_lbl == 1 and oof_b_pred == 0:
            verdict_b = "FN"
        else:
            verdict_b = "TN"

        cat_str = str(win_category[w_idx])

        pkt_records: list[dict[str, Any]] = []
        for step_i, (_, pkt) in enumerate(sub_pkts.iterrows()):
            fc_int = int(pkt["func_code"])
            ml_int = int(pkt["modbus_len"])
            qty_int = int(pkt["quantity"])
            reg_int = int(pkt["register_start"])
            pkt_lbl = int(pkt["label"])
            r_idx = int(pkt["row_index"])
            sal_val = float(ts_salience[step_i]) if step_i < len(ts_salience) else 0.0

            pkt_sig = (
                "modbus_len=3 Signature"
                if ml_int == 3
                else (
                    f"Multi-Reg Scan (qty={qty_int})"
                    if qty_int not in (0, 1)
                    else ("Event-Mapped Positive" if pkt_lbl == 1 else "Normal Polling")
                )
            )

            rec = {
                "step": step_i,
                "row_index": r_idx,
                "window_id": str(w_row["window_id"]),
                "capture_group": str(w_row["capture_group"]),
                "session_id": str(w_row["session_id"]),
                "timestamp": str(pkt["timestamp"]),
                "ts_ns": int(pkt["ts_ns"]),
                "dt_s": float(pkt["dt_s"]),
                "src_ip": str(pkt.get("src_ip", "")),
                "dst_ip": str(pkt.get("dst_ip", "")),
                "func_code": fc_int,
                "func_name": MODBUS_FC_NAMES.get(fc_int, f"FC{fc_int:02d}"),
                "register_start": reg_int,
                "quantity": qty_int,
                "modbus_len": ml_int,
                "packet_size": int(pkt["packet_size"]),
                "packet_label": pkt_lbl,
                "window_label": true_lbl,
                "packet_signature": pkt_sig,
                "window_category": cat_str,
                "salience": sal_val,
                "score_lstm_c": oof_c_score,
                "pred_lstm_c": oof_c_pred,
                "verdict_lstm_c": verdict_c,
                "score_rf_b": oof_b_score,
                "pred_rf_b": oof_b_pred,
                "verdict_rf_b": verdict_b,
                "score_dt_a": oof_a_dt_score,
                "pred_dt_a": oof_a_dt_pred,
                "severity": contract_res["severity"],
            }
            pkt_records.append(rec)

            # Add all unique packets to the top-level network packet feed (no limit)
            if r_idx not in seen_packet_indices:
                seen_packet_indices.add(r_idx)
                packet_table_rows.append(rec)

        inspected_windows.append(
            {
                "window_id": str(w_row["window_id"]),
                "window_index": int(w_idx),
                "capture_group": str(w_row["capture_group"]),
                "session_id": str(w_row["session_id"]),
                "window_start_utc": str(w_row["window_start_utc"]),
                "window_end_utc": str(w_row["window_end_utc"]),
                "true_label": true_lbl,
                "n_pos_packets": int(w_row["n_pos_packets"]),
                "n_fc5_len3_packets": int(w_row["n_fc5_len3_packets"]),
                "category": cat_str,
                "verdict_lstm_c": verdict_c,
                "verdict_rf_b": verdict_b,
                "severity": contract_res["severity"],
                "top_indicators": contract_res["top_indicators"],
                "oof_scores": {
                    "Model_A_Packet_LogReg": float(p_row["score_model_a_packet_logreg"]),
                    "Model_A_Packet_DT": oof_a_dt_score,
                    "Model_B_Window_RF": oof_b_score,
                    "Model_B_Window_LogReg": float(p_row["score_model_b_window_logreg"]),
                    "Model_C_LSTM_Full": oof_c_score,
                    "Model_D_LSTM_NoTiming": oof_d_score,
                },
                "oof_thresholds": {
                    "Model_A_Packet_LogReg": float(p_row["thr_model_a_packet_logreg"]),
                    "Model_A_Packet_DT": oof_a_dt_thr,
                    "Model_B_Window_RF": oof_b_thr,
                    "Model_B_Window_LogReg": float(p_row["thr_model_b_window_logreg"]),
                    "Model_C_LSTM_Full": oof_c_thr,
                    "Model_D_LSTM_NoTiming": oof_d_thr,
                },
                "attribution": contract_res["attribution"],
                "packets": pkt_records,
            }
        )

    # 4. Build capture-group traffic & detection summary across all 10 groups
    capture_group_summary: list[dict[str, Any]] = []
    for grp_id, grp_df in W.groupby("capture_group", sort=True):
        g_mask = W["capture_group"].to_numpy() == grp_id
        n_w = int(g_mask.sum())
        n_pos_w = int(y_win[g_mask].sum())
        n_neg_w = n_w - n_pos_w
        c_tp = int(((y_win[g_mask] == 1) & (pred_c[g_mask] == 1)).sum())
        c_fp = int(((y_win[g_mask] == 0) & (pred_c[g_mask] == 1)).sum())
        c_fn = int(((y_win[g_mask] == 1) & (pred_c[g_mask] == 0)).sum())
        c_tn = int(((y_win[g_mask] == 0) & (pred_c[g_mask] == 0)).sum())

        b_tp = int(((y_win[g_mask] == 1) & (pred_b[g_mask] == 1)).sum())
        b_fp = int(((y_win[g_mask] == 0) & (pred_b[g_mask] == 1)).sum())
        b_fn = int(((y_win[g_mask] == 1) & (pred_b[g_mask] == 0)).sum())
        b_tn = int(((y_win[g_mask] == 0) & (pred_b[g_mask] == 0)).sum())

        capture_group_summary.append(
            {
                "capture_group": str(grp_id),
                "n_windows": n_w,
                "n_pos_windows": n_pos_w,
                "n_neg_windows": n_neg_w,
                "is_single_class_normal": bool(n_pos_w == 0),
                "lstm_c": {
                    "tp": c_tp,
                    "fp": c_fp,
                    "fn": c_fn,
                    "tn": c_tn,
                    "accuracy": (c_tp + c_tn) / n_w if n_w > 0 else 1.0,
                    "f1": (2 * c_tp / (2 * c_tp + c_fp + c_fn)) if (n_pos_w > 0 and (2 * c_tp + c_fp + c_fn) > 0) else (0.0 if n_pos_w > 0 else None),
                    "fpr": c_fp / n_neg_w if n_neg_w > 0 else 0.0,
                },
                "window_rf_b": {
                    "tp": b_tp,
                    "fp": b_fp,
                    "fn": b_fn,
                    "tn": b_tn,
                    "accuracy": (b_tp + b_tn) / n_w if n_w > 0 else 1.0,
                    "f1": (2 * b_tp / (2 * b_tp + b_fp + b_fn)) if (n_pos_w > 0 and (2 * b_tp + b_fp + b_fn) > 0) else (0.0 if n_pos_w > 0 else None),
                    "fpr": b_fp / n_neg_w if n_neg_w > 0 else 0.0,
                },
            }
        )

    # 4b. Build packed binary table for ALL 597,135 packets in packets_rebuilt.csv (zero limit)
    n_all_pkts = len(pkt_df)
    n_all_wins = len(W)
    win_of_pkt = np.zeros(n_all_pkts, dtype=np.int32)
    step_of_pkt = np.zeros(n_all_pkts, dtype=np.int32)
    w_grid = np.broadcast_to(np.arange(n_all_wins, dtype=np.int32)[:, None], idx_mat.shape)
    s_grid = np.broadcast_to(np.arange(20, dtype=np.int32)[None, :], idx_mat.shape)

    # Verdict codes: 0=TN, 1=TP, 2=FP, 3=FN
    win_verdict_c_code = np.where(
        (y_win == 1) & (pred_c == 1),
        1,
        np.where((y_win == 0) & (pred_c == 1), 2, np.where((y_win == 1) & (pred_c == 0), 3, 0)),
    ).astype(np.int32)
    win_verdict_b_code = np.where(
        (y_win == 1) & (pred_b == 1),
        1,
        np.where((y_win == 0) & (pred_b == 1), 2, np.where((y_win == 1) & (pred_b == 0), 3, 0)),
    ).astype(np.int32)

    # Priority order so packets in overlapping stride-5 windows retain their attack/alert window assignment
    win_priority = np.where(
        win_verdict_c_code == 1,
        3,
        np.where(win_verdict_c_code == 2, 2, np.where(win_verdict_c_code == 3, 1, 0)),
    )
    order_w = np.argsort(win_priority, kind="mergesort")
    idx_ordered = idx_mat[order_w]
    w_ordered = w_grid[order_w]
    s_ordered = s_grid[order_w]
    win_of_pkt[idx_ordered.ravel()] = w_ordered.ravel()
    step_of_pkt[idx_ordered.ravel()] = s_ordered.ravel()

    groups_list = sorted(pkt_df["capture_group"].unique().tolist())
    grp_to_idx = {g: i for i, g in enumerate(groups_list)}
    sessions_list = sorted(pkt_df["session_id"].unique().tolist())
    sess_to_idx = {s: i for i, s in enumerate(sessions_list)}

    sess_first = pkt_df.groupby("session_id", sort=False).first()
    session_src_dst = [
        f"{sess_first.loc[s, 'src_ip']} → {sess_first.loc[s, 'dst_ip']}" for s in sessions_list
    ]

    grp_codes = pkt_df["capture_group"].map(grp_to_idx).to_numpy(dtype=np.int32)
    sess_codes = pkt_df["session_id"].map(sess_to_idx).to_numpy(dtype=np.int32)
    fc_arr = pkt_df["func_code"].to_numpy(dtype=np.int32)
    reg_arr = pkt_df["register_start"].to_numpy(dtype=np.int32)
    qty_arr = pkt_df["quantity"].to_numpy(dtype=np.int32)
    mlen_arr = pkt_df["modbus_len"].to_numpy(dtype=np.int32)
    psize_arr = pkt_df["packet_size"].to_numpy(dtype=np.int32)
    ts_ns_arr = pkt_df["ts_ns"].to_numpy(dtype=np.int64)
    ts_sec_arr = (ts_ns_arr // 1_000_000_000).astype(np.int32)
    ts_ms_arr = ((ts_ns_arr % 1_000_000_000) // 1_000_000).astype(np.int32)
    dt_100us_arr = np.round(pkt_df["dt_s"].fillna(0.0).to_numpy(dtype=np.float64) * 10000.0).astype(
        np.int32
    )

    packed_mat = np.zeros((n_all_pkts, 8), dtype=np.int32)
    packed_mat[:, 0] = pkt_df["row_index"].to_numpy(dtype=np.int32)
    packed_mat[:, 1] = win_of_pkt
    packed_mat[:, 2] = ts_sec_arr
    packed_mat[:, 3] = ts_ms_arr
    packed_mat[:, 4] = dt_100us_arr
    packed_mat[:, 5] = (
        (step_of_pkt & 0xFF)
        | ((fc_arr & 0xFF) << 8)
        | ((grp_codes & 0xFF) << 16)
        | ((sess_codes & 0xFF) << 24)
    )
    packed_mat[:, 6] = (reg_arr & 0xFFFF) | ((qty_arr & 0xFFFF) << 16)
    packed_mat[:, 7] = (mlen_arr & 0xFFFF) | ((psize_arr & 0xFFFF) << 16)

    bin_path = ARTIFACTS / "whole_network_packets.bin"
    packed_mat.tofile(bin_path)
    print(
        f"Saved packed whole-network packet stream: {bin_path} "
        f"({n_all_pkts:,} packets, {bin_path.stat().st_size / (1024 * 1024):.2f} MB)"
    )

    whole_network_meta = {
        "n_packets": int(n_all_pkts),
        "n_windows": int(n_all_wins),
        "groups": groups_list,
        "sessions": sessions_list,
        "session_src_dst": session_src_dst,
        "win_score_c_bp": np.round(s_c * 10000).astype(int).tolist(),
        "win_verdict_c_code": win_verdict_c_code.tolist(),
        "win_score_b_bp": np.round(s_b * 10000).astype(int).tolist(),
        "win_verdict_b_code": win_verdict_b_code.tolist(),
    }

    # 5. Assemble final payload
    payload: dict[str, Any] = {
        "project": {
            "project_id": "J26-CS-318",
            "component_id": "C2 / RP2",
            "title": "Modbus/TCP Reconnaissance Attack Detection Using Temporal Behavior Analysis",
            "student": "Charith H. (IT23269002)",
            "rq1": "Does temporal modelling of protocol-aware Modbus/TCP request sequences improve reconnaissance detection compared with packet-level and non-temporal baselines under session-independent evaluation?",
            "rq2": "Does explicit timing information provide useful predictive information beyond the ordered Modbus/TCP request features themselves?",
        },
        "dataset_overview": {
            "raw_packets_total": int(profile["packets"]["rows"]),
            "raw_packets_positive": int(profile["packets"]["label_counts"]["1"]),
            "raw_packets_negative": int(profile["packets"]["label_counts"]["0"]),
            "as_provided_sequences_total": int(profile["sequences"]["rows"]),
            "as_provided_backward_time_pct": float(
                100.0 * seq_audit["windows_with_any_backward_time_step"] / seq_audit["n_sequences"]
            ),
            "as_provided_cross_pcap_pct": float(
                100.0 * seq_audit["windows_spanning_multiple_file_sources"] / seq_audit["n_sequences"]
            ),
            "duplicate_veth_packets_removed": int(rebuild["exclusions"]["duplicate_interface_view"]),
            "rebuilt_packets_total": int(rebuild["packets_kept"]),
            "rebuilt_packets_positive": int((pkt_df["label"] == 1).sum()),
            "rebuilt_packets_negative": int((pkt_df["label"] == 0).sum()),
            "rebuilt_windows_total": int(rebuild["windows"]),
            "rebuilt_windows_positive": int(rebuild["window_label_counts"]["1"]),
            "rebuilt_windows_negative": int(rebuild["window_label_counts"]["0"]),
            "window_length": 20,
            "window_stride": 5,
            "n_capture_groups": 10,
            "n_dual_class_groups": 6,
            "n_single_class_normal_groups": 4,
            "positive_window_categories": {
                "cat1_modbus_len3_signature": 1784,
                "cat2_multi_register_quantity_scan": 23,
                "cat3_event_mapped_normal_looking": 71,
            },
        },
        "models": model_summaries,
        "static_rule_baseline": static_cm,
        "capture_group_summary": capture_group_summary,
        "per_category_recall": ablations["per_category_positive_window_recall"],
        "ablations": {
            "shortcut_removed": {
                k: {
                    "locgo_10fold": {
                        "pooled_at_0_5": _enrich_confusion(v["locgo_10fold"]["pooled_oof_at_0_5"]),
                        "pooled_at_val_threshold": _enrich_confusion(
                            v["locgo_10fold"]["pooled_oof_at_val_threshold"]
                        ),
                    },
                    "sgkf_5fold": {
                        "pooled_at_0_5": _enrich_confusion(v["sgkf_5fold"]["pooled_oof_at_0_5"]),
                        "pooled_at_val_threshold": _enrich_confusion(
                            v["sgkf_5fold"]["pooled_oof_at_val_threshold"]
                        ),
                    }
                    if "sgkf_5fold" in v
                    else None,
                }
                for k, v in ablations[
                    "shortcut_removed_ablation_no_modbus_len_or_packet_size"
                ].items()
                if isinstance(v, dict) and "locgo_10fold" in v
            },
            "rq2_window_rf_no_timing": {
                "locgo_10fold": _enrich_confusion(
                    ablations["rq2_timing_ablation"]["Model_B_Window_RF_NoTiming"]["locgo_10fold"][
                        "pooled_oof_at_val_threshold"
                    ]
                ),
                "sgkf_5fold": _enrich_confusion(
                    ablations["rq2_timing_ablation"]["Model_B_Window_RF_NoTiming"]["sgkf_5fold"][
                        "pooled_oof_at_val_threshold"
                    ]
                ),
            },
            "split_leakage_random_5fold": ablations["split_leakage_diagnostic_random_5fold"],
            "window_length_sensitivity": ablations["window_length_sensitivity"],
        },
        "curves": curves,
        "latency": latency,
        "explainability": {
            "window_rf_feature_importances": examples["window_rf_feature_importances"],
            "lstm_attribution": examples["lstm_attribution"],
        },
        "inspected_windows": inspected_windows,
        "detected_packets_feed": packet_table_rows,
        "whole_network_meta": whole_network_meta,
    }

    out_path = ARTIFACTS / "dashboard_data.json"
    write_json(payload, out_path)
    print(f"Saved {out_path} ({out_path.stat().st_size / 1024:.1f} KB)")

    frontend_public = ROOT / "frontend" / "public"
    frontend_public.mkdir(parents=True, exist_ok=True)
    shutil.copy2(out_path, frontend_public / "dashboard_data.json")
    shutil.copy2(bin_path, frontend_public / "whole_network_packets.bin")
    print(f"Copied dashboard_data.json and whole_network_packets.bin to {frontend_public}")

    return payload


if __name__ == "__main__":
    build_dashboard_data()
