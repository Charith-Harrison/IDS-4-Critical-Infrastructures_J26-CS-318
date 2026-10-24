"""Consolidate metrics, compute explainability/attribution, extract real example sequences,
and generate research-grade figures (Sections 20, 22).

Produces:
- `artifacts/metrics.json`
- `artifacts/confusion.json`
- `artifacts/curves.json`
- `artifacts/predictions.csv`
- `artifacts/example_sequences.json`
- `data/samples/sample_recon_window.json` and `data/samples/sample_normal_window.json`
- `artifacts/plots/fig1_dataset_audit_and_rebuild.png`
- `artifacts/plots/fig2_model_comparison_locgo_and_sgkf5.png`
- `artifacts/plots/fig3_roc_and_pr_curves.png`
- `artifacts/plots/fig4_lstm_training_curves.png`
- `artifacts/plots/fig5_feature_and_timestep_attribution.png`
- `artifacts/plots/fig6_leakage_and_window_sensitivity.png`
"""
from __future__ import annotations

from typing import Any

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import torch

from common import ARTIFACTS, DATA_REBUILT, DATA_SAMPLES, read_json, write_json
from contract import C2InferenceEngine
from evaluate import compute_Downsampled_curves
from features import (
    FC_CODES,
    SEQ_FEATURES,
    SEQ_TIMING,
    packet_level_columns,
    sequence_tensor,
)
from latency import load_saved_lstm


def compute_lstm_occlusion_and_gradient_importance(
    r: pd.DataFrame, W: pd.DataFrame, idx_mat: np.ndarray
) -> dict[str, Any]:
    """Compute input*gradient feature salience and feature-group occlusion drop on positive windows."""
    lstm_c, sc_c, thr_c = load_saved_lstm("model_c_lstm_full")
    pos_mask = (W["label"] == 1).to_numpy()
    X_pos_raw = sequence_tensor(r, idx_mat[pos_mask], features=SEQ_FEATURES)
    Z_pos = sc_c.transform(X_pos_raw)

    # 1. Input * Gradient salience across all 1,878 positive windows
    t_z = torch.from_numpy(Z_pos).requires_grad_(True)
    logits = lstm_c.forward_logits(t_z)
    base_probs = torch.sigmoid(logits).detach().numpy()
    logits.sum().backward()
    grad_input = np.abs(t_z.grad.detach().numpy() * Z_pos)  # (N_pos, L, F)

    mean_feat_sal = grad_input.mean(axis=(0, 1))
    if mean_feat_sal.sum() > 0:
        mean_feat_sal = mean_feat_sal / mean_feat_sal.sum()
    order = np.argsort(mean_feat_sal)[::-1]
    grad_feature_ranking = {
        SEQ_FEATURES[i]: float(mean_feat_sal[i]) for i in order
    }

    mean_timestep_sal = grad_input.mean(axis=0).sum(axis=1)
    if mean_timestep_sal.sum() > 0:
        mean_timestep_sal = mean_timestep_sal / mean_timestep_sal.sum()

    # 2. Feature-group occlusion (zeroing scaled features -> training mean)
    feature_groups = {
        "frame_length_and_size": ["modbus_len", "packet_size"],
        "function_code_indicators": [f"fc_{c}" for c in FC_CODES]
        + ["fc_other", "fc_change", "is_write"],
        "register_and_quantity_progression": [
            "register_start",
            "log_quantity",
            "d_reg",
            "log_abs_d_reg",
            "seq_step",
            "back_step",
        ],
        "explicit_timing_features": list(SEQ_TIMING),
    }
    occlusion_results = {}
    base_mean_score = float(base_probs.mean())
    for gname, flist in feature_groups.items():
        Z_occ = Z_pos.copy()
        f_idx = [SEQ_FEATURES.index(f) for f in flist]
        Z_occ[:, :, f_idx] = 0.0
        with torch.no_grad():
            occ_probs = (
                torch.sigmoid(lstm_c.forward_logits(torch.from_numpy(Z_occ)))
                .cpu()
                .numpy()
            )
        occ_mean = float(occ_probs.mean())
        occlusion_results[gname] = {
            "features_occluded": flist,
            "baseline_mean_positive_score": base_mean_score,
            "occluded_mean_positive_score": occ_mean,
            "mean_score_drop": float(base_mean_score - occ_mean),
        }

    return {
        "gradient_times_input_feature_importance": grad_feature_ranking,
        "mean_timestep_salience_profile_t0_to_t19": [
            float(x) for x in mean_timestep_sal
        ],
        "feature_group_occlusion_on_positive_windows": occlusion_results,
    }


def build_example_sequences(
    r: pd.DataFrame,
    W: pd.DataFrame,
    idx_mat: np.ndarray,
    preds_df: pd.DataFrame,
) -> dict[str, Any]:
    """Select real verifiable windows for TP (Cat 1, Cat 2, Cat 3), TN, FP, FN and run full attribution."""
    engine = C2InferenceEngine().load()
    ml = r["modbus_len"].to_numpy()[idx_mat]
    qty = r["quantity"].to_numpy()[idx_mat]
    y = W["label"].to_numpy(dtype=np.int64)

    has_ml3 = (ml == 3).any(axis=1)
    has_scan_qty = (~np.isin(qty, [0, 1])).any(axis=1)

    s_c = preds_df["score_model_c_lstm"].to_numpy()
    t_c = preds_df["thr_model_c_lstm"].to_numpy()
    p_c = (s_c >= t_c).astype(np.int64)

    # 1. TP Category 1: modbus_len==3 window in G07 with 20 positive packets
    cand_tp1 = np.where(
        (y == 1)
        & has_ml3
        & (W["capture_group"] == "G07_0319_sub10")
        & (W["n_pos_packets"] == 20)
        & (p_c == 1)
    )[0]
    idx_tp1 = int(cand_tp1[0]) if len(cand_tp1) > 0 else int(np.where((y == 1) & has_ml3)[0][0])

    # 2. TP/Hard Positive Category 2: non-shortcut quantity scan window in G05 or G03
    cand_cat2 = np.where((y == 1) & (~has_ml3) & has_scan_qty)[0]
    # Pick the one with highest Model C or Model B score
    idx_cat2 = int(cand_cat2[np.argmax(s_c[cand_cat2])])

    # 3. Category 3: event_mapped normal-protocol window in G05
    cand_cat3 = np.where((y == 1) & (~has_ml3) & (~has_scan_qty))[0]
    idx_cat3 = int(cand_cat3[0])

    # 4. TN: routine normal polling window in G01
    cand_tn = np.where((y == 0) & (W["capture_group"] == "G01_0122_normal4") & (p_c == 0))[0]
    idx_tn = int(cand_tn[len(cand_tn) // 2])

    # 5. FP (or highest-scoring normal window across OOF)
    neg_indices = np.where(y == 0)[0]
    idx_fp = int(neg_indices[np.argmax(s_c[neg_indices])])

    # 6. FN (lowest-scoring positive window across OOF)
    pos_indices = np.where(y == 1)[0]
    idx_fn = int(pos_indices[np.argmin(s_c[pos_indices])])

    raw_cols = [
        "row_index",
        "timestamp",
        "ts_ns",
        "src_ip",
        "dst_ip",
        "session_id",
        "func_code",
        "modbus_len",
        "register_start",
        "quantity",
        "packet_size",
        "dt_s",
        "label",
    ]

    def _pack_example(w_idx: int, role: str, explanation: str) -> dict[str, Any]:
        w_row = W.iloc[w_idx]
        pkt_rows = r.iloc[idx_mat[w_idx]][raw_cols].copy()
        contract_out = engine.score_window(
            pkt_rows, session_id=str(w_row["session_id"]), include_attribution=True
        )
        return {
            "example_role": role,
            "explanation": explanation,
            "window_id": str(w_row["window_id"]),
            "capture_group": str(w_row["capture_group"]),
            "session_id": str(w_row["session_id"]),
            "true_window_label": int(w_row["label"]),
            "n_positive_packets_in_window": int(w_row["n_pos_packets"]),
            "oof_predictions": {
                "Model_A_Packet_LogReg_score": float(
                    preds_df["score_model_a_packet_logreg"].iloc[w_idx]
                ),
                "Model_A_Packet_DT_score": float(
                    preds_df["score_model_a_packet_dt"].iloc[w_idx]
                ),
                "Model_B_Window_RF_score": float(
                    preds_df["score_model_b_window_rf"].iloc[w_idx]
                ),
                "Model_C_LSTM_Full_score": float(
                    preds_df["score_model_c_lstm"].iloc[w_idx]
                ),
                "Model_C_LSTM_Full_val_threshold": float(
                    preds_df["thr_model_c_lstm"].iloc[w_idx]
                ),
                "Model_D_LSTM_NoTiming_score": float(
                    preds_df["score_model_d_lstm_no_timing"].iloc[w_idx]
                ),
            },
            "runtime_contract_output": contract_out,
            "packets": pkt_rows.to_dict(orient="records"),
        }

    examples = {
        "true_positive_cat1_modbus_len3_signature": _pack_example(
            idx_tp1,
            "True Positive (Category 1: modbus_len=3 / func_code=5 signature)",
            "Detected with near-unity score by all models (A, B, C, D) due to the repeated func_code=5, modbus_len=3, packet_size=75 response frames.",
        ),
        "positive_cat2_non_shortcut_quantity_scan": _pack_example(
            idx_cat2,
            "Positive (Category 2: Non-shortcut multi-register quantity scan)",
            "Contains reconnaissance requests with abnormal register quantities (quantity in {2,4,5,9,20,125,2000,65535}) and modbus_len=6 rather than modbus_len=3.",
        ),
        "positive_cat3_event_mapped_normal_protocol": _pack_example(
            idx_cat3,
            "Hard Positive / False Negative (Category 3: event_mapped read/response window)",
            "Packets in this window have routine protocol fields (func_code in {1..4}, modbus_len in {9,10,11}, register_start=0, quantity in {0,1}) identical to normal polling, labelled positive only via timestamp proximity to attack_events_mapped.",
        ),
        "true_negative_routine_polling": _pack_example(
            idx_tn,
            "True Negative (Routine normal polling window)",
            "Standard cyclic Modbus/TCP polling sequence with regular inter-request timing and normal frame lengths.",
        ),
        "highest_scoring_normal_window_fp_analysis": _pack_example(
            idx_fp,
            "Borderline / Highest-Scoring Normal Window (False Positive Analysis)",
            "Normal window with the highest out-of-fold LSTM score, illustrating how unusual timing bursts or function-code transitions can elevate the anomaly score.",
        ),
        "lowest_scoring_positive_window_fn_analysis": _pack_example(
            idx_fn,
            "Lowest-Scoring Positive Window (False Negative Analysis)",
            "Positive window where only a single packet at the boundary carries a label and protocol fields match normal polling.",
        ),
    }

    # Save standalone sample JSONs in data/samples/ for API testing
    DATA_SAMPLES.mkdir(parents=True, exist_ok=True)
    write_json(
        {
            "session_id": examples["true_positive_cat1_modbus_len3_signature"]["session_id"],
            "packets": examples["true_positive_cat1_modbus_len3_signature"]["packets"],
        },
        DATA_SAMPLES / "sample_recon_window.json",
    )
    write_json(
        {
            "session_id": examples["true_negative_routine_polling"]["session_id"],
            "packets": examples["true_negative_routine_polling"]["packets"],
        },
        DATA_SAMPLES / "sample_normal_window.json",
    )
    return examples


def generate_plots(
    metrics_art: dict[str, Any],
    curves_art: dict[str, Any],
    history_art: dict[str, Any],
    ablation_art: dict[str, Any],
    explain_art: dict[str, Any],
    rebuild_art: dict[str, Any],
) -> list[str]:
    """Generate 6 research-grade Matplotlib figures in artifacts/plots/."""
    plots_dir = ARTIFACTS / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({"font.size": 10, "figure.dpi": 150})
    saved_files = []

    # --- Fig 1: Dataset Audit & Capture Group Distribution ---
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))
    groups_summary = rebuild_art["per_group"]
    g_names = [g["capture_group"].replace("_", "\n", 1) for g in groups_summary]
    g_wins = [g["windows"] for g in groups_summary]
    g_pos = [g["recon_windows"] for g in groups_summary]

    x = np.arange(len(g_names))
    axes[0].bar(x, g_wins, color="#4C72B0", alpha=0.85, label="Total Rebuilt Windows")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(g_names, rotation=35, ha="right", fontsize=8)
    axes[0].set_ylabel("Window Count (log scale)")
    axes[0].set_yscale("log")
    axes[0].set_title("(a) Rebuilt Windows per Independent Capture Group (N=119,237)")
    axes[0].grid(axis="y", linestyle="--", alpha=0.4)

    # Panel b: Positive windows breakdown across the 6 positive capture groups
    leak_art = read_json(ARTIFACTS / "leakage_audit.json")
    pg_bk = leak_art["protocol_field_shortcut_risk"]["per_group_breakdown"]
    pos_g = ["G03_0201_veth", "G04_0315_sub1", "G05_0315_sub2", "G06_0316_sub4", "G07_0319_sub10", "G08_0320_sub14"]
    ml3_cnts = [pg_bk[g]["positive_windows_with_modbus_len3"] for g in pos_g]
    non_ml3_cnts = [pg_bk[g]["positive_windows_without_modbus_len3"] for g in pos_g]
    xp = np.arange(len(pos_g))
    axes[1].bar(xp, ml3_cnts, color="#DD8452", label="With modbus_len == 3 shortcut (1,784)")
    axes[1].bar(xp, non_ml3_cnts, bottom=ml3_cnts, color="#55A868", label="Without modbus_len == 3 (94)")
    axes[1].set_xticks(xp)
    axes[1].set_xticklabels([g.replace("_", "\n", 1) for g in pos_g], rotation=25, ha="right", fontsize=8.5)
    axes[1].set_ylabel("Positive Windows")
    axes[1].set_title("(b) Positive Windows by Capture Group & Shortcut Signature")
    axes[1].legend(loc="upper left", fontsize=8.5)
    axes[1].grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    p1 = plots_dir / "fig1_dataset_audit_and_rebuild.png"
    fig.savefig(p1)
    plt.close(fig)
    saved_files.append(str(p1))

    # --- Fig 2: Model Comparison (Full vs No-Shortcut on LOCGO-10 Pooled OOF) ---
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))
    model_keys = [
        ("Model_A_Packet_LogReg", "A1: Pkt LogReg"),
        ("Model_A_Packet_DT", "A2: Pkt DT"),
        ("Model_B_Window_RF", "B1: Win RF"),
        ("Model_C_LSTM_Full", "C: LSTM (Full)"),
        ("Model_D_LSTM_NoTiming", "D: LSTM (NoTime)"),
    ]
    labels = [m[1] for m in model_keys]
    f1_05 = [metrics_art["models"][m[0]]["locgo_10fold"]["pooled_oof_at_0_5"]["f1"] for m in model_keys]
    f1_vt = [metrics_art["models"][m[0]]["locgo_10fold"]["pooled_oof_at_val_threshold"]["f1"] for m in model_keys]
    prauc = [metrics_art["models"][m[0]]["locgo_10fold"]["pooled_oof_at_0_5"]["pr_auc"] for m in model_keys]

    xm = np.arange(len(labels))
    w = 0.26
    axes[0].bar(xm - w, f1_05, width=w, label="Pooled F1 @ 0.5", color="#4C72B0")
    axes[0].bar(xm, f1_vt, width=w, label="Pooled F1 @ Val Thr", color="#55A868")
    axes[0].bar(xm + w, prauc, width=w, label="Pooled PR-AUC", color="#C44E52")
    axes[0].set_xticks(xm)
    axes[0].set_xticklabels(labels, rotation=20, ha="right")
    axes[0].set_ylim(0, 1.08)
    axes[0].set_ylabel("Score")
    axes[0].set_title("(a) Primary Comparison (All Verified Protocol Features, LOCGO-10)")
    axes[0].legend(loc="lower right", fontsize=8.5)
    axes[0].grid(axis="y", linestyle="--", alpha=0.4)

    # Panel b: Shortcut-Removed Ablation (no modbus_len or packet_size)
    ns_art = ablation_art["shortcut_removed_ablation_no_modbus_len_or_packet_size"]
    ns_keys = [
        ("Model_A_Packet_LogReg_NoShortcut", "A1: Pkt LogReg"),
        ("Model_A_Packet_DT_NoShortcut", "A2: Pkt DT"),
        ("Model_B_Window_RF_NoShortcut_WithTiming", "B1: Win RF (+Time)"),
        ("Model_B_Window_RF_NoShortcut_NoTiming", "B1: Win RF (-Time)"),
        ("Model_C_LSTM_NoShortcut_WithTiming", "C: LSTM (+Time)"),
        ("Model_D_LSTM_NoShortcut_NoTiming", "D: LSTM (-Time)"),
    ]
    ns_labels = [k[1] for k in ns_keys]
    ns_f1_vt = [ns_art[k[0]]["locgo_10fold"]["pooled_oof_at_val_threshold"]["f1"] for k in ns_keys]
    ns_prauc = [ns_art[k[0]]["locgo_10fold"]["pooled_oof_at_0_5"]["pr_auc"] for k in ns_keys]
    xns = np.arange(len(ns_labels))
    axes[1].bar(xns - 0.18, ns_f1_vt, width=0.35, label="Pooled F1 @ Val Thr", color="#55A868")
    axes[1].bar(xns + 0.18, ns_prauc, width=0.35, label="Pooled PR-AUC", color="#8172B2")
    axes[1].set_xticks(xns)
    axes[1].set_xticklabels(ns_labels, rotation=25, ha="right", fontsize=8.5)
    axes[1].set_ylim(0, 1.05)
    axes[1].set_ylabel("Score")
    axes[1].set_title("(b) Shortcut-Removed Ablation (No modbus_len / packet_size, LOCGO-10)")
    axes[1].legend(loc="upper left", fontsize=8.5)
    axes[1].grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    p2 = plots_dir / "fig2_model_comparison_locgo_and_sgkf5.png"
    fig.savefig(p2)
    plt.close(fig)
    saved_files.append(str(p2))

    # --- Fig 3: ROC and Precision-Recall Curves (LOCGO-10 Pooled OOF) ---
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.8))
    colors = {
        "Model_A_Packet_LogReg": "#4C72B0",
        "Model_A_Packet_DT": "#64B5CD",
        "Model_B_Window_RF": "#55A868",
        "Model_C_LSTM_Full": "#C44E52",
        "Model_D_LSTM_NoTiming": "#8172B2",
    }
    for m_key, m_label in model_keys:
        c_data = curves_art["locgo_10fold_pooled_oof"][m_key]
        if c_data["defined"]:
            axes[0].plot(
                c_data["roc"]["fpr"],
                c_data["roc"]["tpr"],
                label=f"{m_label} (AUC={c_data['roc_auc']:.4f})",
                color=colors[m_key],
                linewidth=1.8,
            )
            axes[1].plot(
                c_data["pr"]["recall"],
                c_data["pr"]["precision"],
                label=f"{m_label} (AP={c_data['pr_auc']:.4f})",
                color=colors[m_key],
                linewidth=1.8,
            )
    axes[0].plot([0, 1], [0, 1], "k--", alpha=0.4)
    axes[0].set_xlabel("False Positive Rate (FPR)")
    axes[0].set_ylabel("True Positive Rate (Recall)")
    axes[0].set_title("(a) ROC Curves (LOCGO-10 Out-of-Fold)")
    axes[0].legend(loc="lower right", fontsize=8.5)
    axes[0].grid(True, linestyle="--", alpha=0.4)

    axes[1].set_xlabel("Recall")
    axes[1].set_ylabel("Precision")
    axes[1].set_title("(b) Precision-Recall Curves (LOCGO-10 Out-of-Fold)")
    axes[1].legend(loc="lower left", fontsize=8.5)
    axes[1].grid(True, linestyle="--", alpha=0.4)
    fig.tight_layout()
    p3 = plots_dir / "fig3_roc_and_pr_curves.png"
    fig.savefig(p3)
    plt.close(fig)
    saved_files.append(str(p3))

    # --- Fig 4: LSTM Training Curves (Model C vs Model D on Fold G08_0320_sub14) ---
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    target_fold = "LOCGO_07_G08_0320_sub14"
    hc = history_art["Model_C_LSTM_Full"]["locgo_10fold"].get(target_fold)
    hd = history_art["Model_D_LSTM_NoTiming"]["locgo_10fold"].get(target_fold)
    if hc and hd:
        ep_c = [e["epoch"] for e in hc["epochs"]]
        ep_d = [e["epoch"] for e in hd["epochs"]]
        axes[0].plot(ep_c, [e["train_loss"] for e in hc["epochs"]], "o-", color="#C44E52", label="Model C Train Loss")
        axes[0].plot(ep_c, [e["val_loss"] for e in hc["epochs"]], "s--", color="#C44E52", label="Model C Val Loss")
        axes[0].plot(ep_d, [e["train_loss"] for e in hd["epochs"]], "o-", color="#8172B2", label="Model D Train Loss")
        axes[0].plot(ep_d, [e["val_loss"] for e in hd["epochs"]], "s--", color="#8172B2", label="Model D Val Loss")
        axes[0].set_xlabel("Epoch")
        axes[0].set_ylabel("Weighted BCE Loss")
        axes[0].set_title(f"(a) LSTM Training & Inner-Val Loss ({target_fold})")
        axes[0].legend(fontsize=8.5)
        axes[0].grid(True, linestyle="--", alpha=0.4)

        axes[1].plot(ep_c, [e["val_pr_auc"] for e in hc["epochs"]], "o-", color="#C44E52", label="Model C (With Timing) Val PR-AUC")
        axes[1].plot(ep_d, [e["val_pr_auc"] for e in hd["epochs"]], "s-", color="#8172B2", label="Model D (No Timing) Val PR-AUC")
        axes[1].set_xlabel("Epoch")
        axes[1].set_ylabel("Validation PR-AUC")
        axes[1].set_title(f"(b) Inner-Validation PR-AUC Convergence ({target_fold})")
        axes[1].legend(fontsize=8.5)
        axes[1].grid(True, linestyle="--", alpha=0.4)
    fig.tight_layout()
    p4 = plots_dir / "fig4_lstm_training_curves.png"
    fig.savefig(p4)
    plt.close(fig)
    saved_files.append(str(p4))

    # --- Fig 5: Feature Importance & Timestep Salience ---
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))
    grad_imp = explain_art["lstm_attribution"]["gradient_times_input_feature_importance"]
    top_feats = list(grad_imp.keys())[:10][::-1]
    top_vals = [grad_imp[k] for k in top_feats]
    axes[0].barh(top_feats, top_vals, color="#C44E52", alpha=0.85)
    axes[0].set_xlabel("Normalized |Gradient x Input| Attribution")
    axes[0].set_title("(a) Top 10 Sequence Features by LSTM Gradient Attribution")
    axes[0].grid(axis="x", linestyle="--", alpha=0.4)

    ts_sal = explain_art["lstm_attribution"]["mean_timestep_salience_profile_t0_to_t19"]
    axes[1].bar(np.arange(len(ts_sal)), ts_sal, color="#4C72B0", alpha=0.85)
    axes[1].set_xticks(np.arange(len(ts_sal)))
    axes[1].set_xticklabels([f"t={i}" for i in range(len(ts_sal))], rotation=45, fontsize=8)
    axes[1].set_xlabel("Packet Position in 20-Packet Sequence Window")
    axes[1].set_ylabel("Normalized Salience Share")
    axes[1].set_title("(b) Mean Per-Timestep Salience Profile Across Positive Windows")
    axes[1].grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    p5 = plots_dir / "fig5_feature_and_timestep_attribution.png"
    fig.savefig(p5)
    plt.close(fig)
    saved_files.append(str(p5))

    # --- Fig 6: Split-Leakage Inflation & Window-Length Sensitivity ---
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.6))
    rand_d = ablation_art["split_leakage_diagnostic_random_5fold"]
    ns_rf_rand = rand_d["Model_B_Window_RF_NoShortcut_Random5Fold_at_0_5"]["f1"]
    ns_lstm_rand = rand_d["Model_C_LSTM_NoShortcut_Random5Fold_at_0_5"]["f1"]
    ns_rf_locgo = ns_art["Model_B_Window_RF_NoShortcut_WithTiming"]["locgo_10fold"]["pooled_oof_at_val_threshold"]["f1"]
    ns_lstm_locgo = ns_art["Model_C_LSTM_NoShortcut_WithTiming"]["locgo_10fold"]["pooled_oof_at_val_threshold"]["f1"]

    x_lk = np.arange(2)
    axes[0].bar(x_lk - 0.18, [ns_rf_rand, ns_lstm_rand], width=0.35, color="#DD8452", label="Random 5-Fold (Leaky Overlapping Windows)")
    axes[0].bar(x_lk + 0.18, [ns_rf_locgo, ns_lstm_locgo], width=0.35, color="#4C72B0", label="Capture-Independent (LOCGO-10)")
    axes[0].set_xticks(x_lk)
    axes[0].set_xticklabels(["Window RF (No Shortcut)", "LSTM (No Shortcut)"])
    axes[0].set_ylim(0, 1.05)
    axes[0].set_ylabel("Pooled F1 Score")
    axes[0].set_title("(a) Overlap Leakage Inflation (Shortcut Removed)")
    axes[0].legend(fontsize=8.5)
    axes[0].grid(axis="y", linestyle="--", alpha=0.4)

    w_sens = ablation_art["window_length_sensitivity"]
    w_keys = ["L10_stride5", "L20_stride5", "L40_stride10"]
    w_lbls = ["L=10 (stride 5)", "L=20 (stride 5)", "L=40 (stride 10)"]
    w_rf_full = [w_sens[k]["Model_B_RF_Full_SGKF5_pooled_val_thr"]["f1"] for k in w_keys]
    w_rf_ns = [w_sens[k]["Model_B_RF_NoShortcut_SGKF5_pooled_val_thr"]["f1"] for k in w_keys]
    xw = np.arange(len(w_lbls))
    axes[1].bar(xw - 0.18, w_rf_full, width=0.35, color="#55A868", label="Window RF (Full Features)")
    axes[1].bar(xw + 0.18, w_rf_ns, width=0.35, color="#8172B2", label="Window RF (No Shortcut)")
    axes[1].set_xticks(xw)
    axes[1].set_xticklabels(w_lbls)
    axes[1].set_ylim(0, 1.05)
    axes[1].set_ylabel("SGKF-5 Pooled F1 @ Val Thr")
    axes[1].set_title("(b) Window-Length Sensitivity (L in {10, 20, 40})")
    axes[1].legend(fontsize=8.5)
    axes[1].grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    p6 = plots_dir / "fig6_leakage_and_window_sensitivity.png"
    fig.savefig(p6)
    plt.close(fig)
    saved_files.append(str(p6))

    return saved_files


def main() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv")
    r = packet_level_columns(r)
    W = pd.read_csv(DATA_REBUILT / "windows.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")

    base_metrics = read_json(ARTIFACTS / "baseline_metrics.json")
    lstm_metrics = read_json(ARTIFACTS / "lstm_metrics.json")
    ablation_art = read_json(ARTIFACTS / "ablation_results.json")
    history_art = read_json(ARTIFACTS / "training_history.json")
    rebuild_art = read_json(ARTIFACTS / "rebuild_report.json")

    base_preds = pd.read_csv(ARTIFACTS / "baseline_oof_predictions.csv")
    lstm_preds = pd.read_csv(ARTIFACTS / "lstm_oof_predictions.csv")

    # Merge predictions.csv
    preds_df = base_preds.merge(
        lstm_preds[
            [
                "window_id",
                "score_model_c_lstm",
                "thr_model_c_lstm",
                "score_model_d_lstm_no_timing",
                "thr_model_d_lstm_no_timing",
            ]
        ],
        on="window_id",
        how="left",
    )
    preds_df.to_csv(ARTIFACTS / "predictions.csv", index=False)

    all_models = {**base_metrics, **lstm_metrics}

    # Build confusion.json
    confusion_art = {"models": {}}
    for m_name, m_data in all_models.items():
        confusion_art["models"][m_name] = {}
        for scheme in ["locgo_10fold", "sgkf_5fold"]:
            s_data = m_data[scheme]
            confusion_art["models"][m_name][scheme] = {
                "pooled_oof_at_0_5": {
                    k: s_data["pooled_oof_at_0_5"][k]
                    for k in ["tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr", "specificity"]
                },
                "pooled_oof_at_val_threshold": {
                    k: s_data["pooled_oof_at_val_threshold"][k]
                    for k in ["tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr", "specificity"]
                },
                "per_fold_at_val_threshold": [
                    {
                        "fold_id": pf["fold_id"],
                        "test_groups": pf["test_groups"],
                        "threshold": pf["at_val_threshold"]["threshold"],
                        "tp": pf["at_val_threshold"]["tp"],
                        "fp": pf["at_val_threshold"]["fp"],
                        "fn": pf["at_val_threshold"]["fn"],
                        "tn": pf["at_val_threshold"]["tn"],
                        "f1": pf["at_val_threshold"]["f1"],
                        "fpr": pf["at_val_threshold"]["fpr"],
                    }
                    for pf in s_data["per_fold"]
                ],
            }
    write_json(confusion_art, ARTIFACTS / "confusion.json")

    # Build curves.json
    y_true = W["label"].to_numpy(dtype=np.int64)
    score_cols = {
        "Model_A_Packet_LogReg": "score_model_a_packet_logreg",
        "Model_A_Packet_DT": "score_model_a_packet_dt",
        "Model_B_Window_RF": "score_model_b_window_rf",
        "Model_B_Window_LogReg": "score_model_b_window_logreg",
        "Model_C_LSTM_Full": "score_model_c_lstm",
        "Model_D_LSTM_NoTiming": "score_model_d_lstm_no_timing",
    }
    curves_art = {"locgo_10fold_pooled_oof": {}}
    for m_name, col in score_cols.items():
        curves_art["locgo_10fold_pooled_oof"][m_name] = compute_Downsampled_curves(
            y_true, preds_df[col].to_numpy()
        )
    write_json(curves_art, ARTIFACTS / "curves.json")

    # Compute LSTM attribution & example sequences
    print("Computing LSTM gradient attribution and feature-group occlusion...")
    lstm_attr = compute_lstm_occlusion_and_gradient_importance(r, W, idx_mat)
    print("Extracting verifiable example sequences and runtime contracts...")
    examples = build_example_sequences(r, W, idx_mat, preds_df)

    explain_art = {
        "window_rf_feature_importances": base_metrics["Model_B_Window_RF"][
            "locgo_10fold"
        ]["feature_importances_mean"],
        "lstm_attribution": lstm_attr,
        "examples": examples,
    }
    write_json(explain_art, ARTIFACTS / "example_sequences.json")

    # Build unified metrics.json
    metrics_art = {
        "primary_evaluation_scheme": "locgo_10fold",
        "secondary_evaluation_scheme": "sgkf_5fold",
        "models": all_models,
        "ablation_summary": {
            "rq2_timing_ablation_locgo_pooled_val_thr": {
                "Model_C_LSTM_WithTiming": all_models["Model_C_LSTM_Full"][
                    "locgo_10fold"
                ]["pooled_oof_at_val_threshold"],
                "Model_D_LSTM_NoTiming": all_models["Model_D_LSTM_NoTiming"][
                    "locgo_10fold"
                ]["pooled_oof_at_val_threshold"],
                "Model_B_Window_RF_WithTiming": all_models["Model_B_Window_RF"][
                    "locgo_10fold"
                ]["pooled_oof_at_val_threshold"],
                "Model_B_Window_RF_NoTiming": ablation_art["rq2_timing_ablation"][
                    "Model_B_Window_RF_NoTiming"
                ]["locgo_10fold"]["pooled_oof_at_val_threshold"],
            },
            "shortcut_removed_locgo_pooled_val_thr": {
                k: v["locgo_10fold"]["pooled_oof_at_val_threshold"]
                for k, v in ablation_art[
                    "shortcut_removed_ablation_no_modbus_len_or_packet_size"
                ].items()
                if isinstance(v, dict) and "locgo_10fold" in v
            },
        },
    }
    write_json(metrics_art, ARTIFACTS / "metrics.json")

    print("Generating research plots in artifacts/plots/...")
    plot_files = generate_plots(
        metrics_art, curves_art, history_art, ablation_art, explain_art, rebuild_art
    )
    print("Saved artifacts/metrics.json, confusion.json, curves.json, predictions.csv, example_sequences.json")
    print("Generated plots:", plot_files)


if __name__ == "__main__":
    main()
