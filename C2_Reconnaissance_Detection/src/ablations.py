r"""Ablation and diagnostic experiments for C2 (Section 19).

Executes and records in `artifacts/ablation_results.json`:
1. Timing Feature Ablation (RQ2):
   - LSTM Full (19 features) vs LSTM No-Timing (17 features)
   - Window Random Forest Full (29 features) vs Window RF No-Timing (21 features)
2. Protocol Size/Length-Shortcut Ablation (removing `modbus_len` and `packet_size`):
   - Tests whether temporal sequence modelling improves detection when the trivial
     `modbus_len == 3` (`packet_size == 75`) packet-level shortcut is removed.
   - Evaluates Packet LogReg, Packet DT, Window RF (with & without timing),
     LSTM (with timing), and LSTM (without timing) without `modbus_len` / `packet_size`.
3. Per-Category Positive Window Recall Breakdown:
   - Breaks down recall across:
     (a) `modbus_len == 3` signature windows (1,784 windows),
     (b) non-shortcut `quantity` scan windows (35 windows in G03 and G05),
     (c) non-shortcut `event_mapped` normal-looking read/response windows (59 windows in G05 and G07).
4. Split-Leakage Diagnostic:
   - Random 5-fold StratifiedKFold vs Capture-Independent (LOCGO-10 and SGKF-5) vs
     Strict Host-Pair (`session_id`) 5-fold group split (`loso_session_5fold`).
5. As-Provided vs Rebuilt Sequence Dataset Comparison:
   - Evaluates on the as-provided `recon_sequences_ALL` (175,800 windows, 6 active features)
     under random 5-fold split vs session-grouped split, and contrasts with the Rebuilt dataset.
6. Window-Length Sensitivity ($L \in \\{10, 20, 40\\}$):
   - Evaluates Window RF and Packet DT at $L=10$ (stride 5), $L=20$ (stride 5), and $L=40$ (stride 10)
     under 5-fold capture-independent cross-validation.
"""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler

from baselines import (
    _evaluate_precomputed_decisions,
    run_packet_baseline_cv,
    run_window_baseline_cv,
)
from common import ARTIFACTS, DATA_RAW, DATA_REBUILT, read_json, set_seeds, write_json
from evaluate import (
    evaluate_predictions,
    select_validation_threshold,
    summarize_fold_metrics,
)
from features import (
    PACKET_FEATURES_NO_SHORTCUT,
    SEQ_FEATURES,
    SEQ_FEATURES_NO_SHORTCUT,
    SEQ_FEATURES_NO_SHORTCUT_NO_TIMING,
    SEQ_FEATURES_NO_TIMING,
    WINDOW_FEATURES,
    WINDOW_FEATURES_NO_SHORTCUT,
    WINDOW_FEATURES_NO_SHORTCUT_NO_TIMING,
    WINDOW_FEATURES_NO_TIMING,
    packet_level_columns,
    sequence_tensor,
    window_aggregates,
)
from train_lstm import run_lstm_cv, train_one_fold_lstm


def compute_category_recall_breakdown(
    r: pd.DataFrame,
    W: pd.DataFrame,
    idx_mat: np.ndarray,
    scores: np.ndarray,
    thresholds: np.ndarray | float,
) -> dict[str, Any]:
    """Compute recall on the 3 mutually exclusive positive window subcategories + FPR on negatives."""
    ml = r["modbus_len"].to_numpy()[idx_mat]
    qty = r["quantity"].to_numpy()[idx_mat]
    y = W["label"].to_numpy(dtype=np.int64)

    has_ml3 = (ml == 3).any(axis=1)
    has_scan_qty = (~np.isin(qty, [0, 1])).any(axis=1)

    cat_ml3 = (y == 1) & has_ml3
    cat_qty_scan = (y == 1) & (~has_ml3) & has_scan_qty
    cat_event_mapped_normal_proto = (y == 1) & (~has_ml3) & (~has_scan_qty)
    neg_mask = y == 0

    preds = (scores >= thresholds).astype(np.int64)

    def _rate(mask: np.ndarray) -> dict[str, Any]:
        n = int(mask.sum())
        hits = int(preds[mask].sum()) if n > 0 else 0
        return {
            "count": n,
            "detected": hits,
            "rate": float(hits / n) if n > 0 else None,
        }

    return {
        "cat1_modbus_len3_signature_windows": _rate(cat_ml3),
        "cat2_non_shortcut_quantity_scan_windows": _rate(cat_qty_scan),
        "cat3_non_shortcut_event_mapped_windows": _rate(cat_event_mapped_normal_proto),
        "negative_windows_false_positive_rate": _rate(neg_mask),
    }


def run_random_5fold_leakage_diagnostic(
    X_win_df: pd.DataFrame,
    r: pd.DataFrame,
    W: pd.DataFrame,
    idx_mat: np.ndarray,
    seed: int = 42,
) -> dict[str, Any]:
    """Run 5-fold StratifiedKFold random split (leaky across overlapping windows) for RF and LSTM."""
    set_seeds(seed)
    y = W["label"].to_numpy(dtype=np.int64)
    X_win = X_win_df[WINDOW_FEATURES].to_numpy(dtype=np.float32)
    X_win_noshort = X_win_df[WINDOW_FEATURES_NO_SHORTCUT].to_numpy(dtype=np.float32)
    X_seq_noshort = sequence_tensor(r, idx_mat, features=SEQ_FEATURES_NO_SHORTCUT)

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    oof_rf_full = np.zeros(len(W), dtype=np.float64)
    oof_rf_noshort = np.zeros(len(W), dtype=np.float64)
    oof_lstm_noshort = np.zeros(len(W), dtype=np.float64)

    for fold_idx, (tr, te) in enumerate(skf.split(X_win, y)):
        # RF Full
        sc1 = StandardScaler()
        clf1 = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_leaf=3,
            class_weight="balanced",
            n_jobs=-1,
            random_state=seed + fold_idx,
        )
        clf1.fit(sc1.fit_transform(X_win[tr]), y[tr])
        oof_rf_full[te] = clf1.predict_proba(sc1.transform(X_win[te]))[:, 1]

        # RF No-Shortcut
        sc2 = StandardScaler()
        clf2 = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_leaf=3,
            class_weight="balanced",
            n_jobs=-1,
            random_state=seed + fold_idx,
        )
        clf2.fit(sc2.fit_transform(X_win_noshort[tr]), y[tr])
        oof_rf_noshort[te] = clf2.predict_proba(sc2.transform(X_win_noshort[te]))[:, 1]

        # LSTM No-Shortcut (split tr 85/15 for early stopping)
        rng = np.random.default_rng(seed + fold_idx)
        perm = rng.permutation(len(tr))
        n_val = max(int(0.15 * len(tr)), 1)
        val_sub = tr[perm[:n_val]]
        fit_sub = tr[perm[n_val:]]
        _, _, _, test_scores, _ = train_one_fold_lstm(
            X_fit_raw=X_seq_noshort[fit_sub],
            y_fit=y[fit_sub],
            X_val_raw=X_seq_noshort[val_sub],
            y_val=y[val_sub],
            X_test_raw=X_seq_noshort[te],
            features=SEQ_FEATURES_NO_SHORTCUT,
            max_epochs=6,
            batch_size=512,
            patience=2,
            max_neg_per_epoch=8000,
            seed=seed + fold_idx,
        )
        oof_lstm_noshort[te] = test_scores

    return {
        "description": (
            "Random 5-fold StratifiedKFold across stride-5 overlapping windows (99.99% of test windows "
            "share >=1 packet with training windows). Demonstrates severe optimistic bias relative to "
            "capture-independent evaluation, especially when the modbus_len==3 shortcut is removed."
        ),
        "Model_B_Window_RF_Full_Random5Fold_at_0_5": evaluate_predictions(
            y, oof_rf_full, threshold=0.5
        ),
        "Model_B_Window_RF_NoShortcut_Random5Fold_at_0_5": evaluate_predictions(
            y, oof_rf_noshort, threshold=0.5
        ),
        "Model_C_LSTM_NoShortcut_Random5Fold_at_0_5": evaluate_predictions(
            y, oof_lstm_noshort, threshold=0.5
        ),
    }


def run_session_id_holdout_diagnostic(
    X_win_df: pd.DataFrame,
    W: pd.DataFrame,
    sess_folds: list[dict[str, Any]],
    seed: int = 42,
) -> dict[str, Any]:
    """Evaluate Window RF under strict 5-fold session_id grouping (`loso_session_5fold`)."""
    set_seeds(seed)
    X_all = X_win_df[WINDOW_FEATURES].to_numpy(dtype=np.float32)
    y_all = W["label"].to_numpy(dtype=np.int64)
    sids = W["session_id"].to_numpy()

    oof_scores = np.zeros(len(W), dtype=np.float64)
    fold_reports = []
    for f in sess_folds:
        tr_m = np.isin(sids, f["train_session_ids"])
        te_m = np.isin(sids, f["test_session_ids"])
        sc = StandardScaler()
        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_leaf=3,
            class_weight="balanced",
            n_jobs=-1,
            random_state=seed,
        )
        clf.fit(sc.fit_transform(X_all[tr_m]), y_all[tr_m])
        scores = clf.predict_proba(sc.transform(X_all[te_m]))[:, 1]
        oof_scores[te_m] = scores
        ev = evaluate_predictions(y_all[te_m], scores, threshold=0.5)
        fold_reports.append(
            {
                "fold_id": f["fold_id"],
                "test_session_ids": f["test_session_ids"],
                "n_train_pos": f["n_train_pos"],
                "n_test_pos": f["n_test_pos"],
                "at_0_5": ev,
            }
        )
    return {
        "description": (
            "Strict 5-fold StratifiedGroupKFold by directional session_id. Because 94.20% (1,769/1,878) "
            "of all positive windows occur in session s0004 (185.175.0.5->185.175.0.3 slave responses with "
            "func_code=5, modbus_len=3), holding out s0004 deprives the training set of all func_code=5, "
            "modbus_len=3 examples (leaving only 109 positives in training), causing recall on s0004 to collapse."
        ),
        "per_fold": fold_reports,
        "pooled_oof_at_0_5": evaluate_predictions(y_all, oof_scores, threshold=0.5),
    }


def run_as_provided_comparison(seed: int = 42) -> dict[str, Any]:
    """Evaluate summary RF on the as-provided 175,800 sequences (random 5-fold vs session-grouped 5-fold)."""
    from io_data import load_sequences

    set_seeds(seed)
    s_df, X_3d = load_sequences()
    y = s_df["label"].to_numpy(dtype=np.int64)
    sids = s_df["session_id"].to_numpy()

    # Take the 6 active features (positions 1..6, excluding constant unit_id at position 0)
    X_active = X_3d[:, :, 1:].astype(np.float32)
    X_ap = np.concatenate(
        [
            X_active.mean(axis=1),
            X_active.std(axis=1),
            X_active.min(axis=1),
            X_active.max(axis=1),
        ],
        axis=1,
    )

    # 1. Random 5-fold on as-provided
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    oof_rand = np.zeros(len(s_df), dtype=np.float64)
    for tr, te in skf.split(X_ap, y):
        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_leaf=3,
            class_weight="balanced",
            n_jobs=-1,
            random_state=seed,
        )
        clf.fit(X_ap[tr], y[tr])
        oof_rand[te] = clf.predict_proba(X_ap[te])[:, 1]

    # 2. Session-grouped 5-fold on as-provided
    from sklearn.model_selection import StratifiedGroupKFold

    sgkf = StratifiedGroupKFold(n_splits=5)
    oof_sess = np.zeros(len(s_df), dtype=np.float64)
    for tr, te in sgkf.split(X_ap, y, sids):
        clf = RandomForestClassifier(
            n_estimators=100,
            max_depth=16,
            min_samples_leaf=3,
            class_weight="balanced",
            n_jobs=-1,
            random_state=seed,
        )
        clf.fit(X_ap[tr], y[tr])
        oof_sess[te] = clf.predict_proba(X_ap[te])[:, 1]

    return {
        "n_windows": int(len(s_df)),
        "n_positive_windows": int(y.sum()),
        "random_5fold_pooled_at_0_5": evaluate_predictions(y, oof_rand, threshold=0.5),
        "session_grouped_5fold_pooled_at_0_5": evaluate_predictions(
            y, oof_sess, threshold=0.5
        ),
    }


def run_window_length_sensitivity(
    r: pd.DataFrame, sgkf5_folds: list[dict[str, Any]], seed: int = 42
) -> dict[str, Any]:
    """Compare window lengths L in {10, 20, 40} on the rebuilt packet stream under SGKF-5."""
    results = {}
    for L, stride in [(10, 5), (20, 5), (40, 10)]:
        idx_rows = []
        meta_rows = []
        for (cg, sid), g in r.groupby(["capture_group", "session_id"], sort=False):
            pos = g.index.to_numpy(dtype=np.int64)
            y_g = g["label"].to_numpy(dtype=np.int64)
            if len(pos) < L:
                continue
            for s in range(0, len(pos) - L + 1, stride):
                sl = pos[s : s + L]
                idx_rows.append(sl)
                meta_rows.append(
                    {
                        "capture_group": cg,
                        "session_id": sid,
                        "label": int(y_g[s : s + L].max()),
                    }
                )
        I_L = np.stack(idx_rows, axis=0)
        W_L = pd.DataFrame(meta_rows)
        X_win_L = window_aggregates(r, I_L)

        rf_full = run_window_baseline_cv(
            X_win_L, W_L, sgkf5_folds, model_kind="rf", win_features=WINDOW_FEATURES, seed=seed
        )
        rf_noshort = run_window_baseline_cv(
            X_win_L,
            W_L,
            sgkf5_folds,
            model_kind="rf",
            win_features=WINDOW_FEATURES_NO_SHORTCUT,
            seed=seed,
        )
        results[f"L{L}_stride{stride}"] = {
            "window_length": L,
            "stride": stride,
            "n_windows": int(len(W_L)),
            "n_positive_windows": int(W_L["label"].sum()),
            "positive_rate": float(W_L["label"].mean()),
            "Model_B_RF_Full_SGKF5_pooled_val_thr": rf_full[
                "pooled_oof_at_val_threshold"
            ],
            "Model_B_RF_NoShortcut_SGKF5_pooled_val_thr": rf_noshort[
                "pooled_oof_at_val_threshold"
            ],
        }
    return results


def main() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv")
    r = packet_level_columns(r)
    W = pd.read_csv(DATA_REBUILT / "windows.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")
    X_win_df = window_aggregates(r, idx_mat)

    folds_art = read_json(ARTIFACTS / "folds.json")
    locgo_folds = folds_art["locgo_10fold"]["folds"]
    sgkf5_folds = folds_art["sgkf_5fold"]["folds"]
    sess_folds = folds_art["loso_session_5fold"]["folds"]

    print("1. Running Window RF No-Timing ablation (RQ2 for Model B)...")
    b_rf_notiming_locgo = run_window_baseline_cv(
        X_win_df, W, locgo_folds, model_kind="rf", win_features=WINDOW_FEATURES_NO_TIMING
    )
    b_rf_notiming_sgkf5 = run_window_baseline_cv(
        X_win_df, W, sgkf5_folds, model_kind="rf", win_features=WINDOW_FEATURES_NO_TIMING
    )

    print("2. Running Protocol Size/Length-Shortcut Ablation (removing modbus_len & packet_size)...")
    a_lr_ns_locgo = run_packet_baseline_cv(
        r, W, idx_mat, locgo_folds, model_kind="logreg", pkt_features=PACKET_FEATURES_NO_SHORTCUT
    )
    a_dt_ns_locgo = run_packet_baseline_cv(
        r, W, idx_mat, locgo_folds, model_kind="dt", pkt_features=PACKET_FEATURES_NO_SHORTCUT
    )
    b_rf_ns_locgo = run_window_baseline_cv(
        X_win_df, W, locgo_folds, model_kind="rf", win_features=WINDOW_FEATURES_NO_SHORTCUT
    )
    b_rf_ns_nt_locgo = run_window_baseline_cv(
        X_win_df,
        W,
        locgo_folds,
        model_kind="rf",
        win_features=WINDOW_FEATURES_NO_SHORTCUT_NO_TIMING,
    )
    c_lstm_ns_locgo = run_lstm_cv(
        r,
        W,
        idx_mat,
        locgo_folds,
        features=SEQ_FEATURES_NO_SHORTCUT,
        max_epochs=6,
        patience=2,
        max_neg_per_epoch=8000,
    )
    d_lstm_ns_nt_locgo = run_lstm_cv(
        r,
        W,
        idx_mat,
        locgo_folds,
        features=SEQ_FEATURES_NO_SHORTCUT_NO_TIMING,
        max_epochs=6,
        patience=2,
        max_neg_per_epoch=8000,
    )

    # Also SGKF-5 for No-Shortcut models
    a_dt_ns_sgkf5 = run_packet_baseline_cv(
        r, W, idx_mat, sgkf5_folds, model_kind="dt", pkt_features=PACKET_FEATURES_NO_SHORTCUT
    )
    b_rf_ns_sgkf5 = run_window_baseline_cv(
        X_win_df, W, sgkf5_folds, model_kind="rf", win_features=WINDOW_FEATURES_NO_SHORTCUT
    )
    c_lstm_ns_sgkf5 = run_lstm_cv(
        r,
        W,
        idx_mat,
        sgkf5_folds,
        features=SEQ_FEATURES_NO_SHORTCUT,
        max_epochs=6,
        patience=2,
        max_neg_per_epoch=8000,
    )
    d_lstm_ns_nt_sgkf5 = run_lstm_cv(
        r,
        W,
        idx_mat,
        sgkf5_folds,
        features=SEQ_FEATURES_NO_SHORTCUT_NO_TIMING,
        max_epochs=6,
        patience=2,
        max_neg_per_epoch=8000,
    )

    print("3. Computing Per-Category Positive Window Recall Breakdown...")
    base_preds = pd.read_csv(ARTIFACTS / "baseline_oof_predictions.csv")
    lstm_preds = pd.read_csv(ARTIFACTS / "lstm_oof_predictions.csv")

    category_breakdown = {
        "Model_A_Packet_LogReg_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            base_preds["score_model_a_packet_logreg"].to_numpy(),
            base_preds["thr_model_a_packet_logreg"].to_numpy(),
        ),
        "Model_A_Packet_DT_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            base_preds["score_model_a_packet_dt"].to_numpy(),
            base_preds["thr_model_a_packet_dt"].to_numpy(),
        ),
        "Model_B_Window_RF_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            base_preds["score_model_b_window_rf"].to_numpy(),
            base_preds["thr_model_b_window_rf"].to_numpy(),
        ),
        "Model_C_LSTM_Full_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            lstm_preds["score_model_c_lstm"].to_numpy(),
            lstm_preds["thr_model_c_lstm"].to_numpy(),
        ),
        "Model_D_LSTM_NoTiming_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            lstm_preds["score_model_d_lstm_no_timing"].to_numpy(),
            lstm_preds["thr_model_d_lstm_no_timing"].to_numpy(),
        ),
        "NoShortcut_Model_A_Packet_DT_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            a_dt_ns_locgo["oof_scores"],
            a_dt_ns_locgo["oof_val_thresholds"],
        ),
        "NoShortcut_Model_B_Window_RF_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            b_rf_ns_locgo["oof_scores"],
            b_rf_ns_locgo["oof_val_thresholds"],
        ),
        "NoShortcut_Model_C_LSTM_Full_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            c_lstm_ns_locgo["oof_scores"],
            c_lstm_ns_locgo["oof_val_thresholds"],
        ),
        "NoShortcut_Model_D_LSTM_NoTiming_LOCGO_val_thr": compute_category_recall_breakdown(
            r,
            W,
            idx_mat,
            d_lstm_ns_nt_locgo["oof_scores"],
            d_lstm_ns_nt_locgo["oof_val_thresholds"],
        ),
    }

    print("4. Running Split-Leakage Diagnostics (Random 5-fold and Session-ID 5-fold)...")
    random_diag = run_random_5fold_leakage_diagnostic(X_win_df, r, W, idx_mat)
    sess_diag = run_session_id_holdout_diagnostic(X_win_df, W, sess_folds)

    print("5. Running As-Provided vs Rebuilt Sequence Dataset Comparison...")
    ap_diag = run_as_provided_comparison()

    print("6. Running Window-Length Sensitivity Analysis (L in {10, 20, 40})...")
    win_len_diag = run_window_length_sensitivity(r, sgkf5_folds)

    def _strip(res: dict[str, Any]) -> dict[str, Any]:
        return {
            k: v
            for k, v in res.items()
            if not k.startswith("oof_") and k != "training_histories"
        }

    ablation_results = {
        "rq2_timing_ablation": {
            "Model_B_Window_RF_NoTiming": {
                "locgo_10fold": _strip(b_rf_notiming_locgo),
                "sgkf_5fold": _strip(b_rf_notiming_sgkf5),
            },
        },
        "shortcut_removed_ablation_no_modbus_len_or_packet_size": {
            "description": (
                "Removes modbus_len and packet_size from all representations so models cannot exploit "
                "the 100%-precision modbus_len==3 (packet_size==75) signature shortcut and must rely on "
                "function-code order, register progression, quantity, and timing."
            ),
            "Model_A_Packet_LogReg_NoShortcut": {"locgo_10fold": _strip(a_lr_ns_locgo)},
            "Model_A_Packet_DT_NoShortcut": {
                "locgo_10fold": _strip(a_dt_ns_locgo),
                "sgkf_5fold": _strip(a_dt_ns_sgkf5),
            },
            "Model_B_Window_RF_NoShortcut_WithTiming": {
                "locgo_10fold": _strip(b_rf_ns_locgo),
                "sgkf_5fold": _strip(b_rf_ns_sgkf5),
            },
            "Model_B_Window_RF_NoShortcut_NoTiming": {
                "locgo_10fold": _strip(b_rf_ns_nt_locgo)
            },
            "Model_C_LSTM_NoShortcut_WithTiming": {
                "locgo_10fold": _strip(c_lstm_ns_locgo),
                "sgkf_5fold": _strip(c_lstm_ns_sgkf5),
            },
            "Model_D_LSTM_NoShortcut_NoTiming": {
                "locgo_10fold": _strip(d_lstm_ns_nt_locgo),
                "sgkf_5fold": _strip(d_lstm_ns_nt_sgkf5),
            },
        },
        "per_category_positive_window_recall": category_breakdown,
        "split_leakage_diagnostic_random_5fold": random_diag,
        "session_id_strict_holdout_diagnostic": sess_diag,
        "as_provided_vs_rebuilt_comparison": ap_diag,
        "window_length_sensitivity": win_len_diag,
    }

    write_json(ablation_results, ARTIFACTS / "ablation_results.json")
    print("Saved artifacts/ablation_results.json")


if __name__ == "__main__":
    main()
