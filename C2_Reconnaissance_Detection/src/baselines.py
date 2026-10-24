"""Packet-level static baselines (Model A) and non-temporal window baselines (Model B).

All models are trained strictly on `fit_groups` within each fold, with operational thresholds
selected on `val_groups` (targeting validation FPR <= 0.05) and evaluated on `test_groups`.

Models implemented:
- `Model_A_Packet_LogReg`: Packet-level Logistic Regression on static protocol fields
  (`func_code`, `modbus_len`, `register_start`, `log_quantity`, `packet_size`), aggregated
  to 20-packet windows via max packet score (matching the `any_positive` window label rule).
- `Model_A_Packet_DT`: Packet-level Decision Tree on the same static protocol fields,
  aggregated to 20-packet windows via max packet score.
- `Model_B_Window_RF`: Random Forest (300 trees, `class_weight='balanced_subsample'`)
  on the 29 engineered window-summary features (`WINDOW_FEATURES`).
- `Model_B_Window_LogReg`: Standardised Logistic Regression on `WINDOW_FEATURES`.
"""
from __future__ import annotations

from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from common import ARTIFACTS, DATA_REBUILT, read_json, set_seeds, write_json
from evaluate import (
    compute_Downsampled_curves,
    evaluate_predictions,
    select_validation_threshold,
    summarize_fold_metrics,
)
from features import (
    PACKET_FEATURES,
    WINDOW_FEATURES,
    packet_level_columns,
    packet_matrix,
    window_aggregates,
)


def run_packet_baseline_cv(
    r: pd.DataFrame,
    W: pd.DataFrame,
    idx_mat: np.ndarray,
    folds: list[dict[str, Any]],
    model_kind: str = "logreg",
    pkt_features: list[str] = PACKET_FEATURES,
    seed: int = 42,
    save_final_artifact_name: str | None = None,
) -> dict[str, Any]:
    """Run group-independent CV for a packet-level static model aggregated to windows."""
    set_seeds(seed)
    X_pkt_all = packet_matrix(r, features=pkt_features)
    y_pkt_all = r["label"].to_numpy(dtype=np.int64)
    pkt_groups = r["capture_group"].to_numpy()

    y_win_all = W["label"].to_numpy(dtype=np.int64)
    win_groups = W["capture_group"].to_numpy()

    oof_scores = np.zeros(len(W), dtype=np.float64)
    oof_scores_mean = np.zeros(len(W), dtype=np.float64)
    oof_val_thresholds = np.full(len(W), 0.5, dtype=np.float64)
    oof_pred_val_thr = np.zeros(len(W), dtype=np.int64)
    fold_reports = []

    last_scaler = None
    last_clf = None

    for f in folds:
        fit_g = set(f["fit_groups"])
        val_g = set(f["val_groups"])
        test_g = set(f["test_groups"])

        pkt_fit_m = np.isin(pkt_groups, list(fit_g))
        win_val_m = np.isin(win_groups, list(val_g))
        win_test_m = np.isin(win_groups, list(test_g))

        scaler = StandardScaler()
        X_fit = scaler.fit_transform(X_pkt_all[pkt_fit_m])
        y_fit = y_pkt_all[pkt_fit_m]

        if model_kind == "logreg":
            clf = LogisticRegression(
                class_weight="balanced", max_iter=500, C=1.0, random_state=seed
            )
        elif model_kind == "dt":
            clf = DecisionTreeClassifier(
                max_depth=8,
                min_samples_leaf=10,
                class_weight="balanced",
                random_state=seed,
            )
        else:
            raise ValueError(f"Unknown model_kind: {model_kind}")

        clf.fit(X_fit, y_fit)

        # Score all packets once using training-fitted scaler, then index into val and test windows
        pkt_probs = clf.predict_proba(scaler.transform(X_pkt_all))[:, 1]
        win_pkt_probs = pkt_probs[idx_mat]  # (n_windows, L)
        win_scores_max = win_pkt_probs.max(axis=1)
        win_scores_mean = win_pkt_probs.mean(axis=1)

        val_scores = win_scores_max[win_val_m]
        y_val = y_win_all[win_val_m]
        thr_info = select_validation_threshold(y_val, val_scores, max_fpr=0.05)
        thr = thr_info["threshold"]

        test_scores = win_scores_max[win_test_m]
        y_test = y_win_all[win_test_m]

        oof_scores[win_test_m] = test_scores
        oof_scores_mean[win_test_m] = win_scores_mean[win_test_m]
        oof_val_thresholds[win_test_m] = thr
        oof_pred_val_thr[win_test_m] = (test_scores >= thr).astype(np.int64)

        eval_05 = evaluate_predictions(y_test, test_scores, threshold=0.5)
        eval_vt = evaluate_predictions(y_test, test_scores, threshold=thr)

        fold_reports.append(
            {
                "fold_id": f["fold_id"],
                "test_groups": f["test_groups"],
                "val_groups": f["val_groups"],
                "threshold_selection": thr_info,
                "at_0_5": eval_05,
                "at_val_threshold": eval_vt,
            }
        )
        last_scaler = scaler
        last_clf = clf

    # Fit final artifact model on all groups except G08+G10 (held-out representative split) if requested
    if save_final_artifact_name is not None and last_clf is not None:
        models_dir = ARTIFACTS / "models"
        prep_dir = ARTIFACTS / "preprocessing"
        models_dir.mkdir(parents=True, exist_ok=True)
        prep_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(last_clf, models_dir / f"{save_final_artifact_name}.joblib")
        joblib.dump(last_scaler, prep_dir / f"{save_final_artifact_name}_scaler.joblib")

    pooled_05 = evaluate_predictions(y_win_all, oof_scores, threshold=0.5)
    # Pooled evaluation using each fold's validation-selected threshold decisions
    pooled_vt = _evaluate_precomputed_decisions(y_win_all, oof_scores, oof_pred_val_thr)
    pooled_mean_agg_05 = evaluate_predictions(y_win_all, oof_scores_mean, threshold=0.5)

    return {
        "features": list(pkt_features),
        "n_features": len(pkt_features),
        "window_aggregation": "max_packet_score (primary) and mean_packet_score (diagnostic)",
        "per_fold": fold_reports,
        "summary_at_0_5": summarize_fold_metrics(fold_reports, key="at_0_5"),
        "summary_at_val_threshold": summarize_fold_metrics(
            fold_reports, key="at_val_threshold"
        ),
        "pooled_oof_at_0_5": pooled_05,
        "pooled_oof_at_val_threshold": pooled_vt,
        "pooled_oof_mean_aggregation_at_0_5": pooled_mean_agg_05,
        "oof_scores": oof_scores,
        "oof_val_thresholds": oof_val_thresholds,
    }


def run_window_baseline_cv(
    X_win_df: pd.DataFrame,
    W: pd.DataFrame,
    folds: list[dict[str, Any]],
    model_kind: str = "rf",
    win_features: list[str] = WINDOW_FEATURES,
    seed: int = 42,
    save_final_artifact_name: str | None = None,
    n_estimators: int = 150,
    rf_class_weight: str = "balanced",
) -> dict[str, Any]:
    """Run group-independent CV for a non-temporal window-aggregate baseline."""
    set_seeds(seed)
    X_all = X_win_df[list(win_features)].to_numpy(dtype=np.float32)
    y_all = W["label"].to_numpy(dtype=np.int64)
    win_groups = W["capture_group"].to_numpy()

    oof_scores = np.zeros(len(W), dtype=np.float64)
    oof_val_thresholds = np.full(len(W), 0.5, dtype=np.float64)
    oof_pred_val_thr = np.zeros(len(W), dtype=np.int64)
    fold_reports = []
    feature_importances = []

    last_scaler = None
    last_clf = None

    for f in folds:
        fit_m = np.isin(win_groups, list(f["fit_groups"]))
        val_m = np.isin(win_groups, list(f["val_groups"]))
        test_m = np.isin(win_groups, list(f["test_groups"]))

        scaler = StandardScaler()
        X_fit = scaler.fit_transform(X_all[fit_m])
        y_fit = y_all[fit_m]
        X_val = scaler.transform(X_all[val_m])
        y_val = y_all[val_m]
        X_test = scaler.transform(X_all[test_m])
        y_test = y_all[test_m]

        if model_kind == "rf":
            clf = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=16,
                min_samples_leaf=3,
                class_weight=rf_class_weight,
                n_jobs=-1,
                random_state=seed,
            )
        elif model_kind == "logreg":
            clf = LogisticRegression(
                class_weight="balanced", max_iter=500, C=1.0, random_state=seed
            )
        else:
            raise ValueError(f"Unknown model_kind: {model_kind}")

        clf.fit(X_fit, y_fit)
        if hasattr(clf, "feature_importances_"):
            feature_importances.append(clf.feature_importances_.copy())

        val_scores = clf.predict_proba(X_val)[:, 1]
        thr_info = select_validation_threshold(y_val, val_scores, max_fpr=0.05)
        thr = thr_info["threshold"]

        test_scores = clf.predict_proba(X_test)[:, 1]
        oof_scores[test_m] = test_scores
        oof_val_thresholds[test_m] = thr
        oof_pred_val_thr[test_m] = (test_scores >= thr).astype(np.int64)

        eval_05 = evaluate_predictions(y_test, test_scores, threshold=0.5)
        eval_vt = evaluate_predictions(y_test, test_scores, threshold=thr)

        fold_reports.append(
            {
                "fold_id": f["fold_id"],
                "test_groups": f["test_groups"],
                "val_groups": f["val_groups"],
                "threshold_selection": thr_info,
                "at_0_5": eval_05,
                "at_val_threshold": eval_vt,
            }
        )
        last_scaler = scaler
        last_clf = clf

    if save_final_artifact_name is not None and last_clf is not None:
        models_dir = ARTIFACTS / "models"
        prep_dir = ARTIFACTS / "preprocessing"
        models_dir.mkdir(parents=True, exist_ok=True)
        prep_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(last_clf, models_dir / f"{save_final_artifact_name}.joblib")
        joblib.dump(last_scaler, prep_dir / f"{save_final_artifact_name}_scaler.joblib")

    pooled_05 = evaluate_predictions(y_all, oof_scores, threshold=0.5)
    pooled_vt = _evaluate_precomputed_decisions(y_all, oof_scores, oof_pred_val_thr)

    fi_dict = None
    if feature_importances:
        mean_fi = np.mean(feature_importances, axis=0)
        order = np.argsort(mean_fi)[::-1]
        fi_dict = {win_features[i]: float(mean_fi[i]) for i in order}

    return {
        "features": list(win_features),
        "n_features": len(win_features),
        "per_fold": fold_reports,
        "summary_at_0_5": summarize_fold_metrics(fold_reports, key="at_0_5"),
        "summary_at_val_threshold": summarize_fold_metrics(
            fold_reports, key="at_val_threshold"
        ),
        "pooled_oof_at_0_5": pooled_05,
        "pooled_oof_at_val_threshold": pooled_vt,
        "feature_importances_mean": fi_dict,
        "oof_scores": oof_scores,
        "oof_val_thresholds": oof_val_thresholds,
    }


def _evaluate_precomputed_decisions(
    y_true: np.ndarray, scores: np.ndarray, y_pred: np.ndarray
) -> dict[str, Any]:
    """Compute pooled metrics when each fold uses its own validation-selected threshold."""
    base = evaluate_predictions(y_true, scores, threshold=0.5)
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    n_pos = tp + fn
    n_neg = tn + fp
    prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    rec = float(tp / n_pos) if n_pos > 0 else None
    f1 = (
        float(2 * prec * rec / (prec + rec))
        if (rec is not None and (prec + rec) > 0)
        else 0.0
    )
    fpr = float(fp / n_neg) if n_neg > 0 else None
    spec = float(tn / n_neg) if n_neg > 0 else None
    base.update(
        {
            "threshold": "per_fold_validation_selected",
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "fpr": fpr,
            "specificity": spec,
        }
    )
    return base


def main() -> None:
    r = pd.read_csv(DATA_REBUILT / "packets_rebuilt.csv")
    r = packet_level_columns(r)
    W = pd.read_csv(DATA_REBUILT / "windows.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")
    X_win_df = window_aggregates(r, idx_mat)
    folds_art = read_json(ARTIFACTS / "folds.json")
    locgo_folds = folds_art["locgo_10fold"]["folds"]
    sgkf5_folds = folds_art["sgkf_5fold"]["folds"]

    print("Running Model A1 (Packet Logistic Regression) on LOCGO-10 and SGKF-5...")
    a_lr_locgo = run_packet_baseline_cv(
        r, W, idx_mat, locgo_folds, model_kind="logreg", save_final_artifact_name="model_a_packet_logreg"
    )
    a_lr_sgkf5 = run_packet_baseline_cv(r, W, idx_mat, sgkf5_folds, model_kind="logreg")

    print("Running Model A2 (Packet Decision Tree) on LOCGO-10 and SGKF-5...")
    a_dt_locgo = run_packet_baseline_cv(
        r, W, idx_mat, locgo_folds, model_kind="dt", save_final_artifact_name="model_a_packet_dt"
    )
    a_dt_sgkf5 = run_packet_baseline_cv(r, W, idx_mat, sgkf5_folds, model_kind="dt")

    print("Running Model B1 (Window Random Forest) on LOCGO-10 and SGKF-5...")
    b_rf_locgo = run_window_baseline_cv(
        X_win_df, W, locgo_folds, model_kind="rf", save_final_artifact_name="model_b_window_rf"
    )
    b_rf_sgkf5 = run_window_baseline_cv(X_win_df, W, sgkf5_folds, model_kind="rf")

    print("Running Model B2 (Window Logistic Regression) on LOCGO-10 and SGKF-5...")
    b_lr_locgo = run_window_baseline_cv(
        X_win_df, W, locgo_folds, model_kind="logreg", save_final_artifact_name="model_b_window_logreg"
    )
    b_lr_sgkf5 = run_window_baseline_cv(X_win_df, W, sgkf5_folds, model_kind="logreg")

    # Save OOF predictions for baselines
    pred_df = W[["window_id", "capture_group", "session_id", "label"]].copy()
    pred_df["score_model_a_packet_logreg"] = a_lr_locgo["oof_scores"]
    pred_df["thr_model_a_packet_logreg"] = a_lr_locgo["oof_val_thresholds"]
    pred_df["score_model_a_packet_dt"] = a_dt_locgo["oof_scores"]
    pred_df["thr_model_a_packet_dt"] = a_dt_locgo["oof_val_thresholds"]
    pred_df["score_model_b_window_rf"] = b_rf_locgo["oof_scores"]
    pred_df["thr_model_b_window_rf"] = b_rf_locgo["oof_val_thresholds"]
    pred_df["score_model_b_window_logreg"] = b_lr_locgo["oof_scores"]
    pred_df["thr_model_b_window_logreg"] = b_lr_locgo["oof_val_thresholds"]
    pred_df.to_csv(ARTIFACTS / "baseline_oof_predictions.csv", index=False)

    # Strip raw numpy arrays before saving JSON summary
    def _strip(res: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in res.items() if not k.startswith("oof_")}

    out = {
        "Model_A_Packet_LogReg": {
            "locgo_10fold": _strip(a_lr_locgo),
            "sgkf_5fold": _strip(a_lr_sgkf5),
        },
        "Model_A_Packet_DT": {
            "locgo_10fold": _strip(a_dt_locgo),
            "sgkf_5fold": _strip(a_dt_sgkf5),
        },
        "Model_B_Window_RF": {
            "locgo_10fold": _strip(b_rf_locgo),
            "sgkf_5fold": _strip(b_rf_sgkf5),
        },
        "Model_B_Window_LogReg": {
            "locgo_10fold": _strip(b_lr_locgo),
            "sgkf_5fold": _strip(b_lr_sgkf5),
        },
    }
    write_json(out, ARTIFACTS / "baseline_metrics.json")
    print("Saved artifacts/baseline_metrics.json and artifacts/baseline_oof_predictions.csv")
    for name, res in out.items():
        p05 = res["locgo_10fold"]["pooled_oof_at_0_5"]
        pvt = res["locgo_10fold"]["pooled_oof_at_val_threshold"]
        s5 = res["sgkf_5fold"]["summary_at_val_threshold"]["metrics"]["f1"]["mean"]
        print(
            f"  {name}: LOCGO Pooled F1@0.5={p05['f1']:.4f}, F1@val_thr={pvt['f1']:.4f} "
            f"(FPR={pvt['fpr']:.4f}, PR-AUC={p05['pr_auc']:.4f}); SGKF5 mean F1@val_thr={s5:.4f}"
        )


if __name__ == "__main__":
    main()
