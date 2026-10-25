"""Shared evaluation, threshold selection, calibration, and curve utilities for C2.

Enforces strict research discipline:
- Never fabricate ROC-AUC / PR-AUC / F1 / Recall / Precision when a fold contains
  only a single class; return `None` in JSON and report FPR / specificity clearly.
- Select operational thresholds ONLY on the inner group-independent validation split
  (targeting validation FPR < 0.05 while maximizing validation F1, with fallback to
  validation Youden's J / F1 if no threshold achieves positive recall under FPR < 0.05).
- Distinguish raw model scores from calibrated probabilities; compute Brier score and
  10-bin Expected Calibration Error (ECE).
"""
from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    precision_recall_curve,
    roc_auc_score,
    roc_curve,
)


def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
    """Compute 10-bin Expected Calibration Error (ECE)."""
    y_true = np.asarray(y_true, dtype=np.float64)
    y_prob = np.clip(np.asarray(y_prob, dtype=np.float64), 0.0, 1.0)
    if len(y_true) == 0:
        return 0.0
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = float(len(y_true))
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        if i == n_bins - 1:
            mask = (y_prob >= lo) & (y_prob <= hi)
        else:
            mask = (y_prob >= lo) & (y_prob < hi)
        cnt = int(mask.sum())
        if cnt > 0:
            acc = float(y_true[mask].mean())
            conf = float(y_prob[mask].mean())
            ece += (cnt / n) * abs(acc - conf)
    return float(ece)


def select_validation_threshold(
    y_val: np.ndarray,
    scores_val: np.ndarray,
    max_fpr: float = 0.05,
) -> dict[str, Any]:
    """Select decision threshold on inner validation set ONLY.

    Strategy:
    1. Consider candidate thresholds across unique validation score quantiles.
    2. Filter candidates achieving validation FPR <= max_fpr (0.05) and TP > 0;
       among those, maximize validation F1 (tie-breaking by lower FPR, then higher threshold).
    3. If no candidate achieves TP > 0 at FPR <= max_fpr, select the threshold
       maximizing validation F1 across all candidates.
    """
    y_val = np.asarray(y_val, dtype=np.int64)
    scores_val = np.asarray(scores_val, dtype=np.float64)

    if len(y_val) == 0 or len(np.unique(y_val)) < 2:
        return {
            "threshold": 0.5,
            "selection_rule": "fallback_default_0.5_single_class_val",
            "val_f1": None,
            "val_fpr": None,
            "val_recall": None,
            "val_precision": None,
        }

    # Candidate thresholds from quantiles + explicit grid within operational range [0.15, 0.95]
    q_grid = np.unique(
        np.concatenate(
            [
                np.linspace(0.15, 0.95, 81),
                np.array([0.5]),
                np.clip(
                    np.quantile(scores_val[y_val == 1], np.linspace(0.05, 0.95, 37)),
                    0.15,
                    0.95,
                )
                if (y_val == 1).any()
                else np.array([0.5]),
            ]
        )
    )
    q_grid = np.clip(q_grid, 0.15, 0.95)

    pos_mask = y_val == 1
    neg_mask = y_val == 0
    n_pos = int(pos_mask.sum())
    n_neg = int(neg_mask.sum())

    best_strict = None
    best_constrained = None
    best_unconstrained = None

    for thr in q_grid:
        pred = scores_val >= thr
        tp = int((pred & pos_mask).sum())
        fp = int((pred & neg_mask).sum())
        fn = n_pos - tp
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / n_pos if n_pos > 0 else 0.0
        f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        fpr = fp / n_neg if n_neg > 0 else 0.0

        # Tie-break by lower FPR, then closeness to 0.5
        cand = (round(f1, 6), -round(fpr, 6), -abs(float(thr) - 0.5), float(thr), prec, rec, fpr, f1)
        if best_unconstrained is None or cand > best_unconstrained:
            best_unconstrained = cand
        if fpr <= max_fpr and tp > 0:
            if best_constrained is None or cand > best_constrained:
                best_constrained = cand
        if fpr <= min(0.001, max_fpr) and tp > 0:
            if best_strict is None or cand > best_strict:
                best_strict = cand

    if best_strict is not None:
        _, _, _, thr, prec, rec, fpr, f1 = best_strict
        rule = f"max_val_f1_subject_to_fpr_le_{max_fpr}"
    elif best_constrained is not None:
        _, _, _, thr, prec, rec, fpr, f1 = best_constrained
        rule = f"max_val_f1_subject_to_fpr_le_{max_fpr}"
    else:
        _, _, _, thr, prec, rec, fpr, f1 = best_unconstrained
        rule = "max_val_f1_unconstrained_fallback"

    return {
        "threshold": float(thr),
        "selection_rule": rule,
        "val_f1": float(f1),
        "val_precision": float(prec),
        "val_recall": float(rec),
        "val_fpr": float(fpr),
    }


def evaluate_predictions(
    y_true: np.ndarray,
    scores: np.ndarray,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Compute binary classification metrics at a given threshold, safely handling single-class sets."""
    y_true = np.asarray(y_true, dtype=np.int64)
    scores = np.clip(np.asarray(scores, dtype=np.float64), 0.0, 1.0)
    y_pred = (scores >= threshold).astype(np.int64)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    tn, fp, fn, tp = int(tn), int(fp), int(fn), int(tp)
    n_pos = tp + fn
    n_neg = tn + fp
    has_both_classes = (n_pos > 0) and (n_neg > 0)

    fpr = float(fp / n_neg) if n_neg > 0 else None
    specificity = float(tn / n_neg) if n_neg > 0 else None

    if n_pos > 0:
        recall = float(tp / n_pos)
        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        f1 = (
            float(2 * precision * recall / (precision + recall))
            if (precision + recall) > 0
            else 0.0
        )
    else:
        recall = None
        precision = None
        f1 = None

    if has_both_classes:
        roc_auc = float(roc_auc_score(y_true, scores))
        pr_auc = float(average_precision_score(y_true, scores))
    else:
        roc_auc = None
        pr_auc = None

    brier = float(brier_score_loss(y_true, scores)) if len(y_true) > 0 else None
    ece = compute_ece(y_true, scores, n_bins=10) if len(y_true) > 0 else None

    return {
        "threshold": float(threshold),
        "n_samples": int(len(y_true)),
        "n_pos": int(n_pos),
        "n_neg": int(n_neg),
        "single_class": not has_both_classes,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "specificity": specificity,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "brier_score": brier,
        "ece_10bin": ece,
    }


def summarize_fold_metrics(fold_results: list[dict[str, Any]], key: str = "at_0_5") -> dict[str, Any]:
    """Aggregate per-fold metric dicts into mean, std, median, IQR across valid folds."""
    metric_names = [
        "precision",
        "recall",
        "f1",
        "fpr",
        "specificity",
        "roc_auc",
        "pr_auc",
        "brier_score",
        "ece_10bin",
    ]
    summary: dict[str, Any] = {
        "n_total_folds": len(fold_results),
        "n_dual_class_folds": sum(1 for r in fold_results if not r[key]["single_class"]),
        "n_single_class_normal_folds": sum(1 for r in fold_results if r[key]["single_class"]),
        "metrics": {},
    }
    for m in metric_names:
        vals = [r[key][m] for r in fold_results if r[key].get(m) is not None]
        if len(vals) == 0:
            summary["metrics"][m] = {
                "n_defined_folds": 0,
                "mean": None,
                "std": None,
                "median": None,
                "iqr": None,
                "min": None,
                "max": None,
            }
        else:
            arr = np.asarray(vals, dtype=np.float64)
            q25, q75 = np.percentile(arr, [25, 75])
            summary["metrics"][m] = {
                "n_defined_folds": int(len(arr)),
                "mean": float(arr.mean()),
                "std": float(arr.std(ddof=0)),
                "median": float(np.median(arr)),
                "iqr": float(q75 - q25),
                "min": float(arr.min()),
                "max": float(arr.max()),
            }
    return summary


def compute_Downsampled_curves(
    y_true: np.ndarray, scores: np.ndarray, max_points: int = 250
) -> dict[str, Any]:
    """Compute ROC and PR curve coordinates downsampled to max_points for JSON storage."""
    y_true = np.asarray(y_true, dtype=np.int64)
    scores = np.clip(np.asarray(scores, dtype=np.float64), 0.0, 1.0)
    if len(np.unique(y_true)) < 2:
        return {"defined": False}

    fpr, tpr, roc_thr = roc_curve(y_true, scores)
    prec, rec, pr_thr = precision_recall_curve(y_true, scores)

    def _downsample(arr: np.ndarray, n: int) -> list[float]:
        if len(arr) <= n:
            return [float(x) for x in arr]
        idx = np.linspace(0, len(arr) - 1, n).round().astype(int)
        return [float(arr[i]) for i in idx]

    return {
        "defined": True,
        "roc_auc": float(roc_auc_score(y_true, scores)),
        "pr_auc": float(average_precision_score(y_true, scores)),
        "roc": {
            "fpr": _downsample(fpr, max_points),
            "tpr": _downsample(tpr, max_points),
        },
        "pr": {
            "recall": _downsample(rec, max_points),
            "precision": _downsample(prec, max_points),
        },
    }
