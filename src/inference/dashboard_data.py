"""Data-loading helpers for the dashboard (kept outside Streamlit for testing).

Every parquet read goes through the test-partition guard.
"""

from __future__ import annotations

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_curve,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)

from src.data.pairing import pair_events
from src.utils.config import (
    AUDIT_DIR,
    FEATURE_AUDIT_DIR,
    MANIFEST_DIR,
    PROCESSED_DIR,
    RESULTS_DIR,
    TRAIN_PARQUET,
    VALIDATION_DIR,
    read_parquet_safe,
)
from src.utils.io import read_json


class MissingResultError(FileNotFoundError):
    """A generated result file is missing; run the pipeline first."""


def _need(path):
    """Return *path* or raise a clear error if the pipeline has not produced it."""
    if not path.exists():
        raise MissingResultError(f"{path.name} not found. Run: python run_pipeline.py all")
    return path


def dev_captures() -> list[str]:
    """Capture ids of the development partition (from the split manifest)."""
    return read_json(_need(MANIFEST_DIR / "split_manifest.json"))["train_captures"]


def audit_summary() -> dict:
    """Dataset audit JSON (per-file facts)."""
    return read_json(_need(AUDIT_DIR / "dataset_audit.json"))


def capture_report() -> pd.DataFrame:
    """Capture report limited to development captures."""
    df = pd.read_csv(_need(AUDIT_DIR / "capture_report.csv"))
    return df[df["capture_id"].isin(dev_captures())]


def csv_result(name: str, folder=AUDIT_DIR, dev_only: bool = True) -> pd.DataFrame:
    """Read an audit CSV, limited to development captures when it has capture_id."""
    df = pd.read_csv(_need(folder / name))
    if dev_only and "capture_id" in df.columns:
        df = df[df["capture_id"].isin(dev_captures())]
    return df


def json_result(name: str, folder=RESULTS_DIR / "validation") -> dict:
    """Read a JSON result file."""
    return read_json(_need(folder / name))


def oof_predictions() -> pd.DataFrame:
    """Saved out-of-fold validation predictions (development partition only)."""
    return read_parquet_safe(_need(VALIDATION_DIR / "cv_validation_predictions.parquet"))


def summarize_oof_predictions(predictions: pd.DataFrame) -> dict[str, dict]:
    """Calculate binary classification metrics and curves from saved OOF predictions."""
    required = {
        "model_name",
        "fold",
        "actual_class",
        "predicted_class",
        "command_injection_probability",
    }
    missing = required - set(predictions.columns)
    if missing:
        raise ValueError(f"Out-of-fold predictions are missing required columns: {sorted(missing)}")
    if predictions.empty:
        raise ValueError("Out-of-fold predictions contain no records.")

    labels = ["Normal", "Command Injection"]
    summaries = {}
    for model_name, frame in predictions.groupby("model_name", sort=True):
        if frame[["actual_class", "predicted_class", "fold"]].isna().any().any():
            raise ValueError(f"Out-of-fold predictions for {model_name} contain missing labels or folds.")
        unknown = (set(frame["actual_class"]) | set(frame["predicted_class"])) - set(labels)
        if unknown:
            raise ValueError(f"Out-of-fold predictions contain unsupported classes: {sorted(unknown)}")

        y_true = (frame["actual_class"] == labels[1]).to_numpy(dtype=int)
        y_pred = (frame["predicted_class"] == labels[1]).to_numpy(dtype=int)
        y_score = pd.to_numeric(frame["command_injection_probability"], errors="coerce").to_numpy(dtype=float)
        if not pd.Series(y_score).map(lambda value: pd.notna(value) and 0 <= value <= 1).all():
            raise ValueError(f"Out-of-fold probabilities for {model_name} must be finite values from 0 to 1.")
        if set(y_true) != {0, 1}:
            raise ValueError(f"Out-of-fold predictions for {model_name} must contain both actual classes.")

        matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
        true_negative, false_positive, false_negative, true_positive = matrix.ravel()
        precision, recall, f1, support = precision_recall_fscore_support(y_true, y_pred, labels=[0, 1], zero_division=0)
        fpr, tpr, _ = roc_curve(y_true, y_score)
        pr_precision, pr_recall, _ = precision_recall_curve(y_true, y_score)
        fold_f1 = []
        for fold, fold_frame in frame.groupby("fold", sort=True):
            fold_true = (fold_frame["actual_class"] == labels[1]).to_numpy(dtype=int)
            fold_pred = (fold_frame["predicted_class"] == labels[1]).to_numpy(dtype=int)
            fold_scores = precision_recall_fscore_support(fold_true, fold_pred, labels=[0, 1], zero_division=0)[2]
            fold_f1.append({"fold": fold, "macro_f1": float(fold_scores.mean())})

        summaries[str(model_name)] = {
            "metrics": {
                "records": int(len(frame)),
                "accuracy": float(accuracy_score(y_true, y_pred)),
                "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
                "macro_precision": float(precision.mean()),
                "macro_recall": float(recall.mean()),
                "macro_f1": float(f1.mean()),
                "normal_precision": float(precision[0]),
                "normal_recall": float(recall[0]),
                "normal_f1": float(f1[0]),
                "command_injection_precision": float(precision[1]),
                "command_injection_recall": float(recall[1]),
                "command_injection_f1": float(f1[1]),
                "specificity": float(true_negative / max(true_negative + false_positive, 1)),
                "false_positive_rate": float(false_positive / max(true_negative + false_positive, 1)),
                "false_negative_rate": float(false_negative / max(false_negative + true_positive, 1)),
                "roc_auc": float(roc_auc_score(y_true, y_score)),
                "pr_auc": float(average_precision_score(y_true, y_score)),
                "normal_support": int(support[0]),
                "command_injection_support": int(support[1]),
            },
            "confusion_matrix": matrix,
            "roc_curve": {"false_positive_rate": fpr, "true_positive_rate": tpr},
            "precision_recall_curve": {"recall": pr_recall, "precision": pr_precision},
            "fold_macro_f1": fold_f1,
        }
    return summaries


def dev_packets() -> pd.DataFrame:
    """Processed packets of the development partition."""
    return read_parquet_safe(_need(TRAIN_PARQUET))


def dev_pairing_stats() -> dict:
    """Pairing statistics recomputed on the development partition only."""
    _, orphans, stats = pair_events(dev_packets())
    return stats


def feature_inventory() -> pd.DataFrame:
    """Feature inventory produced by the feature audit."""
    return pd.read_csv(_need(FEATURE_AUDIT_DIR / "feature_inventory.csv"))


def preprocess_report() -> dict:
    """Preprocessing report (whole-dataset counts)."""
    return read_json(_need(PROCESSED_DIR / "preprocess_report.json"))
