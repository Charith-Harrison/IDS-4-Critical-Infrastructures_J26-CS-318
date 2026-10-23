"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/evaluate_model.py

Purpose:
    Computes rigorous evaluation metrics comparing the transparent Rule Baseline
    against the supervised XGBoost model on the held-out test partition.
    Exports predictions and metrics artifacts.

Viva Explanation:
    - This module produces the empirical results required for academic evaluation.
    - Metrics computed:
        * Confusion Matrix (TP, FP, TN, FN).
        * Accuracy, Precision, Recall, F1-Score.
        * False Positive Rate (FPR = FP / (FP + TN)).
        * ROC-AUC using continuous XGBoost probabilities.
    - Zero-division handling: If no positive predictions occur, precision and F1 are safely defined as 0.0.
    - Latency breakdown:
        * Differentiates algorithm runtime (computational delay < 1 ms) from the network
          transaction completion delay (waiting for response or timeout).
    - Academic disclaimer:
        * All results are strictly labeled as preliminary Stage 1 prototypes.
        * No premature claims of production readiness or generalizability.
"""

import json
import os
from typing import Dict, Any, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, roc_auc_score, accuracy_score, precision_score, recall_score, f1_score, roc_curve

from src.baseline import ProtocolRuleBaseline
from src.predictor import ReplayPredictor
from src.feature_engineering import MODEL_FEATURE_COLUMNS


def calculate_metrics_dict(y_true: np.ndarray, y_pred: np.ndarray, y_prob: Optional[np.ndarray] = None) -> Dict[str, Any]:
    """
    Computes comprehensive binary classification metrics with zero-division handling.
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    
    total = int(len(y_true))
    acc = float(accuracy_score(y_true, y_pred))
    
    # Precision: TP / (TP + FP)
    prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    
    # Recall: TP / (TP + FN)
    rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    
    # F1 Score: 2 * P * R / (P + R)
    f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    
    # False Positive Rate: FP / (FP + TN)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    
    # ROC-AUC (only computable if both classes exist in y_true and probabilities available)
    auc_score = None
    if y_prob is not None and len(np.unique(y_true)) > 1:
        try:
            auc_score = float(roc_auc_score(y_true, y_prob))
        except Exception:
            auc_score = None

    return {
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp)
        },
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "roc_auc": round(auc_score, 4) if auc_score is not None else "N/A"
    }


def evaluate_test_partition(
    feat_df: pd.DataFrame,
    model_path: str,
    pipeline_path: str,
    rule_baseline_config: Optional[Dict[str, Any]] = None,
    predictions_csv_path: Optional[str] = None,
    metrics_json_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates both the Rule Baseline and XGBoost model on the held-out test partition.

    Parameters:
        feat_df: Feature DataFrame containing 'partition' and 'target_is_attack'
        model_path: Path to the trained XGBoost model
        pipeline_path: Path to the joblib pipeline bundle
        rule_baseline_config: Config options for ProtocolRuleBaseline
        predictions_csv_path: Optional path to save test predictions CSV
        metrics_json_path: Optional path to save evaluation metrics JSON

    Returns:
        Structured evaluation results dictionary
    """
    test_data = feat_df[feat_df["partition"] == "test"].copy().reset_index(drop=True)
    if len(test_data) == 0:
        raise ValueError("No records found with partition == 'test'!")

    y_test = test_data["target_is_attack"].values.astype(int)

    # 1. Evaluate Transparent Rule Baseline
    rb_cfg = rule_baseline_config or {}
    baseline_model = ProtocolRuleBaseline(
        require_tid_previously_seen=rb_cfg.get("require_tid_previously_seen", True),
        enable_non_sequential_repeated_cmd=rb_cfg.get("enable_non_sequential_repeated_cmd", True),
        enable_timeout_rule=rb_cfg.get("enable_timeout_rule", True)
    )
    y_rule_pred = baseline_model.predict(test_data[MODEL_FEATURE_COLUMNS])
    baseline_metrics = calculate_metrics_dict(y_test, y_rule_pred)

    # 2. Evaluate Trained XGBoost Model
    predictor = ReplayPredictor(model_path=model_path, pipeline_path=pipeline_path)
    y_xgb_pred, y_xgb_prob, timing_stats = predictor.predict(test_data[MODEL_FEATURE_COLUMNS])
    xgb_metrics = calculate_metrics_dict(y_test, y_xgb_pred, y_xgb_prob)

    # End-to-end detection delay analysis:
    # Computational runtime (microsecond level ML inference) vs Network resolution delay
    avg_network_latency = float(test_data["response_latency"].mean())
    timing_breakdown = {
        "model_inference_time_per_tx_ms": timing_stats["avg_infer_time_per_tx_ms"],
        "feature_prep_time_per_tx_ms": timing_stats["avg_prep_time_per_tx_ms"],
        "total_computational_delay_per_tx_ms": timing_stats["total_computational_delay_per_tx_ms"],
        "avg_network_resolution_delay_ms": round(avg_network_latency * 1000.0, 2),
        "total_operational_detection_delay_ms": round((avg_network_latency * 1000.0) + timing_stats["total_computational_delay_per_tx_ms"], 2),
        "timing_note": (
            "Feature preparation and XGBoost inference take < 0.1 ms per transaction. "
            "Operational detection latency is dominated by network round-trip time "
            "(or the 1.0s timeout duration when a replayed request elicits no server response)."
        )
    }

    # Attach prediction outputs and confidence to DataFrame
    test_data["rule_pred"] = y_rule_pred
    test_data["xgb_pred"] = y_xgb_pred
    test_data["replay_probability"] = np.round(y_xgb_prob, 4)
    test_data["confidence"] = np.round(np.where(y_xgb_pred == 1, y_xgb_prob, 1.0 - y_xgb_prob) * 100, 1)

    # Determine Prediction Status
    status_list = []
    for actual, pred in zip(y_test, y_xgb_pred):
        if actual == 1 and pred == 1:
            status_list.append("True Positive (TP)")
        elif actual == 0 and pred == 0:
            status_list.append("True Negative (TN)")
        elif actual == 0 and pred == 1:
            status_list.append("False Positive (FP)")
        elif actual == 1 and pred == 0:
            status_list.append("False Negative (FN)")
        else:
            status_list.append("Not Evaluated")
    test_data["prediction_status"] = status_list

    # Ensure source_dataset display column exists
    if "dataset_category" in test_data.columns:
        test_data["source_dataset"] = test_data["dataset_category"].apply(
            lambda cat: "Normal Traffic" if "normal" in str(cat).lower() else "Replay Attack Traffic"
        )
    else:
        test_data["source_dataset"] = test_data["source_file"].apply(
            lambda sf: "Normal Traffic" if "normal" in str(sf).lower() else "Replay Attack Traffic"
        )

    # Ensure IP and function code columns exist
    if "client_ip" not in test_data.columns and "src_ip" in test_data.columns:
        test_data["client_ip"] = test_data["src_ip"]
    if "server_ip" not in test_data.columns and "dst_ip" in test_data.columns:
        test_data["server_ip"] = test_data["dst_ip"]

    # Class distribution and prediction summary statistics
    train_count_normal = int((feat_df[feat_df["partition"] == "train"]["target_is_attack"] == 0).sum())
    train_count_replay = int((feat_df[feat_df["partition"] == "train"]["target_is_attack"] == 1).sum())
    test_count_normal = int((y_test == 0).sum())
    test_count_replay = int((y_test == 1).sum())

    pred_normal_count = int((y_xgb_pred == 0).sum())
    pred_replay_count = int((y_xgb_pred == 1).sum())

    status_counts = {
        "true_positive": int(test_data["prediction_status"].str.contains("True Positive", na=False).sum()),
        "true_negative": int(test_data["prediction_status"].str.contains("True Negative", na=False).sum()),
        "false_positive": int(test_data["prediction_status"].str.contains("False Positive", na=False).sum()),
        "false_negative": int(test_data["prediction_status"].str.contains("False Negative", na=False).sum()),
        "not_evaluated": int(test_data["prediction_status"].str.contains("Not Evaluated", na=False).sum())
    }

    tp = status_counts["true_positive"]
    tn = status_counts["true_negative"]
    fp = status_counts["false_positive"]
    fn = status_counts["false_negative"]

    prediction_summary = {
        "total_count": int(len(test_data)),
        "predicted_normal_count": pred_normal_count,
        "predicted_replay_count": pred_replay_count,
        "correct_predictions": int(tp + tn),
        "incorrect_predictions": int(fp + fn),
        "status_counts": status_counts
    }

    # 3. Compute ROC Curve points for XGBoost
    roc_curve_data = {"fpr": [0.0, 1.0], "tpr": [0.0, 1.0], "auc": xgb_metrics.get("roc_auc")}
    if len(np.unique(y_test)) > 1:
        try:
            fpr_vals, tpr_vals, th_vals = roc_curve(y_test, y_xgb_prob)
            step = max(1, len(fpr_vals) // 40)
            roc_curve_data = {
                "fpr": [round(float(v), 4) for v in fpr_vals[::step]],
                "tpr": [round(float(v), 4) for v in tpr_vals[::step]],
                "thresholds": [round(float(v), 4) for v in th_vals[::step]],
                "auc": xgb_metrics.get("roc_auc")
            }
            if roc_curve_data["fpr"][-1] != round(float(fpr_vals[-1]), 4):
                roc_curve_data["fpr"].append(round(float(fpr_vals[-1]), 4))
                roc_curve_data["tpr"].append(round(float(tpr_vals[-1]), 4))
        except Exception:
            pass

    # 4. Compute Prediction Probability Distribution bins (Normal vs Replay)
    bins = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    norm_probs = y_xgb_prob[y_test == 0]
    rep_probs = y_xgb_prob[y_test == 1]
    norm_hist, _ = np.histogram(norm_probs, bins=bins)
    rep_hist, _ = np.histogram(rep_probs, bins=bins)
    prob_distribution = {
        "bins": [f"{round(bins[i], 1)}-{round(bins[i+1], 1)}" for i in range(len(bins)-1)],
        "normal_counts": [int(c) for c in norm_hist],
        "replay_counts": [int(c) for c in rep_hist]
    }

    results = {
        "evaluation_scope": "Preliminary Stage 1 Evaluation (Held-Out Test Partition)",
        "disclaimer": (
            "All results are preliminary Stage 1 research findings. "
            "They demonstrate feasibility on CIC Modbus 2023 extracts and do NOT claim "
            "production readiness, target accuracy, or generalization across arbitrary industrial setups."
        ),
        "partition_counts": {
            "train": {"normal": train_count_normal, "replay": train_count_replay, "total": train_count_normal + train_count_replay},
            "test": {"normal": test_count_normal, "replay": test_count_replay, "total": test_count_normal + test_count_replay}
        },
        "rule_baseline_metrics": baseline_metrics,
        "xgboost_metrics": xgb_metrics,
        "timing_breakdown": timing_breakdown,
        "prediction_summary": prediction_summary,
        "roc_curve": roc_curve_data,
        "prediction_distribution": prob_distribution
    }

    # Save artifacts
    if predictions_csv_path:
        os.makedirs(os.path.dirname(predictions_csv_path), exist_ok=True)
        export_cols = [
            "transaction_id", "request_timestamp", "source_dataset",
            "client_ip", "server_ip", "modbus_func_code",
            "target_is_attack", "rule_pred", "xgb_pred", "replay_probability",
            "confidence", "prediction_status", "partition", "capture_id", "source_file",
            "trans_id_delta", "tid_previously_seen", "request_iat",
            "is_repeated_command", "duplicate_cmd_freq", "is_timeout", "response_latency"
        ]
        available_export_cols = [c for c in export_cols if c in test_data.columns]
        test_data[available_export_cols].to_csv(predictions_csv_path, index=False)

    if metrics_json_path:
        os.makedirs(os.path.dirname(metrics_json_path), exist_ok=True)
        with open(metrics_json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

    return results
