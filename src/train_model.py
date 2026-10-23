"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/train_model.py

Purpose:
    Trains the initial supervised XGBoost binary classifier on protocol-aware features
    from the 70% training partition.
    Saves model weights, preprocessing artifacts, feature schemas, and training metadata.

Viva Explanation:
    - We use XGBoost (eXtreme Gradient Boosting), a leading gradient boosted decision tree
      algorithm that handles non-linear protocol interactions (e.g. TID deltas conditional on function codes).
    - Leakage and Fairness Control:
        * Model is trained strictly on the 70% training partition containing BOTH classes.
        * Class imbalance is addressed via 'scale_pos_weight', calculated purely from the
          training set: (num_normal / num_attack). The test distribution is left untouched.
        * Fixed random seed (42) guarantees exact reproducibility.
        * Initial classification threshold is set to 0.5 a priori without test set tuning.
    - Persistence:
        * We save both the XGBoost model and a joblib artifact bundle containing feature order,
          imputers/scalers, and metadata.
        * This allows subsequent predictions without retraining and enforces strict schema validation.
"""

from datetime import datetime
import time
import json
import os
from typing import Dict, Any, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
import xgboost as xgb

from src.feature_engineering import MODEL_FEATURE_COLUMNS


def train_xgboost_model(
    feat_df: pd.DataFrame,
    model_params: Optional[Dict[str, Any]] = None,
    model_path: Optional[str] = None,
    pipeline_path: Optional[str] = None,
    history_path: Optional[str] = None
) -> Tuple[xgb.XGBClassifier, Dict[str, Any]]:
    """
    Trains the XGBoost binary classifier on the 70% training partition.
    Records binary log loss across boosting rounds on training data only.

    Parameters:
        feat_df: DataFrame containing model features, target_is_attack, and partition
        model_params: Optional dictionary of hyperparameter settings
        model_path: Path to save the serialized XGBoost model
        pipeline_path: Path to save the joblib preprocessor bundle
        history_path: Optional path to save the training history JSON

    Returns:
        Tuple of (trained_xgb_model, training_metadata)
    """
    params = {
        "random_state": 42,
        "n_estimators": 100,
        "max_depth": 4,
        "learning_rate": 0.1,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "probability_threshold": 0.5,
        "eval_metric": "logloss"
    }
    if model_params:
        params.update(model_params)

    t_start = time.time()

    # 1. Filter strictly to the training partition
    train_data = feat_df[feat_df["partition"] == "train"].copy()
    if len(train_data) == 0:
        raise ValueError("No transactions found with partition == 'train'!")

    # Verify both classes are present
    train_class_counts = train_data["target_is_attack"].value_counts().to_dict()
    n_neg = train_class_counts.get(0, 0)
    n_pos = train_class_counts.get(1, 0)

    if n_neg == 0 or n_pos == 0:
        raise ValueError(
            f"Training partition must contain both classes! Found Normal={n_neg}, Replay={n_pos}. "
            "Check dataset loading or partition assignment."
        )

    # 2. Prepare X and y
    X_train = train_data[MODEL_FEATURE_COLUMNS].copy()
    y_train = train_data["target_is_attack"].values.astype(int)

    # 3. Fit imputer on training data ONLY
    imputer = SimpleImputer(strategy="median")
    X_train_imputed = imputer.fit_transform(X_train)

    # 4. Compute scale_pos_weight from training set statistics only
    scale_pos_weight = float(n_neg / max(1, n_pos))

    # 5. Initialize and train XGBClassifier
    classifier = xgb.XGBClassifier(
        n_estimators=params["n_estimators"],
        max_depth=params["max_depth"],
        learning_rate=params["learning_rate"],
        subsample=params["subsample"],
        colsample_bytree=params["colsample_bytree"],
        scale_pos_weight=scale_pos_weight,
        random_state=params["random_state"],
        eval_metric=params["eval_metric"]
    )

    # Train on training partition and record training loss history (leakage prevention: training data ONLY)
    classifier.fit(
        X_train_imputed,
        y_train,
        eval_set=[(X_train_imputed, y_train)],
        verbose=False
    )

    # Retrieve evaluation history across boosting rounds
    evals = classifier.evals_result()
    raw_loss = evals.get("validation_0", {}).get(params["eval_metric"], [])
    if not raw_loss and "validation_0" in evals:
        raw_loss = list(evals["validation_0"].values())[0]

    loss_list = [round(float(l), 5) for l in raw_loss]
    history_data = {
        "boosting_rounds": list(range(1, len(raw_loss) + 1)),
        "training_logloss": loss_list,
        "eval_metric_history": loss_list,
        "history": [{"round": i + 1, "logloss": l} for i, l in enumerate(loss_list)],
        "n_rounds": len(raw_loss),
        "initial_loss": loss_list[0] if loss_list else None,
        "final_loss": loss_list[-1] if loss_list else None,
        "training_timestamp": datetime.now().isoformat()
    }

    # 6. Extract feature importance from the trained XGBoost model
    raw_importances = classifier.feature_importances_
    feature_importance_list = [
        {"feature": feat, "importance": round(float(imp), 5)}
        for feat, imp in sorted(zip(MODEL_FEATURE_COLUMNS, raw_importances), key=lambda x: x[1], reverse=True)
    ]

    training_duration_sec = round(time.time() - t_start, 3)

    # 7. Build pipeline artifacts bundle
    pipeline_bundle = {
        "feature_order": MODEL_FEATURE_COLUMNS,
        "imputer": imputer,
        "scale_pos_weight": scale_pos_weight,
        "probability_threshold": params["probability_threshold"],
        "train_class_counts": {"normal_0": int(n_neg), "replay_1": int(n_pos)},
        "hyperparameters": params,
        "training_history": history_data,
        "feature_importance": feature_importance_list,
        "training_duration_seconds": training_duration_sec,
        "training_timestamp": datetime.now().isoformat()
    }

    # 8. Save model, pipeline bundle, training history, and feature importances
    if model_path:
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        classifier.save_model(model_path)

    if pipeline_path:
        os.makedirs(os.path.dirname(pipeline_path), exist_ok=True)
        joblib.dump(pipeline_bundle, pipeline_path)

    hist_file = history_path
    if not hist_file and model_path:
        hist_file = os.path.join(os.path.dirname(model_path), "xgboost_training_history.json")

    if hist_file:
        os.makedirs(os.path.dirname(hist_file), exist_ok=True)
        with open(hist_file, "w", encoding="utf-8") as f:
            json.dump(history_data, f, indent=2)

    feat_imp_file = None
    if model_path:
        feat_imp_file = os.path.join(os.path.dirname(model_path), "feature_importance.json")
        with open(feat_imp_file, "w", encoding="utf-8") as f:
            json.dump(feature_importance_list, f, indent=2)

    training_metadata = {
        "status": "success",
        "model_name": "XGBoost Binary Classifier (Modbus Replay Detector)",
        "model_version": "1.0.0",
        "training_samples": len(train_data),
        "class_distribution": {"Normal (0)": int(n_neg), "Replay (1)": int(n_pos)},
        "scale_pos_weight_applied": round(scale_pos_weight, 4),
        "hyperparameters": params,
        "feature_count": len(MODEL_FEATURE_COLUMNS),
        "training_duration_seconds": training_duration_sec,
        "n_boosting_rounds": len(history_data.get("boosting_rounds", [])),
        "model_path": model_path,
        "pipeline_path": pipeline_path,
        "history_path": hist_file,
        "feature_importance_path": feat_imp_file,
        "training_history": history_data,
        "feature_importance": feature_importance_list,
        "trained_at": pipeline_bundle["training_timestamp"]
    }

    # TODO(Stage 2): Hyperparameter and threshold tuning via cross-validation.
    # TODO(Stage 2): Shared fusion integration with physical process anomaly detectors.

    return classifier, training_metadata
