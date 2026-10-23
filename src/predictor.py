"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/predictor.py

Purpose:
    Loads saved model artifacts, validates feature schemas, and executes
    inference on new or test transactions without retraining.
    Measures processing and inference times separately from end-to-end detection delay.

Viva Explanation:
    - This module simulates the live inference component of the detection architecture.
    - Schema validation ensures incoming data contains the exact expected features in the
      correct order, preventing silent misclassification if feature order changes.
    - Inference timing:
        * Feature processing time: elapsed time extracting and preparing features per transaction.
        * Model inference time: elapsed time evaluating the XGBoost tree ensemble per transaction.
        * End-to-end detection delay: the actual operational time required to declare a decision,
          which is dominated by network round-trip time or timeout expiration waiting for the transaction
          to conclude, PLUS the negligible microsecond ML inference.
"""

import time
from typing import Dict, Any, Tuple, Optional
import joblib
import numpy as np
import pandas as pd
import xgboost as xgb


class ReplayPredictor:
    """
    Inference engine that loads saved model artifacts and performs validated predictions.
    """

    def __init__(self, model_path: str, pipeline_path: str):
        self.model_path = model_path
        self.pipeline_path = pipeline_path
        self.model: Optional[xgb.XGBClassifier] = None
        self.pipeline_bundle: Optional[Dict[str, Any]] = None
        self.load_artifacts()

    def load_artifacts(self) -> None:
        """
        Loads the XGBoost model and joblib pipeline artifacts.
        """
        if not self.model_path or not self.pipeline_path:
            raise ValueError("Model path and pipeline path must be specified.")

        self.pipeline_bundle = joblib.load(self.pipeline_path)

        self.model = xgb.XGBClassifier()
        self.model.load_model(self.model_path)

    def validate_schema(self, df: pd.DataFrame) -> None:
        """
        Rejects incompatible feature schemas with a detailed error message.
        """
        expected_features = self.pipeline_bundle["feature_order"]
        missing_features = [f for f in expected_features if f not in df.columns]

        if missing_features:
            raise ValueError(
                f"Feature schema mismatch! Missing {len(missing_features)} required features: {missing_features}. "
                f"Expected exact features: {expected_features}"
            )

    def predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, Dict[str, float]]:
        """
        Generates binary predictions and replay probabilities on the provided DataFrame.

        Parameters:
            df: DataFrame containing required features

        Returns:
            Tuple of:
                y_pred: Binary predictions (0 or 1)
                y_prob: Continuous replay probabilities [0.0, 1.0]
                timing_stats: Dictionary containing feature processing and inference latency
        """
        self.validate_schema(df)

        expected_order = self.pipeline_bundle["feature_order"]
        threshold = self.pipeline_bundle.get("probability_threshold", 0.5)
        imputer = self.pipeline_bundle["imputer"]

        # Measure feature preparation time
        t_prep_start = time.perf_counter()
        X = df[expected_order].copy()
        X_imputed = imputer.transform(X)
        t_prep_end = time.perf_counter()
        prep_time_ms = (t_prep_end - t_prep_start) * 1000.0

        # Measure model inference time
        t_infer_start = time.perf_counter()
        # predict_proba returns probabilities for [class 0, class 1]
        probs = self.model.predict_proba(X_imputed)[:, 1]
        t_infer_end = time.perf_counter()
        infer_time_ms = (t_infer_end - t_infer_start) * 1000.0

        preds = (probs >= threshold).astype(int)

        n_samples = max(1, len(df))
        timing_stats = {
            "total_prep_time_ms": round(prep_time_ms, 3),
            "total_infer_time_ms": round(infer_time_ms, 3),
            "avg_prep_time_per_tx_ms": round(prep_time_ms / n_samples, 4),
            "avg_infer_time_per_tx_ms": round(infer_time_ms / n_samples, 4),
            "total_computational_delay_per_tx_ms": round((prep_time_ms + infer_time_ms) / n_samples, 4)
        }

        return preds, probs, timing_stats
