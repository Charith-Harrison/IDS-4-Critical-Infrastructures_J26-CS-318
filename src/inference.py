# Load the older application's saved model and predict without refitting it.
"""Mode-independent prediction API with explicit invalid-record outcomes."""

from __future__ import annotations

import time

import joblib
import numpy as np
import pandas as pd

from src.event_builder import build_events
from src.explainability import explain_event
from src.feature_engineering import build_features, feature_names
from src.label_mapper import class_names
from src.preprocessing import preprocess_frame
from src.utils import ROOT, checksum, config_digest, read_json


# Check the older model's integrity, class schema, and feature names before using it.
def load_model(kind: str = "contextual", cfg: dict | None = None) -> dict:
    if kind not in {"baseline", "contextual"}:
        raise ValueError("Unknown model kind")
    directory = ROOT / "models" / kind
    metadata = read_json(directory / "metadata.json")
    if checksum(directory / "model.joblib") != metadata["artifact_sha256"]:
        raise ValueError("Model checksum mismatch")
    # joblib is only loaded from trusted local training output, never from an upload.
    artifact = joblib.load(directory / "model.joblib")
    model_cfg = artifact["metadata"]["configuration"]
    if cfg is not None and config_digest(cfg) != artifact["metadata"]["configuration_hash"]:
        raise ValueError("Model/configuration mismatch. Preprocess and train the selected configuration.")
    if set(artifact["pipeline"].classes_) != set(class_names(model_cfg)):
        raise ValueError("Saved model class schema mismatch")
    if artifact["metadata"]["feature_names"] != feature_names(model_cfg, kind):
        raise ValueError("Saved model feature schema mismatch")
    return artifact


# Predict reconstructed events with the saved pipeline and retain IDs for inspection.
def predict_events(events: pd.DataFrame, artifact: dict, explain: bool = True) -> pd.DataFrame:
    """Predict already reconstructed events, retaining identifiers for investigation."""
    metadata = artifact["metadata"]
    output = events.copy()
    if output.empty:
        for name in ["prediction", "confidence", "evidence", "model_version", "model_mode"]:
            output[name] = pd.Series(dtype="object")
        return output
    features = build_features(events, metadata["configuration"], metadata["model_kind"])
    probabilities = artifact["pipeline"].predict_proba(features)
    output["prediction"] = np.asarray(artifact["pipeline"].classes_)[probabilities.argmax(axis=1)]
    output["confidence"] = probabilities.max(axis=1)
    for i, label in enumerate(artifact["pipeline"].classes_):
        output["probability_" + label] = probabilities[:, i]
    output["model_version"] = metadata["model_version"]
    output["model_mode"] = metadata["model_mode"]
    output["processing_status"] = "complete"
    output["evidence"] = (
        [explain_event(row, artifact)["evidence"] for _, row in features.iterrows()]
        if explain
        else [[] for _ in range(len(output))]
    )
    return output


# Remove labels, rebuild the batch history, and leave malformed rows without a predicted class.
def predict_csv(
    frame: pd.DataFrame, artifact: dict, source: str = "upload.csv", explain: bool = True
) -> tuple[pd.DataFrame, dict]:
    """One ordered batch is one context history; separate calls deliberately reset it.

    Uploaded label columns are not needed for inference and cannot affect predictions.
    """
    start = time.perf_counter()
    cfg = artifact["metadata"]["configuration"]
    clean_input = frame.drop(columns=[cfg["dataset"]["label_column"], "is_attack", "attack_sub_type"], errors="ignore")
    records = preprocess_frame(clean_input, cfg, source, labelled=False)
    valid = records[records.processing_status.eq("valid")].copy()
    invalid = records[records.processing_status.ne("valid")].copy()
    events = build_events(valid, cfg)
    output = predict_events(events, artifact, explain=explain)
    invalid["prediction"] = None
    invalid["confidence"] = np.nan
    invalid["model_mode"] = cfg["model_mode"]
    invalid["model_version"] = artifact["metadata"]["model_version"]
    combined = pd.concat([output, invalid], ignore_index=True).sort_values("source_row")
    return combined, {
        "processed": len(output),
        "malformed": len(invalid),
        "total": len(records),
        "elapsed_seconds": time.perf_counter() - start,
    }


# Convert prediction rows to the stable JSON-safe output fields.
def prediction_records(frame: pd.DataFrame) -> list[dict]:
    """Return JSON-safe stable API records, including invalid rows without a class."""
    import json

    fields = [
        "event_id",
        "timestamp",
        "prediction",
        "confidence",
        "modbus_func_code",
        "modbus_ref_num",
        "evidence",
        "model_version",
        "model_mode",
        "processing_status",
        "invalid_reason",
    ]
    result = frame.reindex(columns=fields).rename(
        columns={"modbus_func_code": "function_code", "modbus_ref_num": "address_or_register"}
    )
    return json.loads(result.to_json(orient="records"))
