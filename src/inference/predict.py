"""Reusable inference: model loading, detection pipeline, observations, exports.

Training, validation inference and uploaded-CSV detection all call the same
preprocessing, pairing and feature modules. Detection never retrains a model
and never receives the actual class as an input.
"""

from __future__ import annotations

import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from src.data.loader import DataValidationError, validate_schema
from src.data.pairing import pair_events
from src.data.preprocess import (
    add_protocol_basics,
    map_labels,
    reconstruct_captures,
    standardize,
)
from src.features.builder import build_stat_free_features
from src.features.profile import apply_profile
from src.utils.config import (
    BINARY_LIMITATION,
    CLASS_NAMES,
    FEATURE_SCHEMA_VERSION,
    FORBIDDEN_FEATURE_COLUMNS,
    MANIFEST_DIR,
    MODEL_VERSION,
    MODELS_DIR,
    TRAIN_PARQUET,
    read_parquet_safe,
)
from src.utils.io import read_json, sha256_file

MODEL_FILES = {
    "baseline": ("baseline", "baseline_random_forest.joblib"),
    "contextual": ("contextual", "contextual_rf.joblib"),
}


class ModelLoadError(RuntimeError):
    """Raised when a model or its supporting artefacts are missing/corrupt."""


class FeatureSchemaError(RuntimeError):
    """Raised when the computed features do not match the saved schema."""


def load_artifacts(model: str = "contextual", models_dir: Path = MODELS_DIR) -> dict:
    """Load a saved model plus feature names, statistics and metadata."""
    folder, fname = MODEL_FILES[model]
    d = Path(models_dir) / folder
    needed = [fname, "feature_names.json", "feature_stats.json", "training_manifest.json", "model_checksums.json"]
    missing = [n for n in needed if not (d / n).exists()]
    if missing:
        raise ModelLoadError(f"Missing model artefacts: {', '.join(missing)}")
    try:
        if sha256_file(d / fname) != read_json(d / "model_checksums.json")[fname]:
            raise ModelLoadError("Model checksum mismatch (file modified or corrupted).")
        clf = joblib.load(d / fname)
    except ModelLoadError:
        raise
    except Exception as exc:  # corrupted pickle etc.
        raise ModelLoadError(f"Model could not be loaded: {exc}") from exc
    names = read_json(d / "feature_names.json")
    if int(getattr(clf, "n_features_in_", -1)) != len(names):
        raise FeatureSchemaError("Feature count in the model differs from feature_names.json.")
    if set(names) & set(FORBIDDEN_FEATURE_COLUMNS):
        raise FeatureSchemaError("Forbidden label/metadata column found in the feature schema.")
    return {
        "name": model,
        "clf": clf,
        "features": names,
        "stats": read_json(d / "feature_stats.json"),
        "manifest": read_json(d / "training_manifest.json"),
    }


def load_label_mapping() -> dict:
    """Read the saved label mapping (classes + normal-write combos)."""
    path = MANIFEST_DIR / "label_mapping.json"
    if not path.exists():
        raise ModelLoadError("label_mapping.json is missing.")
    return read_json(path)


def preprocess_raw(df: pd.DataFrame, source_name: str = "upload", prefix: str = "up"):
    """Validate + standardise a raw CSV frame. Returns (packets, invalid, info)."""
    info = validate_schema(df)
    if not info["ok"]:
        raise DataValidationError("Missing required columns: " + ", ".join(info["missing"]))
    clean, invalid = standardize(df, source_name)
    if len(clean) == 0:
        raise DataValidationError("No valid records remain after validation.")
    clean = reconstruct_captures(clean, prefix)
    clean = add_protocol_basics(clean)
    combos = load_label_mapping()["normal_write_combos"]
    # Labels, if present, are kept ONLY for comparison after prediction.
    clean = map_labels(clean, combos)
    clean = clean.sort_values(["capture_id", "timestamp", "frame_number"], kind="mergesort").reset_index(drop=True)
    clean["event_id"] = clean["capture_id"] + ":" + clean["source_row"].astype(str)
    return clean, invalid, info


def observations(row: pd.Series, stats: dict) -> list[str]:
    """Real, calculated supporting contextual observations for one event."""
    out = []
    if row["is_write"] == 1:
        out.append(f"Write operation detected (FC{int(row['func_code'])})")
    if row["access_combo_unseen"] == 1:
        out.append("Function/register combination unseen in normal training traffic")
    if row["writes_prev_k"] >= 3 or row["same_ref_writes_prev_k"] >= 2:
        out.append("Repeated write behaviour in the previous window")
    if row["first_in_stream"] == 0 and row["iat"] <= stats.get("iat_normal_p05", 0):
        out.append("Short inter-arrival time (at or below normal 5th percentile)")
    if row["response_missing"] == 1:
        out.append("No response observed for this request")
    if row["value_outside_normal_range"] == 1:
        out.append("Write value outside learned normal range for this register")
    if row["value_delta"] > 0:
        out.append("Value change on a register written earlier")
    if row["response_exception"] == 1:
        out.append("Exception response returned by the device")
    return out


def _unclassifiable(X: pd.DataFrame) -> pd.DataFrame:
    """Rows with NaN/inf feature values cannot be classified safely."""
    bad = ~np.isfinite(X.to_numpy(float)).all(axis=1)
    rows = []
    for i in np.where(bad)[0]:
        field = X.columns[~np.isfinite(X.iloc[i].to_numpy(float))][0]
        rows.append((X.index[i], field))
    return pd.DataFrame(rows, columns=["row", "field"])


def featurize_packets(packets: pd.DataFrame, stats: dict):
    """Pair requests/responses and build all features (shared by every path).

    Returns (events, pairing_stats, features_with_fitted_profile).
    """
    events, _, pstats = pair_events(packets)
    if len(events) == 0:
        raise DataValidationError("No request records found; nothing to classify.")
    feats = build_stat_free_features(events)
    return events, pstats, apply_profile(feats, stats)


def detect_packets(packets: pd.DataFrame, art: dict, invalid: pd.DataFrame | None = None) -> dict:
    """Run the full detection workflow on processed packets.

    packets -> chronological order -> request/response pairing -> stat-free
    features -> saved fitted statistics -> feature-schema check -> saved
    Random Forest -> class, probabilities, confidence, observations.
    """
    t_total = time.perf_counter()
    _, pstats, full = featurize_packets(packets, art["stats"])
    names = art["features"]
    absent = [c for c in names if c not in full.columns]
    if absent:
        raise FeatureSchemaError(f"Computed features lack: {absent}")
    X = full[names]
    bad = _unclassifiable(X)
    ok_mask = ~X.index.isin(bad["row"]) if len(bad) else np.ones(len(X), dtype=bool)
    Xok = X[ok_mask]
    res = pd.DataFrame(index=full.index)
    t0 = time.perf_counter()
    if len(Xok):
        try:
            proba = art["clf"].predict_proba(Xok)
        except Exception as exc:  # model inference failure
            raise ModelLoadError(f"Model inference failed: {exc}") from exc
    else:
        proba = np.zeros((0, 2))
    infer_ms = (time.perf_counter() - t0) * 1000
    per_event_ms = infer_ms / max(len(Xok), 1)
    classes = list(art["clf"].classes_)
    p1 = pd.Series(np.nan, index=full.index)
    p0 = pd.Series(np.nan, index=full.index)
    if len(Xok):
        p1.loc[Xok.index] = proba[:, classes.index(1)]
        p0.loc[Xok.index] = proba[:, classes.index(0)]
    pred = np.where(p1 > p0, 1, 0)  # highest probability; no stored threshold
    res["event_id"] = full["event_id"]
    res["capture_id"] = full["capture_id"]
    res["timestamp"] = full["timestamp"]
    res["source_role"] = "client (request sender)"
    res["destination_role"] = "server (device)"
    res["function_code"] = full["modbus_func_code"]
    res["function_name"] = full["function_name"]
    res["register"] = full["modbus_ref_num"]
    res["operation"] = np.where(full["is_write"] == 1, "write", "read")
    res["pair_status"] = full["pair_status"]
    res["response_delay"] = np.where(full["response_delay"] >= 0, full["response_delay"], np.nan)
    actual = full["class_id"].map(CLASS_NAMES)
    has_labels = full["class_id"].notna().any() or (full["label_status"] != "no_label_available").any()
    res["actual_class"] = np.where(
        full["class_id"].notna(),
        actual,
        np.where(full["label_status"] == "no_label_available", "Unavailable", "Ambiguous/excluded"),
    )
    res["predicted_class"] = np.where(p1.isna(), "Unclassifiable", pd.Series(pred, index=full.index).map(CLASS_NAMES))
    res["normal_probability"] = p0
    res["command_injection_probability"] = p1
    res["confidence"] = np.maximum(p0, p1)
    obs_list = []
    for i, row in full.iterrows():
        obs_list.append("; ".join(observations(row, art["stats"])) if not np.isnan(p1[i]) else "")
    res["supporting_observations"] = obs_list
    res["main_observation"] = [o.split("; ")[0] if o else "None" for o in obs_list]
    res["model_version"] = MODEL_VERSION
    res["feature_schema_version"] = FEATURE_SCHEMA_VERSION
    res["inference_time_ms"] = np.where(p1.isna(), np.nan, per_event_ms)
    res["processing_status"] = np.where(p1.isna(), "unclassifiable", "complete")
    unclass = []
    for _, r in bad.iterrows():
        unclass.append(
            {
                "event_id": full.loc[r["row"], "event_id"],
                "processing_status": "unclassifiable",
                "failure_reason": "non-finite feature value",
                "affected_field": r["field"],
            }
        )
    inv = invalid if invalid is not None else pd.DataFrame(columns=["source_row", "field", "reason"])
    classified = res[res["processing_status"] == "complete"]
    summary = {
        "input_records": int(len(packets) + (inv["source_row"].nunique() if len(inv) else 0)),
        "valid_records": int(len(packets)),
        "invalid_records": int(inv["source_row"].nunique()) if len(inv) else 0,
        "request_events": int(len(res)),
        "successfully_classified": int(len(classified)),
        "normal_predictions": int((classified["predicted_class"] == "Normal").sum()),
        "command_injection_predictions": int((classified["predicted_class"] == "Command Injection").sum()),
        "failed_predictions": int(len(bad)),
        "average_confidence": float(classified["confidence"].mean()) if len(classified) else None,
        "average_inference_time_ms": float(per_event_ms) if len(classified) else None,
        "total_processing_time_ms": float((time.perf_counter() - t_total) * 1000),
        "labels_available": bool(has_labels),
        "pairing": pstats,
        "limitation": BINARY_LIMITATION,
    }
    return {
        "results": res.reset_index(drop=True),
        "features": full,
        "invalid": inv,
        "unclassifiable": pd.DataFrame(unclass),
        "summary": summary,
    }


def detect_dataframe(df_raw: pd.DataFrame, art: dict, source_name: str = "upload") -> dict:
    """Detect on a raw CSV frame (validation + preprocessing included)."""
    packets, invalid, _ = preprocess_raw(df_raw, source_name)
    out = detect_packets(packets, art, invalid)
    out["packets"] = packets
    return out


def detect_validation_records(art: dict, capture_id: str, max_events: int = 5000) -> dict:
    """Detect on a slice of a DEVELOPMENT capture (never the test partition)."""
    packets = read_parquet_safe(TRAIN_PARQUET)
    sub = packets[packets["capture_id"] == capture_id].sort_values(["timestamp", "frame_number"])
    if sub.empty:
        raise DataValidationError(f"Capture {capture_id} is not in the development partition.")
    sub = sub.iloc[: max_events * 2]  # ~requests+responses, chronological slice
    out = detect_packets(sub.reset_index(drop=True), art)
    out["packets"] = sub
    return out


def single_event_inference(features: pd.DataFrame, event_id: str, art: dict) -> dict:
    """Predict one event using its already-built contextual feature row."""
    row = features[features["event_id"] == event_id]
    if row.empty:
        raise KeyError(f"Event not found: {event_id}")
    X = row[art["features"]]
    t = time.perf_counter()
    proba = art["clf"].predict_proba(X)[0]
    ms = (time.perf_counter() - t) * 1000
    classes = list(art["clf"].classes_)
    p1, p0 = float(proba[classes.index(1)]), float(proba[classes.index(0)])
    return {
        "event_id": event_id,
        "predicted_class": CLASS_NAMES[int(p1 > p0)],
        "normal_probability": p0,
        "command_injection_probability": p1,
        "confidence": max(p0, p1),
        "inference_time_ms": ms,
        "supporting_observations": observations(row.iloc[0], art["stats"]),
    }


# ---- exports -------------------------------------------------------------


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    """Serialise a frame to CSV bytes (used by dashboard downloads/tests)."""
    return df.to_csv(index=False).encode("utf-8")


def to_standard_json(results: pd.DataFrame) -> str:
    """Preliminary progress-stage output (final integration schema pending)."""
    import json

    ok = results[results["processing_status"] == "complete"]
    recs = []
    for r in ok.itertuples():
        recs.append(
            {
                "event_id": r.event_id,
                "timestamp": float(r.timestamp),
                "component": "rp3-command-response-injection",
                "predicted_class": r.predicted_class,
                "class_probabilities": {
                    "Normal": float(r.normal_probability),
                    "Command Injection": float(r.command_injection_probability),
                },
                "confidence": float(r.confidence),
                "supporting_observations": [o for o in r.supporting_observations.split("; ") if o],
                "model_version": r.model_version,
                "feature_schema_version": r.feature_schema_version,
                "processing_time_ms": float(r.inference_time_ms),
                "processing_status": r.processing_status,
            }
        )
    return json.dumps(
        {"note": "Preliminary progress-stage detection output - final integration schema pending.", "events": recs},
        indent=2,
    )


def attach_oof(results: pd.DataFrame, model_name: str = "contextual") -> pd.DataFrame:
    """Join saved out-of-fold CV predictions onto validation-record results.

    Re-scoring development records with the final model is in-sample (the
    final model saw them). The saved out-of-fold probabilities are the
    real validation outputs, so they are shown next to them.
    """
    from src.utils.config import VALIDATION_DIR

    path = VALIDATION_DIR / "cv_validation_predictions.parquet"
    if not path.exists():
        raise ModelLoadError("cv_validation_predictions.parquet is missing; run the pipeline.")
    oof = read_parquet_safe(path)
    oof = oof[oof["model_name"] == model_name][
        ["event_id", "fold", "predicted_class", "command_injection_probability"]
    ].rename(
        columns={
            "fold": "oof_fold",
            "predicted_class": "oof_predicted_class",
            "command_injection_probability": "oof_command_injection_probability",
        }
    )
    return results.merge(oof, on="event_id", how="left")
