# Fit the older pipeline on training rows and choose candidates using validation scores.
"""Fair RF-family comparison with training-only imputation and validation selection."""

from __future__ import annotations

import importlib.metadata
import platform
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

from src.evaluate import predict_and_score
from src.feature_engineering import build_features, feature_groups
from src.feature_profiles import fit_reference_profile
from src.label_mapper import class_names
from src.leakage_guard import validate_features
from src.utils import (
    FEATURE_VERSION,
    PREPROCESSING_VERSION,
    ROOT,
    VERSION,
    checksum,
    config_digest,
    logger,
    now,
    project_path,
    read_json,
    save_json,
)


# Verify prepared data and configuration hashes, then check that partition groups do not overlap.
def load_prepared(cfg: dict) -> tuple[pd.DataFrame, dict]:
    manifest = read_json(ROOT / "data/manifests/preprocessing.json")
    if manifest["configuration_hash"] != config_digest(cfg):
        raise ValueError("Configuration changed since preprocessing. Run prepare_data.py again.")
    for item in manifest["inputs"]:
        if checksum(project_path(item["input_file"])) != item["sha256"]:
            raise ValueError("Raw data changed since preprocessing. Prepare again.")
    path = ROOT / "data/processed/events.parquet"
    if checksum(path) != manifest["events_sha256"]:
        raise ValueError("Processed data checksum mismatch. Prepare again.")
    events = pd.read_parquet(path)
    partitions = {p: set(part.group_id) for p, part in events.groupby("partition")}
    for a, b in [("train", "validation"), ("train", "test"), ("validation", "test")]:
        if partitions[a] & partitions[b]:
            raise ValueError("Group leakage between partitions")
    return events, manifest


# Create the older training pipeline: missing-value imputer followed by Random Forest.
def make_pipeline(cfg: dict, parameters: dict) -> Pipeline:
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=cfg["training"]["n_estimators"],
                    random_state=cfg["random_seed"],
                    n_jobs=cfg["training"]["n_jobs"],
                    **parameters,
                ),
            ),
        ]
    )


# Fit candidates on training rows and select using validation macro F1, never test scores.
def fit_model(
    train: pd.DataFrame, validation: pd.DataFrame, cfg: dict, kind: str, provenance: dict | None = None
) -> dict:
    """Select using validation macro F1; test features and labels are never consumed."""
    log = logger(__name__)
    started = time.perf_counter()
    x_train, x_val = build_features(train, cfg, kind), build_features(validation, cfg, kind)
    validate_features(x_train, cfg, kind)
    if set(train.target) != set(class_names(cfg)):
        raise ValueError("Training partition lacks configured classes")
    trials, best, best_score = [], None, -np.inf
    for parameters in cfg["training"]["candidates"]:
        log.info("Training %s RF: %s", kind, parameters)
        pipeline = make_pipeline(cfg, parameters)
        trial_start = time.perf_counter()
        # Only training features and targets fit the imputer and classifier.
        pipeline.fit(x_train, train.target)
        metrics, _, _ = predict_and_score(pipeline, x_val, validation.target)
        trials.append({"parameters": parameters, "validation": metrics, "seconds": time.perf_counter() - trial_start})
        if metrics["macro_f1"] > best_score:
            best_score, best = metrics["macro_f1"], pipeline
            selected = parameters
            best_metrics = metrics
    if best is None:
        raise ValueError("At least one RF candidate is required")
    # Keep the chosen train-only model: validation performance remains interpretable.
    metadata = {
        "model_type": "RandomForestClassifier",
        "model_kind": kind,
        "model_mode": cfg["model_mode"],
        "classes": list(best.classes_),
        "class_mapping": {str(i): name for i, name in enumerate(best.classes_)},
        "training_date": now(),
        "model_version": VERSION,
        "feature_version": FEATURE_VERSION,
        "preprocessing_version": PREPROCESSING_VERSION,
        "configuration": cfg,
        "configuration_hash": config_digest(cfg),
        "hyperparameters": {**selected, "n_estimators": cfg["training"]["n_estimators"]},
        "random_seed": cfg["random_seed"],
        "training_seconds": time.perf_counter() - started,
        "feature_count": len(x_train.columns),
        "feature_names": list(x_train),
        "feature_groups": feature_groups(cfg),
        "class_distribution": train.target.value_counts().to_dict(),
        "validation_metrics": best_metrics,
        "selection": "highest validation macro F1; first candidate wins ties; no test-based selection",
        "trials": trials,
        "dataset_source": provenance or {},
        "python_version": platform.python_version(),
        "dependencies": {
            p: importlib.metadata.version(p)
            for p in ["numpy", "pandas", "scikit-learn", "joblib", "pyarrow", "streamlit", "PyYAML"]
        },
        "limitations": [
            "Preliminary internal evaluation",
            "Probabilities are uncalibrated RF vote fractions",
            "No independent final three-class data or external validation",
        ],
    }
    return {"pipeline": best, "metadata": metadata, "reference_profile": fit_reference_profile(x_train)}


# Save the fitted pipeline together with its feature names, metadata, and checksum.
def save_model(artifact: dict, directory) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, directory / "model.joblib")
    metadata = {**artifact["metadata"], "artifact_sha256": checksum(directory / "model.joblib")}
    save_json(directory / "metadata.json", metadata)
    save_json(directory / "feature_names.json", metadata["feature_names"])
    save_json(directory / "label_mapping.json", metadata["class_mapping"])
    importance = artifact["pipeline"].named_steps["classifier"].feature_importances_
    pd.DataFrame({"feature": metadata["feature_names"], "importance": importance}).sort_values(
        "importance", ascending=False
    ).to_csv(directory / "feature_importance.csv", index=False)


# Train the older baseline and contextual models only when the holdout guard allows it.
def train_models(cfg: dict) -> dict:
    if (ROOT / "results/metrics/comparison.json").exists():
        raise ValueError(
            "Holdout evaluation already exists. Archive the experiment before retraining; avoid tuning on evaluated test data."
        )
    events, manifest = load_prepared(cfg)
    train = events[events.partition.eq("train")].reset_index(drop=True)
    validation = events[events.partition.eq("validation")].reset_index(drop=True)
    summary = {}
    for kind in ["baseline", "contextual"]:
        artifact = fit_model(train, validation, cfg, kind, manifest)
        save_model(artifact, ROOT / "models" / kind)
        summary[kind] = artifact["metadata"]["validation_metrics"]
    save_json(ROOT / "results/metrics/validation.json", summary)
    return summary
