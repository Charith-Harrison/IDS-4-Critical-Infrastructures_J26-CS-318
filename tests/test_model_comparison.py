"""Tests for the development-only candidate-model comparison."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler

from scripts.compare_models import (
    METRIC_NAMES,
    TARGET_DERIVED_FEATURES,
    build_candidate_pipelines,
    candidate_feature_columns,
    fold_metrics,
    grouped_validation_splits,
    load_selected_candidate,
    validate_development_partition,
)
from scripts.evaluate_diagnostics import (
    _feature_class_profiles,
    _single_feature_oof,
    classification_metrics,
)
from src.models.train import load_dev_features
from src.utils.config import MANIFEST_DIR
from src.utils.io import read_json


def test_feature_matrix_excludes_labels_metadata_and_target_derived_features():
    columns = candidate_feature_columns("contextual")
    forbidden = {
        "is_attack",
        "attack_category",
        "attack_sub_type",
        "class_id",
        "label_status",
        "capture_id",
        "source_name",
    }
    assert forbidden.isdisjoint(columns)
    assert TARGET_DERIVED_FEATURES.isdisjoint(columns)
    assert columns == candidate_feature_columns("contextual")


def test_protected_test_groups_are_rejected_from_development_data():
    manifest = {"train_captures": ["train-a"], "test_captures": ["test-a"]}
    validate_development_partition(pd.DataFrame({"capture_id": ["train-a", "train-a"], "class_id": [0, 1]}), manifest)
    with pytest.raises(ValueError, match="Protected final-test captures"):
        validate_development_partition(
            pd.DataFrame({"capture_id": ["train-a", "test-a"], "class_id": [0, 1]}), manifest
        )


def test_development_records_use_only_manifest_train_groups():
    features = load_dev_features()
    features = features.loc[features["class_id"].notna()].reset_index(drop=True)
    manifest = read_json(MANIFEST_DIR / "split_manifest.json")
    validate_development_partition(features, manifest)
    assert not set(features["capture_id"]) & set(manifest["test_captures"])


def test_grouped_folds_keep_capture_groups_separate():
    frame = pd.DataFrame(
        {
            "capture_id": np.repeat(["a", "b", "c", "d", "e"], 4),
            "class_id": [0, 0, 1, 1] * 5,
        }
    )
    y, folds = grouped_validation_splits(frame, n_splits=5, random_state=42)
    assert len(folds) == 5
    groups = frame["capture_id"].to_numpy()
    validation_counts = np.zeros(len(frame), dtype=int)
    for train_idx, validation_idx in folds:
        assert set(groups[train_idx]).isdisjoint(groups[validation_idx])
        validation_counts[validation_idx] += 1
        assert set(y[validation_idx]) <= {0, 1}
    assert np.all(validation_counts == 1)


def test_evaluation_diagnostics_report_full_binary_metrics():
    metrics = classification_metrics(np.array([0, 0, 1, 1]), np.array([0, 1, 1, 0]))
    assert metrics["accuracy"] == 0.5
    assert metrics["balanced_accuracy"] == 0.5
    assert metrics["macro_f1"] == 0.5
    assert metrics["false_positives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["per_class"]["Normal"]["support"] == 2
    assert metrics["per_class"]["Command Injection"]["support"] == 2
    assert metrics["confusion_matrix"] == [[1, 1], [1, 1]]


def test_baseline_feature_diagnostics_report_class_ranges_and_grouped_single_feature_scores():
    frame = pd.DataFrame(
        {
            "capture_id": np.repeat(["a", "b", "c", "d", "e"], 4),
            "class_id": [0, 0, 1, 1] * 5,
            "only_feature": np.tile([0, 0, 1, 1], 5),
        }
    )
    profiles = _feature_class_profiles(frame, ["only_feature"])
    assert profiles[0]["normal"]["count"] == 10
    assert profiles[0]["command_injection"]["count"] == 10
    assert profiles[0]["range_overlap"] is False

    y, folds = grouped_validation_splits(frame, n_splits=5, random_state=42)
    scores = _single_feature_oof(
        frame,
        y,
        folds,
        ["only_feature"],
        {"n_estimators": 5, "class_weight": "balanced_subsample"},
    )
    assert scores[0]["feature"] == "only_feature"
    assert scores[0]["accuracy"] == 1.0


def test_candidate_preprocessing_is_inside_independent_pipelines():
    columns = ["func_code", "ref_num"]
    candidates = build_candidate_pipelines(columns, n_rows=80)
    assert "Support Vector Machine (LinearSVC)" in candidates
    for name, (pipeline, _) in candidates.items():
        step_names = [step for step, _ in pipeline.steps]
        assert "imputer" in step_names
        assert isinstance(pipeline.named_steps["imputer"], SimpleImputer)
        if name in {"Logistic Regression", "Support Vector Machine (LinearSVC)"}:
            assert isinstance(pipeline.named_steps["scaler"], StandardScaler)
        else:
            assert "scaler" not in step_names


def test_all_required_fold_metrics_are_produced_and_probabilities_are_valid():
    columns = ["func_code", "ref_num"]
    candidates = build_candidate_pipelines(columns, n_rows=80)
    X = pd.DataFrame(
        {
            "func_code": np.tile([3, 5, 6, 16], 20),
            "ref_num": np.arange(80) % 11,
        }
    )
    y = (X["func_code"].to_numpy() == 5).astype(int)
    for pipeline, _ in candidates.values():
        pipeline.fit(X.iloc[:60], y[:60])
        predictions = pipeline.predict(X.iloc[60:])
        assert set(predictions) <= {0, 1}
        classifier = pipeline.named_steps["classifier"]
        if hasattr(pipeline, "predict_proba"):
            probabilities = pipeline.predict_proba(X.iloc[60:])
            assert np.isfinite(probabilities).all()
            assert ((probabilities >= 0) & (probabilities <= 1)).all()
            scores = probabilities[:, list(classifier.classes_).index(1)]
        else:
            scores = pipeline.decision_function(X.iloc[60:])
        metrics = fold_metrics(y[60:], predictions, scores, 0.1, 0.01)
        assert set(metrics) == set(METRIC_NAMES)
        assert all(metrics[name] is not None for name in METRIC_NAMES if name != "roc_auc")


def test_saved_selected_pipeline_loads_with_matching_schema_and_binary_classes():
    artifacts = load_selected_candidate()
    pipeline = artifacts["pipeline"]
    feature_columns = artifacts["feature_columns"]
    metadata = artifacts["metadata"]
    assert feature_columns == list(pipeline.named_steps["imputer"].feature_names_in_)
    assert metadata["classes"] == {"0": "Normal", "1": "Command Injection"}
    assert metadata["scikit_learn_version"]
    assert metadata["random_seed"] == 42
    assert metadata["selection_metric"].startswith("mean_macro_f1")

    sample = pd.DataFrame(np.zeros((4, len(feature_columns))), columns=feature_columns)
    predictions = pipeline.predict(sample)
    assert set(predictions) <= {0, 1}
