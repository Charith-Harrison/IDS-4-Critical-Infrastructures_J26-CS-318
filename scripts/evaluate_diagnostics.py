"""Run focused leakage, function-code, importance, and ablation diagnostics."""

from __future__ import annotations

import json
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

from scripts.compare_models import grouped_validation_splits, validate_development_partition
from src.features.builder import FEATURE_GROUPS
from src.features.profile import apply_profile, fit_profile
from src.models.train import load_dev_features
from src.utils.config import (
    ATTACK_CSV,
    CLASS_NAMES,
    FORBIDDEN_FEATURE_COLUMNS,
    MANIFEST_DIR,
    MODELS_DIR,
    RANDOM_STATE,
    RESULTS_DIR,
    TEST_PARQUET,
    TRAIN_PARQUET,
)
from src.utils.io import read_json, write_json

OUTPUT_DIR = RESULTS_DIR / "evaluation_diagnostics"
LEAKAGE_PRONE_COLUMNS = set(FORBIDDEN_FEATURE_COLUMNS) | {
    "source_name",
    "filename",
    "file_name",
    "capture_filename",
    "scenario_id",
    "row_index",
    "source_row",
    "post_event_annotation",
    "attack_sub_type",
    "attack_category",
    "is_attack",
}
ABLATION_GROUPS = {
    "Full contextual": (),
    "Without sequence": ("SEQUENCE",),
    "Without request-response/pair": ("PAIR",),
    "Without access/register context": ("ACCESS",),
    "Without value transitions": ("VALUE",),
}
LIMITED_FC5_NORMAL_WARNING = (
    "FC5 challenge set contains limited normal FC5 samples; results should be interpreted cautiously."
)


def classification_metrics(actual: np.ndarray, predicted: np.ndarray) -> dict[str, Any]:
    """Return complete binary-class metrics using 0=Normal and 1=Command Injection."""
    matrix = confusion_matrix(actual, predicted, labels=[0, 1])
    tn, fp, fn, tp = matrix.ravel()
    precision, recall, f1, support = precision_recall_fscore_support(actual, predicted, labels=[0, 1], zero_division=0)
    return {
        "records": int(len(actual)),
        "accuracy": float(accuracy_score(actual, predicted)),
        "balanced_accuracy": float(recall.mean()) if len(np.unique(actual)) == 2 else None,
        "precision": float(precision[1]),
        "recall": float(recall[1]),
        "f1": float(f1[1]),
        "macro_f1": float(f1.mean()),
        "per_class": {
            CLASS_NAMES[class_id]: {
                "precision": float(precision[class_id]),
                "recall": float(recall[class_id]),
                "f1": float(f1[class_id]),
                "support": int(support[class_id]),
            }
            for class_id in (0, 1)
        },
        "confusion_matrix": matrix.tolist(),
        "false_positives": int(fp),
        "false_negatives": int(fn),
    }


def _oof_class_ids(frame: pd.DataFrame, column: str) -> np.ndarray:
    mapping = {name: class_id for class_id, name in CLASS_NAMES.items()}
    unknown = set(frame[column].dropna()) - set(mapping)
    if unknown:
        raise ValueError(f"Unsupported class labels in {column}: {sorted(unknown)}")
    return frame[column].map(mapping).to_numpy(dtype=int)


def _validate_model_inputs() -> dict[str, list[str]]:
    schemas: dict[str, list[str]] = {}
    for model, folder in (("baseline", "baseline"), ("contextual", "contextual")):
        feature_names = read_json(MODELS_DIR / folder / "feature_names.json")
        leaked = sorted(set(feature_names) & LEAKAGE_PRONE_COLUMNS)
        if leaked:
            raise ValueError(f"{model} model directly uses leakage-prone predictors: {leaked}")
        schemas[model] = feature_names
    return schemas


def _capture_checks(
    features: pd.DataFrame,
    manifest: dict[str, Any],
    folds: list[tuple[np.ndarray, np.ndarray]],
) -> dict[str, Any]:
    groups = features["capture_id"].astype(str).to_numpy()
    cv_checks = []
    for fold_number, (train_idx, validation_idx) in enumerate(folds, start=1):
        overlap = sorted(set(groups[train_idx]) & set(groups[validation_idx]))
        if overlap:
            raise RuntimeError(f"Capture leakage in fold {fold_number}: {overlap}")
        cv_checks.append({"fold": fold_number, "passed": True, "overlap": overlap})
    train_captures = set(manifest.get("train_captures", []))
    test_captures = set(manifest.get("test_captures", []))
    if train_captures & test_captures:
        raise RuntimeError("Capture leakage between manifest development and final-test captures.")
    if set(groups) - train_captures:
        raise RuntimeError("Development records contain captures absent from the train manifest.")
    return {
        "status": "PASSED",
        "manifest_train_test_capture_overlap": [],
        "cv_folds": cv_checks,
        "message": "Capture leakage check: PASSED",
    }


def _oof_by_model(predictions: pd.DataFrame, features: pd.DataFrame) -> dict[str, pd.DataFrame]:
    required = {
        "event_id",
        "capture_id",
        "fold",
        "actual_class",
        "predicted_class",
        "model_name",
    }
    if required - set(predictions.columns):
        raise ValueError(f"Saved OOF predictions are missing columns: {sorted(required - set(predictions.columns))}")
    joined = predictions.merge(
        features[["event_id", "capture_id", "func_code"]],
        on=["event_id", "capture_id"],
        how="left",
        validate="many_to_one",
    )
    if joined["func_code"].isna().any():
        raise ValueError("Some saved OOF predictions could not be matched to their event features.")
    event_order = {event_id: index for index, event_id in enumerate(features["event_id"])}
    joined["_event_order"] = joined["event_id"].map(event_order)
    if joined["_event_order"].isna().any():
        raise ValueError("Some saved OOF predictions refer to events outside the development feature set.")
    grouped = {}
    for model_name, frame in joined.groupby("model_name", sort=True):
        frame = frame.sort_values("_event_order")
        actual = _oof_class_ids(frame, "actual_class")
        predicted = _oof_class_ids(frame, "predicted_class")
        if len(actual) != len(features) or frame["event_id"].nunique() != len(features):
            raise ValueError(f"Saved OOF predictions for {model_name} do not cover each event exactly once.")
        if not np.array_equal(actual, features["class_id"].astype(int).to_numpy()):
            raise ValueError(f"Saved OOF labels for {model_name} do not match development feature labels.")
        grouped[str(model_name)] = frame.assign(_actual=actual, _predicted=predicted)
    return grouped


def _function_code_diagnostics(oof: dict[str, pd.DataFrame]) -> tuple[pd.DataFrame, pd.DataFrame]:
    reference = next(iter(oof.values()))
    function_counts = (
        reference.groupby(["func_code", "_actual"])
        .size()
        .unstack(fill_value=0)
        .reindex(columns=[0, 1], fill_value=0)
        .rename(columns={0: "normal_count", 1: "command_injection_count"})
    )
    function_counts["total_count"] = function_counts.sum(axis=1)
    function_counts["attack_rate"] = function_counts["command_injection_count"] / function_counts["total_count"]
    function_counts = function_counts.reset_index().rename(columns={"func_code": "function_code"})

    performance_rows = []
    for model_name, frame in oof.items():
        for function_code, subset in frame.groupby("func_code", sort=True):
            row = {
                "model": model_name,
                "function_code": int(function_code),
                **classification_metrics(subset["_actual"].to_numpy(), subset["_predicted"].to_numpy()),
            }
            row["confusion_matrix"] = json.dumps(row["confusion_matrix"])
            row["per_class"] = json.dumps(row["per_class"])
            performance_rows.append(row)
    return function_counts, pd.DataFrame(performance_rows)


def _feature_importance(schemas: dict[str, list[str]], features: pd.DataFrame) -> pd.DataFrame:
    stats = fit_profile(features)
    profiled = apply_profile(features, stats)
    rows = []
    for model_name, folder, filename in (
        ("baseline", "baseline", "baseline_random_forest.joblib"),
        ("contextual", "contextual", "contextual_rf.joblib"),
    ):
        model = joblib.load(MODELS_DIR / folder / filename)
        names = schemas[model_name]
        if int(model.n_features_in_) != len(names) or len(model.feature_importances_) != len(names):
            raise ValueError(f"Saved {model_name} feature names do not match its Random Forest schema.")
        for rank, (name, importance) in enumerate(
            sorted(zip(names, model.feature_importances_), key=lambda item: item[1], reverse=True), start=1
        ):
            rows.append(
                {
                    "model": model_name,
                    "rank": rank,
                    "feature": name,
                    "importance": float(importance),
                    "top_15": rank <= 15,
                    "training_rows": int(len(profiled)),
                }
            )
    return pd.DataFrame(rows)


def _feature_class_profiles(features: pd.DataFrame, feature_columns: list[str]) -> list[dict[str, Any]]:
    """Summarize numeric feature ranges and value overlap by current class."""
    rows = []
    for feature in feature_columns:
        values = pd.to_numeric(features[feature], errors="coerce")
        class_values = {class_id: values[features["class_id"].astype(int) == class_id].dropna() for class_id in (0, 1)}
        normal = class_values[0]
        attack = class_values[1]
        if normal.empty or attack.empty:
            raise ValueError(f"Cannot compare {feature}: one class has no numeric values.")
        normal_min, normal_max = float(normal.min()), float(normal.max())
        attack_min, attack_max = float(attack.min()), float(attack.max())
        overlap_low = max(normal_min, attack_min)
        overlap_high = min(normal_max, attack_max)
        overlap = max(0.0, overlap_high - overlap_low)
        union = max(normal_max, attack_max) - min(normal_min, attack_min)
        shared_values = sorted(set(normal.unique()) & set(attack.unique()))
        normal_counts = normal.value_counts().sort_values(ascending=False).head(20)
        attack_counts = attack.value_counts().sort_values(ascending=False).head(20)
        rows.append(
            {
                "feature": feature,
                "normal": {
                    "count": int(len(normal)),
                    "min": normal_min,
                    "p05": float(normal.quantile(0.05)),
                    "p25": float(normal.quantile(0.25)),
                    "median": float(normal.median()),
                    "p75": float(normal.quantile(0.75)),
                    "p95": float(normal.quantile(0.95)),
                    "max": normal_max,
                    "unique_values": int(normal.nunique()),
                },
                "command_injection": {
                    "count": int(len(attack)),
                    "min": attack_min,
                    "p05": float(attack.quantile(0.05)),
                    "p25": float(attack.quantile(0.25)),
                    "median": float(attack.median()),
                    "p75": float(attack.quantile(0.75)),
                    "p95": float(attack.quantile(0.95)),
                    "max": attack_max,
                    "unique_values": int(attack.nunique()),
                },
                "normal_top_values": [
                    {"value": float(value), "count": int(count)} for value, count in normal_counts.items()
                ],
                "command_injection_top_values": [
                    {"value": float(value), "count": int(count)} for value, count in attack_counts.items()
                ],
                "range_overlap": bool(overlap_low <= overlap_high),
                "range_overlap_width": float(overlap),
                "normalized_range_overlap": float(overlap / union) if union else float(overlap_low == overlap_high),
                "shared_exact_values_count": len(shared_values),
                "shared_exact_values_preview": [float(value) for value in shared_values[:20]],
            }
        )
    return rows


def _single_feature_oof(
    features: pd.DataFrame,
    y: np.ndarray,
    folds: list[tuple[np.ndarray, np.ndarray]],
    feature_columns: list[str],
    params: dict[str, Any],
) -> list[dict[str, Any]]:
    """Train one diagnostic Random Forest per baseline feature on grouped folds."""
    rows = []
    for feature in feature_columns:
        predicted = np.full(len(features), -1, dtype=int)
        for train_idx, validation_idx in folds:
            model = RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1, **params)
            model.fit(features.iloc[train_idx][[feature]], y[train_idx])
            attack_index = list(model.classes_).index(1)
            predicted[validation_idx] = (
                model.predict_proba(features.iloc[validation_idx][[feature]])[:, attack_index] >= 0.5
            ).astype(int)
        if np.any(predicted < 0):
            raise RuntimeError(f"Single-feature diagnostic did not predict every OOF row for {feature}.")
        metrics = classification_metrics(y, predicted)
        rows.append({"feature": feature, **metrics})
    return rows


def _predict_saved_model(
    model_name: str,
    features: pd.DataFrame,
    schemas: dict[str, list[str]],
    profile_stats: dict[str, Any] | None,
) -> np.ndarray:
    folder, filename = (
        ("baseline", "baseline_random_forest.joblib")
        if model_name == "baseline"
        else ("contextual", "contextual_rf.joblib")
    )
    model = joblib.load(MODELS_DIR / folder / filename)
    transformed = apply_profile(features, profile_stats) if profile_stats is not None else features
    probabilities = model.predict_proba(transformed[schemas[model_name]])
    attack_index = list(model.classes_).index(1)
    return (probabilities[:, attack_index] >= 0.5).astype(int)


def _final_test_evaluation(
    train_features: pd.DataFrame,
    manifest: dict[str, Any],
    schemas: dict[str, list[str]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Consume the reserved capture-grouped split once, after user authorization."""
    from src.data.pairing import pair_events
    from src.features.builder import build_stat_free_features

    train_captures = set(manifest["train_captures"])
    test_captures = set(manifest["test_captures"])
    if train_captures & test_captures:
        raise RuntimeError("Capture leakage between manifest train and test groups.")

    # This direct read is intentionally limited to the one-time final evaluation
    # requested by the user; the normal pipeline continues to use its test-path guard.
    test_packets = pd.read_parquet(TEST_PARQUET)
    observed_test_captures = set(test_packets["capture_id"].astype(str))
    if observed_test_captures != test_captures:
        raise RuntimeError(
            "Final test packets do not match the manifest test captures: "
            f"expected={sorted(test_captures)}, observed={sorted(observed_test_captures)}"
        )
    train_packet_captures = set(pd.read_parquet(TRAIN_PARQUET, columns=["capture_id"])["capture_id"].astype(str))
    if train_packet_captures & observed_test_captures:
        raise RuntimeError(
            "Capture leakage detected between saved train and final test packets: "
            f"{sorted(train_packet_captures & observed_test_captures)}"
        )

    test_events, _, pairing_stats = pair_events(test_packets)
    test_events["event_id"] = test_events["capture_id"] + ":" + test_events["source_row"].astype(str)
    test_features = build_stat_free_features(test_events)
    test_features = test_features.loc[test_features["class_id"].notna()].reset_index(drop=True)
    if test_features.empty:
        raise ValueError("The final held-out partition contains no labelled events.")
    if set(test_features["capture_id"].astype(str)) != test_captures:
        raise RuntimeError("Paired test event captures do not match manifest test captures.")
    if set(train_features["capture_id"].astype(str)) & set(test_features["capture_id"].astype(str)):
        raise RuntimeError("Capture leakage detected after test event reconstruction.")

    contextual_stats = read_json(MODELS_DIR / "contextual" / "feature_stats.json")
    if not isinstance(contextual_stats.get("normal_access_counts"), dict):
        raise ValueError("Saved contextual profile statistics are missing or invalid.")

    training_results = {}
    test_results = {}
    fc5_results = {}
    train_y = train_features["class_id"].astype(int).to_numpy()
    test_y = test_features["class_id"].astype(int).to_numpy()
    for model_name in ("baseline", "contextual"):
        stats = contextual_stats if model_name == "contextual" else None
        train_pred = _predict_saved_model(model_name, train_features, schemas, stats)
        test_pred = _predict_saved_model(model_name, test_features, schemas, stats)
        training_results[model_name] = classification_metrics(train_y, train_pred)
        test_results[model_name] = classification_metrics(test_y, test_pred)
        training_results[model_name]["evaluation"] = "in-sample predictions on the development training partition"
        test_results[model_name]["evaluation"] = "one-time capture-grouped final held-out test evaluation"

        fc5_mask = test_features["func_code"].to_numpy() == 5
        fc5_results[model_name] = classification_metrics(test_y[fc5_mask], test_pred[fc5_mask])
        fc5_results[model_name]["warning"] = (
            LIMITED_FC5_NORMAL_WARNING if fc5_results[model_name]["per_class"]["Normal"]["support"] < 100 else None
        )

    separation = {
        "status": "PASSED",
        "train_captures": sorted(train_packet_captures),
        "test_captures": sorted(observed_test_captures),
        "overlap": [],
        "message": "Capture leakage check: PASSED",
    }
    return (
        training_results,
        test_results,
        {
            "capture_separation": separation,
            "pairing_statistics": pairing_stats,
            "fc5": fc5_results,
            "test_features": test_features,
        },
    )


def _ablation_diagnostics(
    features: pd.DataFrame,
    y: np.ndarray,
    folds: list[tuple[np.ndarray, np.ndarray]],
    params: dict[str, Any],
    full_oof: pd.DataFrame,
) -> pd.DataFrame:
    # The full model reuses its saved OOF predictions; only ablations are refit.
    feature_columns = read_json(MODELS_DIR / "contextual" / "feature_names.json")
    rows = []
    for experiment, excluded_groups in ABLATION_GROUPS.items():
        if not excluded_groups:
            predicted = full_oof["_predicted"].to_numpy()
        else:
            excluded = {feature for group in excluded_groups for feature in FEATURE_GROUPS[group]}
            columns = [column for column in feature_columns if column not in excluded]
            if not columns:
                raise ValueError(f"Ablation {experiment} removed every contextual feature.")
            predicted = np.full(len(features), -1, dtype=int)
            for train_idx, validation_idx in folds:
                fold_stats = fit_profile(features.iloc[train_idx])
                train_matrix = apply_profile(features.iloc[train_idx], fold_stats)[columns]
                validation_matrix = apply_profile(features.iloc[validation_idx], fold_stats)[columns]
                model = RandomForestClassifier(random_state=RANDOM_STATE, n_jobs=-1, **params)
                model.fit(train_matrix, y[train_idx])
                attack_index = list(model.classes_).index(1)
                predicted[validation_idx] = (model.predict_proba(validation_matrix)[:, attack_index] >= 0.5).astype(int)
            if np.any(predicted < 0):
                raise RuntimeError(f"Ablation {experiment} left records without out-of-fold predictions.")
        metrics = classification_metrics(y, predicted)
        rows.append(
            {
                "experiment": experiment,
                "excluded_groups": ",".join(excluded_groups),
                **metrics,
                "confusion_matrix": json.dumps(metrics["confusion_matrix"]),
                "per_class": json.dumps(metrics["per_class"]),
            }
        )
    return pd.DataFrame(rows)


def _label_diagnostics() -> dict[str, Any]:
    raw = pd.read_csv(ATTACK_CSV, usecols=["attack_sub_type", "is_attack"])
    subtype_counts = raw.groupby(["attack_sub_type", "is_attack"], dropna=False).size().reset_index(name="records")
    return {
        "observed_attack_dataset_labels": subtype_counts.to_dict(orient="records"),
        "supported_classes": {"0": "Normal", "1": "Command Injection"},
        "response_injection_ground_truth_available": False,
        "limitation": (
            "The supplied data does not provide independently verified, separate Command Injection and Response "
            "Injection labels. Attack-labelled response packets are not evidence of forged responses. A defensible "
            "mapping or additional labelled data is required before claiming three-class detection."
        ),
    }


def run_evaluation_diagnostics() -> dict[str, Any]:
    """Create diagnostics and run the authorized one-time held-out evaluation."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    schemas = _validate_model_inputs()
    manifest = read_json(MANIFEST_DIR / "split_manifest.json")
    features = load_dev_features()
    features = features.loc[features["class_id"].notna()].reset_index(drop=True)
    validate_development_partition(features, manifest)
    y, folds = grouped_validation_splits(features)
    leakage = _capture_checks(features, manifest, folds)

    from src.utils.config import VALIDATION_DIR, read_parquet_safe

    predictions = read_parquet_safe(VALIDATION_DIR / "cv_validation_predictions.parquet")
    oof_models = _oof_by_model(predictions, features)
    missing_models = {"baseline", "contextual"} - set(oof_models)
    if missing_models:
        raise ValueError(f"Saved OOF predictions are missing model outputs: {sorted(missing_models)}")

    main_metrics = {
        model: classification_metrics(frame["_actual"].to_numpy(), frame["_predicted"].to_numpy())
        for model, frame in oof_models.items()
    }
    main_metrics["baseline"]["evaluation"] = "capture-grouped out-of-fold development predictions"
    main_metrics["contextual"]["evaluation"] = "capture-grouped out-of-fold development predictions"
    training_metrics, test_metrics, final_test_details = _final_test_evaluation(features, manifest, schemas)

    function_counts, function_performance = _function_code_diagnostics(oof_models)
    fc5 = {}
    for model, frame in oof_models.items():
        subset = frame[frame["func_code"] == 5]
        fc5[model] = classification_metrics(subset["_actual"].to_numpy(), subset["_predicted"].to_numpy())
        fc5[model]["warning"] = (
            LIMITED_FC5_NORMAL_WARNING if fc5[model]["per_class"]["Normal"]["support"] < 100 else None
        )

    importance = _feature_importance(schemas, features)
    metrics_file = read_json(RESULTS_DIR / "validation" / "cv_metrics.json")
    contextual_params = metrics_file["selected"]["contextual"]["params"]
    baseline_params = read_json(MODELS_DIR / "baseline" / "hyperparameters.json")
    single_feature_results = _single_feature_oof(features, y, folds, schemas["baseline"], baseline_params)
    train_feature_profiles = _feature_class_profiles(features, schemas["baseline"])
    heldout_features = final_test_details.pop("test_features")
    test_feature_profiles = _feature_class_profiles(heldout_features, schemas["baseline"])
    fc5_test_features = heldout_features[heldout_features["func_code"] == 5]
    test_fc5_feature_profiles = _feature_class_profiles(fc5_test_features, schemas["baseline"])
    ablations = _ablation_diagnostics(
        features,
        y,
        folds,
        contextual_params,
        oof_models["contextual"],
    )
    result = {
        "evaluation_partition": "development grouped OOF plus one-time capture-grouped held-out test",
        "final_test_partition_used": True,
        "final_test_partition_usage_note": (
            "The reserved capture-grouped final test split was read once for this user-authorized final evaluation. "
            "Do not use it for model selection, feature changes, threshold tuning, or repeated evaluation."
        ),
        "leakage_prone_predictors": {
            "direct_predictors_found": [],
            "direct_predictors_excluded": sorted(LEAKAGE_PRONE_COLUMNS),
            "model_feature_schemas": schemas,
        },
        "capture_leakage_check": leakage,
        "main_capture_grouped_evaluation": main_metrics,
        "in_sample_training_evaluation": training_metrics,
        "final_test_evaluation": test_metrics,
        "final_test_capture_separation": final_test_details["capture_separation"],
        "final_test_pairing_statistics": final_test_details["pairing_statistics"],
        "fc5_challenge_evaluation": fc5,
        "final_test_fc5_challenge_evaluation": final_test_details["fc5"],
        "function_code_label_distribution": function_counts.to_dict(orient="records"),
        "feature_importance_top_15": {
            model: importance[(importance["model"] == model) & importance["top_15"]].to_dict(orient="records")
            for model in ("baseline", "contextual")
        },
        "baseline_feature_names": schemas["baseline"],
        "baseline_feature_class_profiles_development": train_feature_profiles,
        "baseline_feature_class_profiles_heldout_test": test_feature_profiles,
        "baseline_feature_class_profiles_fc5_heldout_test": test_fc5_feature_profiles,
        "baseline_single_feature_grouped_oof": single_feature_results,
        "label_rule_circularity_warning": {
            "features": [
                name
                for name in schemas["contextual"]
                if name in {"access_combo_unseen", "access_combo_normal_count_log", "access_write_unseen"}
            ],
            "interpretation": (
                "These engineered access-profile features are not raw label or identifier columns, but are closely "
                "related to the function/register novelty rule used to reconstruct Command Injection labels. "
                "Treat performance as partly circular; the access-group ablation is diagnostic, not proof of "
                "independent attack generalization."
            ),
        },
        "ablation_results": ablations.drop(columns=["confusion_matrix", "per_class"]).to_dict(orient="records"),
        "label_limitations": _label_diagnostics(),
    }

    function_counts.to_csv(OUTPUT_DIR / "function_code_distribution.csv", index=False)
    function_performance.to_csv(OUTPUT_DIR / "performance_by_function_code.csv", index=False)
    importance.to_csv(OUTPUT_DIR / "feature_importance.csv", index=False)
    pd.DataFrame(single_feature_results).drop(columns=["per_class", "confusion_matrix"]).to_csv(
        OUTPUT_DIR / "baseline_single_feature_oof.csv", index=False
    )
    profile_rows = []
    for partition, profiles in (
        ("development", train_feature_profiles),
        ("heldout_test", test_feature_profiles),
        ("heldout_test_fc5", test_fc5_feature_profiles),
    ):
        for profile in profiles:
            profile_rows.append(
                {
                    "partition": partition,
                    "feature": profile["feature"],
                    "normal_count": profile["normal"]["count"],
                    "normal_min": profile["normal"]["min"],
                    "normal_median": profile["normal"]["median"],
                    "normal_p95": profile["normal"]["p95"],
                    "normal_max": profile["normal"]["max"],
                    "attack_count": profile["command_injection"]["count"],
                    "attack_min": profile["command_injection"]["min"],
                    "attack_median": profile["command_injection"]["median"],
                    "attack_p95": profile["command_injection"]["p95"],
                    "attack_max": profile["command_injection"]["max"],
                    "normal_unique_values": profile["normal"]["unique_values"],
                    "attack_unique_values": profile["command_injection"]["unique_values"],
                    "normal_top_values": json.dumps(profile["normal_top_values"]),
                    "attack_top_values": json.dumps(profile["command_injection_top_values"]),
                    "range_overlap": profile["range_overlap"],
                    "normalized_range_overlap": profile["normalized_range_overlap"],
                    "shared_exact_values_count": profile["shared_exact_values_count"],
                    "shared_exact_values_preview": json.dumps(profile["shared_exact_values_preview"]),
                }
            )
    pd.DataFrame(profile_rows).to_csv(OUTPUT_DIR / "baseline_feature_class_profiles.csv", index=False)
    ablations.to_csv(OUTPUT_DIR / "ablation_results.csv", index=False)
    write_json(result, OUTPUT_DIR / "evaluation_summary.json")

    print("MAIN CAPTURE-GROUPED EVALUATION")
    for model in ("baseline", "contextual"):
        summary = main_metrics[model]
        print(
            f"{model.title()}: Accuracy={summary['accuracy']:.6f}, Macro F1={summary['macro_f1']:.6f}, "
            f"FP={summary['false_positives']}, FN={summary['false_negatives']}"
        )
    print("FC5 CHALLENGE EVALUATION")
    for model in ("baseline", "contextual"):
        summary = fc5[model]
        print(
            f"{model.title()}: Accuracy={summary['accuracy']:.6f}, Macro F1={summary['macro_f1']:.6f}, "
            f"FP={summary['false_positives']}, FN={summary['false_negatives']}"
        )
        if summary["warning"]:
            print(summary["warning"])
    print("FINAL HELD-OUT TEST EVALUATION (one-time; do not tune on these results)")
    for model in ("baseline", "contextual"):
        summary = test_metrics[model]
        print(
            f"{model.title()}: Accuracy={summary['accuracy']:.6f}, "
            f"Balanced Accuracy={summary['balanced_accuracy']}, Macro F1={summary['macro_f1']:.6f}, "
            f"FP={summary['false_positives']}, FN={summary['false_negatives']}"
        )
    print("FINAL TEST FC5 CHALLENGE")
    for model in ("baseline", "contextual"):
        summary = final_test_details["fc5"][model]
        print(
            f"{model.title()}: samples={summary['records']}, "
            f"normal={summary['per_class']['Normal']['support']}, "
            f"attack={summary['per_class']['Command Injection']['support']}, "
            f"accuracy={summary['accuracy']:.6f}, macro F1={summary['macro_f1']:.6f}, "
            f"FP={summary['false_positives']}, FN={summary['false_negatives']}"
        )
        if summary["warning"]:
            print(summary["warning"])
    print(leakage["message"])
    print("BASELINE FEATURES")
    print(", ".join(schemas["baseline"]))
    print("BASELINE SINGLE-FEATURE GROUPED OOF")
    for row in single_feature_results:
        print(
            f"{row['feature']}: accuracy={row['accuracy']:.6f}, "
            f"balanced_accuracy={row['balanced_accuracy']}, macro_f1={row['macro_f1']:.6f}"
        )
    print(f"Evaluation diagnostics saved to: {OUTPUT_DIR}")
    return result


def main() -> int:
    run_evaluation_diagnostics()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
