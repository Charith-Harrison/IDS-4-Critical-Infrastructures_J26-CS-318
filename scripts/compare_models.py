"""Compare candidate classifiers using capture-grouped development-only CV.

Experiment A compares algorithms on a shared, target-independent contextual
feature set. Experiment B separately compares isolated-event and contextual
Random Forests on the same folds. The protected final-test partition is never
opened by this module.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from matplotlib import pyplot as plt
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import LinearSVC
from sklearn.tree import DecisionTreeClassifier

from src.features.builder import CONTEXT_GROUPS, ISOLATED_GROUPS, group_features
from src.models.train import load_dev_features
from src.utils.config import (
    CLASS_NAMES,
    FORBIDDEN_FEATURE_COLUMNS,
    MANIFEST_DIR,
    MODELS_DIR,
    RANDOM_STATE,
    ROOT,
)
from src.utils.io import read_json, write_json

REPORTS_DIR = ROOT / "reports"
N_FOLDS = 5
SVM_MAX_ROWS = 200_000
SIMILAR_MACRO_F1_TOLERANCE = 0.005
OPERATIONAL_LATENCY_LIMIT_MS = 100.0

LABEL_AND_METADATA_COLUMNS = set(FORBIDDEN_FEATURE_COLUMNS) | {
    "class_id",
    "label_status",
    "source_name",
    "filename",
    "file_name",
    "scenario_id",
    "post_event_annotation",
}
TARGET_DERIVED_FEATURES = {
    # The current label rule is based on novel function/register writes.
    # These profile features are computed from labelled normal rows and can
    # therefore encode that rule rather than independent event behaviour.
    "access_combo_unseen",
    "access_combo_normal_count_log",
    "access_write_unseen",
    "value_outside_normal_range",
}

METRIC_NAMES = (
    "accuracy",
    "balanced_accuracy",
    "macro_precision",
    "macro_recall",
    "macro_f1",
    "command_injection_precision",
    "command_injection_recall",
    "command_injection_f1",
    "false_positive_rate",
    "roc_auc",
    "training_time_seconds",
    "prediction_time_seconds",
    "mean_inference_time_per_event_ms",
)

MODEL_COMPLEXITY_ORDER = {
    "Decision Tree": 0,
    "Logistic Regression": 1,
    "Random Forest": 2,
    "Extra Trees": 3,
    "HistGradientBoosting": 4,
    "Support Vector Machine (LinearSVC)": 5,
}


def candidate_feature_columns(experiment: str = "contextual") -> list[str]:
    """Return an ordered safe feature schema for the requested experiment."""
    if experiment == "contextual":
        groups = CONTEXT_GROUPS
    elif experiment == "isolated":
        groups = ISOLATED_GROUPS
    else:
        raise ValueError(f"Unknown feature experiment: {experiment}")

    columns = [
        column
        for column in group_features(groups)
        if column not in TARGET_DERIVED_FEATURES and column not in LABEL_AND_METADATA_COLUMNS
    ]
    forbidden = set(columns) & LABEL_AND_METADATA_COLUMNS
    if forbidden:
        raise ValueError(f"Label or metadata columns cannot be model inputs: {sorted(forbidden)}")
    return columns


def validate_development_partition(F: pd.DataFrame, split_manifest: dict[str, Any]) -> None:
    """Require labelled records to come only from manifest-listed train captures."""
    required = {"capture_id", "class_id"}
    missing = required - set(F.columns)
    if missing:
        raise ValueError(f"Development features are missing required fields: {sorted(missing)}")
    if F.empty:
        raise ValueError("The development partition contains no labelled events.")
    if F["capture_id"].isna().any():
        raise ValueError("Development records contain an empty capture_id.")
    if F["class_id"].isna().any() or set(F["class_id"].astype(int).unique()) != {0, 1}:
        raise ValueError("The labelled development partition must contain exactly classes 0 and 1.")

    train_captures = set(split_manifest.get("train_captures", []))
    test_captures = set(split_manifest.get("test_captures", []))
    observed_captures = set(F["capture_id"].astype(str))
    if not train_captures:
        raise ValueError("The split manifest has no development capture identifiers.")
    if observed_captures - train_captures:
        raise ValueError(
            "Development feature records include captures not listed in the development manifest: "
            f"{sorted(observed_captures - train_captures)}"
        )
    overlap = observed_captures & test_captures
    if overlap:
        raise ValueError(f"Protected final-test captures entered the development data: {sorted(overlap)}")


def grouped_validation_splits(
    F: pd.DataFrame, n_splits: int = N_FOLDS, random_state: int = RANDOM_STATE
) -> tuple[np.ndarray, list[tuple[np.ndarray, np.ndarray]]]:
    """Create deterministic stratified folds that keep each capture whole."""
    y = F["class_id"].astype(int).to_numpy()
    groups = F["capture_id"].astype(str).to_numpy()
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    folds = list(splitter.split(F, y, groups))
    for fold_number, (train_idx, validation_idx) in enumerate(folds, start=1):
        overlap = set(groups[train_idx]) & set(groups[validation_idx])
        if overlap:
            raise RuntimeError(f"Capture leakage in fold {fold_number}: {sorted(overlap)}")
    return y, folds


def build_candidate_pipelines(
    feature_columns: list[str], n_rows: int, random_state: int = RANDOM_STATE
) -> dict[str, tuple[Pipeline, dict[str, Any]]]:
    """Build independent pipelines, each with fold-local median imputation."""
    classifier_specs: dict[str, tuple[Any, dict[str, Any], bool]] = {
        "Logistic Regression": (
            LogisticRegression(max_iter=2000, class_weight="balanced", random_state=random_state),
            {"max_iter": 2000, "class_weight": "balanced", "random_state": random_state},
            True,
        ),
        "Decision Tree": (
            DecisionTreeClassifier(class_weight="balanced", random_state=random_state),
            {"class_weight": "balanced", "random_state": random_state},
            False,
        ),
        "Random Forest": (
            RandomForestClassifier(
                n_estimators=100,
                class_weight="balanced_subsample",
                n_jobs=-1,
                random_state=random_state,
            ),
            {
                "n_estimators": 100,
                "class_weight": "balanced_subsample",
                "n_jobs": -1,
                "random_state": random_state,
            },
            False,
        ),
        "Extra Trees": (
            ExtraTreesClassifier(
                n_estimators=100,
                class_weight="balanced",
                n_jobs=-1,
                random_state=random_state,
            ),
            {
                "n_estimators": 100,
                "class_weight": "balanced",
                "n_jobs": -1,
                "random_state": random_state,
            },
            False,
        ),
        "HistGradientBoosting": (
            HistGradientBoostingClassifier(
                max_iter=100,
                learning_rate=0.1,
                class_weight="balanced",
                random_state=random_state,
            ),
            {
                "max_iter": 100,
                "learning_rate": 0.1,
                "class_weight": "balanced",
                "random_state": random_state,
            },
            False,
        ),
    }
    if n_rows <= SVM_MAX_ROWS:
        classifier_specs["Support Vector Machine (LinearSVC)"] = (
            LinearSVC(class_weight="balanced", max_iter=5000, dual="auto", random_state=random_state),
            {
                "class_weight": "balanced",
                "max_iter": 5000,
                "dual": "auto",
                "random_state": random_state,
            },
            True,
        )

    pipelines = {}
    for name, (classifier, params, scale) in classifier_specs.items():
        steps: list[tuple[str, Any]] = [
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True))
        ]
        if scale:
            steps.append(("scaler", StandardScaler()))
        steps.append(("classifier", classifier))
        pipelines[name] = (Pipeline(steps), params)
    return pipelines


def build_rf_pipeline(feature_columns: list[str], random_state: int = RANDOM_STATE) -> Pipeline:
    """Build the fixed Random Forest pipeline used by Experiment B."""
    return Pipeline(
        [
            ("imputer", SimpleImputer(strategy="median", keep_empty_features=True)),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    class_weight="balanced_subsample",
                    n_jobs=-1,
                    random_state=random_state,
                ),
            ),
        ]
    )


def _continuous_score(pipeline: Pipeline, X: pd.DataFrame) -> np.ndarray | None:
    """Return a probability or decision score for ROC-AUC, if supported."""
    classifier = pipeline.named_steps["classifier"]
    if hasattr(pipeline, "predict_proba"):
        probabilities = pipeline.predict_proba(X)
        class_labels = list(classifier.classes_)
        if 1 not in class_labels:
            raise ValueError("The fitted classifier does not contain Command Injection class 1.")
        positive = np.asarray(probabilities[:, class_labels.index(1)], dtype=float)
        if not np.isfinite(positive).all() or ((positive < 0) | (positive > 1)).any():
            raise ValueError("Classifier probabilities must be finite and between 0 and 1.")
        return positive
    if hasattr(pipeline, "decision_function"):
        return np.asarray(pipeline.decision_function(X), dtype=float)
    return None


def fold_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    scores: np.ndarray | None,
    training_seconds: float,
    prediction_seconds: float,
) -> dict[str, float | None]:
    """Calculate every requested fold metric; ROC-AUC is absent for one class."""
    if not set(np.asarray(y_pred).astype(int).tolist()) <= {0, 1}:
        raise ValueError("Candidate predictions must contain only classes 0 and 1.")
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=[0, 1], zero_division=0
    )
    matrix = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp = matrix[0]
    fpr = float(fp / (tn + fp)) if tn + fp else None
    roc_auc = (
        float(roc_auc_score(y_true, scores))
        if scores is not None and len(np.unique(y_true)) == 2
        else None
    )
    event_count = len(y_true)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_precision": float(precision.mean()),
        "macro_recall": float(recall.mean()),
        "macro_f1": float(f1.mean()),
        "command_injection_precision": float(precision[1]),
        "command_injection_recall": float(recall[1]),
        "command_injection_f1": float(f1[1]),
        "false_positive_rate": fpr,
        "roc_auc": roc_auc,
        "training_time_seconds": float(training_seconds),
        "prediction_time_seconds": float(prediction_seconds),
        "mean_inference_time_per_event_ms": (
            float(prediction_seconds * 1000.0 / event_count) if event_count else None
        ),
    }


def _run_folds(
    F: pd.DataFrame,
    feature_columns: list[str],
    y: np.ndarray,
    folds: list[tuple[np.ndarray, np.ndarray]],
    model_factories: dict[str, tuple[Any, dict[str, Any]] | tuple[Any, dict[str, Any], list[str]]],
) -> list[dict[str, Any]]:
    """Fit and evaluate each independent pipeline on identical CV folds."""
    records = []
    for model_name, model_spec in model_factories.items():
        factory, params = model_spec[:2]
        model_columns = model_spec[2] if len(model_spec) == 3 else feature_columns
        X = F.loc[:, model_columns]
        fold_results = []
        for fold_number, (train_idx, validation_idx) in enumerate(folds, start=1):
            pipeline = factory() if callable(factory) else sklearn.base.clone(factory)
            started = time.perf_counter()
            pipeline.fit(X.iloc[train_idx], y[train_idx])
            training_seconds = time.perf_counter() - started

            started = time.perf_counter()
            predictions = pipeline.predict(X.iloc[validation_idx])
            scores = _continuous_score(pipeline, X.iloc[validation_idx])
            prediction_seconds = time.perf_counter() - started
            metrics = fold_metrics(
                y[validation_idx], predictions, scores, training_seconds, prediction_seconds
            )
            fold_results.append(
                {
                    "fold": fold_number,
                    "train_captures": sorted(set(F.iloc[train_idx]["capture_id"].astype(str))),
                    "validation_captures": sorted(set(F.iloc[validation_idx]["capture_id"].astype(str))),
                    "validation_class_counts": {
                        str(class_id): int((y[validation_idx] == class_id).sum()) for class_id in (0, 1)
                    },
                    "metrics": metrics,
                }
            )

        records.append(
            {
                "model": model_name,
                "parameters": params,
                "feature_count": len(model_columns),
                "feature_columns": model_columns,
                "folds": fold_results,
                "metrics": _summarize_fold_metrics(fold_results),
                "roc_auc_valid_folds": sum(fold["metrics"]["roc_auc"] is not None for fold in fold_results),
            }
        )
    return records


def _summarize_fold_metrics(fold_results: list[dict[str, Any]]) -> dict[str, dict[str, float | None]]:
    """Return mean and sample standard deviation of each metric across folds."""
    summary: dict[str, dict[str, float | None]] = {}
    for metric_name in METRIC_NAMES:
        values = [
            float(fold["metrics"][metric_name])
            for fold in fold_results
            if fold["metrics"][metric_name] is not None
        ]
        summary[metric_name] = {
            "mean": float(np.mean(values)) if values else None,
            "std": float(np.std(values, ddof=1)) if len(values) > 1 else (0.0 if values else None),
        }
    return summary


def _metric_value(record: dict[str, Any], metric: str) -> float:
    value = record["metrics"][metric]["mean"]
    return float(value) if value is not None and np.isfinite(value) else float("-inf")


def select_ranked_models(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str, bool]:
    """Select by macro-F1; apply close-score tie-breakers and latency eligibility."""
    eligible = [
        row
        for row in records
        if (
            row["metrics"]["mean_inference_time_per_event_ms"]["mean"] is not None
            and row["metrics"]["mean_inference_time_per_event_ms"]["mean"] < OPERATIONAL_LATENCY_LIMIT_MS
        )
    ]
    selection_pool = eligible if eligible else records
    top_macro_f1 = max(_metric_value(row, "macro_f1") for row in selection_pool)
    near_top = [
        row
        for row in selection_pool
        if top_macro_f1 - _metric_value(row, "macro_f1") <= SIMILAR_MACRO_F1_TOLERANCE
    ]

    def tie_break_key(row: dict[str, Any]) -> tuple[float, ...]:
        return (
            -_metric_value(row, "command_injection_recall"),
            _metric_value(row, "false_positive_rate") * -1,
            row["metrics"]["macro_f1"]["std"] or 0.0,
            _metric_value(row, "mean_inference_time_per_event_ms") * -1,
            -MODEL_COMPLEXITY_ORDER.get(row["model"], 100),
            _metric_value(row, "macro_f1"),
        )

    selected = max(near_top, key=tie_break_key)
    remaining = [row for row in records if row["model"] != selected["model"]]
    remaining.sort(
        key=lambda row: (
            -_metric_value(row, "macro_f1"),
            -_metric_value(row, "command_injection_recall"),
            _metric_value(row, "false_positive_rate"),
            row["metrics"]["macro_f1"]["std"] or 0.0,
            _metric_value(row, "mean_inference_time_per_event_ms"),
            MODEL_COMPLEXITY_ORDER.get(row["model"], 100),
        )
    )
    ranked = [selected, *remaining]
    for rank, row in enumerate(ranked, start=1):
        row["rank"] = rank
        latency = row["metrics"]["mean_inference_time_per_event_ms"]["mean"]
        row["operationally_acceptable"] = (
            latency is not None and latency < OPERATIONAL_LATENCY_LIMIT_MS
        )
    return ranked, selected["model"], bool(eligible)


def _save_selected_pipeline(
    F: pd.DataFrame,
    y: np.ndarray,
    feature_columns: list[str],
    model_name: str,
    parameters: dict[str, Any],
    selection_metric: str,
    selection_metric_value: float,
) -> dict[str, Any]:
    """Refit the selected complete pipeline on all development records."""
    candidates = build_candidate_pipelines(feature_columns, len(F))
    if model_name not in candidates:
        raise ValueError(f"Selected model is not an available candidate: {model_name}")
    pipeline, _ = candidates[model_name]
    pipeline.fit(F.loc[:, feature_columns], y)

    model_path = MODELS_DIR / "selected_candidate_model.joblib"
    schema_path = MODELS_DIR / "selected_candidate_feature_names.json"
    metadata_path = MODELS_DIR / "selected_candidate_model.json"
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)
    write_json(feature_columns, schema_path)
    metadata = {
        "model_name": model_name,
        "model_parameters": parameters,
        "classes": {str(key): value for key, value in CLASS_NAMES.items()},
        "scikit_learn_version": sklearn.__version__,
        "random_seed": RANDOM_STATE,
        "selection_metric": selection_metric,
        "selection_metric_value": float(selection_metric_value),
        "feature_schema_file": schema_path.name,
        "feature_count": len(feature_columns),
        "training_partition": "data/splits/train.parquet; capture-grouped development partition",
        "test_partition_used": False,
        "pipeline_steps": [name for name, _ in pipeline.steps],
    }
    write_json(metadata, metadata_path)
    return {
        "model_file": model_path.relative_to(ROOT).as_posix(),
        "feature_schema_file": schema_path.relative_to(ROOT).as_posix(),
        "metadata_file": metadata_path.relative_to(ROOT).as_posix(),
        "metadata": metadata,
    }


def load_selected_candidate(models_dir: str | Path = MODELS_DIR) -> dict[str, Any]:
    """Load the saved pipeline and verify its persisted ordered feature schema."""
    directory = Path(models_dir)
    model_path = directory / "selected_candidate_model.joblib"
    schema_path = directory / "selected_candidate_feature_names.json"
    metadata_path = directory / "selected_candidate_model.json"
    missing = [path.name for path in (model_path, schema_path, metadata_path) if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Selected candidate artefacts are missing: {', '.join(missing)}")

    pipeline = joblib.load(model_path)
    feature_columns = read_json(schema_path)
    metadata = read_json(metadata_path)
    imputer_columns = list(pipeline.named_steps["imputer"].feature_names_in_)
    if feature_columns != imputer_columns:
        raise ValueError("Saved pipeline feature order does not match the persisted feature schema.")
    if int(pipeline.named_steps["classifier"].n_features_in_) != len(feature_columns):
        raise ValueError("Saved pipeline feature count does not match the persisted feature schema.")
    if set(pipeline.named_steps["classifier"].classes_.tolist()) != {0, 1}:
        raise ValueError("Saved candidate pipeline does not contain exactly classes 0 and 1.")
    return {"pipeline": pipeline, "feature_columns": feature_columns, "metadata": metadata}


def _save_comparison_csv(records: list[dict[str, Any]], path: Path) -> None:
    """Write a flat model-level table with mean and standard deviation columns."""
    rows = []
    for record in records:
        row: dict[str, Any] = {
            "rank": record["rank"],
            "model": record["model"],
            "feature_count": record["feature_count"],
            "operationally_acceptable": record["operationally_acceptable"],
            "roc_auc_valid_folds": record["roc_auc_valid_folds"],
            "parameters": json.dumps(record["parameters"], sort_keys=True),
        }
        for metric_name in METRIC_NAMES:
            row[f"{metric_name}_mean"] = record["metrics"][metric_name]["mean"]
            row[f"{metric_name}_std"] = record["metrics"][metric_name]["std"]
        rows.append(row)
    pd.DataFrame(rows).to_csv(path, index=False)


def _format_metric(record: dict[str, Any], metric: str, decimals: int = 4) -> str:
    value = record["metrics"][metric]["mean"]
    std = record["metrics"][metric]["std"]
    if value is None:
        return "N/A"
    return f"{value:.{decimals}f} +/- {std:.{decimals}f}"


def _write_summary(
    path: Path,
    experiment_name: str,
    records: list[dict[str, Any]],
    selected_model: str | None,
    partition_description: str,
    grouping_description: str,
    feature_description: str,
    test_unused: bool,
    operational_candidates_exist: bool,
) -> None:
    """Write a reproducible Markdown explanation of the comparison."""
    selected = next((row for row in records if row["model"] == selected_model), None)
    winner_text = (
        f"**{selected_model}** ranked first by mean macro F1, with Command Injection recall "
        f"{_format_metric(selected, 'command_injection_recall')}, false-positive rate "
        f"{_format_metric(selected, 'false_positive_rate')}, macro-F1 stability "
        f"{_format_metric(selected, 'macro_f1')}, and mean inference latency "
        f"{_format_metric(selected, 'mean_inference_time_per_event_ms', 3)} ms/event."
        if selected is not None
        else "No selected model was produced."
    )
    latency_value = (
        selected["metrics"]["mean_inference_time_per_event_ms"]["mean"] if selected is not None else None
    )
    latency_status = (
        f"Yes ({latency_value:.3f} ms/event)"
        if latency_value is not None and latency_value < OPERATIONAL_LATENCY_LIMIT_MS
        else ("No" if latency_value is not None else "Not measurable")
    )
    lines = [
        f"# Model comparison — {experiment_name}",
        "",
        f"**Experiment:** {experiment_name}",
        f"**Development partition:** {partition_description}",
        f"**Grouping:** {grouping_description}",
        f"**Features:** {feature_description}",
        f"**Cross-validation:** {N_FOLDS}-fold StratifiedGroupKFold, shuffled with random seed {RANDOM_STATE}.",
        "**Preprocessing leakage prevention:** Each candidate is an independent scikit-learn Pipeline. "
        "The median imputer (and scaler for Logistic Regression/LinearSVC) is fitted separately inside "
        "each fold's training data. The contextual features computed by the existing builder are stat-free; "
        "label-informed access-profile and normal-value-range features were excluded.",
        "**Accuracy:** Accuracy was reported but not used alone. Ranking prioritizes mean macro F1, "
        "then Command Injection recall, false-positive rate, fold stability, and inference latency. "
        f"Macro-F1 values within {SIMILAR_MACRO_F1_TOLERANCE:.3f} are treated as similar and resolved "
        "using recall, false-positive rate, stability, latency, then model simplicity.",
        "",
        "## Results",
        "",
        "| Rank | Model | Macro F1 (mean +/- SD) | Attack recall (mean +/- SD) | FPR (mean +/- SD) | ROC-AUC (mean +/- SD) | Inference ms/event (mean +/- SD) | <100 ms |",
        "|---:|---|---:|---:|---:|---:|---:|:---:|",
    ]
    for row in records:
        lines.append(
            f"| {row['rank']} | {row['model']} | {_format_metric(row, 'macro_f1')} | "
            f"{_format_metric(row, 'command_injection_recall')} | "
            f"{_format_metric(row, 'false_positive_rate')} | {_format_metric(row, 'roc_auc')} | "
            f"{_format_metric(row, 'mean_inference_time_per_event_ms', 3)} | "
            f"{'Yes' if row['operationally_acceptable'] else 'No'} |"
        )
    lines.extend(
        [
            "",
            "## Selection",
            "",
            f"{winner_text}",
            f"**Best candidate meets the 100 ms target:** {latency_status}.",
            (
                "At least one model met the latency target; the selected model was chosen from "
                "operationally acceptable candidates."
                if operational_candidates_exist
                else "No model met the latency target; the top-ranked candidate is reported but is not "
                "operationally acceptable."
            ),
            "",
            f"**Protected final 20% test set:** {'Not used' if test_unused else 'Use detected — comparison invalid'}. "
            "The comparison reads only `data/splits/train.parquet` through the existing guarded development "
            "loader and validates capture IDs against the split manifest.",
            "",
            "## Limitations",
            "",
            "- The development data contains nine capture groups and only three attack-containing captures. "
            "Two validation folds contain no Command Injection examples; their attack recall is zero by "
            "definition and ROC-AUC is unavailable. Fold results and valid ROC-AUC fold counts are retained "
            "in the JSON report.",
            "- Labels are researcher-reconstructed and circularity is documented in `docs/limitations.md`; "
            "these scores do not establish generalisation to independently verified attack labels.",
            "- The comparison uses one documented configuration per algorithm, not a hyperparameter search. "
            "SVM is implemented as a scalable LinearSVC and is included only when the labelled development "
            f"set has at most {SVM_MAX_ROWS:,} events.",
            "- Latency is measured on fold validation batches and depends on the current machine and software.",
            "- This is a development-only model comparison, not a final held-out test evaluation.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _save_metric_plot(records: list[dict[str, Any]], metric: str, ylabel: str, path: Path) -> None:
    """Save a bar chart of fold mean and standard deviation."""
    names = [record["model"] for record in records]
    means = [record["metrics"][metric]["mean"] or 0.0 for record in records]
    errors = [record["metrics"][metric]["std"] or 0.0 for record in records]
    fig, ax = plt.subplots(figsize=(10, 5.5))
    positions = np.arange(len(names))
    ax.bar(positions, means, yerr=errors, capsize=4, color="#3572A5")
    ax.set_xticks(positions, names, rotation=20, ha="right")
    ax.set_ylabel(ylabel)
    ax.set_title(f"Experiment A — {ylabel} by candidate model")
    ax.grid(axis="y", alpha=0.25)
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def _experiment_payload(
    experiment: str,
    records: list[dict[str, Any]],
    folds: list[tuple[np.ndarray, np.ndarray]],
    F: pd.DataFrame,
    feature_columns: list[str],
) -> dict[str, Any]:
    """Build the JSON-safe experiment record, including fold group assignments."""
    y = F["class_id"].astype(int).to_numpy()
    groups = F["capture_id"].astype(str).to_numpy()
    fold_groups = [
        {
            "fold": index,
            "train_captures": sorted(set(groups[train_idx])),
            "validation_captures": sorted(set(groups[validation_idx])),
            "validation_class_counts": {
                str(class_id): int((y[validation_idx] == class_id).sum()) for class_id in (0, 1)
            },
        }
        for index, (train_idx, validation_idx) in enumerate(folds, start=1)
    ]
    return {
        "experiment": experiment,
        "partition": "80% capture-grouped development partition (data/splits/train.parquet)",
        "development_labeled_events": len(F),
        "development_capture_count": int(F["capture_id"].nunique()),
        "feature_columns": feature_columns,
        "folds": fold_groups,
        "random_seed": RANDOM_STATE,
        "scikit_learn_version": sklearn.__version__,
        "final_test_partition_used": False,
        "models": records,
    }


def run_comparison() -> dict[str, Any]:
    """Run separate algorithm-selection and feature-context experiments."""
    split_manifest = read_json(MANIFEST_DIR / "split_manifest.json")
    features = load_dev_features()
    labelled = features.loc[features["class_id"].notna()].reset_index(drop=True)
    validate_development_partition(labelled, split_manifest)
    y, folds = grouped_validation_splits(labelled)
    groups = labelled["capture_id"].astype(str).to_numpy()
    fold_assignments = np.zeros(len(labelled), dtype=np.int8)
    for fold_number, (_, validation_idx) in enumerate(folds, start=1):
        fold_assignments[validation_idx] = fold_number
    if np.any(fold_assignments == 0):
        raise RuntimeError("Not every development record received a validation fold.")

    contextual_columns = candidate_feature_columns("contextual")
    if not contextual_columns:
        raise ValueError("No target-independent contextual features are available.")
    candidates = build_candidate_pipelines(contextual_columns, len(labelled))
    model_factories = {
        name: (pipeline, parameters) for name, (pipeline, parameters) in candidates.items()
    }
    experiment_a_records = _run_folds(labelled, contextual_columns, y, folds, model_factories)
    experiment_a_records, selected_model, has_acceptable_candidate = select_ranked_models(experiment_a_records)

    reports = REPORTS_DIR
    reports.mkdir(parents=True, exist_ok=True)
    for filename, metric, ylabel in (
        ("model_comparison_macro_f1.png", "macro_f1", "Macro F1-score"),
        ("model_comparison_attack_recall.png", "command_injection_recall", "Command Injection recall"),
        ("model_comparison_false_positive_rate.png", "false_positive_rate", "False-positive rate"),
    ):
        _save_metric_plot(experiment_a_records, metric, ylabel, reports / filename)
    _save_comparison_csv(experiment_a_records, reports / "model_comparison.csv")

    experiment_a = _experiment_payload(
        "A — Algorithm selection using shared contextual features",
        experiment_a_records,
        folds,
        labelled,
        contextual_columns,
    )
    experiment_a["selection"] = {
        "selected_model": selected_model,
        "selection_metric": "mean_macro_f1",
        "similar_macro_f1_tolerance": SIMILAR_MACRO_F1_TOLERANCE,
        "operational_latency_limit_ms": OPERATIONAL_LATENCY_LIMIT_MS,
        "operational_candidates_available": has_acceptable_candidate,
        "criterion": (
            "Highest mean macro F1; within the similarity tolerance, prefer higher Command Injection recall, "
            "lower false-positive rate, lower macro-F1 standard deviation, lower latency, then simpler models."
        ),
    }
    experiment_a["selected_model_artifacts"] = _save_selected_pipeline(
        labelled,
        y,
        contextual_columns,
        selected_model,
        next(row["parameters"] for row in experiment_a_records if row["model"] == selected_model),
        "mean_macro_f1; tie-breakers: Command Injection recall, false-positive rate, fold stability, latency",
        next(
            row["metrics"]["macro_f1"]["mean"]
            for row in experiment_a_records
            if row["model"] == selected_model
        ),
    )
    write_json(experiment_a, reports / "model_comparison.json")
    _write_summary(
        reports / "model_comparison_summary.md",
        "Experiment A — algorithm selection",
        experiment_a_records,
        selected_model,
        f"{len(labelled):,} labelled events from {labelled['capture_id'].nunique()} manifest-listed "
        "development captures (80% split).",
        "capture_id; StratifiedGroupKFold keeps each capture wholly in train or validation.",
        f"{len(contextual_columns)} stat-free contextual features shared by all candidate classifiers; "
        "label-informed access and normal-range profile features excluded.",
        test_unused=True,
        operational_candidates_exist=has_acceptable_candidate,
    )

    # Experiment B is intentionally a separate run/report and compares only
    # the isolated-event and contextual Random Forest feature representations.
    isolated_columns = candidate_feature_columns("isolated")
    experiment_b_records = _run_folds(
        labelled,
        contextual_columns,
        y,
        folds,
        {
            "Isolated-event Random Forest": (
                lambda: build_rf_pipeline(isolated_columns),
                {
                    "n_estimators": 100,
                    "class_weight": "balanced_subsample",
                    "n_jobs": -1,
                    "random_state": RANDOM_STATE,
                    "feature_set": "isolated current-event features",
                },
                isolated_columns,
            ),
            "Context-aware Random Forest": (
                lambda: build_rf_pipeline(contextual_columns),
                {
                    "n_estimators": 100,
                    "class_weight": "balanced_subsample",
                    "n_jobs": -1,
                    "random_state": RANDOM_STATE,
                    "feature_set": "contextual features",
                },
                contextual_columns,
            ),
        },
    )
    experiment_b = _experiment_payload(
        "B — Isolated-event versus context-aware Random Forest",
        experiment_b_records,
        folds,
        labelled,
        contextual_columns,
    )
    experiment_b["feature_sets"] = {
        "Isolated-event Random Forest": isolated_columns,
        "Context-aware Random Forest": contextual_columns,
    }
    _save_comparison_csv(experiment_b_records, reports / "context_feature_experiment.csv")
    write_json(experiment_b, reports / "context_feature_experiment.json")
    _write_summary(
        reports / "context_feature_experiment_summary.md",
        "Experiment B — contextual feature contribution",
        experiment_b_records,
        None,
        f"{len(labelled):,} labelled events from {labelled['capture_id'].nunique()} development captures.",
        "The exact same capture-grouped validation folds as Experiment A.",
        f"Isolated feature set: {len(isolated_columns)} current-event features. Contextual feature set: "
        f"{len(contextual_columns)} stat-free features. Both models use Random Forest.",
        test_unused=True,
        operational_candidates_exist=True,
    )

    return {
        "experiment_a": experiment_a,
        "experiment_b": experiment_b,
    }


def main() -> int:
    """Run both separate experiments and print their report locations."""
    results = run_comparison()
    print(f"Experiment A selected: {results['experiment_a']['selection']['selected_model']}")
    print(f"Experiment A summary: {REPORTS_DIR / 'model_comparison_summary.md'}")
    print(f"Experiment B summary: {REPORTS_DIR / 'context_feature_experiment_summary.md'}")
    print("Protected final-test partition used: False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
