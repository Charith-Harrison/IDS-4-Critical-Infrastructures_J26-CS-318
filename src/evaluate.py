"""Explicit binary/multiclass metrics and one frozen holdout comparison."""

from __future__ import annotations

import time

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)

from src.utils import ROOT, checksum, read_json, save_json


def score_predictions(actual, predicted, probabilities: np.ndarray, classes: list[str]) -> dict:
    actual, predicted = np.asarray(actual), np.asarray(predicted)
    metrics = {
        "accuracy": float(accuracy_score(actual, predicted)),
        "confusion_matrix": confusion_matrix(actual, predicted, labels=classes).tolist(),
        "classes": classes,
        "per_class": classification_report(actual, predicted, labels=classes, output_dict=True, zero_division=0),
    }
    for average in ["macro", "weighted"]:
        precision, recall, f1, _ = precision_recall_fscore_support(
            actual, predicted, labels=classes, average=average, zero_division=0
        )
        metrics.update(
            {f"{average}_precision": float(precision), f"{average}_recall": float(recall), f"{average}_f1": float(f1)}
        )
    normal = actual == "Normal"
    attack = ~normal
    detected = predicted != "Normal"
    metrics["false_positive_rate"] = float(detected[normal].mean()) if normal.any() else None
    metrics["attack_recall"] = float(detected[attack].mean()) if attack.any() else None
    metrics["roc_auc"] = None
    metrics["pr_auc"] = None
    metrics["auc_definition"] = (
        "attack-class ROC AUC / average precision"
        if len(classes) == 2
        else "macro one-versus-rest ROC AUC / average precision"
    )
    if len(classes) == 2:
        positive = next(c for c in classes if c != "Normal")
        precision, recall, f1, _ = precision_recall_fscore_support(
            actual == positive, predicted == positive, average="binary", zero_division=0
        )
        metrics.update({"binary_precision": float(precision), "binary_recall": float(recall), "binary_f1": float(f1)})
        if normal.any() and attack.any():
            scores = probabilities[:, classes.index(positive)]
            metrics["roc_auc"] = float(roc_auc_score(attack, scores))
            metrics["pr_auc"] = float(average_precision_score(attack, scores))
    else:
        onehot = np.column_stack([actual == c for c in classes])
        if all(column.any() and (~column).any() for column in onehot.T):
            metrics["roc_auc"] = float(roc_auc_score(onehot, probabilities, average="macro"))
            metrics["pr_auc"] = float(average_precision_score(onehot, probabilities, average="macro"))
    return metrics


def predict_and_score(pipeline, features: pd.DataFrame, labels) -> tuple[dict, np.ndarray, np.ndarray]:
    start = time.perf_counter()
    probabilities = pipeline.predict_proba(features)
    elapsed = time.perf_counter() - start
    classes = list(pipeline.classes_)
    predictions = np.asarray(classes)[probabilities.argmax(axis=1)]
    scores = score_predictions(labels, predictions, probabilities, classes)
    scores["batch_inference_ms_per_event"] = elapsed * 1000 / max(len(features), 1)
    sample = features.iloc[:1]
    single_times = []
    for _ in range(10):
        start = time.perf_counter()
        pipeline.predict_proba(sample)
        single_times.append((time.perf_counter() - start) * 1000)
    scores["single_event_model_latency_ms_median"] = float(np.median(single_times))
    scores["latency_scope"] = "model-only; context construction excluded; hardware-dependent"
    return scores, predictions, probabilities


def evaluate_models(cfg: dict) -> dict:
    from src.feature_engineering import build_features
    from src.inference import load_model
    from src.training import load_prepared

    events, manifest = load_prepared(cfg)
    test = events[events.partition.eq("test")].reset_index(drop=True)
    artifacts = {kind: load_model(kind, cfg) for kind in ["baseline", "contextual"]}
    identity = {kind: checksum(ROOT / f"models/{kind}/model.joblib") for kind in artifacts}
    identity["events"] = manifest["events_sha256"]
    output = ROOT / "results/metrics/comparison.json"
    if output.exists():
        previous = read_json(output)
        if previous["evaluation_identity"] == identity:
            return previous
        raise ValueError(
            "Holdout was already evaluated for different artifacts. Archive results and document a new experiment; do not tune against this test set."
        )
    report = {
        "evaluation_identity": identity,
        "evaluation_scope": "preliminary internal grouped holdout",
        "model_mode": cfg["model_mode"],
        "split": manifest["split"],
        "models": {},
    }
    prediction_dir = ROOT / "results/predictions"
    prediction_dir.mkdir(parents=True, exist_ok=True)
    for kind, artifact in artifacts.items():
        features = build_features(test, cfg, kind)
        metrics, predictions, probabilities = predict_and_score(artifact["pipeline"], features, test.target)
        metrics["feature_count"] = len(features.columns)
        metrics["training_seconds"] = artifact["metadata"]["training_seconds"]
        report["models"][kind] = metrics
        export = test[["event_id", "timestamp", "target", "group_id"]].copy()
        export["prediction"] = predictions
        for i, label in enumerate(artifact["pipeline"].classes_):
            export["probability_" + label] = probabilities[:, i]
        export.to_parquet(prediction_dir / f"{kind}_holdout.parquet", index=False)
        save_json(ROOT / f"results/metrics/{kind}_holdout.json", metrics)
    delta = report["models"]["contextual"]["macro_f1"] - report["models"]["baseline"]["macro_f1"]
    report["macro_f1_difference"] = delta
    report["interpretation"] = (
        f"Contextual minus baseline macro F1: {delta:+.6f}. "
        + (
            "Context scored higher on this split."
            if delta > 0
            else "This split does not demonstrate a contextual macro-F1 improvement."
        )
        + " A single provisional grouped split does not establish statistical significance or external validity. "
        "The legacy project previously evaluated these source data; this is not a pristine final research holdout."
    )
    save_json(output, report)
    table = pd.DataFrame(
        [
            {
                key: value
                for key, value in {"model": kind, **metrics}.items()
                if isinstance(value, (str, int, float)) or value is None
            }
            for kind, metrics in report["models"].items()
        ]
    )
    table.to_csv(ROOT / "results/metrics/comparison.csv", index=False)
    (ROOT / "results/metrics/comparison.md").write_text(
        "# Preliminary model comparison\n\n"
        + report["interpretation"]
        + "\n\nSee comparison.csv and comparison.json for all measured metrics and per-class results.\n",
        encoding="utf-8",
    )
    # Save a portable figure without making plotting a training dependency.
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(11, 4), constrained_layout=True)
    for axis, (kind, metrics) in zip(axes, report["models"].items()):
        matrix = np.asarray(metrics["confusion_matrix"])
        axis.imshow(matrix, cmap="Blues")
        labels = [c.replace("_", "\n") for c in metrics["classes"]]
        axis.set(
            xticks=range(len(labels)),
            yticks=range(len(labels)),
            xticklabels=labels,
            yticklabels=labels,
            xlabel="Predicted",
            ylabel="Actual",
            title=kind.title(),
        )
        for (i, j), value in np.ndenumerate(matrix):
            axis.text(
                j, i, str(value), ha="center", va="center", color="white" if value > matrix.max() / 2 else "black"
            )
    directory = ROOT / "results/figures"
    directory.mkdir(parents=True, exist_ok=True)
    fig.savefig(directory / "confusion_matrices.png", dpi=150)
    plt.close(fig)
    return report
