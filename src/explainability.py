"""Descriptive evidence, explicitly separated from causal attribution."""

from __future__ import annotations

import math
from functools import lru_cache


@lru_cache(maxsize=8)
def ranked_features(classifier, names: tuple[str, ...]) -> tuple:
    """RF importance aggregates every tree; compute once per loaded model, not per row."""
    return tuple(sorted(zip(names, classifier.feature_importances_), key=lambda item: item[1], reverse=True))


def explain_event(values, artifact: dict) -> dict:
    """Surface actual feature values and training-range context, not invented reasons."""
    names = artifact["metadata"]["feature_names"]
    ranked = ranked_features(artifact["pipeline"].named_steps["classifier"], tuple(names))
    important = [
        {
            "feature": name,
            "value": float(values[name]) if math.isfinite(values[name]) else None,
            "global_importance": float(weight),
        }
        for name, weight in ranked[:5]
    ]
    evidence = []
    for name, phrase in [
        ("read_to_write_transition", "Read-to-write transition observed"),
        ("write_to_read_transition", "Write-to-read transition observed"),
        ("unexpected_response", "No unambiguous earlier request observed"),
    ]:
        if values.get(name, 0) == 1:
            evidence.append(phrase)
    for name in ["absolute_value_delta", "inter_arrival_time"]:
        ref = artifact["reference_profile"].get(name)
        value = values.get(name)
        if ref and value is not None and math.isfinite(value) and value > ref["p99"]:
            evidence.append(f'{name}={value:.6g} exceeds the training 99th percentile ({ref["p99"]:.6g})')
    if not evidence:
        evidence = [f'{item["feature"]}={item["value"]}' for item in important[:3]]
    return {
        "evidence": evidence,
        "important_features": important,
        "explanation_note": "Observed context and global RF importance; not a local causal explanation or verified attack evidence.",
    }
