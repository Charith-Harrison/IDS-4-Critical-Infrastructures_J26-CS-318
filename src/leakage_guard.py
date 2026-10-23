"""An exact whitelist prevents metadata and target leakage at every model boundary."""

from __future__ import annotations

import pandas as pd

from src.feature_engineering import feature_names

FORBIDDEN = {
    "target",
    "label",
    "attack_category",
    "attack_sub_type",
    "is_attack",
    "source_file",
    "file_source",
    "group_id",
    "context_id",
    "session_key",
    "event_id",
    "source_row",
    "frame_number",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "mbtcp_trans_id",
    "scenario_id",
    "capture_id",
    "prediction",
    "result",
    "partition",
    "observation_hash",
}


def validate_features(features: pd.DataFrame, cfg: dict, kind: str) -> None:
    expected = feature_names(cfg, kind)
    unknown = set(features.columns) - set(expected)
    forbidden = set(features.columns) & FORBIDDEN
    if unknown or forbidden:
        raise ValueError(f"Leakage guard: forbidden or non-whitelisted features: {sorted(unknown | forbidden)}")
    if list(features.columns) != expected:
        raise ValueError("Feature schema/order mismatch; rebuild features with model configuration")
    if any(not pd.api.types.is_numeric_dtype(dtype) for dtype in features.dtypes):
        raise ValueError("Model features must be numeric")
