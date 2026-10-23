"""One feature implementation for training, evaluation, and inference."""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.context_builder import build_context

STATIC = [
    "function_code",
    "is_read",
    "is_write",
    "address",
    "value",
    "word_count",
    "bit_count",
    "byte_count",
    "unit_id",
    "is_request",
    "is_exception",
]
PAIRING = [
    "has_matching_pair",
    "function_match",
    "unit_match",
    "transaction_match",
    "response_delay",
    "unexpected_response",
    "expired_requests",
]


def feature_groups(cfg: dict) -> dict[str, list[str]]:
    groups = {
        "static": STATIC.copy(),
        "sequence": [
            "previous_function_code",
            "previous_operation",
            "function_transition",
            "read_to_write_transition",
            "write_to_read_transition",
        ],
        "pairing": PAIRING.copy(),
        "access": ["previous_register", "address_change", "repeated_access"],
        "timing": ["inter_arrival_time", "previous_inter_arrival_time"],
        "value": ["previous_value", "value_delta", "absolute_value_delta", "value_direction", "repeated_same_value"],
    }
    for w in cfg["features"]["windows"]:
        groups["sequence"] += [f"recent_write_ratio_{w}", f"repeated_write_count_{w}", f"function_diversity_{w}"]
        groups["access"] += [f"distinct_registers_{w}", f"repeated_access_count_{w}"]
        groups["timing"] += [f"rolling_mean_inter_arrival_{w}", f"rolling_std_inter_arrival_{w}"]
        groups["value"] += [f"rolling_value_change_{w}"]
    return groups


def feature_names(cfg: dict, kind: str) -> list[str]:
    if kind not in {"baseline", "contextual"}:
        raise ValueError("Model kind must be baseline or contextual")
    names = [
        column
        for group, columns in feature_groups(cfg).items()
        if group == "static" or (kind == "contextual" and cfg["features"].get(group, False))
        for column in columns
    ]
    return names + [name + "_missing" for name in names]


def build_features(events: pd.DataFrame, cfg: dict, kind: str = "contextual") -> pd.DataFrame:
    if events.empty:
        return pd.DataFrame(columns=feature_names(cfg, kind), index=events.index, dtype=float)
    # Even if a caller concatenates partitions, context never crosses them.
    ordered = events.copy()
    if "partition" in ordered:
        ordered["context_id"] = ordered.partition.astype(str) + ":" + ordered.context_id
    ordered = ordered.sort_values(["context_id", "timestamp", "source_row"], kind="stable")
    static = pd.DataFrame(index=ordered.index)
    mapping = {
        "function_code": "modbus_func_code",
        "address": "modbus_ref_num",
        "value": "modbus_val",
        "word_count": "modbus_word_cnt",
        "bit_count": "modbus_bit_cnt",
        "byte_count": "modbus_byte_cnt",
        "unit_id": "mbtcp_unit_id",
        "is_request": "is_request",
        "is_exception": "is_exception",
    }
    for feature, column in mapping.items():
        static[feature] = pd.to_numeric(ordered[column], errors="coerce")
    function = static.function_code % 128
    static["is_read"] = function.isin([1, 2, 3, 4]).astype(float)
    static["is_write"] = function.isin([5, 6, 15, 16]).astype(float)
    # If exception flag is absent, function-code exception semantics are sufficient.
    static["is_exception"] = static.is_exception.fillna((static.function_code >= 128).astype(float))
    if kind == "contextual":
        result = pd.concat([static, build_context(ordered, static, cfg), ordered[PAIRING]], axis=1)
    else:
        result = static
    names = feature_names(cfg, kind)
    selected = [name for name in names if not name.endswith("_missing")]
    result = result[selected].replace([np.inf, -np.inf], np.nan).astype(float)
    missing = result.isna().astype(float).add_suffix("_missing")
    result = pd.concat([result, missing], axis=1).reindex(events.index)
    from src.leakage_guard import validate_features

    validate_features(result, cfg, kind)
    return result
