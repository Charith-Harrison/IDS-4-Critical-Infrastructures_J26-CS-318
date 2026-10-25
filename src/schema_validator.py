# Normalize known column aliases and mark invalid records instead of inventing missing values.
"""Schema normalization and transparent record-level quality checks."""

from __future__ import annotations

import re

import numpy as np
import pandas as pd

# Canonical protocol vocabulary. Other input schemas use config.dataset.column_map.
NUMERIC = [
    "timestamp",
    "frame_number",
    "modbus_func_code",
    "modbus_ref_num",
    "modbus_val",
    "modbus_word_cnt",
    "modbus_bit_cnt",
    "modbus_byte_cnt",
    "mbtcp_unit_id",
    "mbtcp_trans_id",
    "is_request",
    "is_exception",
    "src_port",
    "dst_port",
]
RANGES = {
    "modbus_func_code": (1, 255),
    "modbus_ref_num": (0, 65535),
    "mbtcp_unit_id": (0, 255),
    "mbtcp_trans_id": (0, 65535),
    "is_request": (0, 1),
    "is_exception": (0, 1),
    "src_port": (0, 65535),
    "dst_port": (0, 65535),
    "modbus_word_cnt": (0, 65535),
    "modbus_bit_cnt": (0, 65535),
    "modbus_byte_cnt": (0, 65535),
}


# Map recognized aliases to canonical names and reject name collisions.
def normalize_columns(frame: pd.DataFrame, column_map: dict | None = None) -> pd.DataFrame:
    out = frame.rename(columns=column_map or {}).copy()
    out.columns = [re.sub(r"[^a-z0-9]+", "_", str(c).strip().lower()).strip("_") for c in out.columns]
    if out.columns.duplicated().any():
        raise ValueError("Column normalization produced duplicate names")
    if "modbus_func_code" not in out:
        raise ValueError("Missing modbus_func_code; configure dataset.column_map for this schema")
    if out.empty:
        raise ValueError("Dataset contains no rows")
    return out


# Check supplied field values and mark invalid records while preserving genuine missingness.
def validate_records(frame: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Missing optional fields remain NaN; malformed supplied values are quarantined."""
    out = frame.copy()
    reasons = pd.Series("", index=out.index, dtype="object")
    for column in NUMERIC:
        if column not in out:
            out[column] = np.nan
            continue
        original = out[column]
        numeric = pd.to_numeric(original, errors="coerce")
        if column == "timestamp" and cfg["dataset"].get("timestamp_unit", "s") == "iso":
            parsed = pd.to_datetime(original, errors="coerce", utc=True)
            numeric = parsed.map(lambda v: v.timestamp() if pd.notna(v) else np.nan)
        elif column == "timestamp":
            numeric = numeric / {"s": 1, "ms": 1000, "us": 1e6, "ns": 1e9}[cfg["dataset"].get("timestamp_unit", "s")]
        bad = original.notna() & (numeric.isna() | ~np.isfinite(numeric))
        if column in RANGES:
            low, high = RANGES[column]
            bad |= numeric.notna() & (~numeric.between(low, high) | (numeric % 1 != 0))
        if column == "timestamp":
            bad |= numeric.notna() & (numeric < 0)
        if column == "modbus_func_code":
            bad |= numeric.isna()
        reasons.loc[bad] += column + ":invalid;"
        out[column] = numeric
    out["invalid_reason"] = reasons
    out["processing_status"] = np.where(reasons.eq(""), "valid", "malformed")
    return out
