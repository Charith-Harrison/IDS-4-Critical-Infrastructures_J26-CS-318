"""Standardisation, capture reconstruction, label mapping and preprocessing.

Labels are built from dataset-provided fields plus documented Modbus evidence.
Reconstructed labels are NOT independently verified ground truth.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.data.loader import (
    LABEL_COLUMNS,
    REQUIRED_COLUMNS,
    STRING_COLUMNS,
    UNUSED_PRECOMPUTED,
)
from src.utils.config import FUNCTION_NAMES, WRITE_FUNCTIONS

NUMERIC_COLUMNS = [c for c in REQUIRED_COLUMNS if c not in STRING_COLUMNS]


def standardize(df: pd.DataFrame, source_name: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Coerce numerics, keep original row ids, split off invalid records.

    Returns (clean, invalid). Invalid rows keep source_row, field and reason so
    they can be reported and never forced into a class.
    """
    out = df.copy()
    out.columns = [c.strip().lower() for c in out.columns]
    out["source_row"] = np.arange(len(out))  # original record identifier
    out["source_name"] = source_name
    problems: list[pd.DataFrame] = []
    for col in NUMERIC_COLUMNS:
        before_null = out[col].isna()
        out[col] = pd.to_numeric(out[col], errors="coerce")
        bad = out[col].isna()
        if bad.any():
            reason = np.where(before_null[bad], "missing value", "non-numeric value")
            problems.append(pd.DataFrame({"source_row": out.loc[bad, "source_row"], "field": col, "reason": reason}))
    for col in STRING_COLUMNS:
        bad = out[col].isna() | (out[col].astype(str).str.strip() == "")
        if bad.any():
            problems.append(
                pd.DataFrame({"source_row": out.loc[bad, "source_row"], "field": col, "reason": "missing value"})
            )
    invalid = (
        pd.concat(problems, ignore_index=True) if problems else pd.DataFrame(columns=["source_row", "field", "reason"])
    )
    bad_rows = set(invalid["source_row"]) if len(invalid) else set()
    if len(out):
        # A timestamp must be a positive epoch value to be orderable.
        neg = out["timestamp"] <= 0
        if neg.any():
            extra = pd.DataFrame(
                {"source_row": out.loc[neg, "source_row"], "field": "timestamp", "reason": "non-positive timestamp"}
            )
            invalid = pd.concat([invalid, extra], ignore_index=True)
            bad_rows |= set(extra["source_row"])
    clean = out[~out["source_row"].isin(bad_rows)].copy()
    for col in NUMERIC_COLUMNS:
        clean[col] = clean[col].astype("int64" if col not in ("timestamp",) else "float64")
    return clean, invalid


def reconstruct_captures(df: pd.DataFrame, prefix: str) -> pd.DataFrame:
    """Assign capture_id from a real capture field or from resets.

    * file_source present -> capture = that field (real capture id).
    * otherwise a new capture starts where frame_number or timestamp goes
      backwards relative to the previous row (reason recorded).
    """
    out = df.copy()
    if "file_source" in out.columns:
        stems = out["file_source"].astype(str).str.replace(".pcap", "", regex=False)
        out["capture_id"] = f"{prefix}-" + stems
        out["boundary_reason"] = "file_source field"
        return out
    frame_reset = out["frame_number"].diff() < 0
    time_reset = out["timestamp"].diff() < 0
    boundary = (frame_reset | time_reset).fillna(False)
    out["capture_id"] = prefix + "-" + boundary.cumsum().astype(str)
    reason = np.where(
        frame_reset & time_reset,
        "frame+timestamp reset",
        np.where(frame_reset, "frame_number reset", np.where(time_reset, "timestamp reset", "")),
    )
    out["boundary_reason"] = np.where(boundary, reason, "")
    return out


def add_protocol_basics(df: pd.DataFrame) -> pd.DataFrame:
    """Add function name / operation columns (interpretation of function codes)."""
    out = df.copy()
    out["function_name"] = out["modbus_func_code"].map(FUNCTION_NAMES).fillna("Other/Unknown")
    out["is_write"] = out["modbus_func_code"].isin(WRITE_FUNCTIONS).astype(int)
    return out


def learn_normal_write_combos(baseline: pd.DataFrame) -> list[str]:
    """(function, register) write requests seen in the baseline file.

    The baseline contains only normal traffic, so these are legitimate writes.
    Used to flag attack-labelled writes that look identical to routine writes.
    """
    w = baseline[(baseline["is_request"] == 1) & baseline["modbus_func_code"].isin(WRITE_FUNCTIONS)]
    return sorted({f"{int(f)}:{int(r)}" for f, r in zip(w["modbus_func_code"], w["modbus_ref_num"])})


def map_labels(df: pd.DataFrame, normal_write_combos: list[str]) -> pd.DataFrame:
    """Map dataset labels to research classes with an explicit status.

    class_id: 0 Normal, 1 Command Injection, NaN = excluded/ambiguous.
    label_status documents WHY. Original dataset labels stay untouched.
    """
    out = df.copy()
    n = len(out)
    cls = np.full(n, np.nan)
    status = np.array(["no_label_available"] * n, dtype=object)
    if all(c in out.columns for c in LABEL_COLUMNS):
        atk = out["is_attack"].to_numpy() == 1
        sub = out["attack_sub_type"].astype(str).to_numpy()
        req = out["is_request"].to_numpy() == 1
        fc = out["modbus_func_code"].to_numpy()
        combo = pd.Series(fc.astype(int).astype(str) + ":" + out["modbus_ref_num"].astype(int).astype(str))
        legit_like = combo.isin(set(normal_write_combos)).to_numpy()
        is_write = np.isin(fc, [5, 6])
        status[:] = "unmapped"
        m = ~atk
        cls[m] = 0
        status[m] = "dataset_normal"
        m = atk & ~req
        status[m] = "attack_labelled_response_packet"  # paired, not an event
        m = atk & req & (sub == "Length_Manipulation")
        status[m] = "unsupported_length_manipulation"
        m = atk & req & (sub == "Coil_Brute_Force") & is_write & legit_like
        status[m] = "ambiguous_write_matches_normal_profile"
        m = atk & req & (sub == "Coil_Brute_Force") & is_write & ~legit_like
        cls[m] = 1
        status[m] = "reconstructed_command_injection"
    out["class_id"] = cls
    out["label_status"] = status
    return out


def preprocess_dataset(
    df: pd.DataFrame, source_name: str, capture_prefix: str, normal_write_combos: list[str]
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Full preprocessing for one dataset; returns (packets, invalid_records)."""
    clean, invalid = standardize(df, source_name)
    clean = reconstruct_captures(clean, capture_prefix)
    clean = add_protocol_basics(clean)
    clean = map_labels(clean, normal_write_combos)
    # Chronological order inside each capture; original ids preserved.
    clean = clean.sort_values(["capture_id", "timestamp", "frame_number"], kind="mergesort")
    clean = clean.drop(columns=[c for c in UNUSED_PRECOMPUTED if c in clean.columns])
    return clean.reset_index(drop=True), invalid
