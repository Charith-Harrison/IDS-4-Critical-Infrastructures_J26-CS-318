"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/data_cleaning.py

Purpose:
    Provides automated and configurable data cleaning and preprocessing for ingested
    industrial network datasets. Identifies and removes duplicate records, handles missing
    values, validates and standardizes timestamps, ensures strict chronological ordering,
    audits inconsistent attack annotations, and excludes corrupted or invalid Modbus frames.

Viva Explanation:
    - In operational ICS/SCADA systems, network captures frequently suffer from packet
      duplications caused by SPAN/mirror port misconfigurations, corrupted packet lengths,
      or unsynchronized clocks.
    - Data cleaning must distinguish between exact duplicate packet captures (which should be
      scrutinized/removed) and legitimate repeated Modbus polling requests (which must be
      preserved to accurately measure command frequency anomalies).
    - Cleaning decisions are tracked transparently in metadata to maintain scientific rigor.
"""

import os
from typing import Dict, Any, Tuple, Optional, List
import pandas as pd
import numpy as np


def analyze_cleaning_candidates(
    df_normal: pd.DataFrame,
    df_replay: pd.DataFrame
) -> Dict[str, Any]:
    """
    Analyzes raw datasets to identify potential data quality anomalies requiring cleaning.

    Parameters:
        df_normal: Raw normal baseline DataFrame.
        df_replay: Raw replay attack DataFrame.

    Returns:
        Dictionary containing counts of duplicate records, missing values, timestamp anomalies,
        and inconsistent labels.
    """
    # 1. Exact Duplicates
    norm_exact_dups = int(df_normal.duplicated().sum()) if len(df_normal) > 0 else 0
    rep_exact_dups = int(df_replay.duplicated().sum()) if len(df_replay) > 0 else 0

    # 2. Missing Values across critical fields
    critical_cols = ["timestamp", "src_ip", "dst_ip", "mbtcp_trans_id", "modbus_func_code", "is_request"]
    norm_crit_nulls = int(df_normal[critical_cols].isnull().any(axis=1).sum()) if set(critical_cols).issubset(df_normal.columns) else 0
    rep_crit_nulls = int(df_replay[critical_cols].isnull().any(axis=1).sum()) if set(critical_cols).issubset(df_replay.columns) else 0

    # 3. Timestamp monotonicity checks
    norm_chrono_inverted = 0
    if "timestamp" in df_normal.columns and len(df_normal) > 1:
        norm_ts = df_normal["timestamp"].values
        norm_chrono_inverted = int((norm_ts[1:] < norm_ts[:-1]).sum())

    rep_chrono_inverted = 0
    if "timestamp" in df_replay.columns and len(df_replay) > 1:
        rep_ts = df_replay["timestamp"].values
        rep_chrono_inverted = int((rep_ts[1:] < rep_ts[:-1]).sum())

    # 4. Inconsistent labels in replay
    inconsistent_labels = 0
    if "is_attack" in df_replay.columns and "attack_category" in df_replay.columns:
        mismatch_mask = (
            ((df_replay["is_attack"] == 1) & (df_replay["attack_category"] == "Normal")) |
            ((df_replay["is_attack"] == 0) & (df_replay["attack_category"] != "Normal"))
        )
        inconsistent_labels = int(mismatch_mask.sum())

    # 5. Invalid Modbus TID / Port values
    invalid_frames = 0
    for df in [df_normal, df_replay]:
        if "mbtcp_trans_id" in df.columns:
            invalid_frames += int(((df["mbtcp_trans_id"] < 0) | (df["mbtcp_trans_id"] > 65535)).sum())
        if "modbus_func_code" in df.columns:
            invalid_frames += int(((df["modbus_func_code"] < 1) | (df["modbus_func_code"] > 127)).sum())

    return {
        "exact_duplicates": {
            "normal": norm_exact_dups,
            "replay": rep_exact_dups,
            "total": norm_exact_dups + rep_exact_dups
        },
        "critical_missing_records": {
            "normal": norm_crit_nulls,
            "replay": rep_crit_nulls,
            "total": norm_crit_nulls + rep_crit_nulls
        },
        "chronological_inversions": {
            "normal": norm_chrono_inverted,
            "replay": rep_chrono_inverted,
            "total": norm_chrono_inverted + rep_chrono_inverted
        },
        "inconsistent_label_records": inconsistent_labels,
        "invalid_protocol_frames": invalid_frames,
        "is_cleaning_recommended": bool(
            (norm_exact_dups + rep_exact_dups > 0) or
            (norm_crit_nulls + rep_crit_nulls > 0) or
            (norm_chrono_inverted + rep_chrono_inverted > 0) or
            (inconsistent_labels > 0) or
            (invalid_frames > 0)
        )
    }


def clean_datasets(
    df_normal: pd.DataFrame,
    df_replay: pd.DataFrame,
    options: Optional[Dict[str, bool]] = None
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """
    Applies configurable cleaning and preprocessing transformations to the datasets.

    Parameters:
        df_normal: Raw normal traffic DataFrame.
        df_replay: Raw replay traffic DataFrame.
        options: Dictionary of cleaning flags:
            - remove_duplicates: bool (default True)
            - handle_missing: bool (default True)
            - validate_timestamps: bool (default True)
            - sort_chronological: bool (default True)
            - inspect_inconsistent_labels: bool (default True)
            - exclude_invalid: bool (default True)

    Returns:
        Tuple of:
            cleaned_df_normal: Preprocessed normal DataFrame.
            cleaned_df_replay: Preprocessed replay DataFrame.
            summary: Detailed audit summary of rows removed or transformed.
    """
    opts = {
        "remove_duplicates": True,
        "handle_missing": True,
        "validate_timestamps": True,
        "sort_chronological": True,
        "inspect_inconsistent_labels": True,
        "exclude_invalid": True
    }
    if options:
        opts.update(options)

    norm = df_normal.copy()
    rep = df_replay.copy()

    initial_norm_count = len(norm)
    initial_rep_count = len(rep)

    duplicates_removed_norm = 0
    duplicates_removed_rep = 0
    missing_handled_norm = 0
    missing_handled_rep = 0
    invalid_frames_removed = 0

    # 1. Remove exact duplicate records if enabled
    if opts.get("remove_duplicates"):
        before_n = len(norm)
        norm = norm.drop_duplicates().reset_index(drop=True)
        duplicates_removed_norm = before_n - len(norm)

        before_r = len(rep)
        rep = rep.drop_duplicates().reset_index(drop=True)
        duplicates_removed_rep = before_r - len(rep)

    # 2. Handle missing values
    critical_cols = ["timestamp", "src_ip", "dst_ip", "mbtcp_trans_id", "modbus_func_code", "is_request"]
    if opts.get("handle_missing"):
        avail_norm_crit = [c for c in critical_cols if c in norm.columns]
        if avail_norm_crit:
            before_n = len(norm)
            norm = norm.dropna(subset=avail_norm_crit).reset_index(drop=True)
            missing_handled_norm = before_n - len(norm)

        avail_rep_crit = [c for c in critical_cols if c in rep.columns]
        if avail_rep_crit:
            before_r = len(rep)
            rep = rep.dropna(subset=avail_rep_crit).reset_index(drop=True)
            missing_handled_rep = before_r - len(rep)

        # Impute non-critical numeric columns with 0
        numeric_cols_norm = norm.select_dtypes(include=[np.number]).columns
        norm[numeric_cols_norm] = norm[numeric_cols_norm].fillna(0)
        numeric_cols_rep = rep.select_dtypes(include=[np.number]).columns
        rep[numeric_cols_rep] = rep[numeric_cols_rep].fillna(0)

    # 3. Validate timestamp formats
    if opts.get("validate_timestamps"):
        for df in [norm, rep]:
            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce")
        norm = norm.dropna(subset=["timestamp"]).reset_index(drop=True)
        rep = rep.dropna(subset=["timestamp"]).reset_index(drop=True)

    # 4. Exclude invalid protocol frames (corrupted TIDs or out-of-range func codes)
    if opts.get("exclude_invalid"):
        if "mbtcp_trans_id" in norm.columns and "modbus_func_code" in norm.columns:
            valid_mask = (
                (norm["mbtcp_trans_id"] >= 0) & (norm["mbtcp_trans_id"] <= 65535) &
                (norm["modbus_func_code"] >= 1) & (norm["modbus_func_code"] <= 127)
            )
            invalid_frames_removed += int((~valid_mask).sum())
            norm = norm[valid_mask].reset_index(drop=True)

        if "mbtcp_trans_id" in rep.columns and "modbus_func_code" in rep.columns:
            valid_mask = (
                (rep["mbtcp_trans_id"] >= 0) & (rep["mbtcp_trans_id"] <= 65535) &
                (rep["modbus_func_code"] >= 1) & (rep["modbus_func_code"] <= 127)
            )
            invalid_frames_removed += int((~valid_mask).sum())
            rep = rep[valid_mask].reset_index(drop=True)

    # 5. Sort records chronologically
    if opts.get("sort_chronological"):
        if "timestamp" in norm.columns:
            norm = norm.sort_values(by="timestamp", ascending=True).reset_index(drop=True)
        if "timestamp" in rep.columns:
            rep = rep.sort_values(by="timestamp", ascending=True).reset_index(drop=True)

    # 6. Re-index original_row_id and frame_number to ensure sequence continuity
    if "original_row_id" in norm.columns:
        norm["original_row_id"] = np.arange(len(norm))
    if "original_row_id" in rep.columns:
        rep["original_row_id"] = np.arange(len(rep))

    summary: Dict[str, Any] = {
        "applied_options": opts,
        "initial_records": {
            "normal": initial_norm_count,
            "replay": initial_rep_count,
            "total": initial_norm_count + initial_rep_count
        },
        "cleaned_records": {
            "normal": len(norm),
            "replay": len(rep),
            "total": len(norm) + len(rep)
        },
        "transformations": {
            "duplicates_removed": duplicates_removed_norm + duplicates_removed_rep,
            "missing_records_handled": missing_handled_norm + missing_handled_rep,
            "invalid_frames_excluded": invalid_frames_removed,
            "total_records_removed": (initial_norm_count + initial_rep_count) - (len(norm) + len(rep))
        },
        "status": "success"
    }

    return norm, rep, summary
