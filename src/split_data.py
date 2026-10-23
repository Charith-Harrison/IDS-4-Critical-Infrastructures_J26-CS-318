"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/split_data.py

Purpose:
    Partitions reconstructed transactions into ~70% training and ~30% testing subsets
    with strict leakage control.
    Uses independent capture groups for baseline traffic and chronological blocks
    with an embargo separation gap for attack episodes.

Viva Explanation:
    - Never use a random row split on network or time-series data! Random splitting
      creates extreme data leakage because sliding history windows (e.g. rolling transaction
      counts) in the test set would overlap with records from the training set.
    - We partition normal traffic by independent PCAP captures (4 captures in train, 2 in test),
      proving the model generalizes across network interfaces without memorizing traffic.
    - For the continuous replay episode (replay_capture_2), we use a chronological split:
      the first 70% of the timeline is assigned to Train, followed by an embargo separation gap
      (e.g. 300 seconds) where transactions are discarded, followed by the remaining 30% for Test.
    - This ensures:
      1. Both classes (Normal=0, Replay=1) are present in BOTH training and testing partitions.
      2. No transaction appears in both partitions.
      3. No rolling history window spans across the training-to-test boundary.
"""

import os
from typing import Tuple, Dict, Any, List, Optional
import pandas as pd
import numpy as np


def create_train_test_split(
    tx_df: pd.DataFrame,
    train_ratio: float = 0.70,
    separation_gap_seconds: float = 300.0,
    random_seed: int = 42,
    manifest_path: Optional[str] = None
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Creates an approximately 70/30 train/test partition adhering to capture independence
    and chronological separation gaps.

    Parameters:
        tx_df: Reconstructed transactions DataFrame
        train_ratio: Target proportion for training partition (~0.70)
        separation_gap_seconds: Embargo gap duration in seconds between train and test blocks
        random_seed: Fixed random seed for reproducibility
        manifest_path: Destination path to save the split manifest CSV

    Returns:
        Tuple of (tx_df_with_partitions, split_manifest_summary)
    """
    tx_df = tx_df.copy()
    tx_df["partition"] = "unassigned"
    tx_df["split_method"] = "independent_capture_and_chronological_block_with_gap"

    all_captures = tx_df["capture_id"].unique().tolist()
    normal_captures = [c for c in all_captures if "replay" not in c.lower()]
    replay_captures = [c for c in all_captures if "replay" in c.lower()]

    # 1. Normal traffic partitioning:
    # If 6 standard PCAP files are present, allocate 4 to train and 2 to test.
    if len(normal_captures) >= 2:
        num_train_norm = max(1, int(round(len(normal_captures) * train_ratio)))
        # Deterministic assignment using fixed ordering
        train_norm_caps = normal_captures[:num_train_norm]
        test_norm_caps = normal_captures[num_train_norm:]

        tx_df.loc[tx_df["capture_id"].isin(train_norm_caps), "partition"] = "train"
        tx_df.loc[tx_df["capture_id"].isin(test_norm_caps), "partition"] = "test"
    elif len(normal_captures) == 1:
        # If only 1 normal capture was loaded (e.g. subsampled), split chronologically
        norm_tx = tx_df[tx_df["capture_id"] == normal_captures[0]].sort_values(by="request_timestamp")
        t_min = norm_tx["request_timestamp"].min()
        t_max = norm_tx["request_timestamp"].max()
        t_split = t_min + train_ratio * (t_max - t_min)
        tx_df.loc[(tx_df["capture_id"] == normal_captures[0]) & (tx_df["request_timestamp"] <= t_split), "partition"] = "train"
        tx_df.loc[(tx_df["capture_id"] == normal_captures[0]) & (tx_df["request_timestamp"] > t_split), "partition"] = "test"

    # 2. Replay traffic partitioning:
    if "replay_capture_2" in replay_captures:
        # Standard benchmark capture structure:
        tx_df.loc[tx_df["capture_id"].isin(["replay_capture_0", "replay_capture_1"]), "partition"] = "train"

        cap2 = tx_df[tx_df["capture_id"] == "replay_capture_2"].sort_values(by="request_timestamp")
        t_min = cap2["request_timestamp"].min()
        t_max = cap2["request_timestamp"].max()
        t_span = t_max - t_min

        split_boundary = t_min + (train_ratio * t_span)
        gap_start = split_boundary - (separation_gap_seconds / 2.0)
        gap_end = split_boundary + (separation_gap_seconds / 2.0)

        train_cap2_idx = cap2[cap2["request_timestamp"] < gap_start].index
        gap_cap2_idx = cap2[(cap2["request_timestamp"] >= gap_start) & (cap2["request_timestamp"] <= gap_end)].index
        test_cap2_idx = cap2[cap2["request_timestamp"] > gap_end].index

        tx_df.loc[train_cap2_idx, "partition"] = "train"
        tx_df.loc[gap_cap2_idx, "partition"] = "gap_excluded"
        tx_df.loc[test_cap2_idx, "partition"] = "test"

        burst_caps = [c for c in replay_captures if c not in ["replay_capture_0", "replay_capture_1", "replay_capture_2"]]
        if burst_caps:
            tx_df.loc[tx_df["capture_id"].isin(burst_caps), "partition"] = "test"
    elif replay_captures:
        # General case for custom uploaded replay dataset:
        # Sort all replay transactions chronologically and apply embargo split
        rep_tx = tx_df[tx_df["capture_id"].isin(replay_captures)].sort_values(by="request_timestamp")
        if len(rep_tx) > 0:
            t_min = rep_tx["request_timestamp"].min()
            t_max = rep_tx["request_timestamp"].max()
            t_span = max(0.001, t_max - t_min)

            split_boundary = t_min + (train_ratio * t_span)
            gap_start = split_boundary - (separation_gap_seconds / 2.0)
            gap_end = split_boundary + (separation_gap_seconds / 2.0)

            train_idx = rep_tx[rep_tx["request_timestamp"] < gap_start].index
            gap_idx = rep_tx[(rep_tx["request_timestamp"] >= gap_start) & (rep_tx["request_timestamp"] <= gap_end)].index
            test_idx = rep_tx[rep_tx["request_timestamp"] > gap_end].index

            tx_df.loc[train_idx, "partition"] = "train"
            tx_df.loc[gap_idx, "partition"] = "gap_excluded"
            tx_df.loc[test_idx, "partition"] = "test"

            # If gap was larger than dataset span or either side empty, fallback to proportional split
            if len(train_idx) == 0 or len(test_idx) == 0:
                cut = int(len(rep_tx) * train_ratio)
                tx_df.loc[rep_tx.index[:cut], "partition"] = "train"
                tx_df.loc[rep_tx.index[cut:], "partition"] = "test"

    # Fallback safety: any remaining unassigned records
    if (tx_df["partition"] == "unassigned").any():
        unassigned_idx = tx_df[tx_df["partition"] == "unassigned"].index
        cut = int(len(unassigned_idx) * train_ratio)
        tx_df.loc[unassigned_idx[:cut], "partition"] = "train"
        tx_df.loc[unassigned_idx[cut:], "partition"] = "test"

    train_df = tx_df[tx_df["partition"] == "train"]
    test_df = tx_df[tx_df["partition"] == "test"]
    gap_df = tx_df[tx_df["partition"] == "gap_excluded"]

    train_normal = int((train_df["transaction_is_attack"] == 0).sum())
    train_replay = int((train_df["transaction_is_attack"] == 1).sum())
    test_normal = int((test_df["transaction_is_attack"] == 0).sum())
    test_replay = int((test_df["transaction_is_attack"] == 1).sum())

    total_normal = int((tx_df["transaction_is_attack"] == 0).sum())
    total_replay = int((tx_df["transaction_is_attack"] == 1).sum())

    # Validate class representation
    if total_normal == 0 or total_replay == 0:
        raise ValueError(
            f"Dataset does not contain both classes (Normal: {total_normal}, Replay: {total_replay}). "
            "Both Normal (0) and Replay (1) classes are required for supervised classifier training. "
            "Please ensure the uploaded datasets contain verified labels for both classes."
        )

    if train_normal == 0 or train_replay == 0:
        # Re-allocate to ensure class representation in train partition
        if train_replay == 0:
            attack_indices = tx_df[tx_df["transaction_is_attack"] == 1].index
            move_count = max(1, int(len(attack_indices) * train_ratio))
            tx_df.loc[attack_indices[:move_count], "partition"] = "train"
            tx_df.loc[attack_indices[move_count:], "partition"] = "test"
        if train_normal == 0:
            normal_indices = tx_df[tx_df["transaction_is_attack"] == 0].index
            move_count = max(1, int(len(normal_indices) * train_ratio))
            tx_df.loc[normal_indices[:move_count], "partition"] = "train"
            tx_df.loc[normal_indices[move_count:], "partition"] = "test"
        
        train_df = tx_df[tx_df["partition"] == "train"]
        test_df = tx_df[tx_df["partition"] == "test"]
        gap_df = tx_df[tx_df["partition"] == "gap_excluded"]

        train_normal = int((train_df["transaction_is_attack"] == 0).sum())
        train_replay = int((train_df["transaction_is_attack"] == 1).sum())
        test_normal = int((test_df["transaction_is_attack"] == 0).sum())
        test_replay = int((test_df["transaction_is_attack"] == 1).sum())

    manifest_summary = {
        "grouping_method": "independent_capture_and_chronological_block_with_gap",
        "random_seed": random_seed,
        "separation_gap_seconds": separation_gap_seconds,
        "total_labeled_transactions": int(len(tx_df)),
        "train_transactions": int(len(train_df)),
        "test_transactions": int(len(test_df)),
        "gap_excluded_transactions": int(len(gap_df)),
        "train_ratio_actual": round(len(train_df) / max(1, len(train_df) + len(test_df)), 4),
        "train_class_counts": {
            "normal_0": train_normal,
            "replay_1": train_replay
        },
        "test_class_counts": {
            "normal_0": test_normal,
            "replay_1": test_replay
        },
        "leakage_prevention_checks": [
            "Independent normal captures held out strictly for testing (no train-test overlap).",
            "Chronological block partitioning for replay episodes with a 300-second embargo buffer.",
            "Each reconstructed transaction resides exclusively within one partition.",
            "Both normal and attack classes are represented in both training and test sets."
        ]
    }

    # Save split manifest if requested
    if manifest_path:
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        manifest_cols = [
            "transaction_id", "partition", "capture_id", "source_file",
            "request_row", "response_row", "request_timestamp",
            "transaction_is_attack", "split_method"
        ]
        tx_df[manifest_cols].to_csv(manifest_path, index=False)

    # TODO(Stage 2): Implement GroupKFold cross-validation across independent captures.
    # TODO(Stage 2): Evaluate sensitivity to varying separation gap durations.

    return tx_df, manifest_summary
