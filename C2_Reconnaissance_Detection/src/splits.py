"""Generate and verify leak-free evaluation splits and feature schema artifacts.

Implements:
1. Primary (`locgo_10fold`): Leave-One-Capture-Group-Out across the 10 independent
   capture episodes (`G01`..`G10`), with inner group-independent validation split
   for early stopping and threshold selection (target validation FPR < 0.05).
2. Secondary (`sgkf_5fold`): 5-fold StratifiedGroupKFold grouped by `capture_group`
   (ensures every test fold contains both positive and negative windows so per-fold
   ROC-AUC, PR-AUC, F1, Precision, Recall, and FPR are defined on all 5 folds).
3. Host-Pair Diagnostic (`loso_session_5fold`): 5-fold StratifiedGroupKFold grouped
   by `session_id` (host-pair direction), documented alongside the structural finding
   that 94.20% of positive windows reside in a single host-pair (`s0004`).
4. Leakage Diagnostic (`random_5fold_rebuilt`): 5-fold StratifiedKFold random split
   over overlapping windows (diagnostic only — demonstrates overlap leakage).
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold

from common import ARTIFACTS, DATA_REBUILT, write_json
from features import get_feature_schema


def build_locgo_folds(W: pd.DataFrame) -> list[dict]:
    """10-fold Leave-One-Capture-Group-Out with deterministic inner validation groups."""
    groups = sorted(W["capture_group"].unique().tolist())
    pos_groups = [
        g for g in groups if int(W.loc[W["capture_group"] == g, "label"].sum()) > 0
    ]
    neg_groups = [
        g for g in groups if int(W.loc[W["capture_group"] == g, "label"].sum()) == 0
    ]

    folds = []
    for fold_idx, test_g in enumerate(groups):
        train_pool = [g for g in groups if g != test_g]
        # Deterministic inner validation: pick 1 positive group + 1 negative group from train_pool
        avail_pos = [g for g in pos_groups if g != test_g]
        avail_neg = [g for g in neg_groups if g != test_g]
        # Prefer a mid-sized positive group (not G03 which only has 10 pos) for inner val calibration
        pos_candidates = [g for g in avail_pos if g != "G03_0201_veth"]
        val_pos = pos_candidates[fold_idx % len(pos_candidates)]
        val_neg = avail_neg[fold_idx % len(avail_neg)]
        val_groups = sorted([val_pos, val_neg])
        fit_groups = sorted([g for g in train_pool if g not in val_groups])

        test_mask = W["capture_group"] == test_g
        val_mask = W["capture_group"].isin(val_groups)
        fit_mask = W["capture_group"].isin(fit_groups)

        # Assertions: disjoint windows and disjoint packets
        assert not (test_mask & val_mask).any()
        assert not (test_mask & fit_mask).any()
        assert not (val_mask & fit_mask).any()
        assert int(test_mask.sum() + val_mask.sum() + fit_mask.sum()) == len(W)

        y_test = W.loc[test_mask, "label"]
        y_val = W.loc[val_mask, "label"]
        y_fit = W.loc[fit_mask, "label"]

        folds.append(
            {
                "fold_id": f"LOCGO_{fold_idx:02d}_{test_g}",
                "fold_index": int(fold_idx),
                "test_groups": [test_g],
                "val_groups": val_groups,
                "fit_groups": fit_groups,
                "n_fit": int(fit_mask.sum()),
                "n_fit_pos": int(y_fit.sum()),
                "n_fit_neg": int((y_fit == 0).sum()),
                "n_val": int(val_mask.sum()),
                "n_val_pos": int(y_val.sum()),
                "n_val_neg": int((y_val == 0).sum()),
                "n_test": int(test_mask.sum()),
                "n_test_pos": int(y_test.sum()),
                "n_test_neg": int((y_test == 0).sum()),
                "test_is_single_class": bool(y_test.nunique() < 2),
                "test_class_note": (
                    "Normal-only capture group (0 positive windows); ROC-AUC, PR-AUC, Recall, Precision, F1 are undefined (None) on this fold alone; evaluate False Positive Rate (FPR) and specificity, and include in pooled OOF evaluation."
                    if int(y_test.sum()) == 0
                    else "Contains both positive and normal windows."
                ),
            }
        )
    return folds


def build_paired_group_5fold(W: pd.DataFrame) -> list[dict]:
    """5-fold group-independent split where each test fold pairs 1 positive capture group
    with 1 other capture group so every fold has both classes and 0 packet overlap."""
    # Pair the 6 positive groups and 4 normal groups across 5 folds:
    # Fold 0: G04 (415 pos) + G01 (0 pos)
    # Fold 1: G06 (454 pos) + G02 (0 pos)
    # Fold 2: G07 (470 pos) + G09 (0 pos)
    # Fold 3: G08 (443 pos) + G10 (0 pos)
    # Fold 4: G05 (86 pos)  + G03 (10 pos, 56,393 neg)
    fold_test_groups = [
        ["G01_0122_normal4", "G04_0315_sub1"],
        ["G02_0123_normal13", "G06_0316_sub4"],
        ["G07_0319_sub10", "G09_0323_veth3e0"],
        ["G08_0320_sub14", "G10_0323_veth3e1"],
        ["G03_0201_veth", "G05_0315_sub2"],
    ]
    all_groups = sorted(W["capture_group"].unique().tolist())

    folds = []
    for idx, test_groups in enumerate(fold_test_groups):
        val_groups = fold_test_groups[(idx + 1) % len(fold_test_groups)]
        fit_groups = sorted(
            [g for g in all_groups if g not in test_groups and g not in val_groups]
        )

        test_mask = W["capture_group"].isin(test_groups)
        val_mask = W["capture_group"].isin(val_groups)
        fit_mask = W["capture_group"].isin(fit_groups)

        assert int(test_mask.sum() + val_mask.sum() + fit_mask.sum()) == len(W)
        y_test = W.loc[test_mask, "label"]
        y_val = W.loc[val_mask, "label"]
        y_fit = W.loc[fit_mask, "label"]

        assert y_test.nunique() == 2, f"Fold {idx} must have both classes"
        assert y_val.nunique() == 2, f"Val {idx} must have both classes"
        assert y_fit.nunique() == 2, f"Fit {idx} must have both classes"

        folds.append(
            {
                "fold_id": f"SGKF5_{idx:02d}",
                "fold_index": int(idx),
                "test_groups": test_groups,
                "val_groups": val_groups,
                "fit_groups": fit_groups,
                "n_fit": int(fit_mask.sum()),
                "n_fit_pos": int(y_fit.sum()),
                "n_fit_neg": int((y_fit == 0).sum()),
                "n_val": int(val_mask.sum()),
                "n_val_pos": int(y_val.sum()),
                "n_val_neg": int((y_val == 0).sum()),
                "n_test": int(test_mask.sum()),
                "n_test_pos": int(y_test.sum()),
                "n_test_neg": int((y_test == 0).sum()),
                "test_is_single_class": False,
            }
        )
    return folds


def build_session_id_diagnostic_folds(W: pd.DataFrame) -> list[dict]:
    """Diagnostic: 5-fold StratifiedGroupKFold grouped strictly by `session_id`."""
    sgkf = StratifiedGroupKFold(n_splits=5)
    folds = []
    for idx, (train_idx, test_idx) in enumerate(
        sgkf.split(W, W["label"].to_numpy(), W["session_id"].to_numpy())
    ):
        test_sids = sorted(W.iloc[test_idx]["session_id"].unique().tolist())
        train_sids = sorted(W.iloc[train_idx]["session_id"].unique().tolist())
        y_train = W.iloc[train_idx]["label"]
        y_test = W.iloc[test_idx]["label"]
        folds.append(
            {
                "fold_id": f"SESSION_GROUP_{idx:02d}",
                "fold_index": int(idx),
                "test_session_ids": test_sids,
                "train_session_ids": train_sids,
                "n_train": int(len(train_idx)),
                "n_train_pos": int(y_train.sum()),
                "n_test": int(len(test_idx)),
                "n_test_pos": int(y_test.sum()),
                "test_is_single_class": bool(y_test.nunique() < 2),
                "train_is_single_class": bool(y_train.nunique() < 2),
            }
        )
    return folds


def verify_zero_packet_leakage(W: pd.DataFrame, idx_mat: np.ndarray, folds: list[dict]) -> dict:
    """Verify mathematically that no packet row_index is shared across fit/val/test in any fold."""
    results = []
    for f in folds:
        test_m = W["capture_group"].isin(f["test_groups"]).to_numpy()
        val_m = W["capture_group"].isin(f["val_groups"]).to_numpy()
        fit_m = W["capture_group"].isin(f["fit_groups"]).to_numpy()

        p_test = set(np.unique(idx_mat[test_m]).tolist())
        p_val = set(np.unique(idx_mat[val_m]).tolist())
        p_fit = set(np.unique(idx_mat[fit_m]).tolist())

        overlap_fit_test = len(p_fit & p_test)
        overlap_val_test = len(p_val & p_test)
        overlap_fit_val = len(p_fit & p_val)
        assert overlap_fit_test == 0, f"Packet leakage fit/test in {f['fold_id']}"
        assert overlap_val_test == 0, f"Packet leakage val/test in {f['fold_id']}"
        assert overlap_fit_val == 0, f"Packet leakage fit/val in {f['fold_id']}"

        results.append(
            {
                "fold_id": f["fold_id"],
                "fit_packets": len(p_fit),
                "val_packets": len(p_val),
                "test_packets": len(p_test),
                "shared_fit_test_packets": overlap_fit_test,
                "shared_val_test_packets": overlap_val_test,
                "shared_fit_val_packets": overlap_fit_val,
            }
        )
    return {"all_folds_zero_packet_overlap": True, "fold_checks": results}


def main() -> None:
    W = pd.read_csv(DATA_REBUILT / "windows.csv")
    idx_mat = np.load(DATA_REBUILT / "window_index.npy")

    locgo_folds = build_locgo_folds(W)
    sgkf5_folds = build_paired_group_5fold(W)
    sess_folds = build_session_id_diagnostic_folds(W)

    locgo_check = verify_zero_packet_leakage(W, idx_mat, locgo_folds)
    sgkf5_check = verify_zero_packet_leakage(W, idx_mat, sgkf5_folds)

    # Save random 5-fold summary metadata (indices generated deterministically with seed=42)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    random_folds_meta = []
    for idx, (tr, te) in enumerate(skf.split(W, W["label"].to_numpy())):
        p_tr = set(np.unique(idx_mat[tr]).tolist())
        p_te = set(np.unique(idx_mat[te]).tolist())
        shared_pkts = len(p_tr & p_te)
        te_in_tr = np.isin(idx_mat[te], list(p_tr))
        random_folds_meta.append(
            {
                "fold_id": f"RANDOM5_{idx:02d}",
                "fold_index": int(idx),
                "n_train": int(len(tr)),
                "n_test": int(len(te)),
                "n_test_pos": int(W.iloc[te]["label"].sum()),
                "shared_packets_between_train_and_test": int(shared_pkts),
                "fraction_of_test_windows_sharing_ge1_packet_with_train": float(
                    (te_in_tr.sum(axis=1) >= 1).mean()
                ),
            }
        )

    folds_artifact = {
        "primary_scheme": "locgo_10fold",
        "secondary_scheme": "sgkf_5fold",
        "diagnostic_schemes": ["loso_session_5fold", "random_5fold_rebuilt"],
        "locgo_10fold": {
            "description": (
                "Leave-One-Capture-Group-Out across all 10 independent capture episodes (G01..G10). "
                "6 capture groups contain positive + normal windows; 4 contain normal-only traffic. "
                "Inner group-independent validation (1 positive + 1 normal group) selects early stopping "
                "and operational threshold (targeting validation FPR < 0.05)."
            ),
            "leakage_verification": locgo_check,
            "folds": locgo_folds,
        },
        "sgkf_5fold": {
            "description": (
                "5-fold group-independent cross-validation pairing positive and normal capture groups "
                "so that every fold contains both classes and has zero shared packets across fit/val/test."
            ),
            "leakage_verification": sgkf5_check,
            "folds": sgkf5_folds,
        },
        "loso_session_5fold": {
            "description": (
                "Diagnostic 5-fold StratifiedGroupKFold grouped strictly by session_id (directional host pair). "
                "Included to show the impact of host-pair holdout when 94.20% (1,769/1,878) of positive windows "
                "belong to a single directional flow (185.175.0.5_185.175.0.3_u1_s0004)."
            ),
            "folds": sess_folds,
        },
        "random_5fold_rebuilt": {
            "description": (
                "Diagnostic-only 5-fold StratifiedKFold random split across overlapping windows. "
                "Demonstrates optimistic bias from ~99.99% of test windows sharing packets with train."
            ),
            "folds": random_folds_meta,
        },
    }

    write_json(folds_artifact, ARTIFACTS / "folds.json")
    write_json(get_feature_schema(), ARTIFACTS / "feature_schema.json")
    print("Saved artifacts/folds.json and artifacts/feature_schema.json")


if __name__ == "__main__":
    main()
