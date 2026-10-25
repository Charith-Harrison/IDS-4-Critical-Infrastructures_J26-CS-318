# Validate, group, and partition the older CSV workflow; this is separate from the frozen testbed experiment.
"""Read-only preprocessing, quarantines, group splits, and provenance manifests."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from src.data_loader import load_csv
from src.event_builder import assign_groups, build_events
from src.label_mapper import class_names, map_labels
from src.schema_validator import normalize_columns, validate_records
from src.utils import PREPROCESSING_VERSION, ROOT, checksum, config_digest, now, project_path, save_json


# Normalize the schema, assign source IDs, validate rows, and keep target handling separate.
def preprocess_frame(frame: pd.DataFrame, cfg: dict, source: str, labelled: bool = True) -> pd.DataFrame:
    out = normalize_columns(frame, cfg["dataset"].get("column_map"))
    if not labelled:
        # Drop labels after alias normalization too: uploads never influence targets.
        out = out.drop(columns=[cfg["dataset"]["label_column"], "is_attack", "attack_sub_type"], errors="ignore")
    # Internal IDs are assigned by us, never trusted from uploads.
    out["source_row"] = np.arange(len(out))
    out["source_file"] = source
    out["event_id"] = source + ":" + out.source_row.astype(str)
    out = validate_records(out, cfg)
    out = assign_groups(out, cfg)
    out = map_labels(out, cfg, required=labelled)
    excluded = out.label_status.eq("excluded_out_of_scope") & out.processing_status.eq("valid")
    out.loc[excluded, "processing_status"] = "excluded"
    out.loc[excluded, "invalid_reason"] = "MSU category 6 or 7 outside component scope"
    return out


# Keep groups whole; use the existing chronological fallback only when its checks pass.
def split_events(frame: pd.DataFrame, cfg: dict) -> tuple[pd.DataFrame, dict]:
    """Keep groups whole; use chronological blocks only when grouping is inadequate.

    Retry group allocations solely for class coverage, never for model scores.
    No feature computation occurs until partitions are fixed.
    """
    out = frame.copy()
    # One supplied capture may be spread across several CSV exports. Keep it in
    # one partition, using the first source's stable ID as the canonical group.
    for method in out.group_method.unique():
        if str(method).startswith("supplied:"):
            column = method.split(":", 1)[1]
            selected = out.group_method.eq(method)
            out.loc[selected, "group_id"] = out.loc[selected].groupby(column, sort=False).group_id.transform("first")
    expected = set(class_names(cfg))
    if set(out.target) != expected:
        raise ValueError(
            f"Training requires all configured classes: {sorted(expected)}; observed {sorted(set(out.target))}"
        )
    split = cfg["split"]
    test_size, val_size = split["test_fraction"], split["validation_fraction"]
    if not 0 < test_size < 1 or not 0 < val_size < 1 - test_size:
        raise ValueError("Invalid train/validation/test fractions")
    eligible_groups = out.group_id.nunique() >= 6 and not out.group_method.eq("source_only").all()
    if eligible_groups:
        for attempt in range(100):
            seed = cfg["random_seed"] + attempt
            development, test = next(
                GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed).split(out, groups=out.group_id)
            )
            dev = out.iloc[development]
            train_local, val_local = next(
                GroupShuffleSplit(n_splits=1, test_size=val_size / (1 - test_size), random_state=seed).split(
                    dev, groups=dev.group_id
                )
            )
            indices = {"train": development[train_local], "validation": development[val_local], "test": test}
            if all(set(out.iloc[ix].target) == expected for ix in indices.values()):
                strategy = "group_holdout_with_class_coverage"
                break
        else:
            raise ValueError(
                "Cannot obtain class-complete disjoint groups. Supply more independent captures; no row-split fallback."
            )
    else:
        if out.timestamp.isna().any():
            raise ValueError("Reliable groups or complete timestamps are required; random row splitting is disabled")
        # Timestamp ties stay on one side of a boundary.
        times = np.sort(out.timestamp.unique())
        a, b = times[int(len(times) * (1 - test_size - val_size))], times[int(len(times) * (1 - test_size))]
        masks = {
            "train": out.timestamp < a,
            "validation": out.timestamp.between(a, b, inclusive="left"),
            "test": out.timestamp >= b,
        }
        indices = {name: np.flatnonzero(mask) for name, mask in masks.items()}
        if not all(set(out.iloc[ix].target) == expected for ix in indices.values()):
            raise ValueError(
                "Chronological partitions lack classes. Supply independent labelled groups; do not manufacture labels."
            )
        strategy, attempt = "chronological_holdout_context_reset", 0
    out["partition"] = ""
    for name, ix in indices.items():
        out.iloc[ix, out.columns.get_loc("partition")] = name
    if strategy.startswith("chronological"):
        out["group_id"] = out.group_id + ":" + out.partition
    summary = {
        "strategy": strategy,
        "allocation_attempt": attempt,
        "random_seed": cfg["random_seed"],
        "limitation": "Inferred reset groups are provisional; this is internal preliminary evaluation, not independent capture validation.",
        "partitions": {
            p: {
                "rows": int((out.partition == p).sum()),
                "groups": sorted(out.loc[out.partition == p, "group_id"].unique()),
                "classes": out.loc[out.partition == p, "target"].value_counts().to_dict(),
            }
            for p in indices
        },
    }
    return out, summary


# Prepare configured inputs and write their partition and provenance records.
def prepare_data(cfg: dict) -> dict:
    from src.experiments import archive_if_changed

    archive_if_changed(cfg)
    inputs, frames = [], []
    for source in cfg["dataset"]["files"]:
        raw = load_csv(source)
        prepared = preprocess_frame(raw, cfg, str(source))
        frames.append(prepared)
        inputs.append({"input_file": source, "sha256": checksum(project_path(source)), "source_rows": len(raw)})
    data = pd.concat(frames, ignore_index=True)
    # Detect duplicate observations independently of labels or source filenames.
    identity = [
        c
        for c in [
            "timestamp",
            "frame_number",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "mbtcp_trans_id",
            "mbtcp_unit_id",
            "modbus_func_code",
            "modbus_ref_num",
            "modbus_val",
            "is_request",
            "modbus_word_cnt",
            "modbus_bit_cnt",
        ]
        if c in data
    ]
    data["observation_hash"] = pd.util.hash_pandas_object(data[identity], index=False).astype(str)
    conflicts = data.groupby("observation_hash").target.transform("nunique") > 1
    duplicates = data.duplicated("observation_hash") & ~conflicts
    data.loc[conflicts, ["processing_status", "invalid_reason"]] = [
        "excluded",
        "conflicting_labels_for_same_observation",
    ]
    data.loc[duplicates & data.processing_status.eq("valid"), ["processing_status", "invalid_reason"]] = [
        "excluded",
        "duplicate_observation",
    ]
    quarantine = data[data.processing_status.ne("valid")].copy()
    clean = data[data.processing_status.eq("valid")].reset_index(drop=True)
    clean, split = split_events(clean, cfg)
    events = pd.concat(
        [build_events(part, cfg) for _, part in clean.groupby("partition", sort=False)], ignore_index=True
    )
    directory = ROOT / "data/processed"
    directory.mkdir(parents=True, exist_ok=True)
    events.to_parquet(directory / "events.parquet", index=False)
    quarantine.to_parquet(directory / "quarantine.parquet", index=False)
    from src.feature_engineering import feature_groups

    manifest = {
        "created_at": now(),
        "preprocessing_version": PREPROCESSING_VERSION,
        "configuration_hash": config_digest(cfg),
        "configuration": cfg,
        "inputs": inputs,
        "source_rows": len(data),
        "retained_rows": len(events),
        "removed_rows": len(quarantine),
        "removal_reasons": quarantine.invalid_reason.value_counts().to_dict(),
        "label_distribution": events.target.value_counts().to_dict(),
        "group_methods": data.group_method.value_counts().to_dict(),
        "pair_status": events.pair_status.value_counts().to_dict(),
        "feature_groups": feature_groups(cfg),
        "split": split,
        "events_sha256": checksum(directory / "events.parquet"),
    }
    save_json(ROOT / "data/manifests/preprocessing.json", manifest)
    save_json(ROOT / "data/manifests/split.json", split)
    return manifest
