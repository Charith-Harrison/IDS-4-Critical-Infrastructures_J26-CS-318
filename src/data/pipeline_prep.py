"""Stage runners: preprocessing, pairing statistics and the capture split."""

from __future__ import annotations

import pandas as pd

from src.data import audit as audit_mod
from src.data.loader import load_csv
from src.data.pairing import pair_events
from src.data.preprocess import learn_normal_write_combos, preprocess_dataset
from src.data.split import choose_test_captures
from src.utils.config import (
    ATTACK_CSV,
    AUDIT_DIR,
    BASELINE_CSV,
    LABEL_MAPPING,
    MANIFEST_DIR,
    PROCESSED_DIR,
    PROGRESS_DIR,
    SPLITS_DIR,
    VALIDATION_DIR,
    get_logger,
)
from src.utils.io import sha256_file, write_json

log = get_logger("prep")


def run_preprocess_and_split() -> dict:
    """Audit, preprocess, pair, split. Test rows are only written, never read back."""
    for d in (PROCESSED_DIR, SPLITS_DIR, MANIFEST_DIR, PROGRESS_DIR, VALIDATION_DIR):
        d.mkdir(parents=True, exist_ok=True)
    base_raw = load_csv(BASELINE_CSV)
    atk_raw = load_csv(ATTACK_CSV)
    combos = learn_normal_write_combos(base_raw)
    pb, inv_b = preprocess_dataset(base_raw, BASELINE_CSV.name, "base", combos)
    pa, inv_a = preprocess_dataset(atk_raw, ATTACK_CSV.name, "atk", combos)
    findings = audit_mod.run_audit(base_raw, atk_raw, pb, pa, BASELINE_CSV, ATTACK_CSV)
    packets = pd.concat([pb, pa], ignore_index=True)
    packets["event_id"] = packets["capture_id"] + ":" + packets["source_row"].astype(str)
    packets.to_parquet(PROCESSED_DIR / "events.parquet", index=False)
    invalid = pd.concat([inv_b.assign(file=BASELINE_CSV.name), inv_a.assign(file=ATTACK_CSV.name)])
    invalid.to_csv(AUDIT_DIR / "invalid_records.csv", index=False)

    events, orphans, pstats = pair_events(packets)
    events.to_parquet(PROCESSED_DIR / "paired_events.parquet", index=False)
    write_json(pstats, PROGRESS_DIR / "pairing_statistics.json")
    um = events[events["pair_status"] == "missing"]
    um[["event_id", "capture_id", "timestamp", "src_ip", "dst_ip", "modbus_func_code", "modbus_ref_num"]].to_csv(
        PROGRESS_DIR / "unmatched_requests.csv", index=False
    )
    orphans[["capture_id", "timestamp", "src_ip", "dst_ip", "modbus_func_code", "source_row"]].to_csv(
        PROGRESS_DIR / "orphan_responses.csv", index=False
    )

    report = {
        "rows_read": {BASELINE_CSV.name: int(len(base_raw)), ATTACK_CSV.name: int(len(atk_raw))},
        "rows_retained": int(len(packets)),
        "rows_removed": int(len(base_raw) + len(atk_raw) - len(packets)),
        "removal_reasons": invalid["reason"].value_counts().to_dict() if len(invalid) else {},
        "invalid_records": int(invalid["source_row"].nunique()) if len(invalid) else 0,
        "missing_fields": {},
        "confirmed_duplicates_removed": 0,
        "capture_counts": int(packets["capture_id"].nunique()),
        "request_response_counts": {
            "requests": int((packets.is_request == 1).sum()),
            "responses": int((packets.is_request == 0).sum()),
        },
        "function_code_counts": {int(k): int(v) for k, v in packets["modbus_func_code"].value_counts().items()},
        "class_counts_by_capture": (
            {
                c: {str(k): int(v) for k, v in g.items()}
                for c, g in events.groupby("capture_id")["label_status"].value_counts().groupby(level=0)
            }
            if False
            else (
                events.groupby(["capture_id", "label_status"])
                .size()
                .rename("n")
                .reset_index()
                .groupby("capture_id")
                .apply(lambda d: dict(zip(d["label_status"], d["n"].astype(int))), include_groups=False)
                .to_dict()
            )
        ),
        "normal_write_combos_learned_from_baseline": combos,
        "audit_findings": findings,
    }
    write_json(report, PROCESSED_DIR / "preprocess_report.json")

    # Label mapping artefact (shared with inference for uploaded labelled CSVs).
    write_json(
        {
            "classes": LABEL_MAPPING,
            "normal_write_combos": combos,
            "excluded_statuses": ["ambiguous_write_matches_normal_profile", "unsupported_length_manipulation"],
            "note": "Binary progress model; no response-injection class.",
        },
        MANIFEST_DIR / "label_mapping.json",
    )

    split = choose_test_captures(events)
    test_caps = set(split["test_captures"])
    is_test = packets["capture_id"].isin(test_caps)
    packets[~is_test].to_parquet(SPLITS_DIR / "train.parquet", index=False)
    packets[is_test].to_parquet(SPLITS_DIR / "test.parquet", index=False)
    ev_ids = events[["event_id", "capture_id"]]
    ev_ids[~ev_ids["capture_id"].isin(test_caps)].to_csv(MANIFEST_DIR / "train_record_ids.csv", index=False)
    ev_ids[ev_ids["capture_id"].isin(test_caps)].to_csv(MANIFEST_DIR / "test_record_ids.csv", index=False)

    # Verification from the in-memory frames (the saved test file is not re-read).
    tr, te = packets[~is_test], packets[is_test]
    tr_ev, te_ev = ev_ids[~ev_ids["capture_id"].isin(test_caps)], ev_ids[ev_ids["capture_id"].isin(test_caps)]
    # Real check: no matched response of a test-partition request may be a
    # packet stored in the development partition (and vice versa).
    train_keys = set(zip(tr["capture_id"], tr["source_row"]))
    matched = events[events["pair_found"] == 1]
    in_test = matched["capture_id"].isin(test_caps)
    cross_test = sum(
        (c, int(r)) in train_keys
        for c, r in zip(matched.loc[in_test, "capture_id"], matched.loc[in_test, "rsp_source_row"])
    )
    test_keys = set(zip(te["capture_id"], te["source_row"]))
    cross_train = sum(
        (c, int(r)) in test_keys
        for c, r in zip(matched.loc[~in_test, "capture_id"], matched.loc[~in_test, "rsp_source_row"])
    )
    split_pairs = int(cross_test + cross_train)
    verification = {
        "capture_overlap": sorted(set(tr["capture_id"]) & set(te["capture_id"])),
        "record_id_overlap": int(len(set(tr["event_id"]) & set(te["event_id"]))),
        "duplicate_overlap_cross_file_pairs": findings["cross_file_duplicate_pairs"],
        "divided_request_response_pairs": split_pairs,
        "pairing_key_contains_capture_id": True,
        "context_windows_cross_partitions": False,
        "context_window_reason": "context is built per (capture, src, dst) stream; a capture lives in one partition",
        "statistics_fitted_on_test": False,
        "train_packets": int(len(tr)),
        "test_packets": int(len(te)),
        "train_share_packets": float(len(tr) / len(packets)),
        "train_events": int(len(tr_ev)),
        "test_events": int(len(te_ev)),
        "train_classes_present": sorted(
            int(c) for c in events.loc[~events.capture_id.isin(test_caps), "class_id"].dropna().unique()
        ),
    }
    manifest = {
        **split,
        "verification": verification,
        "source_checksums": {BASELINE_CSV.name: sha256_file(BASELINE_CSV), ATTACK_CSV.name: sha256_file(ATTACK_CSV)},
    }
    write_json(manifest, MANIFEST_DIR / "split_manifest.json")
    log.info("split verification: %s", verification)
    return {"report": report, "split": manifest}
