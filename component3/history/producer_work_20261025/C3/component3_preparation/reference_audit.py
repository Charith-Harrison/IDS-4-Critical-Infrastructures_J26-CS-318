"""Read-only diagnostics of historical CIC exports; never creates research rows.

Run from the repository root:
  .venv/Scripts/python.exe component3_preparation/reference_audit.py
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "references" / "component3_reference"
OUT = ROOT / "component3_preparation" / "output" / "reference_audit.json"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inspect(path: Path) -> tuple[pd.DataFrame, dict]:
    frame = pd.read_csv(path)
    fractional = 0
    with path.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            # Check exported text, without pretending to restore lost precision.
            fractional += float(row["timestamp"]) % 1 != 0
    requests = frame[(frame.is_request == 1) & frame.modbus_func_code.isin([1, 2, 3, 4])]
    replies = frame[(frame.is_request == 0) & frame.modbus_func_code.isin([1, 2, 3, 4])]
    quantities = requests.modbus_word_cnt.where(requests.modbus_func_code.isin([3, 4]), requests.modbus_bit_cnt)
    shortcut = frame.modbus_func_code.isin([5, 6]) | (frame.len_discrepancy != 0)
    info = {
        "source": str(path.relative_to(ROOT)),
        "sha256": digest(path),
        "bytes": path.stat().st_size,
        "rows": len(frame),
        "columns": list(frame.columns),
        "column_count": len(frame.columns),
        "timestamp_fractional_rows": int(fractional),
        "timestamp_whole_second_rows": len(frame) - int(fractional),
        "subtype_counts": {str(k): int(v) for k, v in frame.attack_sub_type.value_counts().items()},
        "binary_label_counts": {str(k): int(v) for k, v in frame.is_attack.value_counts().items()},
        "read_requests": len(requests),
        "read_requests_val_equals_requested_quantity": int((requests.modbus_val == quantities).sum()),
        "read_responses": len(replies),
        "read_responses_val_zero": int((replies.modbus_val == 0).sum()),
        "shortcut_rule": "function_code in {5,6} OR len_discrepancy != 0",
        "shortcut_disagreements_with_stored_is_attack": int((shortcut != frame.is_attack.astype(bool)).sum()),
        "normal_labelled_fc5_fc6_rows": int(((frame.is_attack == 0) & frame.modbus_func_code.isin([5, 6])).sum()),
    }
    if "file_source" in frame:
        info["source_counts"] = {str(k): int(v) for k, v in frame.file_source.value_counts().items()}
        blocks = frame.groupby(frame.file_source.ne(frame.file_source.shift()).cumsum(), sort=False)
        info["consecutive_source_blocks"] = [
            {"file_source": str(g.file_source.iloc[0]), "rows": len(g),
             "first_physical_line": int(g.index.min() + 2), "last_physical_line": int(g.index.max() + 2)}
            for _, g in blocks
        ]
        info["inter_arrival_matches_previous_export_row_within_1us"] = int(
            ((frame.timestamp.diff() - frame.inter_arrival_time).abs() < 1e-6).sum()
        )
    return frame, info


def main() -> None:
    baseline, normal_info = inspect(REF / "normal_traffic_baseline.csv")
    attack, attack_info = inspect(REF / "command_response_injection_attacks.csv")
    baseline["_physical_line"] = baseline.index + 2
    attack["_physical_line"] = attack.index + 2
    excluded = {"timestamp", "is_attack", "attack_category", "attack_sub_type", "_physical_line"}
    keys = [c for c in attack.columns if c not in excluded]
    baseline["_rounded_epoch_second"] = baseline.timestamp.round()
    attack["_rounded_epoch_second"] = attack.timestamp
    joined = baseline.merge(attack, on=keys + ["_rounded_epoch_second"], suffixes=("_baseline", "_attack"))
    conflict = joined.is_attack_baseline != joined.is_attack_attack
    fields = ["_physical_line_baseline", "_physical_line_attack", "file_source", "frame_number",
              "mbtcp_trans_id", "modbus_func_code", "timestamp_baseline", "timestamp_attack",
              "is_attack_baseline", "is_attack_attack"]
    originals = ["extract_modbus_features.py", "generate_benign_baseline_dataset.py",
                 "generate_recon_lstm_dataset.py", "finalize_lstm_recon_dataset.py", "walkthrough.md",
                 "normal_sequences_baseline.csv"]
    # Enumerate repository names only; do not open unrelated dataset contents.
    discovered = {name: [] for name in originals}
    for parent, dirs, names in __import__("os").walk(ROOT):
        dirs[:] = [d for d in dirs if d not in {".git", ".venv", "node_modules", "__pycache__"}]
        for name in originals:
            if name in names:
                discovered[name].append(str((Path(parent) / name).relative_to(ROOT)))
    additional = []
    for name in ("normal_traffic_baseline.csv", "command_response_injection_attacks.csv"):
        path = ROOT / "data" / "raw" / name
        if path.is_file():
            _, info = inspect(path)
            info["same_bytes_as_reference_pack_copy"] = digest(path) == digest(REF / name)
            additional.append(info)
    report = {
        "scope": "Diagnostic references only; no derivative rows used in the new extracted event stream",
        "baseline": normal_info, "attack_derivative": attack_info,
        "additional_existing_derivative_copies": additional,
        "overlap": {
            "identity_keys": keys,
            "timestamp_rule": "Round baseline epoch to nearest whole second; attack export already whole seconds",
            "joined_rows": len(joined), "conflicting_binary_labels": int(conflict.sum()),
            "unique_baseline_rows": int(joined._physical_line_baseline.nunique()),
            "unique_attack_rows": int(joined._physical_line_attack.nunique()),
            "examples": joined.loc[conflict, fields].head(6).to_dict("records"),
            "interpretation": "Exact equality on exported fields under stated timestamp rounding, not raw-byte proof",
        },
        "named_historical_files_found": discovered,
        "historical_sequence_count_diagnostic": {
            "global_150000_length20_stride5": (150000 - 20) // 5 + 1,
            "six_blocks_25000_length20_stride5": 6 * ((25000 - 20) // 5 + 1),
            "new_windows_generated": False,
            "interpretation": "Arithmetic comparison only; actual historical membership unavailable",
        },
        "model_preprocessing_or_training_executed": False,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(OUT.relative_to(ROOT)), "baseline_rows": len(baseline),
                      "attack_rows": len(attack), "overlap": len(joined), "conflicts": int(conflict.sum())}))


if __name__ == "__main__":
    main()
