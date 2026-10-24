"""Master end-to-end execution script for the C2 Reconnaissance Detection research pipeline.

Executes in deterministic order:
  1. convert_raw.py       (stream .xlsx originals into data/raw/*.csv with SHA-256 verification)
  2. inspect_data.py      (generate artifacts/dataset_profile.json & tables)
  3. audit_sequences.py   (audit as-provided 175,800 sequences -> artifacts/sequence_audit.json)
  4. audit_labels.py      (audit attack_events_mapped & positive categories -> artifacts/label_audit.json)
  5. rebuild_sequences.py (deduplicate simultaneous veth views & rebuild chronological windows)
  6. audit_leakage.py     (quantify overlap, identifier, and shortcut leakage -> artifacts/leakage_audit.json)
  7. splits.py            (generate and assert zero-packet-overlap folds -> artifacts/folds.json)
  8. baselines.py         (train & evaluate Model A and Model B baselines)
  9. train_lstm.py        (train & evaluate Model C [LSTM Full] and Model D [LSTM No-Timing])
 10. ablations.py         (run shortcut removal, split leakage, as-provided, and window-length ablations)
 11. latency.py           (benchmark preprocessing, inference, and end-to-end latency -> artifacts/latency.json)
 12. explain.py           (consolidate metrics.json, confusion.json, curves.json, predictions.csv, examples, plots)
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from common import ARTIFACTS, DATA_RAW, DATA_REBUILT, ROOT

STEPS = [
    ("convert_raw.py", DATA_RAW / "raw_manifest.json"),
    ("inspect_data.py", ARTIFACTS / "dataset_profile.json"),
    ("audit_sequences.py", ARTIFACTS / "sequence_audit.json"),
    ("audit_labels.py", ARTIFACTS / "label_audit.json"),
    ("rebuild_sequences.py", DATA_REBUILT / "windows.csv"),
    ("audit_leakage.py", ARTIFACTS / "leakage_audit.json"),
    ("splits.py", ARTIFACTS / "folds.json"),
    ("baselines.py", ARTIFACTS / "baseline_metrics.json"),
    ("train_lstm.py", ARTIFACTS / "lstm_metrics.json"),
    ("ablations.py", ARTIFACTS / "ablation_results.json"),
    ("latency.py", ARTIFACTS / "latency.json"),
    ("explain.py", ARTIFACTS / "metrics.json"),
]


def run_step(script_name: str) -> None:
    script_path = ROOT / "src" / script_name
    print(f"\n=== [C2 Pipeline] Running {script_name} ===", flush=True)
    t0 = time.perf_counter()
    res = subprocess.run(
        [sys.executable, "-u", str(script_path)],
        cwd=str(ROOT),
        check=True,
    )
    dt = time.perf_counter() - t0
    print(f"=== [C2 Pipeline] Completed {script_name} in {dt:.1f}s (exit={res.returncode}) ===", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the complete C2 research pipeline.")
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip steps whose primary output artifact already exists.",
    )
    args = parser.parse_args()

    t_start = time.perf_counter()
    for script_name, target_artifact in STEPS:
        if args.skip_existing and Path(target_artifact).exists():
            print(f"[SKIP] {script_name} -> {target_artifact} already exists.", flush=True)
            continue
        run_step(script_name)

    total_s = time.perf_counter() - t_start
    print(f"\nAll C2 pipeline stages completed in {total_s:.1f}s.")


if __name__ == "__main__":
    main()
