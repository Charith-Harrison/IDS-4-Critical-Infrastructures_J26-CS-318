"""Project-wide constants, project-relative paths and the test-partition guard.

All paths are derived from this file's location with pathlib, so the project
works wherever it is copied (no machine-specific paths anywhere).
"""

from __future__ import annotations

import logging
from pathlib import Path

# Project root = two levels above src/utils/config.py
ROOT = Path(__file__).resolve().parents[2]

RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
VALIDATION_DIR = ROOT / "data" / "validation"
SPLITS_DIR = ROOT / "data" / "splits"
MANIFEST_DIR = ROOT / "data" / "manifests"
MODELS_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"
AUDIT_DIR = RESULTS_DIR / "data_audit"
FEATURE_AUDIT_DIR = RESULTS_DIR / "feature_audit"
PROGRESS_DIR = RESULTS_DIR / "progress_70"

BASELINE_CSV = RAW_DIR / "normal_traffic_baseline.csv"
ATTACK_CSV = RAW_DIR / "command_response_injection_attacks.csv"

TRAIN_PARQUET = SPLITS_DIR / "train.parquet"
# The final held-out partition. It must never be read before the final stage.
TEST_PARQUET = SPLITS_DIR / "test.parquet"
TEST_IDS_CSV = MANIFEST_DIR / "test_record_ids.csv"

RANDOM_STATE = 42
FEATURE_SCHEMA_VERSION = "fs-1.0"
MODEL_VERSION = "rp3-progress70-rf-0.1"
MAX_UPLOAD_MB = 50

# Class labels supported by the current progress model (binary).
LABEL_MAPPING = {"0": "Normal", "1": "Command Injection"}
CLASS_NAMES = {0: "Normal", 1: "Command Injection"}

BINARY_LIMITATION = (
    "The current progress model supports Normal and Command Injection only. "
    "Verified response-injection training examples are unavailable in the "
    "supplied datasets, so final three-class implementation remains pending."
)

# Columns that carry labels, file names or identifiers: never model inputs.
FORBIDDEN_FEATURE_COLUMNS = [
    "target_class",
    "class_id",
    "class_name",
    "label",
    "actual_class",
    "predicted_class",
    "attack_sub_type",
    "attack_category",
    "is_attack",
    "file_source",
    "capture_id",
    "source_row",
    "event_id",
    "frame_number",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "mbtcp_trans_id",
    "label_status",
]

FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}
WRITE_FUNCTIONS = {5, 6, 15, 16}
COIL_FUNCTIONS = {1, 2, 5, 15}


def get_logger(name: str) -> logging.Logger:
    """Return a structured logger (timestamp | level | module | message)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    return logging.getLogger(name)


def assert_not_test_path(path: str | Path) -> Path:
    """Raise PermissionError if *path* points at the final test partition.

    Every reader used by the dashboard, inference, training and validation
    code goes through this guard so the 20% partition stays untouched.
    """
    resolved = Path(path).resolve()
    blocked = {TEST_PARQUET.resolve(), TEST_IDS_CSV.resolve()}
    if resolved in blocked or resolved.name.startswith("test."):
        raise PermissionError(f"Access to the final test partition is blocked: {resolved.name}")
    return resolved


def read_parquet_safe(path: str | Path):
    """Read a parquet file after applying the test-partition guard."""
    import pandas as pd

    return pd.read_parquet(assert_not_test_path(path))
