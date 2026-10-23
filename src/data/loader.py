"""CSV loading, file validation and schema validation.

Used by training (raw datasets) and by dashboard uploads so both paths apply
identical checks before any processing happens.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from src.utils.config import MAX_UPLOAD_MB

# Raw columns required to build any feature (labels are optional).
REQUIRED_COLUMNS = [
    "frame_number",
    "timestamp",
    "frame_len",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "payload_len",
    "is_request",
    "tcp_flags_syn",
    "tcp_flags_ack",
    "tcp_flags_fin",
    "tcp_flags_rst",
    "tcp_flags_psh",
    "mbtcp_trans_id",
    "mbtcp_proto_id",
    "mbtcp_len",
    "mbtcp_unit_id",
    "modbus_func_code",
    "is_exception",
    "modbus_exception_code",
    "modbus_ref_num",
    "modbus_word_cnt",
    "modbus_bit_cnt",
    "modbus_byte_cnt",
    "modbus_val",
    "len_discrepancy",
    "has_stacked_frames",
]
STRING_COLUMNS = ["src_ip", "dst_ip"]
LABEL_COLUMNS = ["attack_sub_type", "is_attack", "attack_category"]
# Dataset-supplied columns that are not used (derivation not verifiable).
UNUSED_PRECOMPUTED = ["inter_arrival_time", "packet_rate_1s", "response_time", "trans_id_diff"]


class DataValidationError(ValueError):
    """Raised when a file or schema fails validation."""


def validate_file(path: str | Path, max_mb: float = MAX_UPLOAD_MB) -> Path:
    """Check that *path* exists, is a non-empty .csv and below the size limit."""
    p = Path(path)
    if not p.exists():
        raise DataValidationError(f"File not found: {p.name}")
    if p.suffix.lower() != ".csv":
        raise DataValidationError("Only .csv files are accepted.")
    size = p.stat().st_size
    if size == 0:
        raise DataValidationError("The CSV file is empty.")
    if size > max_mb * 1024 * 1024:
        raise DataValidationError(f"File exceeds the {max_mb} MB limit.")
    return p


def validate_schema(df: pd.DataFrame) -> dict:
    """Return {'ok', 'missing', 'has_labels'}; raises on empty frames."""
    if df is None or len(df) == 0:
        raise DataValidationError("The CSV contains no records.")
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    return {
        "ok": not missing,
        "missing": missing,
        "has_labels": all(c in df.columns for c in LABEL_COLUMNS),
    }


def load_csv(path: str | Path, max_mb: float = MAX_UPLOAD_MB * 10) -> pd.DataFrame:
    """Validate a CSV path then load it (raw strings are preserved as read)."""
    p = validate_file(path, max_mb=max_mb)
    try:
        df = pd.read_csv(p)
    except pd.errors.EmptyDataError as exc:
        raise DataValidationError("The CSV contains no data.") from exc
    except Exception as exc:  # malformed CSV
        raise DataValidationError(f"CSV could not be parsed: {exc}") from exc
    validate_schema(df)
    return df


def validate_upload(name: str, data: bytes, max_mb: float = MAX_UPLOAD_MB) -> pd.DataFrame:
    """Validate an uploaded CSV held in memory; never writes it to disk."""
    import io

    if not name.lower().endswith(".csv"):
        raise DataValidationError("Only .csv files are accepted.")
    if len(data) == 0:
        raise DataValidationError("The CSV file is empty.")
    if len(data) > max_mb * 1024 * 1024:
        raise DataValidationError(f"File exceeds the {max_mb} MB limit.")
    try:
        df = pd.read_csv(io.BytesIO(data))
    except Exception as exc:
        raise DataValidationError(f"CSV could not be parsed: {exc}") from exc
    info = validate_schema(df)
    if not info["ok"]:  # reject incompatible files before any processing
        raise DataValidationError("Missing required columns: " + ", ".join(info["missing"]))
    return df
