"""
Protocol-Aware Replay Attack Detection for Modbus/TCP
Module: src/data_loader.py

Purpose:
    Handles ingestion of raw network traffic datasets (both CSV extracts and PCAP captures).
    Provides file validation, column schema mapping, capture boundary detection,
    and provenance tracking for both baseline normal traffic and replay attack traffic.

Academic Context:
    - Modbus/TCP datasets in industrial control systems research come in diverse formats:
      standard CSV logs or raw PCAP/PCAPNG packet traces.
    - This loader standardizes heterogeneous schemas into a unified, protocol-compliant
      representation with verified MBAP headers, Modbus PDUs, timestamps, and row identifiers.
    - It preserves dataset provenance: records are never assigned labels based on filenames.
      Where ground truth is absent (such as unannotated PCAP captures), records are marked
      as unlabeled (-1 / Unknown) rather than fabricating ground-truth annotations.
"""

import json
import os
from typing import Tuple, Dict, Any, Optional, List
import pandas as pd
import numpy as np

from src.pcap_loader import load_pcap_to_dataframe, is_valid_pcap_signature

# Maximum allowed file size: 200 MB in bytes
MAX_UPLOAD_SIZE_BYTES = 200 * 1024 * 1024

# Column aliases for mapping heterogeneous CSV schemas to standard protocol fields
COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "frame.time_epoch", "epoch_time", "ts", "date_time"],
    "frame_number": ["frame_number", "frame.number", "frame_no", "packet_number", "packet_id", "index"],
    "src_ip": ["src_ip", "ip.src", "source_ip", "srcip", "client_ip", "source_address"],
    "dst_ip": ["dst_ip", "ip.dst", "destination_ip", "dstip", "server_ip", "destination_address"],
    "src_port": ["src_port", "tcp.srcport", "source_port", "sport", "client_port"],
    "dst_port": ["dst_port", "tcp.dstport", "destination_port", "dport", "server_port"],
    "mbtcp_trans_id": ["mbtcp_trans_id", "mbtcp.trans_id", "trans_id", "transaction_id", "tid", "mbtcp_transaction_id"],
    "mbtcp_unit_id": ["mbtcp_unit_id", "mbtcp.unit_id", "unit_id", "slave_id", "device_id"],
    "modbus_func_code": ["modbus_func_code", "modbus.func_code", "func_code", "function_code", "fc"],
    "modbus_ref_num": ["modbus_ref_num", "modbus.reference_num", "ref_num", "register_address", "register"],
    "modbus_word_cnt": ["modbus_word_cnt", "modbus.word_cnt", "word_cnt", "quantity", "length_words"],
    "modbus_bit_cnt": ["modbus_bit_cnt", "modbus.bit_cnt", "bit_cnt", "coil_count", "quantity_bits"],
    "modbus_val": ["modbus_val", "modbus.val", "val", "value", "write_value"],
    "payload_len": ["payload_len", "tcp.len", "length", "len", "bytes"],
    "is_request": ["is_request", "direction", "query_response", "is_query"],
    "is_attack": ["is_attack", "label", "class", "target", "attack", "ground_truth"],
    "attack_category": ["attack_category", "category", "attack_type", "type"],
    "attack_sub_type": ["attack_sub_type", "sub_type", "subtype", "attack_detail"],
    "file_source": ["file_source", "pcap_source", "capture_source", "capture_id"]
}


def get_active_dataset_config_path(project_root: str) -> str:
    """Returns the persistent JSON file path tracking user-uploaded active datasets."""
    return os.path.join(project_root, "uploads", "active_dataset.json")


def load_active_dataset_config(project_root: str) -> Dict[str, Any]:
    """
    Reads the active dataset configuration. If no custom datasets have been uploaded,
    returns default paths pointing to the benchmark CIC Modbus 2023 CSV files.
    """
    cfg_path = get_active_dataset_config_path(project_root)
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    # Default fallback to benchmark CSV files
    return {
        "normal_path": "normal_traffic_baseline.csv",
        "replay_path": "replay_attacks.csv",
        "normal_filename": "normal_traffic_baseline.csv",
        "replay_filename": "replay_attacks.csv",
        "normal_type": "csv",
        "replay_type": "csv",
        "normal_size": os.path.getsize(os.path.join(project_root, "normal_traffic_baseline.csv")) if os.path.exists(os.path.join(project_root, "normal_traffic_baseline.csv")) else 0,
        "replay_size": os.path.getsize(os.path.join(project_root, "replay_attacks.csv")) if os.path.exists(os.path.join(project_root, "replay_attacks.csv")) else 0,
        "is_custom_uploaded": False
    }


def save_active_dataset_config(project_root: str, cfg: Dict[str, Any]) -> None:
    """Persists active dataset paths and upload metadata to JSON."""
    cfg_path = get_active_dataset_config_path(project_root)
    os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def reset_active_dataset_config(project_root: str) -> Dict[str, Any]:
    """Resets the active dataset configuration back to the default benchmark CSV files."""
    cfg = {
        "normal_path": "normal_traffic_baseline.csv",
        "replay_path": "replay_attacks.csv",
        "normal_filename": "normal_traffic_baseline.csv",
        "replay_filename": "replay_attacks.csv",
        "normal_type": "csv",
        "replay_type": "csv",
        "normal_size": os.path.getsize(os.path.join(project_root, "normal_traffic_baseline.csv")) if os.path.exists(os.path.join(project_root, "normal_traffic_baseline.csv")) else 0,
        "replay_size": os.path.getsize(os.path.join(project_root, "replay_attacks.csv")) if os.path.exists(os.path.join(project_root, "replay_attacks.csv")) else 0,
        "is_custom_uploaded": False
    }
    save_active_dataset_config(project_root, cfg)
    return cfg


def resolve_file_path(path: str, base_dir: Optional[str] = None) -> str:
    """
    Resolves relative or absolute paths against the project root or current directory.
    """
    if os.path.isabs(path) and os.path.exists(path):
        return path

    if os.path.exists(path):
        return os.path.abspath(path)

    if base_dir:
        candidate = os.path.join(base_dir, path)
        if os.path.exists(candidate):
            return os.path.abspath(candidate)

    basename = os.path.basename(path)
    if os.path.exists(basename):
        return os.path.abspath(basename)

    if base_dir:
        candidate_base = os.path.join(base_dir, basename)
        if os.path.exists(candidate_base):
            return os.path.abspath(candidate_base)

    raise FileNotFoundError(f"Cannot resolve dataset file: '{path}'. Checked local and base directories.")


def map_columns_to_standard_schema(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, str]]:
    """
    Maps heterogeneous column headers to the standardized Modbus protocol schema
    using flexible alias definitions.

    Parameters:
        df: Input DataFrame.

    Returns:
        Tuple of (normalized_df, mapping_report)
    """
    normalized_df = df.copy()
    lower_cols = {col.lower().strip(): col for col in df.columns}
    mapping_report: Dict[str, str] = {}

    for standard_name, aliases in COLUMN_ALIASES.items():
        if standard_name in normalized_df.columns:
            mapping_report[standard_name] = standard_name
            continue

        matched_original = None
        for alias in aliases:
            if alias.lower() in lower_cols:
                matched_original = lower_cols[alias.lower()]
                break

        if matched_original:
            normalized_df[standard_name] = normalized_df[matched_original]
            mapping_report[standard_name] = matched_original

    # Provide defaults for non-critical missing numeric fields
    defaults = {
        "modbus_ref_num": 0.0,
        "modbus_word_cnt": 0.0,
        "modbus_bit_cnt": 0.0,
        "modbus_val": 0.0,
        "payload_len": 12.0,
        "is_attack": -1,
        "attack_category": "Unknown",
        "attack_sub_type": "Unknown"
    }
    for field, d_val in defaults.items():
        if field not in normalized_df.columns:
            normalized_df[field] = d_val

    # Ensure direction is mapped
    if "is_request" not in normalized_df.columns:
        if "dst_port" in normalized_df.columns:
            normalized_df["is_request"] = (normalized_df["dst_port"].astype(str) == "502").astype(int)
        else:
            normalized_df["is_request"] = 1

    return normalized_df, mapping_report


def validate_dataset_file(file_path: str) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validates an uploaded file's extension, size, signature, and preliminary protocol fields.

    Parameters:
        file_path: Path to the target file.

    Returns:
        Tuple of (is_valid, message, metadata_summary)
    """
    if not os.path.exists(file_path):
        return False, f"File does not exist: {file_path}", {}

    file_size = os.path.getsize(file_path)
    if file_size > MAX_UPLOAD_SIZE_BYTES:
        return False, f"File size exceeds 200 MB limit ({file_size / (1024*1024):.1f} MB).", {}

    if file_size == 0:
        return False, "File is completely empty (0 bytes).", {}

    ext = os.path.splitext(file_path)[1].lower()

    if ext in (".pcap", ".pcapng"):
        if not is_valid_pcap_signature(file_path):
            return False, "File extension is PCAP, but the binary magic signature is invalid or corrupted.", {}
        return True, "Valid PCAP network capture file verified.", {
            "format": "pcap",
            "size_bytes": file_size,
            "size_formatted": f"{file_size / (1024*1024):.2f} MB"
        }

    elif ext == ".csv":
        try:
            # Read first few lines to verify CSV syntax and header
            preview = pd.read_csv(file_path, nrows=5)
            if preview.shape[1] < 3:
                return False, f"CSV contains only {preview.shape[1]} columns. Expected Modbus protocol headers.", {}
            return True, f"Valid CSV file verified ({preview.shape[1]} columns detected).", {
                "format": "csv",
                "size_bytes": file_size,
                "size_formatted": f"{file_size / (1024*1024):.2f} MB",
                "detected_columns": list(preview.columns)
            }
        except Exception as e:
            return False, f"CSV validation error: Unable to parse file headers ({str(e)}).", {}

    else:
        return False, f"Unsupported file extension '{ext}'. Only .csv, .pcap, and .pcapng files are supported.", {}


def load_single_dataset(
    file_path: str,
    dataset_category: str,
    max_rows: Optional[int] = None,
    base_dir: Optional[str] = None
) -> Tuple[pd.DataFrame, Dict[str, Any]]:
    """
    Loads a single dataset (either CSV or PCAP) into a standardized DataFrame.
    """
    abs_path = resolve_file_path(file_path, base_dir)
    ext = os.path.splitext(abs_path)[1].lower()

    if ext in (".pcap", ".pcapng"):
        df = load_pcap_to_dataframe(abs_path, dataset_category=dataset_category, max_packets=max_rows)
        meta = {
            "format": "pcap",
            "filename": os.path.basename(abs_path),
            "rows": len(df),
            "size_bytes": os.path.getsize(abs_path)
        }
        return df, meta

    # CSV path: use chunking for large files to avoid OOM
    if os.path.getsize(abs_path) > 50 * 1024 * 1024:
        chunks = []
        rows_read = 0
        for chunk in pd.read_csv(abs_path, chunksize=50000):
            chunks.append(chunk)
            rows_read += len(chunk)
            if max_rows and rows_read >= max_rows:
                break
        df = pd.concat(chunks, ignore_index=True)
        if max_rows:
            df = df.iloc[:max_rows]
    else:
        df = pd.read_csv(abs_path, nrows=max_rows)

    df["source_file"] = os.path.basename(abs_path)
    df["original_row_id"] = df.index
    df["dataset_category"] = dataset_category

    # Map headers to standard protocol columns
    df, _ = map_columns_to_standard_schema(df)

    meta = {
        "format": "csv",
        "filename": os.path.basename(abs_path),
        "rows": len(df),
        "size_bytes": os.path.getsize(abs_path)
    }
    return df, meta


def load_datasets(
    normal_csv_path: str,
    replay_csv_path: str,
    normal_max_rows: Optional[int] = None,
    inter_capture_gap_seconds: float = 100.0,
    base_dir: Optional[str] = None
) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
    """
    Loads normal and replay datasets (supporting both CSV and PCAP), attaches provenance
    metadata, and partitions replay records into capture segments based on discontinuities.

    Parameters:
        normal_csv_path: Path to normal traffic file (.csv or .pcap)
        replay_csv_path: Path to replay traffic file (.csv or .pcap)
        normal_max_rows: Maximum normal rows to read (None reads full dataset)
        inter_capture_gap_seconds: Time gap indicating distinct capture sessions
        base_dir: Optional base directory for path resolution

    Returns:
        Tuple of (df_normal, df_replay, load_summary)
    """
    df_normal, norm_meta = load_single_dataset(
        file_path=normal_csv_path,
        dataset_category="normal_traffic",
        max_rows=normal_max_rows,
        base_dir=base_dir
    )

    df_replay, rep_meta = load_single_dataset(
        file_path=replay_csv_path,
        dataset_category="replay_traffic",
        max_rows=None,
        base_dir=base_dir
    )

    # Provenance tracking:
    # If file_source exists, use it as capture_id.
    # Otherwise, detect discontinuities to segment distinct sessions.
    if "file_source" in df_normal.columns and df_normal["file_source"].notna().any():
        df_normal["capture_id"] = df_normal["file_source"].astype(str)
    elif "capture_id" not in df_normal.columns:
        df_normal["capture_id"] = f"normal_{norm_meta['filename']}"

    if "file_source" in df_replay.columns and df_replay["file_source"].notna().any():
        df_replay["capture_id"] = df_replay["file_source"].astype(str)
    elif "capture_id" not in df_replay.columns:
        if "timestamp" in df_replay.columns and "frame_number" in df_replay.columns and len(df_replay) > 1:
            time_diffs = df_replay["timestamp"].diff().fillna(0)
            frame_diffs = df_replay["frame_number"].diff().fillna(0)
            discontinuities = (time_diffs < 0) | (frame_diffs < 0) | (time_diffs > inter_capture_gap_seconds)
            episode_ids = discontinuities.cumsum()
            df_replay["capture_id"] = episode_ids.apply(lambda eid: f"replay_capture_{eid}")
        else:
            df_replay["capture_id"] = f"replay_{rep_meta['filename']}"

    # Ensure dataset_category is explicitly set
    df_normal["dataset_category"] = "normal_traffic"
    df_replay["dataset_category"] = "replay_traffic"

    summary = {
        "normal_path": resolve_file_path(normal_csv_path, base_dir),
        "replay_path": resolve_file_path(replay_csv_path, base_dir),
        "normal_rows_loaded": int(len(df_normal)),
        "replay_rows_loaded": int(len(df_replay)),
        "normal_captures_count": int(df_normal["capture_id"].nunique()),
        "replay_captures_count": int(df_replay["capture_id"].nunique()),
        "normal_columns": list(df_normal.columns),
        "replay_columns": list(df_replay.columns),
        "normal_format": norm_meta["format"],
        "replay_format": rep_meta["format"]
    }

    return df_normal, df_replay, summary
