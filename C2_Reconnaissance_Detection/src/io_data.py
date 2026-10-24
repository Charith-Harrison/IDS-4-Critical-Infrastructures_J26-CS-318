"""Loaders for the CSV working copies of the supplied data (never the originals in place)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import load_config, resolve  # noqa: E402

PACKET_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "unit_id", "func_code", "modbus_len",
    "register_start", "quantity", "packet_size", "time_delta", "session_id",
    "sequence_position", "label", "file_source",
]
SEQUENCE_COLUMNS = [
    "sequence_id", "session_id", "window_start_time", "window_end_time",
    "window_length", "label", "features_json",
]
EVENT_COLUMNS = [
    "packet_timestamp", "packet_epoch", "src_ip", "dst_ip", "func_code", "quantity",
    "file_source", "log_attack", "log_timestamp", "log_file",
]


class SchemaError(ValueError):
    pass


def check_schema(df: pd.DataFrame, expected: list[str], name: str) -> None:
    missing = [c for c in expected if c not in df.columns]
    if missing:
        raise SchemaError(f"{name}: missing required columns {missing}; got {list(df.columns)}")


def parse_iso_offset_ns(s: pd.Series) -> pd.Series:
    """Parse strings like '2023-01-22T09:40:36.658912000+0530' to UTC int64 nanoseconds.

    Nanosecond digits are preserved (no float conversion). Unparseable values -> pd.NA
    (reported, never silently dropped).
    """
    s = s.astype("string")
    base = s.str.slice(0, 29)
    off = s.str.slice(29)
    good = (s.str.len() == 34) & off.str.fullmatch(r"[+-]\d{4}")
    good = good.fillna(False).astype(bool)
    t = pd.to_datetime(base.where(good), format="%Y-%m-%dT%H:%M:%S.%f", errors="coerce")
    valid = t.notna().to_numpy()
    ns = np.zeros(len(s), dtype=np.int64)
    ns[valid] = t[valid].to_numpy(dtype="datetime64[ns]").astype(np.int64)
    sign = np.where(off.str.slice(0, 1).fillna("+").to_numpy() == "-", -1, 1)
    hh = pd.to_numeric(off.str.slice(1, 3), errors="coerce").fillna(0).to_numpy(dtype=np.int64)
    mm = pd.to_numeric(off.str.slice(3, 5), errors="coerce").fillna(0).to_numpy(dtype=np.int64)
    ns = ns - sign * (hh * 3600 + mm * 60) * 1_000_000_000
    out = pd.Series(ns, index=s.index, dtype="Int64")
    return out.mask(~valid)


def raw_paths(cfg: dict | None = None) -> dict:
    cfg = cfg or load_config()
    d = resolve(cfg["paths"]["raw_copy_dir"])
    return {
        "packets": d / "recon_labeled_packets_ALL.csv",
        "sequences": d / "recon_sequences_ALL.csv",
        "events": d / "attack_events_mapped.csv",
    }


def load_packets(path: str | Path | None = None, parse_time: bool = True) -> pd.DataFrame:
    path = Path(path) if path else raw_paths()["packets"]
    df = pd.read_csv(path, dtype={"timestamp": "string", "src_ip": "string", "dst_ip": "string",
                                   "session_id": "string", "file_source": "string"})
    check_schema(df, PACKET_COLUMNS, "packets")
    df.insert(0, "row_index", np.arange(len(df), dtype=np.int64))  # original file order
    if parse_time:
        df["ts_ns"] = parse_iso_offset_ns(df["timestamp"])
    return df


def load_sequences(path: str | Path | None = None, parse_features: bool = True):
    path = Path(path) if path else raw_paths()["sequences"]
    df = pd.read_csv(path, dtype={"sequence_id": "string", "session_id": "string",
                                   "window_start_time": "string", "window_end_time": "string",
                                   "features_json": "string"})
    check_schema(df, SEQUENCE_COLUMNS, "sequences")
    X = None
    if parse_features:
        X = np.array([json.loads(s) for s in df["features_json"]], dtype=np.float64)
    df["start_ns"] = parse_iso_offset_ns(df["window_start_time"])
    df["end_ns"] = parse_iso_offset_ns(df["window_end_time"])
    return df, X


def load_events(path: str | Path | None = None) -> pd.DataFrame:
    path = Path(path) if path else raw_paths()["events"]
    df = pd.read_csv(path, dtype={"packet_timestamp": "string", "src_ip": "string",
                                   "dst_ip": "string", "file_source": "string",
                                   "log_attack": "string", "log_timestamp": "string",
                                   "log_file": "string"})
    check_schema(df, EVENT_COLUMNS, "events")
    df["packet_ts_ns"] = parse_iso_offset_ns(df["packet_timestamp"])
    return df
