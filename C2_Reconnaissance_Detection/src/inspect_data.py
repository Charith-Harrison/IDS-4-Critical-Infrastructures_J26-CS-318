"""Phase 2 - hostile dataset inventory and profile.

Outputs
  artifacts/dataset_profile.json
  artifacts/tables/session_profile.csv, file_profile.csv
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ARTIFACTS, load_config, read_json, resolve, write_json  # noqa: E402
from io_data import load_events, load_packets, load_sequences  # noqa: E402


def iso(ns):
    return None if ns is None or pd.isna(ns) else pd.Timestamp(int(ns), tz="UTC").isoformat()


def _imin(x):
    x = x.dropna()
    return None if x.empty else int(x.astype("int64").min())


def _imax(x):
    x = x.dropna()
    return None if x.empty else int(x.astype("int64").max())


def column_profile(df: pd.DataFrame, cols) -> dict:
    out = {}
    for c in cols:
        s = df[c]
        d = {"dtype": str(s.dtype), "missing": int(s.isna().sum()), "n_unique": int(s.nunique(dropna=True))}
        if pd.api.types.is_numeric_dtype(s) and c not in ("label",):
            d.update({"min": s.min(), "max": s.max(), "mean": float(s.mean()), "std": float(s.std())})
        if d["n_unique"] <= 30:
            d["value_counts"] = {str(k): int(v) for k, v in s.value_counts(dropna=False).items()}
        out[c] = d
    return out


def main():
    cfg = load_config()
    manifest = read_json(resolve(cfg["paths"]["raw_copy_dir"]) / "raw_manifest.json")
    tables = ARTIFACTS / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    p = load_packets()
    s, X = load_sequences()
    e = load_events()

    # ---- packets ----
    pkt_cols = [c for c in p.columns if c not in ("row_index", "ts_ns")]
    unparsed = p[p.ts_ns.isna()]
    content_cols = ["src_ip", "dst_ip", "unit_id", "func_code", "modbus_len", "register_start",
                    "quantity", "packet_size"]
    p["dt_fileorder"] = p.groupby("session_id").ts_ns.diff()

    sess = p.groupby("session_id").agg(
        total_packets=("label", "size"), recon_packets=("label", "sum"),
        n_files=("file_source", "nunique"), files=("file_source", lambda x: sorted(set(x))),
        start_ns=("ts_ns", _imin), end_ns=("ts_ns", _imax),
        negative_steps_in_file_order=("dt_fileorder", lambda x: int((x < 0).sum())))
    sess["normal_packets"] = sess.total_packets - sess.recon_packets
    sseq = s.groupby("session_id").agg(total_sequences=("label", "size"), recon_sequences=("label", "sum"),
                                       start_gt_end=("start_ns", "size"))
    sseq["start_gt_end"] = s.assign(b=s.start_ns > s.end_ns).groupby("session_id").b.sum()
    sess = sess.join(sseq, how="left")
    sess["total_sequences"] = sess.total_sequences.fillna(0).astype(int)
    sess["recon_sequences"] = sess.recon_sequences.fillna(0).astype(int)
    sess["normal_sequences"] = sess.total_sequences - sess.recon_sequences
    sess["positive_packet_fraction"] = sess.recon_packets / sess.total_packets
    sess["positive_sequence_fraction"] = np.where(sess.total_sequences > 0,
                                                  sess.recon_sequences / sess.total_sequences.replace(0, 1), np.nan)
    sess["start_utc"] = sess.start_ns.map(iso)
    sess["end_utc"] = sess.end_ns.map(iso)
    sess = sess.drop(columns=["start_ns", "end_ns"])
    sess.to_csv(tables / "session_profile.csv")

    fil = p.groupby("file_source").agg(
        total_packets=("label", "size"), recon_packets=("label", "sum"),
        n_sessions=("session_id", "nunique"), start_ns=("ts_ns", _imin), end_ns=("ts_ns", _imax),
        unparsed_timestamps=("ts_ns", lambda x: int(x.isna().sum())))
    fil["normal_packets"] = fil.total_packets - fil.recon_packets
    fil["start_utc"] = fil.start_ns.map(iso)
    fil["end_utc"] = fil.end_ns.map(iso)
    fil = fil.drop(columns=["start_ns", "end_ns"]).sort_values("start_utc")
    fil.to_csv(tables / "file_profile.csv")
    pd.crosstab(p.file_source, p.session_id).to_csv(tables / "file_by_session_packets.csv")
    pd.crosstab(p.file_source, p.session_id, values=p.label, aggfunc="sum").fillna(0).astype(int).to_csv(
        tables / "file_by_session_recon_packets.csv")

    profile = {
        "raw_files": manifest["files"],
        "note_format": "Supplied files are named *.csv.xlsx but are OOXML workbooks (zip magic 'PK'); "
                       "one sheet each. CSV working copies were streamed with openpyxl; originals verified "
                       "unchanged by SHA-256 before/after.",
        "packets": {
            "rows": len(p), "columns": pkt_cols,
            "column_profile": column_profile(p, pkt_cols),
            "unparseable_timestamps": int(len(unparsed)),
            "unparseable_timestamp_examples": unparsed.timestamp.head(5).tolist(),
            "unparseable_timestamp_files": unparsed.file_source.value_counts().to_dict(),
            "exact_duplicate_rows_excluding_index_cols": int(p[pkt_cols].drop(columns=["sequence_position"]).duplicated().sum()),
            "duplicate_content_same_timestamp": int(p.duplicated(subset=["timestamp"] + content_cols).sum()),
            "label_counts": p.label.value_counts().to_dict(),
            "n_session_id": int(p.session_id.nunique()),
            "n_file_source": int(p.file_source.nunique()),
            "session_ids_with_ge20_packets": int((p.session_id.value_counts() >= 20).sum()),
            "negative_time_steps_in_supplied_order_within_session": int((p.dt_fileorder < 0).sum()),
            "sequence_position_is_0..n-1_per_session": bool(p.groupby("session_id").sequence_position.apply(
                lambda x: (x.to_numpy() == np.arange(len(x))).all()).all()),
            "timestamp_offsets_seen": p.timestamp.str.slice(29).value_counts().to_dict(),
        },
        "sequences": {
            "rows": len(s), "columns": [c for c in s.columns if c not in ("start_ns", "end_ns")],
            "features_tensor_shape": list(X.shape),
            "window_length_values": s.window_length.value_counts().to_dict(),
            "label_counts": s.label.value_counts().to_dict(),
            "n_session_id": int(s.session_id.nunique()),
            "window_start_after_end": int((s.start_ns > s.end_ns).sum()),
            "duplicate_sequence_id": int(s.sequence_id.duplicated().sum()),
            "duplicate_feature_matrices": int(s.features_json.duplicated().sum()),
        },
        "events": {
            "rows": len(e), "columns": list(e.columns[:10]),
            "log_attack_counts": e.log_attack.value_counts().to_dict(),
            "file_source_counts": e.file_source.value_counts().to_dict(),
            "log_file_counts": e.log_file.value_counts().to_dict(),
        },
        "proposal_claims_check": {
            "claimed_windowed_sequences": 175800, "observed_sequences": len(s),
            "claimed_timesteps": 20, "observed_timesteps": int(X.shape[1]),
            "claimed_features_per_timestep": 7, "observed_features_per_timestep": int(X.shape[2]),
            "claimed_sessions": 13, "observed_session_ids_in_sequences": int(s.session_id.nunique()),
            "observed_session_ids_in_packets": int(p.session_id.nunique()),
        },
    }
    write_json(profile, ARTIFACTS / "dataset_profile.json")
    print(sess.to_string())
    print(fil.to_string())
    print({k: v for k, v in profile["proposal_claims_check"].items()})


if __name__ == "__main__":
    main()
