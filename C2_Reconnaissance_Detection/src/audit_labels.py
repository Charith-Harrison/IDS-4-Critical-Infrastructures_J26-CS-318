"""Label audit: provenance of packet labels, event-map agreement, positive-packet signatures.

Packet label (supplied, preserved) != derived window label.
Output: artifacts/label_audit.json, artifacts/tables/positive_categories_by_file.csv
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ARTIFACTS, write_json  # noqa: E402
from io_data import load_events, load_packets  # noqa: E402


def categorise(p: pd.DataFrame, event_keys: set) -> pd.DataFrame:
    """Add boolean signature columns and an exclusive positive category (priority order)."""
    p = p.copy()
    key = list(zip(p.timestamp, p.src_ip, p.dst_ip))
    p["is_event_mapped"] = [k in event_keys for k in key]
    p["is_len3"] = p.modbus_len.eq(3)
    p["is_fc5_len3"] = p.is_len3 & p.func_code.eq(5)
    neg = p[p.label == 0]
    routine = neg.groupby(["src_ip", "dst_ip", "func_code"]).quantity.agg(lambda x: set(x)).to_dict()
    p["is_nonroutine_quantity"] = [
        (q not in routine.get((s, d, f), set())) and f in (1, 2, 3, 4)
        for s, d, f, q in zip(p.src_ip, p.dst_ip, p.func_code, p.quantity)]
    cat = np.select(
        [p.file_source.eq("attached_recon_flows.csv"), p.is_fc5_len3, p.is_event_mapped,
         p.is_nonroutine_quantity, p.is_len3],
        ["external_attached_flow_no_date", "fc5_len3_response", "event_mapped",
         "nonroutine_quantity_read", "len3_response_fc1_4"], default="other_positive")
    p["positive_category"] = np.where(p.label == 1, cat, "")
    return p


def main():
    p = load_packets()
    e = load_events()
    event_keys = set(zip(e.packet_timestamp, e.src_ip, e.dst_ip))
    p = categorise(p, event_keys)
    out = {}

    # --- event map vs packets ---
    m = e.merge(p[["timestamp", "src_ip", "dst_ip", "func_code", "quantity", "label", "file_source"]],
                left_on=["packet_timestamp", "src_ip", "dst_ip"], right_on=["timestamp", "src_ip", "dst_ip"],
                how="left", suffixes=("", "_pkt"))
    log_ns = pd.to_datetime(e.log_timestamp).dt.as_unit("ns").astype("int64")
    pkt_utc = e.packet_ts_ns.astype("int64")
    e["offset_utc_minus_log_min"] = (pkt_utc - log_ns) / 60e9
    e["offset_local_minus_log_min"] = (pkt_utc + 19800 * 10**9 - log_ns) / 60e9
    per_log = e.groupby(["file_source", "log_attack", "log_timestamp"]).agg(
        n=("src_ip", "size"),
        offset_utc_min_min=("offset_utc_minus_log_min", "min"),
        offset_utc_min_max=("offset_utc_minus_log_min", "max")).reset_index()
    out["event_map"] = {
        "rows": len(e),
        "rows_matched_to_packet_by_timestamp_src_dst": int(m.label.notna().sum()),
        "matched_packet_label_counts": m.label.value_counts().to_dict(),
        "func_code_agreement": float((m.func_code == m.func_code_pkt).mean()),
        "quantity_agreement": float((m.quantity == m.quantity_pkt).mean()),
        "file_source_agreement": float((m.file_source == m.file_source_pkt).mean()),
        "files_covered": sorted(e.file_source.unique().tolist()),
        "event_mapped_packets_that_are_requests_from_185.175.0.3": int((e.src_ip == "185.175.0.3").sum()),
        "per_log_entry_offsets_minutes": per_log.to_dict(orient="records"),
        "offset_utc_minus_log_minutes_range": [float(e.offset_utc_minus_log_min.min()),
                                               float(e.offset_utc_minus_log_min.max())],
        "interpretation_note": "Packet-minus-log offsets are not constant across log entries "
                               "(see per_log_entry_offsets_minutes), so the mapping is not a fixed clock "
                               "shift; how packets were assigned to log entries is [VERIFY: mapping procedure].",
    }

    # --- positives by category & file ---
    pos = p[p.label == 1]
    tab = pd.crosstab(pos.file_source, pos.positive_category)
    tab.to_csv(ARTIFACTS / "tables" / "positive_categories_by_file.csv")
    out["positive_category_counts"] = pos.positive_category.value_counts().to_dict()
    out["positive_categories_by_file"] = {f: {k: int(v) for k, v in r.items() if v} for f, r in tab.iterrows()}
    out["shortcut_checks"] = {
        "packets_with_modbus_len_3": int(p.is_len3.sum()),
        "positive_rate_given_modbus_len_3": float(p.loc[p.is_len3, "label"].mean()),
        "fraction_of_positives_with_modbus_len_3": float(pos.is_len3.mean()),
        "packets_fc5_len3": int(p.is_fc5_len3.sum()),
        "positive_rate_given_fc5_len3": float(p.loc[p.is_fc5_len3, "label"].mean()),
        "fraction_of_positives_fc5_len3": float(pos.is_fc5_len3.mean()),
        "fc5_len3_by_src_dst": {f"{a}->{b}": int(n) for (a, b), n in
                                p[p.is_fc5_len3].groupby(["src_ip", "dst_ip"]).size().items()},
        "fc5_len3_files": p[p.is_fc5_len3].file_source.value_counts().to_dict(),
        "fc5_requests_preceding_are_labelled_0": int(p[(p.func_code == 5) & (p.modbus_len == 6)].label.sum()) == 0,
    }
    # --- supplied labels by file with/without event map support ---
    sup = {}
    for f, d in p.groupby("file_source"):
        sup[f] = {"positives": int(d.label.sum()),
                  "event_mapped_positives": int((d.label.eq(1) & d.is_event_mapped).sum()),
                  "has_event_map_rows": bool(f in set(e.file_source))}
    out["label_support_by_file"] = sup
    out["external_attached_flows"] = {
        "rows": int(p.file_source.eq("attached_recon_flows.csv").sum()),
        "timestamp_examples": p.loc[p.file_source.eq("attached_recon_flows.csv"), "timestamp"].head(4).tolist(),
        "note": "Time-of-day only (no date/offset), different subnet (192.168.10.x), sessions of 2-4 packets "
                "(< window length 20). Cannot be placed chronologically or windowed.",
    }
    out["label_creation_procedure"] = "[VERIFY: how packet labels were generated is not documented in the supplied files]"
    write_json(out, ARTIFACTS / "label_audit.json")
    p[["row_index", "is_event_mapped", "is_len3", "is_fc5_len3", "is_nonroutine_quantity",
       "positive_category"]].to_csv(ARTIFACTS / "tables" / "packet_signature_flags.csv", index=False)
    print(tab.to_string())
    print(per_log.to_string())
    print(out["shortcut_checks"])
    print(out["event_map"]["rows_matched_to_packet_by_timestamp_src_dst"], out["event_map"]["matched_packet_label_counts"])


if __name__ == "__main__":
    main()
