"""Dataset audit: checksums, schema, captures, duplicates, label evidence.

Every number is computed from the supplied CSV files at run time; nothing is
hard-coded. Outputs are written to results/data_audit/.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from src.utils.config import AUDIT_DIR, ROOT, get_logger
from src.utils.io import sha256_file, write_json

log = get_logger("audit")

# Fields available to look for a real capture/grouping identifier.
GROUP_FIELDS = ["file_source", "frame_number", "timestamp", "src_ip", "dst_ip", "mbtcp_unit_id"]

JUSTIFICATION = {
    "dataset_normal": (
        "Normal",
        "Dataset label is_attack=0 (read traffic; baseline also has routine writes).",
        "Label is dataset-provided, not independently verified.",
        "Retain as Normal",
    ),
    "reconstructed_command_injection": (
        "Command Injection",
        "Dataset-labelled Coil_Brute_Force write REQUEST (FC5/6) whose function/register combination never occurs as a write in the normal baseline.",
        "Mapping uses function code + register, which are also candidate model inputs (circular-labelling risk). Not independently verified ground truth.",
        "Retain as Command Injection (researcher-reconstructed)",
    ),
    "ambiguous_write_matches_normal_profile": (
        "Excluded (ambiguous)",
        "Attack-labelled write whose function/register combination also appears as a routine write in the baseline normal file.",
        "Cannot tell routine operator write from attack write with the supplied fields.",
        "Exclude from supervised training; keep for audit",
    ),
    "attack_labelled_response_packet": (
        "Not an event (paired response)",
        "Server reply to an attack-labelled request; these are normal device replies, not forged responses.",
        "No evidence of a forged/modified response exists in the data.",
        "Used only as the paired response of its request",
    ),
    "unsupported_length_manipulation": (
        "Excluded (out of scope)",
        "Length_Manipulation requests: protocol-length manipulation, not a command/response semantic injection.",
        "Very few records; belongs to protocol-manipulation, not injection classes.",
        "Exclude from the core model",
    ),
}


def file_audit(path, label: str) -> tuple[dict, pd.DataFrame]:
    """Audit one CSV: checksum, size, rows, dtypes, missing, duplicates, labels."""
    df = pd.read_csv(path)
    dup_all = int(df.duplicated().sum())
    info = {
        "filename": path.name,
        "relative_path": path.relative_to(ROOT).as_posix(),
        "sha256": sha256_file(path),
        "size_bytes": int(path.stat().st_size),
        "rows": int(len(df)),
        "columns": list(df.columns),
        "dtypes": {c: str(t) for c, t in df.dtypes.items()},
        "missing_counts": {c: int(v) for c, v in df.isna().sum().items() if v},
        "exact_duplicate_rows": dup_all,
        "timestamp_min": float(df["timestamp"].min()),
        "timestamp_max": float(df["timestamp"].max()),
        "timestamp_monotonic": bool(df["timestamp"].is_monotonic_increasing),
        "frame_number_resets": int((df["frame_number"].diff() < 0).sum()),
        "timestamp_resets": int((df["timestamp"].diff() < 0).sum()),
        "original_labels": df.groupby(["attack_category", "attack_sub_type", "is_attack"])
        .size()
        .rename("rows")
        .reset_index()
        .to_dict("records"),
        "grouping_fields_available": [c for c in GROUP_FIELDS if c in df.columns],
        "capture_field": "file_source" if "file_source" in df.columns else None,
        "has_exception_rows": int(df["is_exception"].sum()),
        "role": label,
    }
    schema = pd.DataFrame(
        {
            "file": path.name,
            "column": df.columns,
            "dtype": [str(t) for t in df.dtypes],
            "missing": [int(df[c].isna().sum()) for c in df.columns],
            "n_unique": [int(df[c].nunique()) for c in df.columns],
        }
    )
    return info, schema


def capture_report(packets: pd.DataFrame) -> pd.DataFrame:
    """One row per capture with timing, counts, label mix and boundary reason."""
    rows = []
    for cap, g in packets.groupby("capture_id", sort=False):
        pairs = g.groupby(["src_ip", "dst_ip"]).size()
        fc = g[g["is_request"] == 1]["modbus_func_code"].value_counts().sort_index()
        labels = g["attack_sub_type"].value_counts() if "attack_sub_type" in g else {}
        reasons = g["boundary_reason"].replace("", np.nan).dropna()
        rows.append(
            {
                "capture_id": cap,
                "first_timestamp": g["timestamp"].min(),
                "last_timestamp": g["timestamp"].max(),
                "records": len(g),
                "requests": int((g["is_request"] == 1).sum()),
                "responses": int((g["is_request"] == 0).sum()),
                "src_dst_pairs": "; ".join(f"{a}>{b}:{n}" for (a, b), n in pairs.items()),
                "function_codes_requests": "; ".join(f"FC{int(k)}:{v}" for k, v in fc.items()),
                "original_labels": "; ".join(f"{k}:{v}" for k, v in dict(labels).items()),
                "boundary_reason": (
                    reasons.iloc[0] if len(reasons) else g["boundary_reason"].iloc[0] or "first capture in file"
                ),
            }
        )
    return pd.DataFrame(rows)


def duplicate_investigation(base_raw: pd.DataFrame, atk_raw: pd.DataFrame) -> dict:
    """Look for records shared between the two files and inside each file."""
    key = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "mbtcp_trans_id", "modbus_func_code", "frame_len"]
    merged = base_raw[key].merge(atk_raw[key], on=key, how="inner")
    overlap_range = max(base_raw["timestamp"].min(), atk_raw["timestamp"].min()) <= min(
        base_raw["timestamp"].max(), atk_raw["timestamp"].max()
    )
    return {
        "matching_key": key,
        "timestamp_precision": "microseconds as recorded in the CSV (float epoch)",
        "cross_file_duplicate_pairs": int(len(merged)),
        "baseline_rows_involved": int(len(merged)),
        "attack_file_rows_involved": int(len(merged)),
        "rows_removed": 0,
        "copy_preserved": "n/a - no duplicates found" if len(merged) == 0 else "baseline copy",
        "within_baseline_duplicates_on_key": int(base_raw.duplicated(key).sum()),
        "within_attack_duplicates_on_key": int(atk_raw.duplicated(key).sum()),
        "timestamp_ranges_overlap": bool(overlap_range),
        "note": (
            "Timestamp ranges of the two files do not overlap, so shared " "records are not expected."
            if not overlap_range
            else "Timestamp ranges overlap; matching key used."
        ),
    }


def label_evidence(packets: pd.DataFrame) -> pd.DataFrame:
    """Per (label_status, direction, function) evidence table with decisions."""
    rows = []
    g = packets[packets["attack_sub_type"].notna()]
    for (status, req, fc), d in g.groupby(["label_status", "is_request", "modbus_func_code"]):
        proposed, why, limit, decision = JUSTIFICATION.get(status, ("Unmapped", "No rule", "Unknown", "Exclude"))
        ev = d[d["is_request"] == 1]
        rows.append(
            {
                "label_status": status,
                "original_sub_types": "; ".join(sorted(d["attack_sub_type"].unique())),
                "direction": "request" if req == 1 else "response",
                "function_code": int(fc),
                "records": len(d),
                "register_top": "; ".join(
                    f"{int(k)}:{v}" for k, v in d["modbus_ref_num"].value_counts().head(5).items()
                ),
                "sources": "; ".join(sorted(d["src_ip"].unique())),
                "destinations": "; ".join(sorted(d["dst_ip"].unique())),
                "median_gap_s": float(ev["timestamp"].diff().median()) if len(ev) > 1 else np.nan,
                "proposed_class": proposed,
                "technical_justification": why,
                "limitations": limit,
                "mapping_decision": decision,
                "label_provenance": (
                    "dataset-provided"
                    if status == "dataset_normal"
                    else "researcher-reconstructed" if "command_injection" in status else "ambiguous/unsupported"
                ),
            }
        )
    return pd.DataFrame(rows)


def run_audit(base_raw, atk_raw, packets_base, packets_atk, base_path, atk_path) -> dict:
    """Run every audit step and write the outputs; returns the summary dict."""
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    bi, bs = file_audit(base_path, "normal baseline")
    ai, as_ = file_audit(atk_path, "attack file")
    write_json({"baseline": bi, "attack": ai}, AUDIT_DIR / "dataset_audit.json")
    pd.concat([bs, as_]).to_csv(AUDIT_DIR / "column_schema.csv", index=False)
    packets = pd.concat([packets_base, packets_atk], ignore_index=True)
    caps = capture_report(packets)
    caps.to_csv(AUDIT_DIR / "capture_report.csv", index=False)
    dup = duplicate_investigation(base_raw, atk_raw)
    write_json(dup, AUDIT_DIR / "duplicate_investigation.json")
    lab = label_evidence(packets)
    lab.to_csv(AUDIT_DIR / "label_evidence.csv", index=False)
    req = packets[packets["is_request"] == 1]
    req.groupby(["capture_id", "modbus_func_code"]).size().rename("requests").reset_index().to_csv(
        AUDIT_DIR / "function_code_distribution.csv", index=False
    )
    req.groupby(["capture_id", "modbus_func_code", "modbus_ref_num"]).size().rename("requests").reset_index().to_csv(
        AUDIT_DIR / "register_distribution.csv", index=False
    )
    packets.groupby(["capture_id", "src_ip", "dst_ip", "is_request"]).size().rename("records").reset_index().to_csv(
        AUDIT_DIR / "source_destination_roles.csv", index=False
    )
    resp = packets.groupby("capture_id")["is_request"].agg(lambda s: int((s == 0).sum()))
    findings = {
        "captures_baseline": int(caps["capture_id"].str.startswith("base").sum()),
        "captures_attack_reconstructed": int(caps["capture_id"].str.startswith("atk").sum()),
        "captures_without_any_response_packet": [c for c, n in resp.items() if n == 0],
        "length_manipulation_present_rows": int((packets["attack_sub_type"] == "Length_Manipulation").sum()),
        "genuine_response_injection_labels_in_data": int(
            packets["attack_sub_type"].astype(str).str.contains("Response", case=False).sum()
        ),
        "label_status_counts": packets["label_status"].value_counts().to_dict(),
        "cross_file_duplicate_pairs": dup["cross_file_duplicate_pairs"],
    }
    write_json(findings, AUDIT_DIR / "audit_findings.json")
    log.info("audit complete: %s", findings)
    return findings
