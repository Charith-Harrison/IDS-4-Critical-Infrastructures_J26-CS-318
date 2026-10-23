"""Feature audit: classifies every feature/field and writes the audit files.

Categories: A direct dataset feature, B valid derived, C training-derived
profile, D metadata/grouping, E label/target, F unavailable, G invalid.
"""

from __future__ import annotations

import pandas as pd

from src.features.builder import FEATURE_GROUPS
from src.utils.config import FEATURE_AUDIT_DIR, MODELS_DIR
from src.utils.io import read_json

# name -> (category, source columns, derivation) for current-event features.
DIRECT = {
    "func_code": "modbus_func_code",
    "ref_num": "modbus_ref_num",
    "word_cnt": "modbus_word_cnt",
    "bit_cnt": "modbus_bit_cnt",
    "frame_len": "frame_len",
    "payload_len": "payload_len",
    "mbtcp_len": "mbtcp_len",
    "unit_id": "mbtcp_unit_id",
    "tcp_syn": "tcp_flags_syn",
    "tcp_ack": "tcp_flags_ack",
    "tcp_fin": "tcp_flags_fin",
    "tcp_rst": "tcp_flags_rst",
    "tcp_psh": "tcp_flags_psh",
    "len_discrepancy": "len_discrepancy",
    "has_stacked_frames": "has_stacked_frames",
}
DERIVED = {
    "write_value": ("modbus_val, is_write", "modbus_val if the request is a write else -1"),
    "is_write": ("modbus_func_code", "function code in {5,6,15,16}"),
    "is_coil_op": ("modbus_func_code", "function code in {1,2,5,15}"),
    "is_known_fc": ("modbus_func_code", "function code in {1-6,15,16}"),
    "proto_id_valid": ("mbtcp_proto_id", "protocol id == 0"),
    "length_consistent": ("payload_len, mbtcp_len", "payload_len == mbtcp_len + 6"),
    "pair_found": (
        "pairing",
        "request has a matched response (time-ordered, keyed by capture, endpoints, ports, transaction id)",
    ),
    "pair_status_code": ("pairing", "0 matched, 1 exception, 2 missing, 3 out_of_order"),
    "response_missing": ("pairing", "1 if no response found"),
    "unit_id_match": ("pairing", "response unit id == request unit id (-1 if no response)"),
    "function_code_match": ("pairing", "response function == request function (-1 if no response)"),
    "address_match": ("pairing", "write only, non-exception: response register == request register (-1 otherwise)"),
    "quantity_match": ("pairing", "read only: response byte count == expected from request quantity (-1 otherwise)"),
    "value_echo_match": ("pairing", "write only: response value == request value (-1 otherwise)"),
    "response_delay": ("pairing", "response timestamp - request timestamp; -1 if no response"),
    "response_exception": ("pairing", "1 if the paired response is an exception (-1 if no response)"),
    "response_length_valid": ("pairing", "MBAP length consistent with response type (-1 if no response)"),
    "first_in_stream": ("stream order", "1 if first event of the (capture, src, dst) stream"),
    "prev_fc": ("stream order", "function code of the previous event in the stream (-1 none)"),
    "prev_is_write": ("stream order", "previous event was a write (-1 none)"),
    "prev_ref": ("stream order", "register of the previous event (-1 none)"),
    "read_to_write": ("stream order", "previous read and current write"),
    "write_to_write": ("stream order", "previous write and current write"),
    "same_ref_as_prev": ("stream order", "current register == previous register"),
    "writes_prev_k": ("stream order", "writes among the previous 5 events"),
    "reads_prev_k": ("stream order", "reads among the previous 5 events"),
    "distinct_fc_prev_k": ("stream order", "distinct function codes in previous 5 events"),
    "distinct_ref_prev_k": ("stream order", "distinct registers in previous 5 events"),
    "same_ref_writes_prev_k": ("stream order", "previous-5 writes to the same register"),
    "prev_value_same_ref": ("write history", "previous written value for same register in the stream (-1 none)"),
    "value_delta": ("write history", "|value - previous value| same register (-1 none; clipped)"),
    "value_changed": ("write history", "value differs from previous value (-1 none)"),
    "value_rate": ("write history", "value_delta / seconds since previous write to the register (clipped)"),
    "iat": ("timestamps", "seconds since previous event in the stream (fold-filled for first event)"),
    "iat_mean_prev_k": ("timestamps", "mean of the previous 5 inter-arrival times"),
    "iat_min_prev_k": ("timestamps", "minimum of the previous 5 inter-arrival times"),
    "events_last_1s": ("timestamps", "earlier events in the stream within the last 1 s"),
    "events_last_10s": ("timestamps", "earlier events in the stream within the last 10 s"),
    "writes_last_1s": ("timestamps", "earlier writes in the stream within the last 1 s"),
    "time_since_last_write": ("timestamps", "seconds since an earlier write (fitted fill if none)"),
    "time_since_last_read": ("timestamps", "seconds since an earlier read (fitted fill if none)"),
}
FITTED = {
    "access_combo_unseen": "1 if (function, register) never seen as Normal in fold-training traffic",
    "access_combo_normal_count_log": "log1p(count of the combo in fold-training Normal events)",
    "access_write_unseen": "write whose (function, register) is unseen in fold-training Normal events",
    "value_outside_normal_range": "write value outside fold-training Normal min/max for that register (-1 if combo unseen)",
}
RATE_LIKE = {"events_last_1s", "events_last_10s", "writes_last_1s", "iat", "iat_mean_prev_k", "iat_min_prev_k"}
PAIR_RISK = {"response_missing", "pair_found", "pair_status_code", "response_exception", "response_delay"}


def build_inventory(used_baseline: list[str], used_context: list[str], dropped: list[str]) -> pd.DataFrame:
    """One row per feature with category, derivation and leakage assessment."""
    rows = []
    for g, fs in FEATURE_GROUPS.items():
        for f in fs:
            if f in DIRECT:
                cat, src, how = "A", DIRECT[f], "copied from dataset column"
            elif f in FITTED:
                cat, src, how = "C", "func_code, ref_num, write_value (+ fold-training labels)", FITTED[f]
            else:
                cat = "B"
                src, how = DERIVED[f]
            past = (
                "current event only"
                if g in ("BASELINE", "PROTOCOL")
                else (
                    "current event's own response (completed-event assumption)"
                    if g == "PAIR"
                    else "current + past only"
                )
            )
            if f in FITTED:
                leak = "HIGH: label rule uses the same (function, register) evidence (circular-labelling risk)"
            elif f in (
                "func_code",
                "ref_num",
                "is_write",
                "write_value",
                "is_coil_op",
                "prev_ref",
                "prev_fc",
                "prev_value_same_ref",
                "same_ref_as_prev",
                "distinct_ref_prev_k",
                "same_ref_writes_prev_k",
            ):
                leak = "MEDIUM-HIGH: function/register are label-construction fields"
            elif f in PAIR_RISK:
                leak = "MEDIUM: capture-vantage artefact (e.g. one capture contains no responses) and exception replies appear only in attack captures"
            elif f in RATE_LIKE:
                leak = "LOW-MEDIUM: brute-force bursts are fast; rate is context, not a label field"
            else:
                leak = "LOW"
            rows.append(
                {
                    "name": f,
                    "category": cat,
                    "group": g,
                    "source_columns": src,
                    "exact_derivation": how,
                    "type": "int/float",
                    "missing_value_handling": (
                        "-1 sentinel for not-applicable; fitted fill for 'no earlier event'"
                        if g in ("PAIR", "RATE", "VALUE")
                        else "none needed"
                    ),
                    "grouping_requirement": (
                        "stream = capture_id + src_ip + dst_ip"
                        if g in ("SEQUENCE", "RATE", "VALUE")
                        else ("capture_id (pairing key)" if g == "PAIR" else "none")
                    ),
                    "current_or_past_only": past,
                    "baseline_usage": "used" if f in used_baseline else "not used",
                    "contextual_usage": (
                        "used"
                        if f in used_context
                        else ("dropped: constant on development data" if f in dropped else "not used")
                    ),
                    "leakage_risk": leak,
                    "validity_decision": (
                        "valid"
                        if (f in used_context or f in used_baseline)
                        else "valid but constant on this data (not used)"
                    ),
                }
            )
    return pd.DataFrame(rows)


METADATA = {
    "capture_id": "grouping/traceability only",
    "event_id": "traceability only",
    "source_row": "original record id",
    "frame_number": "ordering only",
    "timestamp": "ordering only",
    "src_ip": "stream grouping only",
    "dst_ip": "stream grouping only",
    "src_port": "pairing key only",
    "dst_port": "pairing key only",
    "mbtcp_trans_id": "pairing key only",
    "file_source": "baseline capture id (metadata)",
}
LABELS = ["is_attack", "attack_sub_type", "attack_category", "class_id", "label_status"]
UNAVAILABLE = {
    "source_role_map": "No device-role/authorisation map exists; only client/server direction is derivable.",
    "authorised_register_map": "No authorisation map supplied; 'unseen in normal training traffic' is used instead.",
    "recent_missing_responses_window": "Whether an earlier request gets a response is only known later; using it would leak future information.",
    "recent_exceptions_window": "Same reason: earlier responses may arrive after the current request.",
    "response_delay_context_window": "Same reason (depends on later response arrival).",
    "response_injection_pair_forgery_evidence": "No forged-response labels or evidence exist in the data.",
    "value_echo_for_reads": "Read requests carry no value to echo.",
}
INVALID = {
    "inter_arrival_time (dataset column)": "Derivation not verifiable (capture-wide?); recomputed past-only per stream instead.",
    "packet_rate_1s (dataset column)": "Derivation not verifiable and may include the current/following packets; recomputed past-only.",
    "response_time (dataset column)": "Response-side measurement of unknown construction; recomputed from pairing.",
    "trans_id_diff (dataset column)": "Depends on transaction-id sequence across the capture; replay-related and ID values are metadata.",
    "transaction_id_match": "Constant 1 by construction of the pairing key (transaction id is part of the key).",
    "raw src_ip / dst_ip / ports / transaction id as inputs": "Identify capture hosts (e.g. the attacking host) rather than behaviour: label leakage.",
    "frame_number / absolute timestamp": "Capture position leaks the scenario.",
    "file_source / capture_id / attack_* / is_attack": "Label or scenario identifiers.",
}


def run_feature_audit(evidence: pd.DataFrame | None = None) -> None:
    """Write all feature-audit files (evidence matrix needs dev features)."""
    FEATURE_AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    cbase = read_json(MODELS_DIR / "baseline" / "feature_names.json")
    cctx = read_json(MODELS_DIR / "contextual" / "feature_names.json")
    dropped = read_json(MODELS_DIR / "contextual" / "training_manifest.json")["dropped_constant_features"]
    inv = build_inventory(cbase, cctx, dropped)
    inv.to_csv(FEATURE_AUDIT_DIR / "feature_inventory.csv", index=False)
    schema = pd.read_csv(FEATURE_AUDIT_DIR.parent / "data_audit" / "column_schema.csv")
    schema["category"] = schema["column"].map(lambda c: "E" if c in LABELS else "D" if c in METADATA else "A/G")
    schema.to_csv(FEATURE_AUDIT_DIR / "actual_dataset_schema.csv", index=False)
    pd.DataFrame([{"feature": k, "category": "F", "reason": v} for k, v in UNAVAILABLE.items()]).to_csv(
        FEATURE_AUDIT_DIR / "unavailable_features.csv", index=False
    )
    pd.DataFrame([{"feature": k, "category": "G", "reason": v} for k, v in INVALID.items()]).to_csv(
        FEATURE_AUDIT_DIR / "invalid_features.csv", index=False
    )
    inv[["name", "group", "leakage_risk"]].to_csv(FEATURE_AUDIT_DIR / "leakage_risks.csv", index=False)
    if evidence is not None:
        evidence.to_csv(FEATURE_AUDIT_DIR / "feature_evidence_matrix.csv", index=False)
    cats = inv["category"].value_counts().to_dict()
    md = [
        "# Feature audit summary",
        "",
        f"Features by category (A direct, B derived, C training-derived): {cats}.",
        f"Dropped as constant on development data: {', '.join(dropped) or 'none'}.",
        "",
        "Metadata/grouping fields (D): " + ", ".join(METADATA),
        "",
        "Label/target fields (E): " + ", ".join(LABELS),
        "",
        "## Unavailable (F)",
        *[f"- **{k}**: {v}" for k, v in UNAVAILABLE.items()],
        "",
        "## Invalid or unsupported (G)",
        *[f"- **{k}**: {v}" for k, v in INVALID.items()],
        "",
        "## Leakage notes",
        "- Labels are constructed from function code and register novelty; features built from the same fields can re-learn the labelling rule (see results/progress_70/circularity_diagnostics.json).",
        "- PAIR features use the current event's own response, so they assume a completed request/response.",
        "- Capture atk-0 contains no response packets, so `response_missing` is partly a capture-vantage artefact.",
    ]
    (FEATURE_AUDIT_DIR / "feature_audit_summary.md").write_text("\n".join(md), encoding="utf-8")


def evidence_matrix(full: pd.DataFrame, names: list[str]) -> pd.DataFrame:
    """Per-feature observed evidence on the development events."""
    rows = []
    for f in names:
        s = full[f]
        rows.append(
            {
                "feature": f,
                "n_events": len(s),
                "distinct_values": int(s.nunique(dropna=False)),
                "share_not_applicable(-1)": float((s == -1).mean()),
                "min": float(s.min()),
                "max": float(s.max()),
            }
        )
    return pd.DataFrame(rows)
