"""Causal protocol events: one valid CSV record, enriched only with available history.

Requests are not backfilled with future responses. A response may reference an
earlier unambiguous request. This keeps online and offline features equivalent.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def assign_groups(frame: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    out = frame.copy()
    requested = cfg["dataset"].get("group_column", "auto")
    candidates = ["capture_id", "file_source", "scenario_id", "session_id"] if requested == "auto" else [requested]
    real = next((c for c in candidates if c in out and out[c].notna().all()), None)
    if real:
        out["group_id"] = out["source_file"] + ":" + out[real].astype(str)
        out["group_method"] = "supplied:" + real
    elif (
        cfg["dataset"].get("infer_reset_groups", False)
        and out["timestamp"].notna().all()
        and out["frame_number"].notna().all()
    ):
        boundary = (out["timestamp"].diff() < 0) | (out["frame_number"].diff() < 0)
        out["group_id"] = out["source_file"] + ":inferred:" + boundary.cumsum().astype(str)
        out["group_method"] = "inferred_frame_or_time_reset"
    else:
        out["group_id"] = out["source_file"] + ":ungrouped"
        out["group_method"] = "source_only"
    return out


def build_events(frame: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Construct bidirectional TCP sessions and conservative partial pair evidence."""
    out = frame.sort_values(["group_id", "timestamp", "source_row"], kind="stable", na_position="last").copy()
    out = out.reset_index(drop=True)
    if out.empty:
        for column in ["session_key", "context_id", "pair_status", "pair_event_id"]:
            out[column] = pd.Series(dtype="string")
        for column in [
            "has_matching_pair",
            "function_match",
            "unit_match",
            "transaction_match",
            "response_delay",
            "unexpected_response",
            "expired_requests",
        ]:
            out[column] = pd.Series(dtype=float)
        return out
    endpoint_columns = ["src_ip", "dst_ip", "src_port", "dst_port"]
    available = all(c in out for c in endpoint_columns)
    if available:
        complete = out[endpoint_columns].notna().all(axis=1)
        left = out.src_ip.astype(str) + ":" + out.src_port.astype(str)
        right = out.dst_ip.astype(str) + ":" + out.dst_port.astype(str)
        endpoints = pd.Series(np.where(left < right, left + "|" + right, right + "|" + left), index=out.index)
        # Missing endpoints must not accidentally connect unrelated records.
        endpoints = endpoints.where(complete, "unknown:" + out.event_id)
    else:
        complete = pd.Series(False, index=out.index)
        endpoints = "unknown:" + out.event_id
    out["session_key"] = out.group_id + ":" + endpoints
    gaps = out.groupby("session_key", sort=False).timestamp.diff()
    starts = gaps.gt(cfg["events"]["session_idle_seconds"])
    session_index = starts.groupby(out.session_key, sort=False).cumsum().astype(str)
    out["context_id"] = out.session_key + ":" + session_index
    # With no endpoints, a supplied logical session identifier can support context.
    if not available and "session_id" in out:
        out["context_id"] = out.group_id + ":session:" + out.session_id.astype(str)
    if "scenario_id" in out:
        # Reset context at scenarios without splitting a supplied capture across
        # train/test partitions.
        out["context_id"] += ":scenario:" + out.scenario_id.fillna("unknown").astype(str)
    out["pair_status"] = "unavailable"
    out["pair_event_id"] = None
    fields = [
        "has_matching_pair",
        "function_match",
        "unit_match",
        "transaction_match",
        "response_delay",
        "unexpected_response",
        "expired_requests",
    ]
    values = {key: np.full(len(out), np.nan) for key in fields}
    pending: dict[tuple, list] = {}
    timeout = cfg["events"]["response_timeout_seconds"]
    rows = out[
        ["context_id", "timestamp", "mbtcp_trans_id", "is_request", "modbus_func_code", "mbtcp_unit_id", "event_id"]
    ].itertuples(index=False, name=None)
    statuses, pair_ids = [], []
    for i, (session, timestamp, transaction, request, function, unit, event_id) in enumerate(rows):
        if not complete.iloc[i] or pd.isna(timestamp) or pd.isna(transaction) or pd.isna(request):
            statuses.append("unavailable")
            pair_ids.append(None)
            continue
        key = (session, transaction)
        candidates = pending.get(key, [])
        expired = sum(timestamp - item[0] > timeout for item in candidates)
        candidates = [item for item in candidates if timestamp - item[0] <= timeout]
        values["expired_requests"][i] = expired
        if request == 1:
            candidates.append((timestamp, function, unit, event_id))
            pending[key] = candidates
            statuses.append("pending_at_observation")
            pair_ids.append(None)
        elif len(candidates) == 1:
            previous_time, previous_function, previous_unit, previous_id = candidates[0]
            values["has_matching_pair"][i] = 1
            values["function_match"][i] = int(int(function) % 128 == int(previous_function) % 128)
            values["unit_match"][i] = (
                float(unit == previous_unit) if pd.notna(unit) and pd.notna(previous_unit) else np.nan
            )
            values["transaction_match"][i] = 1
            values["response_delay"][i] = timestamp - previous_time
            values["unexpected_response"][i] = 0
            statuses.append("partial_transaction_match")
            pair_ids.append(previous_id)
            pending.pop(key, None)
        else:
            values["has_matching_pair"][i] = 0 if not candidates else np.nan
            values["unexpected_response"][i] = 1 if not candidates else np.nan
            statuses.append("unmatched_response" if not candidates else "ambiguous_transaction")
            pair_ids.append(None)
            pending.pop(key, None)
    out["pair_status"] = statuses
    out["pair_event_id"] = pair_ids
    for key, value in values.items():
        out[key] = value
    return out
