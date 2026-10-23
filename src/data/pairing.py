"""Request-response reconstruction for Modbus/TCP.

Pairing key: capture, client/server endpoints, ports and transaction ID. The
n-th request with a key is paired with the n-th response with the matching
(swapped) key, which handles transaction-ID reuse in time order. Unit id and
function code are *checked* (not part of the key) so mismatches are visible.
Unavailable values are NaN here; feature building encodes them with -1.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

KEY = ["capture_id", "c_ip", "s_ip", "c_port", "s_port", "tid"]


def _keyed(df: pd.DataFrame, request: bool) -> pd.DataFrame:
    """Return a frame with canonical client/server key columns + order index."""
    d = df.copy()
    if request:
        d["c_ip"], d["s_ip"] = d["src_ip"], d["dst_ip"]
        d["c_port"], d["s_port"] = d["src_port"], d["dst_port"]
    else:  # response travels server -> client, so swap
        d["c_ip"], d["s_ip"] = d["dst_ip"], d["src_ip"]
        d["c_port"], d["s_port"] = d["dst_port"], d["src_port"]
    d["tid"] = d["mbtcp_trans_id"]
    d = d.sort_values(["capture_id", "timestamp", "frame_number"], kind="mergesort")
    d["occ"] = d.groupby(KEY).cumcount()
    return d


def pair_events(packets: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Pair requests with responses.

    Returns (events, orphan_responses, stats). events = one row per request
    with response_* columns and pair_* indicators.
    """
    req = _keyed(packets[packets["is_request"] == 1], True)
    rsp = _keyed(packets[packets["is_request"] == 0], False)
    keep = [
        "timestamp",
        "frame_number",
        "modbus_func_code",
        "mbtcp_unit_id",
        "modbus_ref_num",
        "modbus_val",
        "modbus_byte_cnt",
        "mbtcp_len",
        "is_exception",
        "modbus_exception_code",
        "source_row",
    ]
    r = rsp[KEY + ["occ"] + keep].rename(columns={c: f"rsp_{c}" for c in keep})
    ev = req.merge(r, on=KEY + ["occ"], how="left", indicator=True)
    found = ev["_merge"] == "both"
    ev = ev.drop(columns="_merge")

    # Request key reused inside a capture => several possible matches.
    ev["tid_reuse"] = (ev.groupby(KEY)["occ"].transform("max") > 0).astype(int)
    delay = ev["rsp_timestamp"] - ev["timestamp"]
    out_of_order = found & (delay < 0)
    matched = found & ~out_of_order
    ev["pair_found"] = matched.astype(int)
    ev["response_delay"] = np.where(matched, delay, np.nan)
    exc = matched & (ev["rsp_is_exception"] == 1)
    status = np.full(len(ev), "missing", dtype=object)
    status[matched.to_numpy()] = "matched"
    status[exc.to_numpy()] = "exception"
    status[out_of_order.to_numpy()] = "out_of_order"
    ev["pair_status"] = status
    ev["response_missing"] = (~found).astype(int)
    ev["response_exception"] = np.where(matched, exc.astype(int), np.nan)
    ev["unit_id_match"] = np.where(matched, (ev["rsp_mbtcp_unit_id"] == ev["mbtcp_unit_id"]).astype(int), np.nan)
    ev["function_code_match"] = np.where(
        matched, (ev["rsp_modbus_func_code"] == ev["modbus_func_code"]).astype(int), np.nan
    )
    fc = ev["modbus_func_code"]
    wr = fc.isin([5, 6])
    rd = fc.isin([1, 2, 3, 4])
    # Writes echo address and value; reads return a byte count only.
    ev["address_match"] = np.where(
        matched & wr & ~exc, (ev["rsp_modbus_ref_num"] == ev["modbus_ref_num"]).astype(int), np.nan
    )
    ev["value_echo_match"] = np.where(
        matched & wr & ~exc, (ev["rsp_modbus_val"] == ev["modbus_val"]).astype(int), np.nan
    )
    expected = np.where(fc.isin([1, 2]), np.ceil(ev["modbus_bit_cnt"].clip(lower=0) / 8.0), 2 * ev["modbus_word_cnt"])
    # Dataset stores quantity in word_cnt/bit_cnt; quantity_match is only
    # computed where an expected byte count can be derived (reads).
    qty_ok = (ev["rsp_modbus_byte_cnt"] == expected).astype(int)
    ev["quantity_match"] = np.where(matched & rd & ~exc & (expected > 0), qty_ok, np.nan)
    length_ok = np.where(rd, ev["rsp_mbtcp_len"] == ev["rsp_modbus_byte_cnt"] + 3, ev["rsp_mbtcp_len"] == 6)
    length_ok = np.where(exc, ev["rsp_mbtcp_len"] == 3, length_ok)
    ev["response_length_valid"] = np.where(matched, np.asarray(length_ok).astype(int), np.nan)

    used = set(zip(ev.loc[matched, "capture_id"], ev.loc[matched, "rsp_source_row"].astype("int64")))
    orphan_mask = [(c, s) not in used for c, s in zip(rsp["capture_id"], rsp["source_row"])]
    orphans = rsp.loc[orphan_mask]
    stats = {
        "requests": int(len(ev)),
        "responses": int(len(rsp)),
        "matched_pairs": int(matched.sum()),
        "exception_responses": int(exc.sum()),
        "missing_responses": int((~found).sum()),
        "out_of_order_pairs": int(out_of_order.sum()),
        "orphan_responses": int(len(orphans)),
        "requests_with_reused_transaction_key": int(ev["tid_reuse"].sum()),
        "pairing_level": "full (endpoint+port+transaction-id keyed, time ordered)",
    }
    return ev.drop(columns=["occ"]), orphans.drop(columns=["occ"]), stats
