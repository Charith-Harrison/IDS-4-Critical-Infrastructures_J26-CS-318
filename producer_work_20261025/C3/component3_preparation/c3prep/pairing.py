"""Offline audit relations. These tables are metadata, never predictor features."""
from collections import Counter, defaultdict, deque
import json
from pathlib import Path
import sqlite3

import pyarrow as pa
import pyarrow.parquet as pq


PAIR_SCHEMA = pa.schema([
    ("recording_id", pa.string()), ("view_id", pa.string()), ("conn_uid", pa.string()),
    ("request_uid", pa.string()), ("response_uid", pa.string()),
    ("candidate_request_uids", pa.list_(pa.string())), ("transaction_generation", pa.int32()),
    ("status", pa.string()), ("reasons", pa.list_(pa.string())),
    ("request_complete_us", pa.int64()), ("response_complete_us", pa.int64()),
    ("elapsed_us_audit_only", pa.int64()), ("request_address_audit_only", pa.int32()),
    ("request_quantity_audit_only", pa.int32()), ("expected_response_bytes_audit_only", pa.int32()),
    ("request_first_chunk", pa.int16()), ("request_last_chunk", pa.int16()),
    ("response_first_chunk", pa.int16()), ("response_last_chunk", pa.int16()),
])

SLIM = ["event_uid", "event_seq", "recording_id", "view_id", "conn_uid", "protocol_role", "record_kind",
        "mbap_trans_id", "unit_id", "func_code", "is_exception", "ts_complete_us", "address",
        "quantity", "byte_count", "single_value", "and_mask", "or_mask", "parse_status", "first_chunk", "last_chunk"]


def consistency(req, rsp):
    reasons = []
    if req["unit_id"] != rsp["unit_id"]:
        reasons.append("unit_mismatch")
    if req["func_code"] != rsp["func_code"]:
        reasons.append("function_mismatch")
    fc, qty = req["func_code"], req["quantity"]
    expected = None
    if qty is not None and fc in (1, 2, 3, 4, 23):
        expected = (qty + 7) // 8 if fc in (1, 2) else 2 * qty
        if not rsp["is_exception"] and rsp["byte_count"] != expected:
            reasons.append("response_byte_count_vs_request_quantity")
    if fc in (5, 6, 15, 16, 22) and not rsp["is_exception"]:
        if req["address"] != rsp["address"]:
            reasons.append("write_echo_address_mismatch")
        if fc in (5, 6) and req["single_value"] != rsp["single_value"]:
            reasons.append("write_echo_value_mismatch")
        if fc in (15, 16) and qty != rsp["quantity"]:
            reasons.append("write_echo_quantity_mismatch")
        if fc == 22 and (req["and_mask"] != rsp["and_mask"] or req["or_mask"] != rsp["or_mask"]):
            reasons.append("write_echo_mask_mismatch")
    if rsp["parse_status"] not in ("ok", "exception"):
        reasons.append("response_parse_" + rsp["parse_status"])
    return reasons, expected


def pair_connection(events, max_pending=8192, capture_end=True):
    """Input one connection in completion-time order. Never assume FIFO TID reuse.

    No time cutoff is applied: pending count is bounded; evictions are explicit.
    Late/duplicate response is a candidate status, not an attack annotation.
    """
    pending = defaultdict(list)
    generations = Counter()
    recent = {}
    recent_keys = deque()
    count = 0

    def relation(req, rsp, status, candidates=(), reasons=(), expected=None):
        base = req or rsp
        a = req["ts_complete_us"] if req else None
        b = rsp["ts_complete_us"] if rsp else None
        return dict(recording_id=base["recording_id"], view_id=base["view_id"], conn_uid=base["conn_uid"],
                    request_uid=req["event_uid"] if req else None,
                    response_uid=rsp["event_uid"] if rsp else None,
                    candidate_request_uids=list(candidates), transaction_generation=req.get("_gen") if req else None,
                    status=status, reasons=list(reasons), request_complete_us=a, response_complete_us=b,
                    elapsed_us_audit_only=b-a if a is not None and b is not None else None,
                    request_address_audit_only=req["address"] if req else None,
                    request_quantity_audit_only=req["quantity"] if req else None,
                    expected_response_bytes_audit_only=expected,
                    request_first_chunk=req.get("first_chunk") if req else None,
                    request_last_chunk=req.get("last_chunk") if req else None,
                    response_first_chunk=rsp.get("first_chunk") if rsp else None,
                    response_last_chunk=rsp.get("last_chunk") if rsp else None)

    for ev in events:
        if ev["record_kind"] != "adu" or ev["mbap_trans_id"] is None:
            req, rsp = (ev, None) if ev["protocol_role"] == "request" else (None, ev)
            yield relation(req, rsp, "unpairable_record", reasons=[ev["record_kind"]])
            continue
        tid = ev["mbap_trans_id"]
        if ev["protocol_role"] == "request":
            generations[tid] += 1
            ev["_gen"] = generations[tid]
            pending[tid].append(ev)
            count += 1
            if count > max_pending:
                oldtid = min(pending, key=lambda t: pending[t][0]["ts_complete_us"])
                old = pending[oldtid].pop(0)
                if not pending[oldtid]:
                    del pending[oldtid]
                count -= 1
                yield relation(old, None, "pending_evicted_capacity", reasons=["audit_pending_capacity"])
            continue
        candidates = pending.get(tid, [])
        compatible = [q for q in candidates if q["unit_id"] == ev["unit_id"] and q["func_code"] == ev["func_code"]]
        if len(compatible) == 1:
            req = compatible[0]
            # Shape validation cannot establish uniqueness when same identity is outstanding twice.
            pending[tid].remove(req)
            if not pending[tid]:
                del pending[tid]
            count -= 1
            reasons, expected = consistency(req, ev)
            status = "matched_exception" if ev["is_exception"] else "matched"
            if reasons:
                status = "matched_inconsistent"
            yield relation(req, ev, status, reasons=reasons, expected=expected)
            recent[tid] = req
            recent_keys.append((tid, req["event_uid"]))
            if len(recent_keys) > max_pending:
                k, uid = recent_keys.popleft()
                if recent.get(k, {}).get("event_uid") == uid:
                    del recent[k]
        elif candidates:
            status = "ambiguous_reused_transaction" if compatible else "unit_or_function_mismatch"
            yield relation(None, ev, status, [q["event_uid"] for q in candidates], [status])
        elif tid in recent:
            yield relation(None, ev, "late_or_duplicate_response_candidate", [recent[tid]["event_uid"]])
        else:
            yield relation(None, ev, "orphan_response", reasons=["no_observed_outstanding_request"])
    for qs in pending.values():
        for req in qs:
            yield relation(req, None, "pending_at_capture_end" if capture_end else "pending_at_connection_end")


def build_pairs(events_path, output_path, max_pending=8192):
    """SQLite performs a disk-backed chronological audit sort, not a model transform."""
    output_path = Path(output_path)
    dbpath = output_path.with_suffix(".sqlite.tmp")
    if dbpath.exists():
        dbpath.unlink()
    db = sqlite3.connect(dbpath)
    db.execute("PRAGMA journal_mode=OFF")
    db.execute("PRAGMA synchronous=OFF")
    db.execute("PRAGMA cache_size=-32768")
    db.execute("CREATE TABLE events (seq INTEGER, conn TEXT, ts INTEGER, row TEXT)")
    count = 0
    for batch in pq.ParquetFile(events_path).iter_batches(batch_size=30000, columns=SLIM):
        rows = batch.to_pylist()
        db.executemany("INSERT INTO events VALUES (?,?,?,?)", [(r["event_seq"], r["conn_uid"], r["ts_complete_us"], json.dumps(r, separators=(",", ":"))) for r in rows])
        count += len(rows)
    db.commit()
    db.execute("CREATE INDEX ordering ON events(conn,ts,seq)")
    ends = {}
    conn_path = Path(events_path).with_name("connections.parquet")
    if conn_path.exists():
        for batch in pq.ParquetFile(conn_path).iter_batches(columns=["conn_uid", "end_reason"]):
            ends.update((r["conn_uid"], r["end_reason"] == "chain_end") for r in batch.to_pylist())
    writer = pq.ParquetWriter(output_path.with_suffix(".parquet.tmp"), PAIR_SCHEMA, compression="zstd")
    stats = Counter()
    delays = Counter()
    boundaries = Counter()
    buffer = []

    def write(rel):
        buffer.append(rel)
        stats[rel["status"]] += 1
        if rel["request_uid"] and rel["response_uid"]:
            boundaries["matched_relations"] += 1
            boundaries["request_response_cross_chunk"] += rel["request_first_chunk"] != rel["response_last_chunk"]
        delta = rel["elapsed_us_audit_only"]
        if delta is not None:
            for horizon in (5, 60, 300):
                if delta > horizon * 1000000:
                    delays[f"matched_over_{horizon}s"] += 1
        if len(buffer) >= 30000:
            writer.write_table(pa.Table.from_pylist(buffer, schema=PAIR_SCHEMA))
            buffer.clear()

    # Group by a cursor iterator; no connection's entire history is loaded.
    import itertools
    cur = db.execute("SELECT conn,row FROM events ORDER BY conn,ts,seq")
    for conn, group in itertools.groupby(cur, key=lambda r: r[0]):
        for rel in pair_connection((json.loads(r[1]) for r in group), max_pending=max_pending, capture_end=ends.get(conn, True)):
            write(rel)
    if buffer:
        writer.write_table(pa.Table.from_pylist(buffer, schema=PAIR_SCHEMA))
    writer.close()
    output_path.with_suffix(".parquet.tmp").replace(output_path)
    db.close()
    dbpath.unlink()
    return {"input_records": count, "relation_counts": dict(stats), "pair_chunk_boundaries": dict(boundaries), "timeout_sensitivity_audit": dict(delays),
            "timeout_policy": "No time expiry. Explicit bounded outstanding capacity per connection.", "max_pending_per_connection": max_pending}
