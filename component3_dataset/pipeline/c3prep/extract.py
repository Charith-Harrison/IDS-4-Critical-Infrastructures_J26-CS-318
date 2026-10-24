"""View-chain extraction: TCP reassembly -> Modbus/TCP ADU events.

A *view chain* is the ordered list of rotated capture chunks recorded on one
observation interface during one recording run.  Reassembly state is carried
across chunk boundaries of the same chain (chunks were verified contiguous by
timestamps in the manifest stage); it is never shared between different views.

Outputs (per chain, written atomically):
  events.parquet       one row per ADU / non-framed run / incomplete run
  connections.parquet  one row per TCP connection generation
  accounting.json      frame, byte and record reconciliation counters
"""
from __future__ import annotations

import json
import os
import shutil
import time
from collections import Counter, deque
from typing import Optional

import pyarrow as pa
import pyarrow.parquet as pq

from .modbus import FC_NAMES, StreamFramer, decode_pdu
from .pcapio import ACK, FIN, RST, SYN, decode_l2l3l4, iter_records, open_pcap

MASK32 = 0xFFFFFFFF

EVENT_SCHEMA = pa.schema([
    ("event_uid", pa.string()),
    ("recording_id", pa.string()),
    ("view_id", pa.string()),
    ("event_seq", pa.int64()),
    ("record_kind", pa.string()),          # adu | nonframed | incomplete
    ("conn_uid", pa.string()),
    ("client_ip", pa.string()), ("client_port", pa.int32()),
    ("server_ip", pa.string()), ("server_port", pa.int32()),
    ("direction", pa.string()),            # c2s | s2c
    ("protocol_role", pa.string()),        # request | response (from direction only)
    ("dir_record_index", pa.int32()),      # index of the record within conn-direction
    ("stream_off_start", pa.int64()), ("stream_off_end", pa.int64()),
    ("ts_first_us", pa.int64()),           # epoch microseconds of segment carrying first byte
    ("ts_complete_us", pa.int64()),        # epoch microseconds when last missing byte arrived
    ("first_chunk", pa.int16()), ("first_frame", pa.int64()),
    ("last_chunk", pa.int16()), ("last_frame", pa.int64()),
    ("n_segments", pa.int16()),
    ("frame_refs", pa.string()),           # "chunk:frame;..." (bounded)
    ("starts_at_segment_start", pa.bool_()),
    ("ends_at_segment_end", pa.bool_()),
    ("reasm_ooo", pa.bool_()), ("reasm_overlap", pa.bool_()), ("reasm_after_gap", pa.bool_()),
    ("conn_midstream", pa.bool_()),
    ("adu_bytes", pa.binary()), ("adu_len", pa.int32()),
    ("mbap_trans_id", pa.int32()), ("mbap_proto_id", pa.int32()), ("mbap_length", pa.int32()),
    ("unit_id", pa.int16()), ("func_raw", pa.int16()), ("func_code", pa.int16()), ("func_name", pa.string()),
    ("is_exception", pa.bool_()), ("exception_code", pa.int16()),
    ("pdu_len", pa.int32()),
    ("address", pa.int32()), ("quantity", pa.int32()),
    ("write_address", pa.int32()), ("write_quantity", pa.int32()),
    ("byte_count", pa.int32()), ("single_value", pa.int32()),
    ("reg_values", pa.list_(pa.int32())), ("bit_bytes", pa.binary()),
    ("sub_function", pa.int32()), ("and_mask", pa.int32()), ("or_mask", pa.int32()), ("mei_type", pa.int16()),
    ("expected_pdu_len", pa.int32()), ("shape_ok", pa.bool_()), ("shape_reason", pa.string()),
    ("parse_status", pa.string()),         # ok | exception | malformed | unsupported | nonframed | incomplete
    ("parse_reason", pa.string()),
])

CONN_SCHEMA = pa.schema([
    ("conn_uid", pa.string()), ("recording_id", pa.string()), ("view_id", pa.string()),
    ("conn_seq", pa.int64()),
    ("client_ip", pa.string()), ("client_port", pa.int32()),
    ("server_ip", pa.string()), ("server_port", pa.int32()),
    ("syn_seen", pa.bool_()), ("midstream", pa.bool_()),
    ("first_ts_us", pa.int64()), ("last_ts_us", pa.int64()),
    ("first_chunk", pa.int16()), ("last_chunk", pa.int16()),
    ("spans_chunks", pa.bool_()),
    ("fin_c2s", pa.bool_()), ("fin_s2c", pa.bool_()), ("rst", pa.bool_()),
    ("end_reason", pa.string()),
    ("frames", pa.int64()),
    ("c2s_bytes", pa.int64()), ("s2c_bytes", pa.int64()),
    ("c2s_records", pa.int32()), ("s2c_records", pa.int32()),
    ("retrans_segments", pa.int32()), ("retrans_conflicts", pa.int32()),
    ("ooo_segments", pa.int32()), ("gaps", pa.int32()), ("gap_bytes", pa.int64()),
    ("truncated_segments", pa.int32()), ("post_close_payload_segments", pa.int32()),
])


class DirState:
    __slots__ = ("isn1", "next", "ooo", "ooo_bytes", "segs", "tail", "tail_off", "framer",
                 "rec_idx", "bytes", "after_gap", "seen")

    def __init__(self):
        self.isn1: Optional[int] = None
        self.next = 0
        self.ooo: dict = {}
        self.ooo_bytes = 0
        self.segs: deque = deque()        # (off, end, chunk, frame, ts, ooo_flag, overlap_flag)
        self.tail = b""                   # last delivered bytes, for retransmission comparison
        self.tail_off = 0
        self.framer: Optional[StreamFramer] = None
        self.rec_idx = 0
        self.bytes = 0
        self.after_gap = False
        self.seen = False


class Conn:
    __slots__ = ("uid", "seq", "key", "d", "syn_seen", "midstream", "first_ts", "last_ts", "first_chunk",
                 "last_chunk", "fin", "rst", "closed_ts", "frames", "client_isn", "c", "post_close")

    def __init__(self, uid, seq, key, ts, chunk):
        self.uid = uid
        self.seq = seq
        self.key = key
        self.d = (DirState(), DirState())
        self.syn_seen = False
        self.midstream = False
        self.first_ts = ts
        self.last_ts = ts
        self.first_chunk = chunk
        self.last_chunk = chunk
        self.fin = [False, False]
        self.rst = False
        self.closed_ts = None
        self.frames = 0
        self.client_isn = None
        self.c = Counter()
        self.post_close = 0


class ChainExtractor:
    def __init__(self, recording_id: str, view_id: str, cfg: dict, out_dir: str):
        self.rec = recording_id
        self.view = view_id
        self.cfg = cfg
        self.ports = set(cfg["modbus_ports"])
        self.idle_us = int(cfg["conn_idle_timeout_s"] * 1e6)
        self.linger_us = int(cfg["closed_linger_s"] * 1e6)
        self.max_conns = cfg["max_open_connections"]
        self.max_ooo_segments = cfg["max_ooo_segments"]
        self.max_ooo_bytes = cfg["max_ooo_bytes"]
        self.max_pending = cfg["max_pending_bytes"]
        self.max_refs = cfg["max_frame_refs"]
        self.out_dir = out_dir
        self.conns: dict = {}
        self.conn_seq = 0
        self.event_seq = 0
        self.rows: list = []
        self.conn_rows: list = []
        self.acc = Counter()
        self.nonmodbus = Counter()
        self.writer = None
        self.conn_writer = None
        self.now = 0
        self.chunk = 0

    # ------------------------------------------------------------------ output
    def _flush_rows(self, force=False):
        if self.rows and (force or len(self.rows) >= 200_000):
            t = pa.Table.from_pylist(self.rows, schema=EVENT_SCHEMA)
            if self.writer is None:
                self.writer = pq.ParquetWriter(os.path.join(self.out_dir, "events.parquet"), EVENT_SCHEMA,
                                               compression="zstd")
            self.writer.write_table(t)
            self.rows.clear()
        if self.conn_rows and (force or len(self.conn_rows) >= 200_000):
            t = pa.Table.from_pylist(self.conn_rows, schema=CONN_SCHEMA)
            if self.conn_writer is None:
                self.conn_writer = pq.ParquetWriter(os.path.join(self.out_dir, "connections.parquet"), CONN_SCHEMA,
                                                    compression="zstd")
            self.conn_writer.write_table(t)
            self.conn_rows.clear()

    # ------------------------------------------------------------- connections
    def _new_conn(self, key, ts):
        self.conn_seq += 1
        uid = f"{self.view}:c{self.conn_seq}"
        c = Conn(uid, self.conn_seq, key, ts, self.chunk)
        for i in (0, 1):
            c.d[i].framer = StreamFramer(self._make_emit(c, i), max_pending=self.max_pending)
        self.conns[key] = c
        self.acc["connections"] += 1
        if len(self.conns) > self.max_conns:
            oldest = min(self.conns.values(), key=lambda x: x.last_ts)
            self._finalize(oldest, "evicted_capacity")
            self.acc["conn_evicted_capacity"] += 1
        return c

    def _finalize(self, c: Conn, reason: str):
        for i in (0, 1):
            ds = c.d[i]
            # deliver any buffered out-of-order data after declaring gaps
            while ds.ooo:
                off = min(ds.ooo)
                payload, ch, fr, ts = ds.ooo.pop(off)
                ds.ooo_bytes -= len(payload)
                if off + len(payload) <= ds.next:
                    self.acc["bytes_dup_dropped"] += len(payload)
                    continue
                if off > ds.next:
                    c.c["gaps"] += 1
                    c.c["gap_bytes"] += off - ds.next
                    self.acc["gap_bytes"] += off - ds.next
                    ds.framer.gap(off, "stream_gap_at_finalize")
                    ds.next = off
                    ds.after_gap = True
                elif off < ds.next:
                    cut = ds.next - off
                    self.acc["bytes_dup_dropped"] += cut
                    payload = payload[cut:]
                    off = ds.next
                self._deliver(c, i, off, payload, ch, fr, ts, ooo=True, overlap=False)
            ds.framer.flush(f"conn_end:{reason}")
        self.conn_rows.append({
            "conn_uid": c.uid, "recording_id": self.rec, "view_id": self.view, "conn_seq": c.seq,
            "client_ip": c.key[0], "client_port": c.key[1], "server_ip": c.key[2], "server_port": c.key[3],
            "syn_seen": c.syn_seen, "midstream": c.midstream,
            "first_ts_us": c.first_ts, "last_ts_us": c.last_ts,
            "first_chunk": c.first_chunk, "last_chunk": c.last_chunk, "spans_chunks": c.first_chunk != c.last_chunk,
            "fin_c2s": c.fin[0], "fin_s2c": c.fin[1], "rst": c.rst, "end_reason": reason,
            "frames": c.frames, "c2s_bytes": c.d[0].bytes, "s2c_bytes": c.d[1].bytes,
            "c2s_records": c.d[0].rec_idx, "s2c_records": c.d[1].rec_idx,
            "retrans_segments": c.c["retrans"], "retrans_conflicts": c.c["retrans_conflict"],
            "ooo_segments": c.c["ooo"], "gaps": c.c["gaps"], "gap_bytes": c.c["gap_bytes"],
            "truncated_segments": c.c["truncated"], "post_close_payload_segments": c.post_close,
        })
        self.acc[f"conn_end:{reason}"] += 1
        if self.conns.get(c.key) is c:
            del self.conns[c.key]

    def _sweep(self):
        now = self.now
        dead = []
        for c in self.conns.values():
            if c.closed_ts is not None and now - c.closed_ts > self.linger_us:
                dead.append((c, "closed"))
            elif now - c.last_ts > self.idle_us:
                dead.append((c, "idle_timeout"))
        for c, r in dead:
            self._finalize(c, r)

    # ---------------------------------------------------------------- emission
    def _make_emit(self, c: Conn, i: int):
        def emit(kind, s, e, data, reason):
            self._emit_record(c, i, kind, s, e, data, reason)
        return emit

    def _emit_record(self, c: Conn, i: int, kind: str, s: int, e: int, data: bytes, reason: str):
        ds = c.d[i]
        # locate contributing segments
        segs = [g for g in ds.segs if g[1] > s and g[0] < e]
        if segs:
            first = segs[0]
            last = max(segs, key=lambda g: g[4])
            ts_first, ts_complete = first[4], last[4]
            refs = ";".join(f"{g[2]}:{g[3]}" for g in segs[: self.max_refs])
            if len(segs) > self.max_refs:
                refs += f";+{len(segs) - self.max_refs}"
            starts = first[0] == s
            ends = segs[-1][1] == e
            ooo = any(g[5] for g in segs)
            ovl = any(g[6] for g in segs)
            fc_, ff_ = first[2], first[3]
            lc_, lf_ = segs[-1][2], segs[-1][3]
        else:  # should not happen; keep visible
            ts_first = ts_complete = None
            refs = ""
            starts = ends = ooo = ovl = None
            fc_ = ff_ = lc_ = lf_ = None
            self.acc["records_without_segments"] += 1
        # prune segments no longer needed
        while ds.segs and ds.segs[0][1] <= e:
            ds.segs.popleft()
        self.event_seq += 1
        is_req = i == 0
        row = {
            "event_uid": f"{self.view}:e{self.event_seq}", "recording_id": self.rec, "view_id": self.view,
            "event_seq": self.event_seq, "record_kind": kind, "conn_uid": c.uid,
            "client_ip": c.key[0], "client_port": c.key[1], "server_ip": c.key[2], "server_port": c.key[3],
            "direction": "c2s" if is_req else "s2c", "protocol_role": "request" if is_req else "response",
            "dir_record_index": ds.rec_idx, "stream_off_start": s, "stream_off_end": e,
            "ts_first_us": ts_first, "ts_complete_us": ts_complete,
            "first_chunk": fc_, "first_frame": ff_, "last_chunk": lc_, "last_frame": lf_,
            "n_segments": len(segs), "frame_refs": refs,
            "starts_at_segment_start": starts, "ends_at_segment_end": ends,
            "reasm_ooo": ooo, "reasm_overlap": ovl, "reasm_after_gap": ds.after_gap,
            "conn_midstream": c.midstream,
            "adu_bytes": data, "adu_len": len(data),
            "mbap_trans_id": None, "mbap_proto_id": None, "mbap_length": None, "unit_id": None,
            "func_raw": None, "func_code": None, "func_name": None, "is_exception": None, "exception_code": None,
            "pdu_len": None, "address": None, "quantity": None, "write_address": None, "write_quantity": None,
            "byte_count": None, "single_value": None, "reg_values": None, "bit_bytes": None,
            "sub_function": None, "and_mask": None, "or_mask": None, "mei_type": None,
            "expected_pdu_len": None, "shape_ok": None, "shape_reason": None,
            "parse_status": kind if kind != "adu" else None, "parse_reason": reason or None,
        }
        ds.after_gap = False
        ds.rec_idx += 1
        self.acc[f"records_{kind}"] += 1
        self.acc[f"bytes_in_{kind}"] += len(data)
        if len(data) >= 7:
            row["mbap_trans_id"] = (data[0] << 8) | data[1]
            row["mbap_proto_id"] = (data[2] << 8) | data[3]
            row["mbap_length"] = (data[4] << 8) | data[5]
            row["unit_id"] = data[6]
        if kind == "adu":
            pdu = data[7:]
            row["pdu_len"] = len(pdu)
            if pdu:
                raw = pdu[0]
                row["func_raw"] = raw
                row["func_code"] = raw & 0x7F
                row["func_name"] = FC_NAMES.get(raw & 0x7F, "unassigned_or_user_defined")
                row["is_exception"] = bool(raw & 0x80)
                if raw & 0x80 and len(pdu) >= 2:
                    row["exception_code"] = pdu[1]
            dec = decode_pdu(pdu, is_req)
            row.update(dec)
            if not pdu:
                status = "malformed"
            elif dec["shape_reason"] == "unsupported_function":
                status = "unsupported"
            elif dec["shape_ok"] is False:
                status = "malformed"
            elif row["is_exception"]:
                status = "exception"
            else:
                status = "ok"
            if reason == "mbap_length_exceeds_spec":
                status = "malformed"
            row["parse_status"] = status
            reasons = [r for r in (reason, dec["shape_reason"]) if r]
            row["parse_reason"] = "|".join(reasons) or None
            self.acc[f"adu_status_{status}"] += 1
        self.rows.append(row)

    # ------------------------------------------------------------- reassembly
    def _deliver(self, c: Conn, i: int, off: int, payload: bytes, ch, fr, ts, ooo: bool, overlap: bool):
        ds = c.d[i]
        end = off + len(payload)
        ds.segs.append((off, end, ch, fr, ts, ooo, overlap))
        ds.next = end
        ds.bytes += len(payload)
        self.acc["bytes_delivered"] += len(payload)
        keep = 4096
        if len(ds.tail) + len(payload) > keep:
            nt = (ds.tail + payload)[-keep:]
            ds.tail_off = end - len(nt)
            ds.tail = nt
        else:
            if not ds.tail:
                ds.tail_off = off
            ds.tail += payload
        ds.framer.feed(off, payload)

    def _check_retrans(self, c: Conn, ds: DirState, off: int, payload: bytes) -> None:
        a = max(off, ds.tail_off)
        b = min(off + len(payload), ds.tail_off + len(ds.tail))
        if a < b:
            if payload[a - off:b - off] != ds.tail[a - ds.tail_off:b - ds.tail_off]:
                c.c["retrans_conflict"] += 1
                self.acc["retrans_conflict_segments"] += 1

    def _on_payload(self, c: Conn, i: int, seq: int, payload: bytes, ch, fr, ts, truncated_missing: int):
        ds = c.d[i]
        if ds.isn1 is None:
            ds.isn1 = seq
            c.midstream = True
        off = (seq - ds.isn1) & MASK32
        n = len(payload)
        end = off + n
        if off > ds.next and off - ds.next > 0x7FFFFFFF:
            # sequence before the stream start / far in the past: stale retransmission
            c.c["retrans"] += 1
            self.acc["bytes_dup_dropped"] += n
            return
        if end <= ds.next:
            c.c["retrans"] += 1
            self.acc["retrans_segments"] += 1
            self.acc["bytes_dup_dropped"] += n
            self._check_retrans(c, ds, off, payload)
            return
        overlap = False
        if off < ds.next:
            cut = ds.next - off
            self._check_retrans(c, ds, off, payload[:cut])
            self.acc["bytes_dup_dropped"] += cut
            payload = payload[cut:]
            off = ds.next
            overlap = True
            c.c["retrans"] += 1
        if off > ds.next:
            c.c["ooo"] += 1
            self.acc["ooo_segments"] += 1
            if off in ds.ooo:
                old = ds.ooo[off][0]
                if len(old) >= len(payload):
                    self.acc["bytes_dup_dropped"] += len(payload)
                    return
                self.acc["bytes_dup_dropped"] += len(old)
                ds.ooo_bytes -= len(old)
            ds.ooo[off] = (payload, ch, fr, ts)
            ds.ooo_bytes += len(payload)
            if len(ds.ooo) > self.max_ooo_segments or ds.ooo_bytes > self.max_ooo_bytes:
                # bounded buffering: declare the hole a gap and continue
                nxt = min(ds.ooo)
                c.c["gaps"] += 1
                c.c["gap_bytes"] += nxt - ds.next
                self.acc["gap_bytes"] += nxt - ds.next
                self.acc["gaps_ooo_overflow"] += 1
                ds.framer.gap(nxt, "stream_gap_ooo_overflow")
                ds.next = nxt
                ds.after_gap = True
                self._drain_ooo(c, i)
            return
        self._deliver(c, i, off, payload, ch, fr, ts, ooo=False, overlap=overlap)
        if truncated_missing:
            c.c["truncated"] += 1
            c.c["gaps"] += 1
            c.c["gap_bytes"] += truncated_missing
            self.acc["gap_bytes_truncated_capture"] += truncated_missing
            ds.framer.gap(ds.next + truncated_missing, "capture_truncated_segment")
            ds.next += truncated_missing
            ds.after_gap = True
        if ds.ooo:
            self._drain_ooo(c, i)

    def _drain_ooo(self, c: Conn, i: int):
        ds = c.d[i]
        while ds.ooo:
            off = min(ds.ooo)
            if off > ds.next:
                return
            payload, ch, fr, ts = ds.ooo.pop(off)
            ds.ooo_bytes -= len(payload)
            end = off + len(payload)
            if end <= ds.next:
                self.acc["bytes_dup_dropped"] += len(payload)
                continue
            ovl = False
            if off < ds.next:
                cut = ds.next - off
                self.acc["bytes_dup_dropped"] += cut
                payload = payload[cut:]
                off = ds.next
                ovl = True
            self._deliver(c, i, off, payload, ch, fr, ts, ooo=True, overlap=ovl)

    # ------------------------------------------------------------------ frames
    def process_frame(self, ch: int, fr: int, ts: int, data: bytes, linktype: int):
        kind, seg = decode_l2l3l4(data, linktype)
        if seg is None:
            self.nonmodbus[kind] += 1
            return
        if seg.dst_port in self.ports:
            key = (seg.src_ip, seg.src_port, seg.dst_ip, seg.dst_port)
            i = 0
        elif seg.src_port in self.ports:
            key = (seg.dst_ip, seg.dst_port, seg.src_ip, seg.src_port)
            i = 1
        else:
            self.nonmodbus[f"tcp_port_{min(seg.src_port, seg.dst_port)}"] += 1
            return
        self.acc["frames_modbus_port"] += 1
        self.acc["payload_bytes_captured"] += len(seg.payload)
        flags = seg.flags
        c = self.conns.get(key)
        if flags & SYN and not flags & ACK and i == 0:
            if c is not None and (c.closed_ts is not None or (c.client_isn is not None and c.client_isn != seg.seq)
                                  or c.client_isn is None):
                if c.client_isn == seg.seq and c.closed_ts is None:
                    pass
                else:
                    self._finalize(c, "superseded_by_new_syn")
                    c = None
            if c is None:
                c = self._new_conn(key, ts)
            c.syn_seen = True
            c.client_isn = seg.seq
            c.d[0].isn1 = (seg.seq + 1) & MASK32
        elif c is None:
            c = self._new_conn(key, ts)
            if not (flags & SYN):
                c.midstream = True
        if flags & SYN and flags & ACK and i == 1:
            if c.d[1].isn1 is None or c.d[1].next == 0:
                c.d[1].isn1 = (seg.seq + 1) & MASK32
        c.last_ts = ts
        c.last_chunk = ch
        c.frames += 1
        if seg.payload:
            if c.closed_ts is not None:
                c.post_close += 1
            missing = 0
            if seg.truncated and seg.ip_total_len:
                # bytes declared by IP but not captured
                hdr_guess = len(data) - len(seg.payload)
                missing = max(0, seg.ip_total_len + 14 - len(data)) if hdr_guess >= 0 else 0
            self._on_payload(c, i, seg.seq, seg.payload, ch, fr, ts, missing)
        if flags & RST:
            c.rst = True
            if c.closed_ts is None:
                c.closed_ts = ts
        if flags & FIN:
            c.fin[i] = True
            if c.fin[0] and c.fin[1] and c.closed_ts is None:
                c.closed_ts = ts

    def run(self, chunks: list[tuple[int, str]], progress=None) -> dict:
        t0 = time.time()
        frames = 0
        per_chunk = []
        for ch, path in chunks:
            self.chunk = ch
            cf = Counter()
            with open(path, "rb") as fh:
                hdr = open_pcap(fh)
                for fr, sec, frac, caplen, origlen, data, off in iter_records(fh, hdr):
                    if data is None:
                        cf["truncated_pcap_record"] += 1
                        continue
                    ts = sec * 1_000_000 + (frac if hdr.ticks_per_second == 1_000_000 else frac // 1000)
                    if ts < self.now:
                        cf["non_monotonic_frames"] += 1
                    else:
                        self.now = ts
                    cf["frames"] += 1
                    if caplen < origlen:
                        cf["frames_caplen_lt_origlen"] += 1
                    self.process_frame(ch, fr, ts, data, hdr.linktype)
                    frames += 1
                    if frames % 50000 == 0:
                        self._sweep()
                        self._flush_rows()
            per_chunk.append({"chunk": ch, "path": path, **cf})
            self.acc["frames_total"] += cf["frames"]
            if progress:
                progress(self.view, ch, frames, time.time() - t0)
        for c in list(self.conns.values()):
            self._finalize(c, "chain_end")
        self._flush_rows(force=True)
        if self.writer:
            self.writer.close()
        if self.conn_writer:
            self.conn_writer.close()
        acc = dict(self.acc)
        acc["nonmodbus_frames"] = dict(self.nonmodbus)
        acc["per_chunk"] = per_chunk
        acc["elapsed_s"] = round(time.time() - t0, 2)
        # reconciliation: every captured payload byte is either a duplicate or delivered;
        # every delivered byte belongs to exactly one record.
        rec_bytes = sum(v for k, v in self.acc.items() if k.startswith("bytes_in_"))
        acc["check_bytes_captured_eq_dup_plus_delivered"] = (
            self.acc["payload_bytes_captured"] == self.acc["bytes_dup_dropped"] + self.acc["bytes_delivered"])
        acc["check_bytes_delivered_eq_records"] = self.acc["bytes_delivered"] == rec_bytes
        acc["check_frames_accounted"] = (
            self.acc["frames_total"] == self.acc["frames_modbus_port"] + sum(self.nonmodbus.values()))
        return acc


def extract_chain(recording_id: str, view_id: str, chunks: list, cfg: dict, final_dir: str,
                  progress=None) -> dict:
    """Run one chain into a temporary directory and atomically publish it."""
    tmp = final_dir + ".tmp"
    if os.path.exists(tmp):
        shutil.rmtree(tmp)
    os.makedirs(tmp)
    ex = ChainExtractor(recording_id, view_id, cfg, tmp)
    acc = ex.run(chunks, progress)
    with open(os.path.join(tmp, "accounting.json"), "w") as fh:
        json.dump(acc, fh, indent=1, default=str)
    if os.path.exists(final_dir):
        shutil.rmtree(final_dir)
    os.replace(tmp, final_dir)
    return acc
