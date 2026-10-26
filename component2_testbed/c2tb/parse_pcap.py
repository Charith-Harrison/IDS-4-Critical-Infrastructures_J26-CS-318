"""Lineage-preserving Modbus/TCP ADU extraction from an immutable run PCAP.

Reuses the read-only libpcap reader/decoder from the forensic audit (component2_forensic_review/scripts/pcapio.py).
Each TCP direction is reassembled by sequence number; ADUs are framed by the MBAP length field, and every ADU keeps
the frame number and payload offset of its first byte (plus the frame holding its last byte), so it can be traced
back to the source bytes.  Address/quantity are populated only for FC1-4 requests; responses never receive request
fields from defaults.  Responses are paired causally with the earlier request (in capture frame order) on the reversed
connection that has the same transaction ID, unit ID and base function code.
"""
from __future__ import annotations

from collections import defaultdict

import pandas as pd

from pcapio import ACK, FIN, RST, SYN, decode_l2l3l4, iter_records, open_pcap  # forensic audit reader
from c2tb.wire import decode_adu, decode_request_fields, decode_response_fields

MODBUS_PORT = 502


def read_segments(pcap_path):
    segs, kinds, ips = [], defaultdict(int), set()
    with open(pcap_path, "rb") as fh:
        hdr = open_pcap(fh)
        scale = 1_000_000_000 // hdr.ticks_per_second
        for frame, sec, frac, caplen, origlen, data, off in iter_records(fh, hdr):
            if data is None:
                kinds["truncated_record"] += 1
                continue
            kind, seg = decode_l2l3l4(data, hdr.linktype)
            kinds[kind] += 1
            if seg is None:
                continue
            ips.update((seg.src_ip, seg.dst_ip))
            segs.append({"frame": frame, "ts_ns": sec * 1_000_000_000 + frac * scale, "origlen": origlen,
                         "caplen": caplen, "record_offset": off, "seg": seg})
    return hdr, segs, dict(kinds), ips


def reassemble(segs):
    """Return per-direction byte streams with a byte->frame map, plus TCP anomaly counts."""
    streams = {}
    anomalies = defaultdict(int)
    for s in segs:
        g = s["seg"]
        key = (g.src_ip, g.src_port, g.dst_ip, g.dst_port)
        st = streams.setdefault(key, {"next_seq": None, "buf": bytearray(), "pieces": [], "syn": 0})
        if g.flags & SYN:
            st["syn"] += 1
            if st["next_seq"] is not None and st["buf"]:
                anomalies["syn_after_data_same_4tuple"] += 1
            st["next_seq"] = (g.seq + 1) & 0xFFFFFFFF
            continue
        if not g.payload:
            continue
        if g.truncated:
            anomalies["truncated_payload"] += 1
        if st["next_seq"] is None:
            st["next_seq"] = g.seq
            anomalies["stream_without_syn"] += 1
        delta = (g.seq - st["next_seq"]) & 0xFFFFFFFF
        if delta == 0:
            payload, poff = g.payload, 0
        elif delta > 0x7FFFFFFF:  # seq before expected: retransmission / overlap
            back = 0x100000000 - delta
            anomalies["retransmitted_or_overlapping_segment"] += 1
            if back >= len(g.payload):
                continue
            payload, poff = g.payload[back:], back
        else:
            anomalies["gap_or_out_of_order_segment"] += 1
            continue
        st["pieces"].append((len(st["buf"]), len(payload), s, poff))
        st["buf"] += payload
        st["next_seq"] = (st["next_seq"] + len(payload)) & 0xFFFFFFFF
    return streams, dict(anomalies)


def locate(pieces, pos):
    for start, n, s, poff in pieces:
        if start <= pos < start + n:
            return s, poff + (pos - start)
    return None, None


def extract_adus(pcap_path, run_id, pcap_name="capture.pcap"):
    hdr, segs, kinds, ips = read_segments(pcap_path)
    streams, anomalies = reassemble(segs)
    rows = []
    trailing = 0
    for (sip, sport, dip, dport), st in streams.items():
        buf, pos = bytes(st["buf"]), 0
        while len(buf) - pos >= 7:
            length = int.from_bytes(buf[pos + 4:pos + 6], "big")
            end = pos + 6 + length
            if length < 2 or end > len(buf):
                break
            adu = buf[pos:end]
            first, first_off = locate(st["pieces"], pos)
            last, _ = locate(st["pieces"], end - 1)
            d = decode_adu(adu)
            is_req = dport == MODBUS_PORT
            row = {
                "run_id": run_id, "pcap_file": pcap_name,
                "adu_id": f"{run_id}:{first['frame']}:{first_off}",
                "frame_number": first["frame"], "pcap_record_offset": first["record_offset"],
                "adu_offset_in_tcp_payload": first_off, "end_frame_number": last["frame"],
                "spans_segments": first["frame"] != last["frame"],
                "ts_ns": first["ts_ns"], "frame_len": first["origlen"],
                "src_ip": sip, "src_port": sport, "dst_ip": dip, "dst_port": dport,
                "direction": "request" if is_req else "response",
                "tid": d["tid"], "protocol_id": d["protocol_id"], "mbap_len": d["mbap_len"], "unit": d["unit"],
                "wire_fc": d["wire_fc"], "base_fc": d["wire_fc"] & 0x7F, "adu_len": len(adu), "adu_hex": adu.hex(),
            }
            if is_req:
                row.update(decode_request_fields(d["pdu"]), is_exception=False, exception_code=None, byte_count=None)
            else:
                row.update(address=None, quantity=None, **decode_response_fields(d["pdu"]))
            rows.append(row)
            pos = end
        trailing += len(buf) - pos
    adus = pd.DataFrame(rows).sort_values(["ts_ns", "frame_number", "adu_offset_in_tcp_payload"]).reset_index(drop=True)
    for c in ("address", "quantity", "exception_code", "byte_count"):
        adus[c] = adus[c].astype("Int64")
    stats = {"linktype": hdr.linktype, "ticks_per_second": hdr.ticks_per_second, "frames_by_kind": kinds,
             "tcp_anomalies": anomalies, "trailing_unframed_bytes": trailing,
             "syn_count_by_direction": {f"{k[0]}:{k[1]}->{k[2]}:{k[3]}": v["syn"] for k, v in streams.items()},
             "n_adus": len(adus), "tcp_ip_endpoints": sorted(ips)}
    return adus, stats


def pair_responses(adus: pd.DataFrame) -> pd.DataFrame:
    """Attach the causally later matching response to each request (one-to-one)."""
    req = adus[adus.direction == "request"].copy()
    rsp = adus[adus.direction == "response"]
    pending = defaultdict(list)
    for r in req.itertuples():
        pending[(r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.tid, r.unit, r.base_fc)].append(r)
    match = {}
    unmatched_rsp = 0
    for s in rsp.itertuples():
        k = (s.dst_ip, s.dst_port, s.src_ip, s.src_port, s.tid, s.unit, s.base_fc)
        # Causal order = capture (frame) order, not wall-clock time: the VM wall clock can step backwards between a
        # request and its response (observed in pilot v3), while frame order is the kernel's delivery order.
        cands = [r for r in pending.get(k, []) if r.frame_number < s.frame_number and r.adu_id not in match]
        if not cands:
            unmatched_rsp += 1
            continue
        r = cands[0]
        match[r.adu_id] = s
    cols = {"response_adu_id": "adu_id", "response_frame_number": "frame_number", "response_ts_ns": "ts_ns",
            "response_wire_fc": "wire_fc", "response_is_exception": "is_exception",
            "response_exception_code": "exception_code", "response_byte_count": "byte_count",
            "response_frame_len": "frame_len", "response_adu_len": "adu_len", "response_hex": "adu_hex"}
    for new, old in cols.items():
        req[new] = [getattr(match[a], old) if a in match else None for a in req.adu_id]
    req["response_latency_us"] = [(match[a].ts_ns - t) / 1000 if a in match else None
                                  for a, t in zip(req.adu_id, req.ts_ns)]
    req["response_pairing"] = ["reversed_endpoints_same_tid_unit_basefc_first_later_frame" if a in match else "unmatched"
                               for a in req.adu_id]
    req.attrs["unmatched_responses"] = unmatched_rsp
    return req.reset_index(drop=True)
