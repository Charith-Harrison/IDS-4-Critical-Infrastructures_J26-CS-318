"""Offline software fixtures only: no network traffic is generated."""
import struct
from io import BytesIO

from component3_preparation.c3prep.extract import ChainExtractor
from component3_preparation.c3prep.modbus import StreamFramer, decode_pdu
from component3_preparation.c3prep.pcapio import decode_l2l3l4, iter_records, open_pcap

CFG = {"modbus_ports": [502], "conn_idle_timeout_s": 300, "closed_linger_s": 2,
       "max_open_connections": 20000, "max_ooo_segments": 128,
       "max_ooo_bytes": 262144, "max_pending_bytes": 70000,
       "max_frame_refs": 1000, "row_batch_size": 10000}


def adu(tid=1, pdu=b"\x03\x00\x00\x00\x01"):
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu


def frame(seq, payload=b"", flags=0x18, reverse=False, ack=1):
    a, b = bytes([185, 175, 0, 2]), bytes([185, 175, 0, 4])
    sp, dp = 40000, 502
    if reverse:
        a, b, sp, dp = b, a, dp, sp
    tcp = struct.pack("!HHIIHHHH", sp, dp, seq, ack, 0x5000 | flags, 1024, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40 + len(payload), 1, 0, 64, 6, 0, a, b)
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp + payload


def test_decoding_preserves_zero_and_read_values():
    req = decode_pdu(b"\x03\x00\x00\x00\x01", True)
    assert req["address"] == 0 and req["quantity"] == 1 and req["reg_values"] is None
    reply = decode_pdu(bytes.fromhex("030400000009"), False)
    assert reply["reg_values"] == [0, 9]
    assert decode_pdu(bytes.fromhex("0600000000"), True)["single_value"] == 0
    assert decode_pdu(bytes.fromhex("0500000000"), True)["single_value"] == 0
    assert decode_pdu(bytes.fromhex("8302"), False)["shape_ok"]
    assert not decode_pdu(bytes.fromhex("01abcd"), False)["shape_ok"]


def test_multi_adu_and_segmented_stream():
    rows = []
    framer = StreamFramer(lambda *x: rows.append(x))
    data = adu(7) + adu(8)
    framer.feed(0, data[:3])
    framer.feed(3, data[3:15])
    framer.feed(15, data[15:])
    assert [x[3] for x in rows] == [adu(7), adu(8)]
    assert rows[0][1:3] == (0, len(adu(7)))


def test_reassembly_ooo_retrans_chunk_reconnect(tmp_path):
    ex = ChainExtractor("run", "view", CFG, str(tmp_path))
    ex.chunk = 0
    ex.process_frame(0, 1, 1, frame(100, flags=2), 1, 24)
    ex.process_frame(0, 2, 2, frame(500, flags=0x12, reverse=True), 1, 80)
    data = adu(7)
    ex.process_frame(0, 3, 3, frame(107, data[6:]), 1, 140)
    ex.process_frame(0, 4, 4, frame(101, data[:6]), 1, 210)
    ex.process_frame(0, 5, 5, frame(101, data), 1, 280)
    assert len(ex.rows) == 1 and ex.rows[0]["adu_bytes"] == data
    assert ex.rows[0]["reasm_ooo"]
    assert {r["pcap_offset"] for r in ex.rows[0]["segment_refs"]} == {140, 210}
    assert ex.obs_rows[0]["comparison"] == "identical_bytes"
    # A partial ADU continues over a verified rotation boundary.
    more = adu(8)
    ex.process_frame(0, 6, 6, frame(113, more[:4]), 1, 360)
    ex.chunk = 1
    ex.process_frame(1, 1, 7, frame(117, more[4:]), 1, 24)
    assert ex.rows[1]["first_chunk"] == 0 and ex.rows[1]["last_chunk"] == 1
    # Same tuple, different SYN sequence must become a new generation.
    old = ex.rows[0]["conn_uid"]
    ex.process_frame(1, 2, 8, frame(1000, flags=2), 1, 90)
    ex.process_frame(1, 3, 9, frame(1001, adu(7)), 1, 150)
    assert ex.rows[2]["conn_uid"] != old
    for c in list(ex.conns.values()):
        ex._finalize(c, "test_end")
    assert ex.conn_rows[0]["spans_chunks"]


def test_conflicting_overlap_visible(tmp_path):
    ex = ChainExtractor("run", "view", CFG, str(tmp_path))
    ex.process_frame(0, 1, 1, frame(100, adu()), 1)
    ex.process_frame(0, 2, 2, frame(100, adu(pdu=b"\x03\x00\x00\x00\x02")), 1)
    assert ex.obs_rows[0]["comparison"] == "conflicting_bytes"
    assert next(iter(ex.conns.values())).c["retrans_conflict"] == 1


def test_gap_and_unsupported_byte_accounting():
    rows = []
    framer = StreamFramer(lambda *x: rows.append(x))
    framer.feed(0, adu()[:9])
    framer.gap(20, "test_gap")
    framer.feed(20, adu(pdu=b"\x7f\xaa"))
    assert rows[0][0] == "incomplete"
    assert rows[1][0] == "adu"
    assert decode_pdu(b"\x7f\xaa", True)["shape_reason"] == "unsupported_function"
    assert sum(len(x[3]) for x in rows) == 9 + len(adu(pdu=b"\x7f\xaa"))


def test_invalid_tcp_header_is_accounted():
    b = bytearray(frame(1, adu()))
    b[46] = 0x10  # illegal TCP data offset (<20 bytes)
    assert decode_l2l3l4(bytes(b), 1)[0] == "invalid_tcp_header"


def test_wire_tid_reuse_and_concurrent_requests_are_preserved(tmp_path):
    ex = ChainExtractor("run", "view", CFG, str(tmp_path))
    payload = adu(10) + adu(11) + adu(10)
    ex.process_frame(0, 1, 1, frame(100, payload), 1)
    assert [x["mbap_trans_id"] for x in ex.rows] == [10, 11, 10]
    assert len({x["event_uid"] for x in ex.rows}) == 3


def test_legitimate_repeated_poll_is_not_deduplicated(tmp_path):
    ex = ChainExtractor("run", "view", CFG, str(tmp_path))
    request = adu(7)
    ex.process_frame(0, 1, 1, frame(100, request), 1)
    ex.process_frame(0, 2, 2, frame(100 + len(request), request), 1)
    assert len(ex.rows) == 2
    assert ex.rows[0]["adu_bytes"] == ex.rows[1]["adu_bytes"]
    assert ex.rows[0]["stream_off_start"] != ex.rows[1]["stream_off_start"]
    assert not ex.obs_rows


def test_multi_write_raw_payload_arrays_and_mask():
    coil = decode_pdu(bytes.fromhex("0f0000000902a501"), True)
    assert coil["address"] == 0 and coil["quantity"] == 9 and coil["bit_bytes"] == b"\xa5\x01"
    regs = decode_pdu(bytes.fromhex("10000000020400000009"), True)
    assert regs["reg_values"] == [0, 9] and regs["shape_ok"]
    mask = decode_pdu(bytes.fromhex("1600000000ffff"), True)
    assert mask["address"] == 0 and mask["and_mask"] == 0 and mask["or_mask"] == 65535


def test_pcap_truncated_record_is_visible():
    header = bytes.fromhex("d4c3b2a1") + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    source = BytesIO(header + struct.pack("<IIII", 1679588811, 798717, 100, 100) + b"abc")
    hdr = open_pcap(source)
    rows = list(iter_records(source, hdr))
    assert len(rows) == 1 and rows[0][0] == 1 and rows[0][5] is None and rows[0][6] == 24


def test_capture_snaplen_gap_does_not_invent_bytes(tmp_path):
    ex = ChainExtractor("run", "view", CFG, str(tmp_path))
    raw = frame(100, adu())
    ex.process_frame(0, 1, 1, raw[:-3], 1)
    assert ex.rows[0]["record_kind"] == "incomplete"
    assert ex.rows[0]["adu_bytes"] == adu()[:-3]
    assert ex.acc["gap_bytes_truncated_capture"] == 3
    assert ex.rows[0]["parse_reason"] == "capture_truncated_segment"
