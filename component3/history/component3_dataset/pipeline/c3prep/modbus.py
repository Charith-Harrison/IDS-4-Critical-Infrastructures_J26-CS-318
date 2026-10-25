"""Modbus/TCP ADU framing and function-specific PDU decoding.

Framing operates on a reassembled, per-direction TCP byte stream.  One emitted
record corresponds to one Modbus/TCP application data unit (MBAP header + PDU),
or to an explicitly labelled non-framed / incomplete byte run.  Nothing is
silently discarded: every byte delivered by reassembly is assigned to exactly one
record (``adu`` / ``nonframed`` / ``incomplete``) so that byte counts reconcile.

References: Modbus Application Protocol Specification V1.1b3 and the Modbus
Messaging on TCP/IP Implementation Guide V1.0b (MBAP length = unit id + PDU,
maximum ADU 260 bytes, PDU <= 253 bytes).
"""
from __future__ import annotations

from typing import Optional

MBAP_LEN = 7
SPEC_MAX_MBAP_LENGTH = 254      # unit id (1) + max PDU (253)
SPEC_MAX_ADU = 260

# Public function-code table (spec section 6).  Anything else is preserved raw.
FC_NAMES = {
    1: "read_coils", 2: "read_discrete_inputs", 3: "read_holding_registers",
    4: "read_input_registers", 5: "write_single_coil", 6: "write_single_register",
    7: "read_exception_status", 8: "diagnostics", 11: "get_comm_event_counter",
    12: "get_comm_event_log", 15: "write_multiple_coils", 16: "write_multiple_registers",
    17: "report_server_id", 20: "read_file_record", 21: "write_file_record",
    22: "mask_write_register", 23: "read_write_multiple_registers",
    24: "read_fifo_queue", 43: "encapsulated_interface_transport",
}
WRITE_FCS = {5, 6, 15, 16, 21, 22, 23}
READ_FCS = {1, 2, 3, 4, 23, 24, 20}
OBJECT_SPACE = {
    1: "coil", 5: "coil", 15: "coil",
    2: "discrete_input",
    3: "holding_register", 6: "holding_register", 16: "holding_register",
    22: "holding_register", 23: "holding_register",
    4: "input_register",
}
# Spec quantity limits for requests.
QTY_LIMITS = {1: (1, 2000), 2: (1, 2000), 3: (1, 125), 4: (1, 125), 15: (1, 1968), 16: (1, 123)}


def _u16(b: bytes, i: int) -> int:
    return (b[i] << 8) | b[i + 1]


def _words(b: bytes) -> list[int]:
    return [(b[i] << 8) | b[i + 1] for i in range(0, len(b) - 1, 2)]


def empty_decoded() -> dict:
    return {
        "address": None, "quantity": None, "write_address": None, "write_quantity": None,
        "byte_count": None, "single_value": None, "reg_values": None, "bit_bytes": None,
        "sub_function": None, "and_mask": None, "or_mask": None, "mei_type": None,
        "expected_pdu_len": None, "shape_ok": None, "shape_reason": None,
    }


def decode_pdu(pdu: bytes, is_request: bool) -> dict:
    """Decode a PDU (function byte + data).  Returns a dict of decoded fields.

    Missing information stays ``None``; zero is only ever a decoded wire value.
    ``shape_ok`` is False when the PDU violates the spec structure for that
    function; the original bytes are always preserved by the caller.
    """
    d = empty_decoded()
    if not pdu:
        d["shape_ok"] = False
        d["shape_reason"] = "empty_pdu"
        return d
    raw = pdu[0]
    fc = raw & 0x7F
    data = pdu[1:]
    n = len(data)
    if raw & 0x80:
        d["expected_pdu_len"] = 2
        if is_request:
            d["shape_ok"] = False
            d["shape_reason"] = "exception_bit_in_request"
        else:
            d["shape_ok"] = n == 1
            d["shape_reason"] = None if n == 1 else "exception_len"
        return d

    def need(exp: int, reason: str = "pdu_len") -> bool:
        d["expected_pdu_len"] = exp
        ok = len(pdu) == exp
        d["shape_ok"] = ok
        if not ok:
            d["shape_reason"] = f"{reason}:{len(pdu)}!={exp}"
        return len(pdu) >= exp

    if is_request:
        if fc in (1, 2, 3, 4):
            if need(5):
                d["address"], d["quantity"] = _u16(data, 0), _u16(data, 2)
                lo, hi = QTY_LIMITS[fc]
                if not lo <= d["quantity"] <= hi and d["shape_ok"]:
                    d["shape_ok"], d["shape_reason"] = False, "quantity_out_of_spec"
        elif fc in (5, 6):
            if need(5):
                d["address"], d["single_value"] = _u16(data, 0), _u16(data, 2)
                d["quantity"] = 1
                if fc == 5 and d["single_value"] not in (0x0000, 0xFF00) and d["shape_ok"]:
                    d["shape_ok"], d["shape_reason"] = False, "coil_value_not_0000_or_ff00"
        elif fc in (15, 16):
            if n >= 5:
                d["address"], d["quantity"], d["byte_count"] = _u16(data, 0), _u16(data, 2), data[4]
                payload = data[5:]
                need(6 + d["byte_count"])
                if fc == 15:
                    d["bit_bytes"] = bytes(payload)
                    exp_bc = (d["quantity"] + 7) // 8
                else:
                    d["reg_values"] = _words(payload)
                    exp_bc = 2 * d["quantity"]
                if d["shape_ok"] and d["byte_count"] != exp_bc:
                    d["shape_ok"], d["shape_reason"] = False, "byte_count_vs_quantity"
                lo, hi = QTY_LIMITS[fc]
                if d["shape_ok"] and not lo <= d["quantity"] <= hi:
                    d["shape_ok"], d["shape_reason"] = False, "quantity_out_of_spec"
            else:
                d["shape_ok"], d["shape_reason"] = False, "short_pdu"
        elif fc == 22:
            if need(7):
                d["address"], d["and_mask"], d["or_mask"] = _u16(data, 0), _u16(data, 2), _u16(data, 4)
        elif fc == 23:
            if n >= 9:
                d["address"], d["quantity"] = _u16(data, 0), _u16(data, 2)
                d["write_address"], d["write_quantity"] = _u16(data, 4), _u16(data, 6)
                d["byte_count"] = data[8]
                need(10 + d["byte_count"])
                d["reg_values"] = _words(data[9:])
                if d["shape_ok"] and d["byte_count"] != 2 * d["write_quantity"]:
                    d["shape_ok"], d["shape_reason"] = False, "byte_count_vs_quantity"
            else:
                d["shape_ok"], d["shape_reason"] = False, "short_pdu"
        elif fc == 8:
            if n >= 2:
                d["sub_function"] = _u16(data, 0)
                d["shape_ok"] = True
            else:
                d["shape_ok"], d["shape_reason"] = False, "short_pdu"
        elif fc == 43:
            if n >= 1:
                d["mei_type"] = data[0]
                d["shape_ok"] = True
            else:
                d["shape_ok"], d["shape_reason"] = False, "short_pdu"
        elif fc in (7, 11, 12, 17):
            need(1)
        else:
            d["shape_ok"] = None
            d["shape_reason"] = "unsupported_function"
    else:
        if fc in (1, 2, 3, 4, 23):
            if n >= 1:
                d["byte_count"] = data[0]
                need(2 + d["byte_count"])
                payload = data[1:]
                if fc in (1, 2):
                    d["bit_bytes"] = bytes(payload)
                else:
                    d["reg_values"] = _words(payload)
                    if d["shape_ok"] and d["byte_count"] % 2:
                        d["shape_ok"], d["shape_reason"] = False, "odd_register_byte_count"
            else:
                d["shape_ok"], d["shape_reason"] = False, "short_pdu"
        elif fc in (5, 6):
            if need(5):
                d["address"], d["single_value"] = _u16(data, 0), _u16(data, 2)
                d["quantity"] = 1
        elif fc in (15, 16):
            if need(5):
                d["address"], d["quantity"] = _u16(data, 0), _u16(data, 2)
        elif fc == 22:
            if need(7):
                d["address"], d["and_mask"], d["or_mask"] = _u16(data, 0), _u16(data, 2), _u16(data, 4)
        elif fc == 8:
            if n >= 2:
                d["sub_function"] = _u16(data, 0)
                d["shape_ok"] = True
            else:
                d["shape_ok"], d["shape_reason"] = False, "short_pdu"
        elif fc == 43:
            if n >= 1:
                d["mei_type"] = data[0]
                d["shape_ok"] = True
            else:
                d["shape_ok"], d["shape_reason"] = False, "short_pdu"
        else:
            d["shape_ok"] = None
            d["shape_reason"] = "unsupported_function"
    return d


class StreamFramer:
    """Frame MBAP ADUs from one direction of one TCP connection.

    ``feed`` receives contiguous stream bytes with their stream offset and a
    segment reference.  ``emit`` callback receives tuples
    ``(kind, start_off, end_off, bytes, reason)`` where kind is ``adu``,
    ``nonframed`` or ``incomplete``.  Pending bytes are bounded by
    ``max_pending``; overflow is emitted as ``incomplete`` with a reason.
    """

    __slots__ = ("buf", "buf_off", "emit", "max_pending", "accept_max_len", "resync_pending")

    def __init__(self, emit, max_pending: int = 70000, accept_max_len: int = 65535):
        self.buf = bytearray()
        self.buf_off = 0          # stream offset of buf[0]
        self.emit = emit
        self.max_pending = max_pending
        self.accept_max_len = accept_max_len
        self.resync_pending = False

    def feed(self, off: int, data: bytes, segment_start: bool = True) -> None:
        if not self.buf:
            self.buf_off = off
        elif self.buf_off + len(self.buf) != off:
            # caller guarantees contiguity; defensive
            self.flush("discontinuity")
            self.buf_off = off
        if self.resync_pending and segment_start and self.buf:
            # unframed residue preceding a new segment boundary
            self._emit_nonframed(len(self.buf), "unframed_residue_before_segment")
        self.resync_pending = False
        self.buf += data
        self._drain(segment_end=True)

    def _emit_nonframed(self, n: int, reason: str) -> None:
        b = bytes(self.buf[:n])
        self.emit("nonframed", self.buf_off, self.buf_off + n, b, reason)
        del self.buf[:n]
        self.buf_off += n

    def _drain(self, segment_end: bool) -> None:
        buf = self.buf
        while len(buf) >= MBAP_LEN:
            proto = (buf[2] << 8) | buf[3]
            length = (buf[4] << 8) | buf[5]
            if proto != 0 or length < 2:
                # Not a plausible MBAP header: keep bytes up to the end of the
                # current delivered data as a non-framed run and resynchronise
                # at the next TCP segment boundary.
                self._emit_nonframed(len(buf), "invalid_mbap_header" if proto != 0 else "mbap_length_lt_2")
                return
            if length > self.accept_max_len:
                self._emit_nonframed(len(buf), "mbap_length_over_accept_limit")
                return
            total = 6 + length
            if len(buf) < total:
                if len(buf) > self.max_pending:
                    self.emit("incomplete", self.buf_off, self.buf_off + len(buf), bytes(buf), "pending_overflow")
                    self.buf_off += len(buf)
                    buf.clear()
                return
            adu = bytes(buf[:total])
            reason = "mbap_length_exceeds_spec" if length > SPEC_MAX_MBAP_LENGTH else ""
            self.emit("adu", self.buf_off, self.buf_off + total, adu, reason)
            del buf[:total]
            self.buf_off += total
        if buf and segment_end:
            # partial header (<7 bytes) waits for more data
            pass

    def flush(self, reason: str) -> None:
        if self.buf:
            kind = "incomplete"
            self.emit(kind, self.buf_off, self.buf_off + len(self.buf), bytes(self.buf), reason)
            self.buf_off += len(self.buf)
            self.buf.clear()
        self.resync_pending = False

    def gap(self, new_off: int, reason: str) -> None:
        """Stream bytes are missing before ``new_off``: flush and restart framing."""
        self.flush(reason)
        self.buf_off = new_off
