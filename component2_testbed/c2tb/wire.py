"""Minimal Modbus/TCP ADU encoding/decoding for read functions FC1-FC4.

The client side is implemented here (rather than through the pymodbus client) so the ledger can record the exact
request bytes, the transaction ID and the local TCP port of every action.  The target is an independent
implementation (pymodbus server), so request/response agreement is a genuine interoperability check.
"""
from __future__ import annotations

import struct

READ_FUNCTIONS = {1: "coils", 2: "discrete_inputs", 3: "holding_registers", 4: "input_registers"}
MBAP = struct.Struct(">HHHB")  # transaction id, protocol id, length, unit id


def encode_read_request(tid: int, unit: int, fc: int, address: int, quantity: int) -> bytes:
    if fc not in READ_FUNCTIONS:
        raise ValueError(f"unsupported function {fc}")
    pdu = struct.pack(">BHH", fc, address, quantity)
    return MBAP.pack(tid & 0xFFFF, 0, len(pdu) + 1, unit) + pdu


def decode_adu(adu: bytes) -> dict:
    """Decode one complete ADU.  Request/response role is decided by the caller (TCP direction)."""
    tid, proto, length, unit = MBAP.unpack_from(adu, 0)
    pdu = adu[7:]
    fc = pdu[0] if pdu else None
    return {"tid": tid, "protocol_id": proto, "mbap_len": length, "unit": unit, "wire_fc": fc, "pdu": pdu}


def decode_request_fields(pdu: bytes) -> dict:
    """Address/quantity are semantically defined only for FC1-4 requests with a 5-byte PDU."""
    fc = pdu[0]
    if fc in READ_FUNCTIONS and len(pdu) == 5:
        address, quantity = struct.unpack(">HH", pdu[1:5])
        return {"address": address, "quantity": quantity}
    return {"address": None, "quantity": None}


def decode_response_fields(pdu: bytes) -> dict:
    fc = pdu[0]
    if fc & 0x80:
        return {"is_exception": True, "exception_code": pdu[1] if len(pdu) > 1 else None, "byte_count": None}
    return {"is_exception": False, "exception_code": None, "byte_count": pdu[1] if len(pdu) > 1 else None}


def expected_byte_count(fc: int, quantity: int) -> int:
    return (quantity + 7) // 8 if fc in (1, 2) else 2 * quantity
