"""Small explicit Modbus/TCP subset; not a production PLC implementation.

FC1/3/5/6, unit1, single-object requests. All wire addresses are zero-based.
Register0=operator enable mode, register1=stored setpoint, coil1=pump flag.
The PLC accepts protocol-valid coil writes; the declared lab policy is audited
separately. No industrial process or safety-interlock fidelity is claimed.
"""
from __future__ import annotations

import socket
import struct
from dataclasses import dataclass


def make_adu(tid: int, pdu: bytes, unit: int = 1) -> bytes:
    if not 0 <= tid <= 65535 or unit != 1 or not 1 <= len(pdu) <= 253:
        raise ValueError("Invalid transaction, unit or PDU length")
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def parse_adu(adu: bytes) -> tuple[int, int, bytes]:
    if len(adu) < 8:
        raise ValueError("Incomplete MBAP/PDU")
    tid, protocol, length, unit = struct.unpack("!HHHB", adu[:7])
    if protocol != 0 or not 2 <= length <= 254 or len(adu) != 6 + length or unit != 1:
        raise ValueError("Invalid MBAP protocol/length/unit")
    return tid, unit, adu[7:]


def recv_exact(sock: socket.socket, size: int) -> bytes:
    pieces = []
    while size:
        part = sock.recv(size)
        if not part:
            raise EOFError("TCP ended before the requested bytes arrived")
        pieces.append(part)
        size -= len(part)
    return b"".join(pieces)


def recv_adu(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 7)
    _, protocol, length, unit = struct.unpack("!HHHB", header)
    if protocol != 0 or not 2 <= length <= 254 or unit != 1:
        raise ValueError("Unsupported/invalid incoming MBAP")
    return header + recv_exact(sock, length - 1)


def request(fc: int, address: int, value: int) -> bytes:
    if fc not in (1, 3, 5, 6) or not 0 <= address <= 65535 or not 0 <= value <= 65535:
        raise ValueError("Unsupported request")
    pdu = struct.pack("!BHH", fc, address, value)
    validate_pdu(pdu, True)
    return pdu


def validate_pdu(pdu: bytes, is_request: bool) -> None:
    if not pdu:
        raise ValueError("Empty PDU")
    fc = pdu[0]
    if fc not in (1, 3, 5, 6):
        raise ValueError("Pilot does not accept unsupported or exception functions")
    if is_request or fc in (5, 6):
        if len(pdu) != 5:
            raise ValueError("Expected five-byte PDU")
        _, address, value = struct.unpack("!BHH", pdu)
        if fc in (1, 3) and value != 1:
            raise ValueError("Pilot reads exactly one object")
        if fc == 5 and value not in (0, 0xFF00):
            raise ValueError("FC5 requires output word 0000 or FF00")
        if fc in (1, 5) and address != 1:
            raise ValueError("Pilot exposes coil1 only")
        if fc in (3, 6) and address not in (0, 1):
            raise ValueError("Pilot exposes holding registers0/1 only")
        if fc == 6 and address == 0 and value not in (0, 1):
            raise ValueError("Mode is either0 or1")
    elif fc == 1:
        if len(pdu) != 3 or pdu[1] != 1 or pdu[2] not in (0, 1):
            raise ValueError("Invalid single-coil reply or nonzero unused bits")
    elif fc == 3:
        if len(pdu) != 4 or pdu[1] != 2:
            raise ValueError("Invalid single-register reply")


@dataclass
class PLCState:
    mode: int = 0
    setpoint: int = 50
    coil: int = 0

    def snapshot(self) -> dict:
        return {"mode": self.mode, "setpoint": self.setpoint, "coil": self.coil}

    def handle(self, pdu: bytes) -> bytes:
        validate_pdu(pdu, True)
        fc, address, value = struct.unpack("!BHH", pdu)
        if fc == 1:
            reply = bytes((1, 1, self.coil))
        elif fc == 3:
            word = self.mode if address == 0 else self.setpoint
            reply = bytes((3, 2)) + struct.pack("!H", word)
        elif fc == 5:
            self.coil = int(value == 0xFF00)
            reply = pdu
        else:
            if address == 0:
                self.mode = value
            else:
                self.setpoint = value
            reply = pdu
        validate_pdu(reply, False)
        return reply
