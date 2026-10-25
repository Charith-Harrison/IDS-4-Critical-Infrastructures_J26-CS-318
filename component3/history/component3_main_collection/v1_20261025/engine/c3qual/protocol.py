"""Generator's explicit FC1/3/5/6 process. Validator decodes/replays separately."""
import socket
import struct


def adu(tid, pdu):
    if not 0 <= tid <= 65535 or not 1 <= len(pdu) <= 253:
        raise ValueError('Invalid TID or PDU length')
    return struct.pack('!HHHB', tid, 0, len(pdu) + 1, 1) + pdu


def parse(raw):
    if len(raw) < 8:
        raise ValueError('Incomplete ADU')
    tid, pid, size, unit = struct.unpack('!HHHB', raw[:7])
    if pid or unit != 1 or not 2 <= size <= 254 or len(raw) != size + 6:
        raise ValueError('Invalid MBAP')
    return tid, raw[7:]


def recv_adu(sock):
    def exact(n):
        data = bytearray()
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise EOFError('Connection ended')
            data.extend(chunk)
        return bytes(data)
    header = exact(7)
    _, pid, size, unit = struct.unpack('!HHHB', header)
    if pid or unit != 1 or not 2 <= size <= 254:
        raise ValueError('Invalid incoming MBAP')
    return header + exact(size - 1)


def req(fc, addr, value):
    return struct.pack('!BHH', fc, addr, value)


class Process:
    def __init__(self, mapping):
        self.mapping = mapping
        self.mode, self.setpoint, self.coil = 0, 50, 0

    def snapshot(self):
        return dict(mode=self.mode, setpoint=self.setpoint, coil=self.coil)

    def handle(self, pdu):
        if len(pdu) != 5:
            raise ValueError('Only five-byte requests supported')
        fc, addr, word = struct.unpack('!BHH', pdu)
        m = self.mapping
        if fc in (1, 5):
            if addr != m['pump_coil']:
                raise ValueError('Unknown coil')
        elif fc in (3, 6):
            if addr not in (m['mode_register'], m['setpoint_register']):
                raise ValueError('Unknown register')
        else:
            raise ValueError('Unsupported function')
        if fc in (1, 3) and word != 1:
            raise ValueError('Single-object reads only')
        if fc == 1:
            return bytes((1, 1, self.coil))
        if fc == 3:
            value = self.mode if addr == m['mode_register'] else self.setpoint
            return b'\x03\x02' + struct.pack('!H', value)
        if fc == 5:
            if word not in (0, 0xff00):
                raise ValueError('Illegal FC5 word')
            self.coil = int(word == 0xff00)
        elif addr == m['mode_register']:
            if word not in (0, 1):
                raise ValueError('Mode must be 0 or 1')
            self.mode = word
        else:
            self.setpoint = word
        return pdu
