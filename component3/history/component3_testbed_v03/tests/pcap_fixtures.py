"""Vendored unchanged selected helpers from frozen v0.1; see evidence/vendor_receipt.json."""
import struct, json


def packet(source, destination, sequence, payload=b"", flags=16, linktype=1, fragment=0):
    ip = bytes((0x45, 0)) + struct.pack("!HHH", 40 + len(payload), 1, fragment) + bytes((64, 6)) + b"\0\0" + b"\x7f\0\0\x01" * 2
    tcp = struct.pack("!HHIIBBHHH", source, destination, sequence & 0xFFFFFFFF, 0, 0x50, flags, 65535, 0, 0)
    if linktype == 1:
        header = b"\0" * 12 + b"\x08\0"
    elif linktype == 113:
        header = b"\0" * 14 + b"\x08\0"
    else:
        header = b"\x08\0" + b"\0" * 18
    return header + ip + tcp + payload


def write_pcap(path, frames, linktype=1, endian="<", nanoseconds=False, truncate=False):
    magic = 0xA1B23C4D if nanoseconds else 0xA1B2C3D4
    with path.open("wb") as stream:
        stream.write(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, linktype))
        for number, frame in enumerate(frames):
            stream.write(struct.pack(endian + "IIII", 1, number * 100, len(frame), len(frame) + int(truncate)))
            stream.write(frame)


def jsonl(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

