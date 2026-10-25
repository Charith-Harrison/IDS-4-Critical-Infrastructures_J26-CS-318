"""Streaming, read-only libpcap reader and minimal Ethernet/IPv4/TCP decoder.

The reader never loads a whole capture into memory.  It yields one record per
captured frame with the original frame index (1-based, as in Wireshark), the
lossless integer timestamp (seconds, sub-second ticks and tick resolution), the
captured/original lengths and the raw bytes.  Only the classic libpcap format is
supported here; pcapng files are detected and rejected explicitly so they are
never silently mis-parsed.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),   # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_RAW = 101


class PcapFormatError(Exception):
    pass


@dataclass
class PcapHeader:
    endian: str
    ticks_per_second: int
    version: tuple
    snaplen: int
    linktype: int


def open_pcap(fh: BinaryIO) -> PcapHeader:
    head = fh.read(24)
    if len(head) < 24:
        raise PcapFormatError("file shorter than libpcap global header")
    magic = head[:4]
    if magic == PCAPNG_MAGIC:
        raise PcapFormatError("pcapng is not supported by this reader")
    if magic not in PCAP_MAGIC:
        raise PcapFormatError(f"unknown magic {magic.hex()}")
    endian, tps = PCAP_MAGIC[magic]
    vmaj, vmin, _tz, _sig, snaplen, linktype = struct.unpack(endian + "HHiIII", head[4:])
    return PcapHeader(endian, tps, (vmaj, vmin), snaplen, linktype & 0x0FFFFFFF)


def iter_records(fh: BinaryIO, hdr: PcapHeader, read_size: int = 1 << 22) -> Iterator[tuple]:
    """Yield (frame_no, ts_sec, ts_frac, caplen, origlen, data, file_offset).

    Reads the file in bounded blocks.  A truncated final record is reported by
    yielding a record with data=None so callers can account for it.
    """
    rec = struct.Struct(hdr.endian + "IIII")
    buf = b""
    pos = 0
    base_offset = 24
    frame = 0
    while True:
        if len(buf) - pos < 16:
            more = fh.read(read_size)
            buf = buf[pos:] + more
            base_offset += pos
            pos = 0
            if len(buf) < 16:
                if buf:
                    frame += 1
                    yield (frame, None, None, None, None, None, base_offset)
                return
        ts_sec, ts_frac, caplen, origlen = rec.unpack_from(buf, pos)
        if caplen > 0x4000000:
            raise PcapFormatError(f"implausible caplen {caplen} at offset {base_offset + pos}")
        end = pos + 16 + caplen
        if end > len(buf):
            more = fh.read(max(read_size, caplen + 16))
            if not more:
                frame += 1
                yield (frame, ts_sec, ts_frac, caplen, origlen, None, base_offset + pos)
                return
            buf = buf[pos:] + more
            base_offset += pos
            pos = 0
            continue
        frame += 1
        yield (frame, ts_sec, ts_frac, caplen, origlen, buf[pos + 16:end], base_offset + pos)
        pos = end


@dataclass(slots=True)
class TcpSeg:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes
    ip_id: int
    ip_total_len: int
    truncated: bool   # captured bytes shorter than IP total length
    payload_missing: int  # bytes declared after TCP header but not captured


def _ip(b: bytes) -> str:
    return f"{b[0]}.{b[1]}.{b[2]}.{b[3]}"


def decode_l2l3l4(data: bytes, linktype: int) -> tuple[str, Optional[TcpSeg]]:
    """Return (kind, TcpSeg|None).  kind classifies non-TCP traffic for accounting."""
    off = 0
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return "short_l2", None
        etype = (data[12] << 8) | data[13]
        off = 14
        while etype in (0x8100, 0x88A8):
            if len(data) < off + 4:
                return "short_l2", None
            etype = (data[off + 2] << 8) | data[off + 3]
            off += 4
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return "short_l2", None
        etype = (data[14] << 8) | data[15]
        off = 16
    elif linktype == LINKTYPE_RAW:
        etype = 0x0800
    else:
        return f"linktype_{linktype}", None
    if etype == 0x0806:
        return "arp", None
    if etype == 0x86DD:
        return "ipv6", None
    if etype != 0x0800:
        return f"ethertype_{etype:04x}", None
    if len(data) < off + 20:
        return "short_ip", None
    vihl = data[off]
    if vihl >> 4 != 4:
        return "bad_ip_version", None
    ihl = (vihl & 0x0F) * 4
    total = (data[off + 2] << 8) | data[off + 3]
    if ihl < 20 or total < ihl or len(data) < off + ihl:
        return "invalid_ip_header", None
    ip_id = (data[off + 4] << 8) | data[off + 5]
    frag = ((data[off + 6] << 8) | data[off + 7]) & 0x3FFF
    proto = data[off + 9]
    src = _ip(data[off + 12:off + 16])
    dst = _ip(data[off + 16:off + 20])
    if proto == 1:
        return "icmp", None
    if proto == 17:
        return "udp", None
    if proto != 6:
        return f"ipproto_{proto}", None
    if frag:
        return "ip_fragment", None
    t = off + ihl
    if len(data) < t + 20:
        return "short_tcp", None
    sport, dport, seq, ack, offflags, win = struct.unpack_from("!HHIIHH", data, t)
    doff = (offflags >> 12) * 4
    if doff < 20 or total < ihl + doff or len(data) < t + doff:
        return "invalid_tcp_header", None
    flags = offflags & 0x01FF
    p0 = t + doff
    ip_end = off + total if total else len(data)
    truncated = ip_end > len(data)
    payload = data[p0:min(ip_end, len(data))] if p0 <= len(data) else b""
    return "tcp", TcpSeg(src, dst, sport, dport, seq, ack, flags, win, payload, ip_id, total, truncated,
                         max(0, ip_end - len(data)))


FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
