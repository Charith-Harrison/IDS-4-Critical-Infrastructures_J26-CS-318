"""Vendored unchanged selected helpers from frozen v0.1; see evidence/vendor_receipt.json."""
import struct
from collections import Counter


class ValidationError(ValueError):
    pass


def _check(condition, message):
    if not condition:
        raise ValidationError(message)


def _read_pcap(path, port, client_port):
    """Return unique stream bytes and exact frame/file lineage, with no resync."""
    statistics = Counter()
    segments = {"client_to_server": [], "server_to_client": []}
    bases = {}
    magics = {
        b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
        b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1),
    }
    with path.open("rb") as stream:
        header = stream.read(24)
        _check(len(header) == 24 and header[:4] in magics, "missing/unsupported classic PCAP header")
        endian, scale = magics[header[:4]]
        major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
        _check((major, minor) == (2, 4), "unsupported PCAP version")
        _check(linktype in (1, 113, 276), "unsupported PCAP link type")
        while True:
            record_offset = stream.tell()
            record = stream.read(16)
            if not record:
                break
            _check(len(record) == 16, "truncated PCAP record header")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
            _check(captured <= snaplen and captured <= 16 * 1024 * 1024, "invalid captured frame size")
            _check(captured == original, "capture contains truncated packet")
            _check(fraction < (1_000_000 if scale == 1000 else 1_000_000_000), "invalid capture timestamp")
            frame = stream.read(captured)
            _check(len(frame) == captured, "truncated PCAP frame data")
            statistics["frames"] += 1
            number = statistics["frames"]
            if linktype == 1:
                _check(len(frame) >= 14, "short Ethernet header")
                network, offset = struct.unpack("!H", frame[12:14])[0], 14
                while network in (0x8100, 0x88A8):
                    _check(offset <= 22 and len(frame) >= offset + 4, "invalid VLAN header")
                    network = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
                    offset += 4
            elif linktype == 113:
                _check(len(frame) >= 16, "short Linux cooked header")
                network, offset = struct.unpack("!H", frame[14:16])[0], 16
            else:
                _check(len(frame) >= 20, "short Linux cooked v2 header")
                network, offset = struct.unpack("!H", frame[:2])[0], 20
            _check(network != 0x86DD, "IPv6 is outside this IPv4-only pilot")
            if network != 0x0800:
                statistics["non_ipv4_frames"] += 1
                continue
            _check(len(frame) >= offset + 20 and frame[offset] >> 4 == 4, "invalid IPv4 header")
            ihl = (frame[offset] & 15) * 4
            total = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            _check(ihl >= 20 and total >= ihl and len(frame) >= offset + total, "truncated IPv4 packet")
            fragment = struct.unpack("!H", frame[offset + 6:offset + 8])[0]
            _check((fragment & 0x3FFF) == 0, "fragmented IPv4 is unsupported")
            if frame[offset + 9] != 6:
                statistics["non_tcp_frames"] += 1
                continue
            source_ip = ".".join(str(x) for x in frame[offset + 12:offset + 16])
            destination_ip = ".".join(str(x) for x in frame[offset + 16:offset + 20])
            tcp = offset + ihl
            _check(total >= ihl + 20, "short TCP header")
            source, destination, sequence = struct.unpack("!HHI", frame[tcp:tcp + 8])
            tcp_length = (frame[tcp + 12] >> 4) * 4
            _check(tcp_length >= 20 and ihl + tcp_length <= total, "invalid TCP data offset")
            _check(source_ip == destination_ip == "127.0.0.1", "unexpected non-loopback endpoint")
            if (source, destination) == (client_port, port):
                direction = "client_to_server"
            elif (source, destination) == (port, client_port):
                direction = "server_to_client"
            else:
                raise ValidationError("capture contains another TCP connection")
            flags = frame[tcp + 13]
            _check(not flags & 4, "TCP connection was reset")
            if flags & 2:
                if direction == "client_to_server":
                    _check(not flags & 16, "unexpected client SYN+ACK")
                else:
                    _check(bool(flags & 16), "server SYN lacks ACK")
                base = (sequence + 1) & 0xFFFFFFFF
                _check(direction not in bases or bases[direction] == base, "multiple TCP connection generations")
                bases[direction] = base
            payload_offset = tcp + tcp_length
            payload = frame[payload_offset:offset + total]
            statistics["tcp_frames"] += 1
            statistics["observed_tcp_payload_bytes"] += len(payload)
            if payload:
                segments[direction].append({
                    "sequence": (sequence + bool(flags & 2)) & 0xFFFFFFFF,
                    "payload": payload, "frame_number": number,
                    "capture_timestamp_ns": seconds * 1_000_000_000 + fraction * scale,
                    "frame_byte_offset": payload_offset,
                    "pcap_file_byte_offset": record_offset + 16 + payload_offset,
                })
    _check(set(bases) == set(segments), "capture lacks both TCP SYN sequence bases")
    streams, lineage = {}, {}
    for direction, items in segments.items():
        values, refs = {}, {}
        for item in items:
            start = (item["sequence"] - bases[direction]) & 0xFFFFFFFF
            _check(start + len(item["payload"]) <= 16 * 1024 * 1024, "TCP stream span outside pilot limit")
            for index, byte in enumerate(item["payload"]):
                position = start + index
                if position in values:
                    _check(values[position] == byte, "conflicting TCP retransmission/overlap")
                    statistics["retransmitted_payload_bytes"] += 1
                values[position] = byte
                refs.setdefault(position, []).append((item, index))
        _check(values and len(values) == max(values) + 1, "gap or empty TCP stream")
        streams[direction] = bytes(values[index] for index in range(len(values)))
        lineage[direction] = refs
    statistics["unique_tcp_payload_bytes"] = sum(map(len, streams.values()))
    _check(statistics["observed_tcp_payload_bytes"] == statistics["unique_tcp_payload_bytes"] +
           statistics["retransmitted_payload_bytes"], "payload accounting failure")
    return streams, lineage, dict(statistics)


def _message_refs(lineage, start, length):
    """Coalesce per-byte source references, retaining duplicate observations."""
    spans = []
    by_frame = {}
    for relative in range(length):
        for item, index in lineage[start + relative]:
            by_frame.setdefault(item["frame_number"], []).append((relative, item, index))
    for number in sorted(by_frame):
        for relative, item, index in by_frame[number]:
            frame_offset = item["frame_byte_offset"] + index
            if spans and spans[-1]["frame_number"] == number and \
                    spans[-1]["message_byte_offset"] + spans[-1]["length"] == relative and \
                    spans[-1]["frame_byte_offset"] + spans[-1]["length"] == frame_offset:
                spans[-1]["length"] += 1
            else:
                spans.append({"frame_number": number, "capture_timestamp_ns": item["capture_timestamp_ns"],
                              "message_byte_offset": relative, "frame_byte_offset": frame_offset,
                              "pcap_file_byte_offset": item["pcap_file_byte_offset"] + index, "length": 1})
    return spans

