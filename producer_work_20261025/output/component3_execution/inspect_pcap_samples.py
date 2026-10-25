"""Bounded read-only packet inspection; not an extraction/splitting pipeline.

Only decodes complete ADUs wholly contained in sampled TCP payloads. It does not
reassemble TCP or assign attack labels, and must not be used for model datasets.
"""
from pathlib import Path
import argparse
import ipaddress
import json
import struct


def decode_frame(data, linktype):
    if linktype == 1:
        if len(data) < 14:
            return None
        offset, etype = 14, int.from_bytes(data[12:14], 'big')
        while etype in (0x8100, 0x88a8):
            if len(data) < offset+4:
                return None
            etype = int.from_bytes(data[offset+2:offset+4], 'big')
            offset += 4
    elif linktype == 113:
        offset, etype = 16, int.from_bytes(data[14:16], 'big')
    elif linktype == 276:
        offset, etype = 20, int.from_bytes(data[:2], 'big')
    else:
        return {'unsupported_linktype': linktype}
    if etype != 0x0800 or len(data) < offset+20:
        return None
    ip = data[offset:]
    ihl = (ip[0] & 15)*4
    total = int.from_bytes(ip[2:4], 'big')
    if ip[9] != 6 or len(ip) < ihl+20:
        return None
    if int.from_bytes(ip[6:8], 'big') & 0x3fff:
        return {'fragmented_ip': True}
    tcp = ip[ihl:total]
    thl = (tcp[12] >> 4)*4
    srcport, dstport = struct.unpack('!HH', tcp[:4])
    payload = tcp[thl:]
    record = {
        'src_ip': str(ipaddress.ip_address(ip[12:16])),
        'dst_ip': str(ipaddress.ip_address(ip[16:20])),
        'src_port': srcport, 'dst_port': dstport,
        'seq': int.from_bytes(tcp[4:8], 'big'),
        'ack': int.from_bytes(tcp[8:12], 'big'),
        'tcp_flags': tcp[13], 'tcp_payload_bytes': len(payload),
        'tcp_payload_hex': payload[:300].hex(),
    }
    if 502 not in (srcport, dstport):
        return record
    role = 'response_by_port' if srcport == 502 else 'request_by_port'
    record['direction_inference'] = role
    adus, pos = [], 0
    while len(payload)-pos >= 7:
        tid, proto, length, unit = struct.unpack('!HHHB', payload[pos:pos+7])
        complete = length >= 2 and pos+6+length <= len(payload)
        a = {'payload_offset': pos, 'transaction_id': tid, 'protocol_id': proto,
             'mbap_length': length, 'unit_id': unit, 'complete_in_payload': complete}
        if not complete:
            adus.append(a)
            break
        pdu = payload[pos+7:pos+6+length]
        a['pdu_hex'] = pdu.hex()
        a['raw_function'] = pdu[0]
        a['base_function'] = pdu[0] & 0x7f
        a['exception'] = bool(pdu[0] & 0x80)
        fc = a['base_function']
        if a['exception']:
            a['exception_code'] = pdu[1] if len(pdu) > 1 else None
        elif role == 'request_by_port' and fc in (1, 2, 3, 4) and len(pdu) >= 5:
            a['requested_start'], a['requested_quantity'] = struct.unpack('!HH', pdu[1:5])
        elif fc in (5, 6) and len(pdu) >= 5:
            a['start'], a['write_or_echo_raw_word'] = struct.unpack('!HH', pdu[1:5])
        elif role == 'response_by_port' and fc in (1, 2, 3, 4) and len(pdu) >= 2:
            a['returned_byte_count'] = pdu[1]
            values = pdu[2:2+pdu[1]]
            a['returned_data_hex'] = values.hex()
            if fc in (3, 4) and len(values) == pdu[1] and len(values) % 2 == 0:
                a['returned_register_words'] = list(struct.unpack('!'+'H'*(len(values)//2), values))
        elif fc in (15, 16) and len(pdu) >= 5:
            a['start'], a['quantity'] = struct.unpack('!HH', pdu[1:5])
        adus.append(a)
        pos += 6+length
    record['adus_without_reassembly'] = adus
    return record


def inspect(path, frames, max_frames):
    output = {'source': str(path), 'requested_frames': sorted(frames),
              'limitations': 'Bounded selected-frame sample only; no TCP reassembly, attack labels or coverage claims.'}
    with path.open('rb') as f:
        header = f.read(24)
        magic = header[:4]
        formats = {b'\xd4\xc3\xb2\xa1': ('<', 1000000), b'\xa1\xb2\xc3\xd4': ('>', 1000000),
                   b'\x4d\x3c\xb2\xa1': ('<', 1000000000), b'\xa1\xb2\x3c\x4d': ('>', 1000000000)}
        if magic not in formats:
            raise ValueError('Not supported classic PCAP magic: '+magic.hex())
        endian, resolution = formats[magic]
        linktype = struct.unpack(endian+'I', header[20:24])[0] & 0xffff
        output.update(linktype=linktype, timestamp_ticks_per_second=resolution, samples=[])
        for n in range(1, max_frames+1):
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            sec, frac, captured, wirelen = struct.unpack(endian+'IIII', packet_header)
            if captured > 16*1024*1024:
                raise ValueError('Suspicious record length in bounded inspector')
            data = f.read(captured)
            if len(data) != captured:
                raise ValueError('Truncated PCAP record')
            if n in frames:
                output['samples'].append({'frame': n, 'epoch_seconds': sec,
                    'fraction_ticks': frac, 'captured_len': captured, 'wire_len': wirelen,
                    'decoded': decode_frame(data, linktype)})
            if n >= max(frames):
                break
    return output


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('pcap', type=Path)
    p.add_argument('--frames', default='3,5,14924,14926')
    p.add_argument('--max-frames', type=int, default=15000)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    result = inspect(args.pcap, {int(x) for x in args.frames.split(',')}, args.max_frames)
    content = json.dumps(result, indent=2)
    if args.output:
        args.output.write_text(content, encoding='utf-8')
    print(content)
