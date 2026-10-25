"""Inspect one log-linked time window in one PCAP, without making a dataset."""
from pathlib import Path
from datetime import datetime, timezone
import json
import mmap
import struct
from inspect_pcap_samples import decode_frame

root = Path('G:/modbus cic 2023/Modbus Dataset')
relative = Path('attack/compromised-ied/trust-scada-hmi/trust-scada-network-captures/veth3efd353-1.pcap')
source = root/relative
epoch = datetime(2023, 3, 23, 16, 26, 51, 793000, tzinfo=timezone.utc).timestamp()
result = {
    'source': str(source),
    'scope': 'One-PCAP bounded record-header scan and payload inspection within +/-2 seconds; no extraction, splitting or labels.',
    'log_reference': 'attack/compromised-ied/attack logs/03-23-2023/03-23-2023-1.csv:35',
    'log_timestamp_text': '2023-03-23 16:26:51.793',
    'trial_time_interpretation': 'UTC, zero offset; a single event does not establish clock alignment for every scenario.',
    'log_attack': 'False Data Injection Attack', 'log_target': '185.175.0.2',
    'log_transaction_id': 7485, 'time_window_seconds': 2,
    'matching_transaction_samples': [],
}
with source.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
    header = mapped[:24]
    assert header[:4] == b'\xd4\xc3\xb2\xa1'
    linktype = struct.unpack('<I', header[20:24])[0] & 0xffff
    n = 0
    window_records = 0
    offset = 24
    limit = min(len(mapped), 101_000_000)
    while offset < limit:
        ph = mapped[offset:offset+16]
        if len(ph) < 16:
            break
        sec, micros, caplen, wirelen = struct.unpack('<IIII', ph)
        if caplen > 16*1024*1024:
            raise ValueError('Invalid record length')
        offset += 16
        if offset+caplen > len(mapped):
            raise ValueError('Truncated PCAP record')
        n += 1
        timestamp = sec+micros/1_000_000
        if abs(timestamp-epoch) <= 2:
            window_records += 1
            data = mapped[offset:offset+caplen]
            record = decode_frame(data, linktype)
            if record and any(a.get('transaction_id') == 7485 for a in record.get('adus_without_reassembly', [])):
                result['matching_transaction_samples'].append({
                    'frame': n, 'epoch_seconds': sec, 'fraction_microseconds': micros,
                    'delta_from_log_seconds': round(timestamp-epoch, 6),
                    'wire_len': wirelen, 'decoded': record,
                })
        offset += caplen
    result['record_headers_scanned'] = n
    result['records_in_window'] = window_records
result['interpretation'] = 'Candidates for manual semantic validation, not final ground-truth labels.'
out = Path(__file__).parent/'response_candidate_sample.json'
out.write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, indent=2))
