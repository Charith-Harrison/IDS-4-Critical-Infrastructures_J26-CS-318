"""Read-only checks of the supplied preparation bundle and selected source bytes."""
from pathlib import Path
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import struct

workspace = Path('D:/VSCode/GitHub/4th Year Cyber')
bundle = workspace/'C3/component3_preparation'
raw = Path('G:/modbus cic 2023/Modbus Dataset')
out = workspace/'output/component3_execution/review'
out.mkdir(parents=True, exist_ok=True)

spec = importlib.util.spec_from_file_location('review_modbus', bundle/'c3prep/modbus.py')
modbus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modbus)
spec2 = importlib.util.spec_from_file_location('inspection_decoder', workspace/'output/component3_execution/inspect_pcap_samples.py')
decoder = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(decoder)

report = json.loads((bundle/'output/accepted_command_review.json').read_text(encoding='utf-8'))
events = report.get('events') or report.get('checks') or report.get('results')
if events is None:
    events = next(v for v in report.values() if isinstance(v, list) and v and isinstance(v[0], dict) and 'source_path' in v[0])
checks = []
with ExitStack() as stack:
    handles = {}
    for event in events:
        rel = event['source_path']
        if rel not in handles:
            fh = stack.enter_context((raw/rel).open('rb'))
            hdr = fh.read(24)
            assert hdr[:4] == b'\xd4\xc3\xb2\xa1'
            handles[rel] = fh, struct.unpack('<I', hdr[20:24])[0]&0xffff
        fh, link = handles[rel]
        fh.seek(event['pcap_record_header_offset'])
        sec, micros, caplen, wirelen = struct.unpack('<IIII', fh.read(16))
        decoded = decoder.decode_frame(fh.read(caplen), link)
        adus = decoded.get('adus_without_reassembly', []) if decoded else []
        candidates = [a for a in adus if a.get('transaction_id') == event['tid'] and a.get('base_function') == 5
                      and a.get('start') == event['coil_address'] and a.get('write_or_echo_raw_word') == event['wire_value']]
        checks.append({
            'event_uid': event['event_uid'], 'source_path': rel,
            'raw_packet_matches_report': len(candidates) == 1,
            'wire_value': event['wire_value'],
            'independently_allowed_coil_value': event['wire_value'] in (0, 0xff00),
            'reported_parse_status': event['parse_status'],
            'packet_time_utc': datetime.fromtimestamp(sec, timezone.utc).isoformat(),
            'pdu_hex': candidates[0]['pdu_hex'] if len(candidates) == 1 else None,
        })

env = json.loads((bundle/'output/environment.json').read_text())
code_integrity = {}
for rel, expected in env.get('source_code_sha256', {}).items():
    path = bundle/rel
    code_integrity[rel] = path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected

examples = json.loads((bundle/'output/label_examples.json').read_text())
shape = {}
for view, labels in examples.items():
    for label, detail in labels.items():
        shape[label] = {'events': detail['events'], 'parse_status_counts': detail['parse_status_counts'],
                        'unique_pdu_patterns': len(detail['pdu_hex_counts']), 'pdu_patterns': detail['pdu_hex_counts']}

label_report = json.loads((bundle/'output/label_report.json').read_text())
source_selection = label_report.get('signature_match_states')
result = {
    'scope': 'Read-only bundle review, independent direct-PCAP checks of accepted commands; no extraction, labels, splits, model preprocessing or training rerun.',
    'command_records_checked': len(checks),
    'raw_packet_report_mismatches': sum(not c['raw_packet_matches_report'] for c in checks),
    'wire_value_counts': dict(Counter(str(c['wire_value']) for c in checks)),
    'independent_shape_status_disagreements': sum((c['reported_parse_status'] == 'ok') != c['independently_allowed_coil_value'] for c in checks),
    'command_days_utc': dict(Counter(c['packet_time_utc'][:10] for c in checks)),
    'reported_code_hashes_match_downloaded_code': code_integrity,
    'accepted_shape_and_pattern_summary': shape,
    'log_signature_selection_counts': source_selection,
    'strict_tolerance_sensitivity': label_report.get('strict_candidate_uniqueness_sensitivity'),
    'command_checks': checks,
}
(out/'independent_review_checks.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k != 'command_checks'}, indent=2))
