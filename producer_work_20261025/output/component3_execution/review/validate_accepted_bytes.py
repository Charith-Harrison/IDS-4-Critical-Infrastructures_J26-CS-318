"""Check accepted ADU bytes against their declared original frame references."""
from pathlib import Path
from collections import Counter
from contextlib import ExitStack
import importlib.util
import json
import struct
import pyarrow.parquet as pq

workspace = Path('D:/VSCode/GitHub/4th Year Cyber')
output = workspace/'C3/component3_preparation/output'
raw = Path('G:/modbus cic 2023/Modbus Dataset')
spec = importlib.util.spec_from_file_location('inspector',workspace/'output/component3_execution/inspect_pcap_samples.py')
inspector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inspector)
checks = []
with ExitStack() as stack:
    handles = {}
    for view in ('scada_ied1a','ied_ied1b'):
        directory = output/'extraction'/view
        ann = pq.read_table(directory/'annotations.parquet',columns=['event_uid','component_label'],
            filters=[('component_label','in',['command_injection','response_injection'])]).to_pylist()
        targets = {r['event_uid']:r['component_label'] for r in ann}
        sources = {s['chunk']:s['path'] for s in json.loads((directory/'checkpoint.json').read_text())['contract']['sources']}
        events = pq.read_table(directory/'events.parquet',columns=['event_uid','adu_bytes','segment_refs','n_segments','parse_status'],
            filters=[('event_uid','in',list(targets))]).to_pylist()
        for e in events:
            status = 'not_checked_multi_segment'
            refs = e['segment_refs']
            if len(refs) == 1:
                ref = refs[0]
                source = sources[ref['chunk']]
                if source not in handles:
                    fh = stack.enter_context((raw/source).open('rb'))
                    header = fh.read(24)
                    assert header[:4] == b'\xd4\xc3\xb2\xa1'
                    handles[source] = fh, struct.unpack('<I',header[20:24])[0]&0xffff
                fh,link = handles[source]
                fh.seek(ref['pcap_offset'])
                sec,micros,caplen,wirelen = struct.unpack('<IIII',fh.read(16))
                decoded = inspector.decode_frame(fh.read(caplen),link)
                payload = bytes.fromhex(decoded['tcp_payload_hex'])
                status = 'matched_original_frame_payload' if e['adu_bytes'] in payload else 'MISMATCH'
            checks.append({'event_uid':e['event_uid'],'label':targets[e['event_uid']],
                'parse_status':e['parse_status'],'source_byte_check':status,'adu_hex':e['adu_bytes'].hex()})
result = {'scope':'Read-only original-frame byte validation of accepted event cohort; does not establish authorization, label independence or full extraction correctness.',
    'events':len(checks),'statuses':dict(Counter(c['source_byte_check'] for c in checks)),
    'by_label':dict(Counter(c['label']+'|'+c['source_byte_check'] for c in checks)), 'checks':checks}
(Path(__file__).parent/'accepted_original_bytes_check.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps({k:v for k,v in result.items() if k!='checks'},indent=2))
