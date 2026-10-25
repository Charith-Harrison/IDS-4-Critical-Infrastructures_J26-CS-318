"""Package measured pilot evidence, not fabricated observations or ML inputs."""
from pathlib import Path
from collections import Counter
import gzip
import hashlib
import importlib.util
import json
import shutil
import sys
import zipfile

ROOT = Path(r'D:\VSCode\GitHub\4th Year Cyber')
LAB = ROOT/'C3/component3_testbed_pilot'
OUT = ROOT/'output/component3_testbed_handoff'
RUN_NAME = 'pilot-20261024T145730Z-4a7f6472'
FAILED_NAME = 'pilot-20261024T145617Z-80339fda'
RUN = LAB/'outputs'/RUN_NAME
OUT.mkdir(parents=True, exist_ok=True)

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for data in iter(lambda:f.read(1<<20), b''):
            h.update(data)
    return h.hexdigest()

def dump(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n',encoding='utf-8')

sys.path.insert(0,str(LAB))
from c3lab.explain import explain_run
walkthrough = explain_run(RUN)
(RUN/'EVIDENCE_WALKTHROUGH.txt').write_text(walkthrough+'\n',encoding='utf-8')
report = json.loads((RUN/'validation_report.json').read_text(encoding='utf-8'))
assert report['status']=='PASSED'
rows = [json.loads(s) for s in (RUN/'verified_labels.jsonl').read_text(encoding='utf-8').splitlines()]
capture = (RUN/'capture.pcap').read_bytes()
assert hashlib.sha256(capture).hexdigest()==report['capture_sha256']
module_path = ROOT/'C3/component3_preparation/c3prep/modbus.py'
spec=importlib.util.spec_from_file_location('independent_cic_decoder', module_path)
decoder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)
byte_errors, shape_errors = [], []
for row in rows:
    raw=bytes.fromhex(row['adu_hex'])
    recovered=bytearray(len(raw)); covered=set()
    for ref in row['frame_byte_references']:
        start,length,pos=ref['pcap_file_byte_offset'],ref['length'],ref['message_byte_offset']
        piece=capture[start:start+length]
        assert len(piece)==length
        recovered[pos:pos+length]=piece
        covered.update(range(pos,pos+length))
    if bytes(recovered)!=raw or len(covered)!=len(raw): byte_errors.append(row['event_id'])
    if not decoder.decode_pdu(raw[7:],row['role']=='request')['shape_ok']: shape_errors.append(row['event_id'])
assert not byte_errors and not shape_errors
independent={'date':'2026-10-24','run_id':RUN_NAME,'checked_complete_messages':len(rows),
    'byte_reference_disagreements':byte_errors,'independent_decoder_shape_disagreements':shape_errors,
    'decoder_source':'C3/component3_preparation/c3prep/modbus.py','decoder_sha256':sha(module_path),
    'capture_sha256':report['capture_sha256'],
    'limits':'Exact captured bytes and narrow structural checks do not establish independent campaigns, realistic physical dynamics or ML benefit.'}
dump(RUN/'INDEPENDENT_CAPTURE_CHECKS.json',independent)
dump(LAB/'INDEPENDENT_CAPTURE_CHECKS.json',independent)

counts=Counter(r['label'] for r in rows)
targets=[r for r in rows if r['label']!='normal']
lines=['| Event | Label | Frame(s) | PDU |','|---|---|---|---|']
for row in targets:
    frames=','.join(str(n) for n in sorted({r['frame_number'] for r in row['frame_byte_references']}))
    lines.append(f"| {row['event_id'].split(':')[-1]} | {row['label']} | {frames} | `{row['pdu_hex']}` |")
inventory=[{'file':p.name,'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(RUN.iterdir()) if p.is_file()]
dump(OUT/'VERIFIED_RUN_FILE_INVENTORY.json',inventory)
total=sum(r['bytes'] for r in inventory)

card=f'''# Dataset card: controlled Modbus/TCP feasibility pilot

**Collection date:** 24 October 2026, approximately20:27 Sri Lanka time (14:57UTC).  
**Collection machine:** Thithira's Windows PC; shared with Kaveesha afterward.  
**Run:** `{RUN_NAME}`.  
**Status:** real capture, message bytes/state/labels VERIFIED; small feasibility pilot only.

| Measurement | Actual result |
|---|---:|
| TCP transactions | {report['transaction_count']} |
| Complete Modbus messages | {report['message_count']} |
| Normal messages | {counts['normal']} |
| Command-injection requests | {counts['command_injection']} |
| Response-injection replies | {counts['response_injection']} |
| Captured network frames | {report['capture_statistics']['frames']} |
| Complete reconstructed TCP payload bytes | {report['capture_statistics']['unique_tcp_payload_bytes']} |
| Reported kernel capture drops | 0 |
| Independent original-byte-reference disagreements | 0 |
| Structural disagreements with existing CIC decoder | 0 |

## What was generated

Two Python programs act as a controller and a machine, sending actual Modbus/TCP over loopback15020 inside one Docker container with no external network. tcpdump records real frames. No spreadsheet rows were invented as measured traffic. Synthetic PCAP fixtures exist only inside software tests.

The lab implements only FC1/3/5/6, unit1, holding registers0/1 and coil1. Register0 is mode; pump ON is permitted only in mode1 under the declared lab rule. Register1 stores a setpoint that changes only on an acknowledged FC6 write. There are no hidden writers or autonomous setpoint changes. Those are toy assumptions, not claims about a real industrial process.

A compromised-controller hook sends a valid pump-ON command in mode0. A compromised-server hook returns a valid but incorrect stored-setpoint reply after an acknowledged write. Normal observations include the same target PDU/value patterns. No malformed-target or ABCD-marker rule labels the attacks. The threats are already-compromised endpoints, not a demonstrated network break-in or TCP-spoofing attack.

## Label meanings

- `normal`: genuine unaltered communication under this experiment's direct-message task. A real acknowledgement of an injected command stays normal.
- `command_injection`: the direct deliberately unauthorized FC5 pump-ON request while mode0 was observed.
- `response_injection`: the specific reply whose value was deliberately changed from the genuine server answer.

Labels depend on exact application bytes/stream positions, recorded frame-byte lineage and a separately audited intervention/state ledger. Whole attack periods are not blanket-labelled malicious. Private state, scenario IDs, run IDs and labels are audit evidence, never model predictors.

## Locate every accepted target

The event suffix below belongs to `{RUN_NAME}`. Frame numbers refer only to this supplied `capture.pcap`.

{chr(10).join(lines)}

See `outputs/{RUN_NAME}/EVIDENCE_WALKTHROUGH.txt` for paired normal examples and earlier observable context. Each row in `verified_labels.jsonl` also contains exact frame and file byte references.

## Verification and provenance

The Docker image build and27 tests inside the container passed. The captured run passed byte/state/label checks and repeat verification. All216 messages were independently recovered from their file-byte references and structurally checked with the existing CIC decoder. This last check does not make this CIC data; this is newly collected lab data, kept separate from CIC.

Capture SHA256: `{report['capture_sha256']}`.

Original manifest, application ledger, server audit and PCAP remain unchanged. The successful run is approximately{total/1024:.1f}KiB including its current human-readable/check reports. One failed recorder-startup attempt is separately retained and contributes zero accepted messages. The original permission failure was fixed by adding SETGID alongside NET_RAW, with runtime networking still disabled.

## Limits and allowed interpretation

This is ONE related run with12 shuffled toy episodes and8 direct attack targets. It establishes collection/annotation feasibility. It is not a complete training dataset, an independent-campaign evaluation, proof of realistic physical process behavior, or evidence that contextual ML beats simple rules. Fixed templates can introduce shortcuts. Changing seeds alone does not establish independent environments.

No model feature preparation, preprocessing, imputation, encoding, scaling, resampling, training or final split was performed. Before larger collection, agree on research scope, controls, causal decision time, varied scenarios and genuinely held-out conditions. A deterministic history-rule baseline may solve this toy task completely.

Read `HANDOVER.md` for inspection without regeneration and for optional exact-image reuse. This data must be described as collected on the collaborator's PC; Kaveesha can receive, inspect, understand and demonstrate it without claiming collection on her own laptop.
'''
(LAB/'DATASET_CARD.md').write_text(card,encoding='utf-8')

handover=f'''# Handover to Kaveesha

You are receiving already-collected **controlled feasibility data**, its source code, exact evidence and a recorded software environment. Collection occurred on Thithira's Windows PC on24 October2026. Preserve that provenance and describe the implementation assistance accurately.

## Inspect without generating anything

1. Extract the evidence ZIP into your repository. It contains `component3_testbed_pilot/`; keep that folder beside existing CIC preparation/reassessment folders.
2. Open `DATASET_CARD.md` in this folder.
3. Open `outputs/{RUN_NAME}/validation_report.json`: status must be PASSED; counts208 normal/4command/4response.
4. Read that run's `EVIDENCE_WALKTHROUGH.txt`. It shows normal and malicious messages with matching PDU patterns and exact frame numbers.
5. Inspect `capture.pcap` in Wireshark if available. Use Decode As Modbus/TCP for port15020 if required. The event IDs/frame numbers belong to this capture, not to a CIC file.
6. Follow those events in `verified_labels.jsonl`. The application ledger and private server audit explain label evidence; they are not a model-ready feature table.

Docker is not needed to read JSON/text evidence. Wireshark or a comparable packet reader is needed for graphical packet inspection. You do not need to regenerate the supplied run merely to receive or demonstrate it.

## Evidence files

| File | What it establishes |
|---|---|
| capture.pcap | Actual recorded traffic |
| capture.log | Recorder startup/statistics/drop count |
| application_ledger.jsonl | Sent/received bytes and message identities |
| server_audit.jsonl | Original state and genuine-versus-altered reply evidence |
| run_manifest.json | Original seed, source hashes, platform and raw-artifact hashes |
| host_execution.json | Actual image identity and launch information |
| validation_report.json | Stream, state and label verification result |
| verified_labels.jsonl | Accepted messages with frame/file byte references |
| EVIDENCE_WALKTHROUGH.txt | Human explanation of specific matching examples |
| INDEPENDENT_CAPTURE_CHECKS.json | Extra byte-reference and decoder checks |

The included failed initialization attempt is debugging history, not training data. Test fixtures and Windows smoke checks are not extra measured captures. Preserve the supplied original files; do not edit labels to change a result.

## Optional reproduction

To rebuild from source and generate a NEW uniquely named run, install/start Docker Desktop's Linux engine and run from this folder:

```powershell
.\\start-pilot.ps1
```

For the separately supplied exact image archive, replace the sample path below with its downloaded location:

```powershell
docker image load --input 'C:\\YOUR-DOWNLOAD-FOLDER\\KAVEESHA_C3_DOCKER_IMAGE.tar.gz'
.\\start-pilot.ps1 -SkipBuild
```

Docker supports loading gzip image archives; see [its official load documentation](https://docs.docker.com/reference/cli/docker/image/load/). Loading an image does not install Docker. It avoids rebuilding image dependencies. A fresh run has new timestamps, TCP headers, source port and capture hash even with the same seed. Never overwrite the supplied capture to make a rerun identical.

To verify and explain the existing supplied recording using the image:

```powershell
.\\verify-pilot.ps1 -Run {RUN_NAME}
```

Your drive letters need not match the collection PC; the scripts resolve paths from their own folder. Do not import MSU or mix CIC rows into this lab. New runs remain feasibility demonstrations until a larger design is agreed.

## Be able to explain

- Messages were actually transmitted and captured, not invented CSV rows.
- A valid message can be unauthorized: identical pump-ON PDU, different earlier mode.
- A reply can be structurally valid but conflict with a prior acknowledged write under this toy process's rules.
- Genuine acknowledgements do not inherit response-injection labels.
- Bytes, stream positions and frame references establish the exact targeted messages; time/IP proximity alone does not.
- The private oracle is the answer sheet for labelling, not an input available to a deployed detector.
- Simple contextual rules may already solve this pilot; ML superiority and real-factory performance remain unproved.

Use `docs/DISCORD_LESSON.md` for the walkthrough. Future preprocessing remains separate. Discuss the main-data-source change with the supervisor before treating this pilot as the final assessed experiment.
'''
(LAB/'HANDOVER.md').write_text(handover,encoding='utf-8')

status=f'''# Pilot status — 24 October 2026

**Docker build,27 tests inside Docker, real packet capture and exact message/state/label verification PASSED on Thithira's PC.** Successful run: `{RUN_NAME}`. This is measured feasibility data, not a complete ML training dataset.

Actual results:216 complete messages in108 transactions;208 normal,4command injections,4response injections;224 captured network frames;2,532 accounted TCP payload bytes;0 reported kernel capture drops. All216 message-byte references were independently checked and all PDUs passed the existing CIC decoder's structural checks.

The first attempt `{FAILED_NAME}` failed before application traffic because tcpdump could not initialize process groups. The fix adds only SETGID alongside NET_RAW; the container keeps network_mode:none, a read-only root filesystem, no published ports and one writable output mount. The failed run is preserved separately and has zero accepted messages.

The source code, raw recording, ledgers, immutable original run manifest, host/image identity, validation results and teaching notes are included in the verified handoff. An optional exact Linux/amd64 image archive is provided separately. The image reports184,449,590bytes; this does not measure all Docker Desktop/WSL/cache overhead. Rebuilding from moving apt/base-image sources may change image bytes; keep the exported image/archive hash for exact environment reuse.

Before Docker execution,27 Windows software tests and a216-message actual-loopback smoke check also passed. Synthetic PCAPs in tests remain fixtures, never measured research data. Smoke outputs are not part of the accepted captured cohort.

Limits: one related run; fixed nine-exchange template; deterministic stored setpoint; no hidden writer; one declared permission rule; one TCP connection. Passing verification does not establish absence of shortcuts, independent plants, ML benefit, or deployment generalization. Private experiment state is not a predictor. Genuine acknowledgements remain normal under the direct-message task.

No bulk collection, final split, model preprocessing, training or deployment occurred. Existing CIC outputs remain separate. Collection-machine provenance must stay accurate when handed to Kaveesha. She can inspect this evidence without regenerating it.
'''
(LAB/'BUILD_STATUS.md').write_text(status,encoding='utf-8')
checks=json.loads((LAB/'LOCAL_CHECK_RESULTS.json').read_text(encoding='utf-8'))
checks.update(docker_build_and_capture_executed=True,docker_tests_passed=27,verified_run_id=RUN_NAME,
              verified_message_count=216,captured_frames=224,kernel_drops=0,accepted_label_counts=dict(counts),
              original_byte_reference_disagreements=0,container_capability_fix='Added SETGID for tcpdump initgroups; network remains none')
dump(LAB/'LOCAL_CHECK_RESULTS.json',checks)

background=LAB/'background'
background.mkdir(exist_ok=True)
for original,name in (
    (ROOT/'output/component3_execution/COMPONENT3_FULL_PROGRESS_REPORT_2026-10-24.md','CIC_REVIEW_BEFORE_TESTBED.md'),
    (ROOT/'C3/component3_reassessment/v1_20261024/DECISION_REPORT.md','CIC_REASSESSMENT_DECISION.md'),
):
    shutil.copyfile(original,background/name)
(background/'READ_CONTEXT_FIRST.txt').write_text(
    'These reports describe the earlier CIC-only audit, before this new lab pilot.\n'
    'Their no-training conclusions remain true. Their current-status statements\n'
    'do not describe the later testbed capture. Read DATASET_CARD.md for the new\n'
    'measured pilot. Historical links/drive letters refer to the reviewer copy.\n'
    'The individual proposal identified CIC as primary; a testbed-primary study\n'
    'is a methodology change to document/discuss. MSU remains excluded.\n',encoding='utf-8')

tar=OUT/'kaveesha-c3-pilot-0.1.0-linux-amd64.tar'
image_gz=OUT/'KAVEESHA_C3_DOCKER_IMAGE.tar.gz'
with tar.open('rb') as source, image_gz.open('wb') as target:
    with gzip.GzipFile(filename='',mode='wb',fileobj=target,compresslevel=1,mtime=0) as packed:
        shutil.copyfileobj(source,packed,1<<20)
unpacked_hash=hashlib.sha256()
with gzip.open(image_gz,'rb') as f:
    for chunk in iter(lambda:f.read(1<<20),b''): unpacked_hash.update(chunk)
assert unpacked_hash.hexdigest()==sha(tar)
dump(OUT/'DOCKER_IMAGE_ARCHIVE.json',{'platform':'linux/amd64','source_image':'kaveesha-c3-pilot:0.1.0',
    'gzip_file':image_gz.name,'gzip_bytes':image_gz.stat().st_size,'gzip_sha256':sha(image_gz),
    'uncompressed_tar_bytes':tar.stat().st_size,'uncompressed_tar_sha256':sha(tar),
    'note':'Optional image for reproduction; Docker is not required to read supplied text/JSON evidence.'})

source_files=[p for p in sorted(LAB.rglob('*')) if p.is_file() and 'outputs' not in p.relative_to(LAB).parts
              and '__pycache__' not in p.relative_to(LAB).parts and p.suffix!='.pyc' and p.name!='FILE_HASHES.json']
dump(LAB/'FILE_HASHES.json',{p.relative_to(LAB).as_posix():sha(p) for p in source_files})
source_files.append(LAB/'FILE_HASHES.json')
recorded_files=[p for name in (RUN_NAME,FAILED_NAME) for p in sorted((LAB/'outputs'/name).iterdir()) if p.is_file()]
all_files=source_files+recorded_files
bundle_manifest={'purpose':'VERIFIED_FEASIBILITY_PILOT_NOT_FINAL_TRAINING_DATASET','collection_machine':'Thithira PC',
    'successful_run':RUN_NAME,'failed_initialization_run':FAILED_NAME,'success_counts':dict(counts),
    'files':{('component3_testbed_pilot/'+p.relative_to(LAB).as_posix()):{'bytes':p.stat().st_size,'sha256':sha(p)} for p in all_files},
    'optional_image_archive':json.loads((OUT/'DOCKER_IMAGE_ARCHIVE.json').read_text(encoding='utf-8'))}
reimport=OUT/'IMAGE_REIMPORT_CHECK.json'
if reimport.exists():
    bundle_manifest['exact_image_load_and_verification']=json.loads(reimport.read_text(encoding='utf-8-sig'))
dump(OUT/'HANDOFF_MANIFEST.json',bundle_manifest)
bundle=OUT/'KAVEESHA_COMPONENT3_VERIFIED_PILOT.zip'
with zipfile.ZipFile(bundle,'w',compression=zipfile.ZIP_DEFLATED) as z:
    for p in all_files:z.write(p,'component3_testbed_pilot/'+p.relative_to(LAB).as_posix())
    z.write(OUT/'HANDOFF_MANIFEST.json','HANDOFF_MANIFEST.json')
    z.write(OUT/'DOCKER_IMAGE_ARCHIVE.json','DOCKER_IMAGE_ARCHIVE.json')
    if reimport.exists(): z.write(reimport,'IMAGE_REIMPORT_CHECK.json')
with zipfile.ZipFile(bundle) as z:
    assert z.testzip() is None
    for name, row in bundle_manifest['files'].items():
        assert hashlib.sha256(z.read(name)).hexdigest()==row['sha256']
# Refresh the earlier source-only ZIP so its previously shared link has the fix.
starter=ROOT/'output/component3_testbed_review/KAVEESHA_COMPONENT3_TESTBED_PILOT.zip'
with zipfile.ZipFile(starter,'w',compression=zipfile.ZIP_DEFLATED) as z:
    for p in source_files:z.write(p,'component3_testbed_pilot/'+p.relative_to(LAB).as_posix())
print(json.dumps({'verified_bundle':str(bundle),'verified_bundle_bytes':bundle.stat().st_size,
    'image_archive':str(image_gz),'image_archive_bytes':image_gz.stat().st_size,
    'verified_run_bytes':total,'verified_messages':len(rows),'independent_shape_errors':shape_errors,
    'independent_byte_reference_errors':byte_errors,'image_tar_roundtrip_sha256_matches':True},indent=2))
