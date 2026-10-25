from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import shutil
import subprocess

source = Path(r'D:\VSCode\GitHub\4th Year Cyber')
repo = Path(r'D:\VSCode\Github-Other\Github-Kavisha\IDS-4-Critical-Infrastructures_J26-CS-318')
target = (repo / 'producer_work_20261025').resolve()
if not target.is_relative_to(repo.resolve()) or target.exists():
    raise ValueError('Import requires a new, contained destination; existing evidence is never overwritten')

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''): h.update(b)
    return h.hexdigest()

paths = list((source/'C3').rglob('*'))
for folder in (source/'output').glob('component3*'):
    if folder.is_dir(): paths.extend(folder.rglob('*'))
paths = [p for p in paths if p.is_file() and '__pycache__' not in p.parts
         and 'review_deps' not in p.parts and not p.name.endswith(('.pyc','.pyo'))]
size = sum(p.stat().st_size for p in paths)
if shutil.disk_usage(repo).free < size + 2 * 1024**3:
    raise ValueError('Insufficient free space for preserved import plus 2GiB working reserve')
records = {}
for i,p in enumerate(paths,1):
    relative=p.relative_to(source); dest=target/relative
    dest.parent.mkdir(parents=True,exist_ok=True)
    before=sha(p); shutil.copy2(p,dest)
    if sha(dest)!=before or sha(p)!=before: raise ValueError('Source changed or copy mismatch: '+str(relative))
    records[relative.as_posix()]={'sha256':before,'bytes':p.stat().st_size}
    if i%250==0:print(f'Copied and hashed {i}/{len(paths)} files',flush=True)
manifest={'status':'COPIED_AND_BYTE_VERIFIED','imported_at_utc':datetime.now(timezone.utc).isoformat(),
          'source_root':str(source),'destination_relative_to_repository':target.name,
          'files':records,'total_bytes':size,
          'excluded':'Python bytecode/cache and review_deps installed third-party dependencies only',
          'canonical_collection_relative_to_repository':target.name+'/C3/Component3_Modbus_Collector/component3_collection_runs/main-frozen-v1-20261025',
          'note':'Existing repository snapshots/partial collections were not overwritten; only the indexed canonical104-run source is model data.'}
(repo/'PRODUCER_IMPORT_MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
(repo/'PRODUCER_WORK_INDEX.md').write_text('''# Producer work imported on 25 October 2026

All C3 source work and related component3 output reports/handoffs from the producer PC are copied byte-for-byte under `producer_work_20261025/`. `PRODUCER_IMPORT_MANIFEST.json` records original hashes and destinations. Installed dependency folders and Python bytecode caches were excluded. Existing repository history and partial recordings were preserved.

The completed modelling source is `producer_work_20261025/C3/Component3_Modbus_Collector/component3_collection_runs/main-frozen-v1-20261025`. Its `collection_complete.json` indexes exactly104acceptedruns. Earlier root-level recordings are historical and must not be loaded as extra samples.

Heavy raw data, annotated ledgers, extracted records and image/ZIP archives are retained locally and excluded from Git. Source, documentation and this integrity manifest can be committed. Transfer the verified complete handoff ZIP separately when moving machines. The legacy application and its binary CSV results are not the new lab experiment.

New preprocessing/model development belongs in `component3_model_pipeline/v1_20261025`, separate from frozen collection code and the historical design scaffold. See its README for runnable stages and scientific limits.
''',encoding='utf8')
ignore=repo/'.gitignore'; old=ignore.read_text(encoding='utf8')
block='''
# Producer PC evidence import: preserve locally, transfer via verified archive
/producer_work_20261025/**/component3_collection_runs/
/producer_work_20261025/**/component3_preparation/output/
/producer_work_20261025/**/component3_reassessment/**/output/
/producer_work_20261025/**/*.jsonl
/producer_work_20261025/**/*.parquet
/producer_work_20261025/**/*.pcap
/producer_work_20261025/**/*.pcapng
/producer_work_20261025/**/*.csv
/producer_work_20261025/**/*.tar
/producer_work_20261025/**/*.gz
/producer_work_20261025/**/*.zip
/producer_work_20261025/**/original_attempt_backup/
/component3_model_pipeline/v1_20261025/artifacts/
/.venv-c3/
'''
if '# Producer PC evidence import' not in old:ignore.write_text(old.rstrip()+'\n'+block,encoding='utf8')
git=['git','--git-dir='+str(repo/'.git'),'--work-tree='+str(repo)]
subprocess.run(git+['config','--local','user.name','Kavisha Harshangi Rathnayaka'],check=True)
subprocess.run(git+['config','--local','user.email','harshangirathnayake@gmail.com'],check=True)
print(json.dumps({'status':manifest['status'],'files':len(paths),'MiB':round(size/1024**2,2),
                  'target':str(target),'git_identity':'Existing Kaveesha commit identity configured locally; global identity unchanged'}),flush=True)
