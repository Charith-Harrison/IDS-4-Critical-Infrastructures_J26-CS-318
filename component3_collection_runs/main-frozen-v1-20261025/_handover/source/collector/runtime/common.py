from pathlib import Path
from datetime import datetime,timezone
import hashlib
import json
import os
import sys
import uuid

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'engine'))
PURPOSE='FROZEN_MAIN_RAW_EVIDENCE_NOT_MODEL_DATA'


def utc(): return datetime.now(timezone.utc).isoformat()


def read(path): return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(8<<20),b''): h.update(b)
    return h.hexdigest()


def digest(data): return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def atomic(path,data):
    path=Path(path)
    temp=path.with_name(path.name+'.tmp-'+uuid.uuid4().hex)
    with temp.open('x',encoding='utf8') as f:
        json.dump(data,f,indent=2,sort_keys=True);f.write('\n');f.flush();os.fsync(f.fileno())
    temp.replace(path)


def source_inventory(root=ROOT):
    selected=[]
    for p in Path(root).rglob('*'):
        rel=p.relative_to(root)
        if not p.is_file() or rel.parts[0]=='evidence' or '__pycache__' in rel.parts: continue
        if rel.as_posix() in ('frozen/freeze_manifest.json','image_identity.json'): continue
        if p.suffix in ('.py','.ps1','.json') or p.name in ('Dockerfile','.dockerignore','.gitignore'):
            selected.append(p)
    return {p.relative_to(root).as_posix():sha(p) for p in sorted(selected)}


def bundle_id(): return digest(source_inventory())


def verify_package():
    frozen=read(ROOT/'frozen/freeze_manifest.json')
    current=source_inventory()
    if current!=frozen['source_configuration_sha256'] or digest(current)!=frozen['bundle_id']:
        raise ValueError('Frozen source/configuration changed. Refusing collection/resume; do not auto-refreeze.')
    return frozen


def roster(): return read(ROOT/'frozen/main_roster.json')['runs']


def planned(run_id):
    rows=[r for r in roster() if r['planned_run_id']==run_id]
    if len(rows)!=1: raise ValueError('Only frozen main IDs MX001-MX104 are accepted; pilots/EQ excluded')
    row=dict(rows[0])
    row.update(policy_id='lab-policy-v1',source_bundle_id=bundle_id(),
               frozen_protocol_sha256=sha(ROOT/'frozen/protocol.json'),
               frozen_roster_sha256=sha(ROOT/'frozen/main_roster.json'))
    return row


def validator():
    # Only the collection envelope changes. Qualified decoding/replay functions remain byte-identical.
    import c3qual.validation as v
    v.PURPOSE=PURPOSE;v.planned=planned;v.source_hashes=source_inventory
    return v.validate


def artifacts(folder,exclude=()):
    return {p.name:sha(p) for p in sorted(Path(folder).iterdir()) if p.is_file()
            and p.name not in exclude and '.tmp-' not in p.name}
