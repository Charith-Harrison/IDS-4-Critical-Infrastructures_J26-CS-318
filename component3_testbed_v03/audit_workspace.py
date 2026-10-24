"""Check frozen predecessors without running any predecessor writer."""
from pathlib import Path
import hashlib
import json

HERE=Path(__file__).resolve().parent
REPO=HERE.parent


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for b in iter(lambda:f.read(8<<20),b''): h.update(b)
    return h.hexdigest()


def check():
    old=json.loads((HERE/'evidence/protected_before.json').read_text())
    changed=[name for name,row in old.items() if not (REPO/name).is_file()
             or (REPO/name).stat().st_size!=row['bytes'] or sha(REPO/name)!=row['sha256']]
    result=dict(status='FAILED' if changed else 'PASSED',protected_files=len(old),changed_files=changed,
                original_raw='Not written, rehashed or re-extracted',main_collection='Not performed')
    (HERE/'evidence/protected_after.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__=='__main__':
    result=check()
    print(json.dumps(result,indent=2))
    raise SystemExit(result['status']!='PASSED')
