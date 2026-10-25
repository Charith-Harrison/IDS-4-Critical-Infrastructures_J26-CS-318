# Record and compare file hashes when checking that a bundle was preserved intact.
"""Record/verify an intact relocation. Does not move or delete anything."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / 'component3/reports/preservation.json'

# Calculate a SHA-256 digest of the file bytes.
def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

# Record paths, sizes, and hashes before checking preservation.
def snapshot():
    if RECORD.exists():
        raise ValueError('Preservation record already exists; refusing to overwrite')
    roots = sorted(p for p in ROOT.iterdir() if p.is_dir() and
                   (p.name.startswith('component3_') or p.name == 'producer_work_20261025'))
    moves = []
    for source in roots:
        destination = ('component3/locked' if source.name == 'component3_model_pipeline' else
                       'component3/data' if source.name == 'component3_raw' else
                       'component3/history/' + source.name)
        target = (ROOT / destination).resolve()
        if not target.is_relative_to(ROOT) or target.exists():
            raise ValueError('Unsafe/existing destination: ' + str(target))
        files = {}
        for p in sorted(source.rglob('*')):
            if p.is_symlink():
                raise ValueError('Review symbolic link before moving: ' + str(p))
            if p.is_file():
                files[p.relative_to(source).as_posix()] = {'sha256': sha(p), 'bytes': p.stat().st_size}
        moves.append({'before': source.name, 'after': destination, 'files': files})
        print(source.name, len(files), flush=True)
    pattern = '|'.join(p.name for p in roots)
    refs = subprocess.run(['git', 'grep', '-n', '-I', '-E', pattern], cwd=ROOT,
                          capture_output=True, check=False)
    if refs.returncode not in (0, 1):
        raise RuntimeError(refs.stderr.decode(errors='replace'))
    (RECORD.parent / 'path_references_before.txt').write_bytes(refs.stdout)
    record = {'version': 1, 'git_head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
              'command': 'python -B component3/tools/preservation.py snapshot', 'moves': moves}
    RECORD.write_text(json.dumps(record, indent=2) + '\n', encoding='utf-8')

# Compare current file bytes against the recorded preservation snapshot.
def verify():
    record = json.loads(RECORD.read_text(encoding='utf-8'))
    errors, count = [], 0
    for move in record['moves']:
        root = ROOT / move['after']
        actual = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
        expected = set(move['files'])
        if actual != expected:
            errors.append({'root': move['after'], 'added': sorted(actual-expected), 'missing': sorted(expected-actual)})
        for name, item in move['files'].items():
            p = root / name
            if not p.is_file() or sha(p) != item['sha256']:
                errors.append({'changed_or_missing': str(p)})
            count += 1
    result = {'status': 'PASSED' if not errors else 'FAILED', 'files_checked': count,
              'preservation_record_sha256': sha(RECORD), 'errors': errors}
    (RECORD.parent/'preservation_verification.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(result))
    if errors:
        raise SystemExit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['snapshot', 'verify'])
    args = parser.parse_args()
    snapshot() if args.action == 'snapshot' else verify()
