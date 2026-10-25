"""Read-only hashes for frozen component-3 evidence. Never scan/re-extract raw PCAPs."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
BASELINE = HERE / 'evidence/protected_before.json'


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def snapshot():
    result = {}
    for name in ('component3_preparation', 'component3_reassessment',
                 'component3_testbed_pilot', 'component3_collection_design'):
        for p in sorted((REPO / name).rglob('*')):
            if p.is_file() and '__pycache__' not in p.parts:
                result[p.relative_to(REPO).as_posix()] = {'bytes': p.stat().st_size, 'sha256': sha(p)}
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['snapshot', 'check'])
    args = parser.parse_args()
    current = snapshot()
    if args.command == 'snapshot':
        with BASELINE.open('x', encoding='utf8') as f:
            json.dump(current, f, indent=2)
        print(f'Protected snapshot: {len(current)} files')
    else:
        old = json.loads(BASELINE.read_text(encoding='utf8'))
        changes = [name for name in old if current.get(name) != old[name]]
        extra = sorted(set(current) - set(old))
        result = {'status': 'PASSED' if not changes and not extra else 'FAILED',
                  'protected_files': len(old), 'changed_or_missing': changes, 'added_in_frozen_roots': extra,
                  'raw_sources': 'Not written or re-extracted; original raw location retained'}
        (HERE / 'evidence/protected_after.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf8')
        print(json.dumps(result, indent=2))
        raise SystemExit(bool(changes or extra))
