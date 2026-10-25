"""Read-only inputs and bounded audit helpers; outputs confined to this version."""
import hashlib
import json
import statistics
from pathlib import Path
from datetime import datetime, timezone

HERE = Path(__file__).resolve().parent
REPO = next(p for p in HERE.parents if (p / 'component3_preparation/config.json').is_file())
CONFIG = json.loads((HERE / 'config.json').read_text())
BASE = REPO / CONFIG['baseline']
RAW = (REPO / CONFIG['raw_root']).resolve()
OUT = HERE / 'output'
REVIEW = REPO / CONFIG['review']


def read(path):
    return json.loads(Path(path).read_text(encoding='utf8'))


def write(name, value):
    OUT.mkdir(parents=True, exist_ok=True)
    destination = (OUT / name).resolve()
    if not destination.is_relative_to(OUT.resolve()):
        raise ValueError('Audit output escaped its versioned directory')
    destination.write_text(json.dumps(value, indent=2, default=serial) + '\n', encoding='utf8')


def serial(value):
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (set, tuple)):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    raise TypeError(type(value).__name__)


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(8 << 20), b''):
            h.update(block)
    return h.hexdigest()


def day(us):
    return datetime.fromtimestamp(us / 1000000, timezone.utc).date().isoformat() if us is not None else None


def stats(values):
    values = sorted(values)
    if not values:
        return {'n': 0}
    def q(p):
        return values[min(len(values)-1, int(p * (len(values)-1)))]
    return {'n': len(values), 'min': values[0], 'p05': q(.05), 'median': statistics.median(values), 'p95': q(.95), 'max': values[-1],
            'quantile_method':'p05/p95 lower empirical order statistic; median averages central values for even n'}


def freeze():
    inventory = read(BASE / 'output/inventory.json')
    assert RAW.is_dir() and Path(inventory['raw_root']).resolve() == RAW
    existing = OUT / 'baseline_frozen.json'
    files = {}
    for p in sorted(BASE.rglob('*')):
        if p.is_file():
            files[p.relative_to(BASE).as_posix()] = {'bytes': p.stat().st_size, 'sha256': sha(p)}
    snapshot = {'repository_root': str(REPO), 'raw_root': str(RAW), 'baseline_root': str(BASE), 'files': files,
                'raw_inventory_sha256': sha(BASE/'output/inventory.json'),
                'raw_files': [{'path': r['path'], 'bytes': r['bytes'], 'mtime_ns': (RAW/r['path']).stat().st_mtime_ns,
                               'recorded_sha256': r['sha256'], 'size_matches': (RAW/r['path']).stat().st_size == r['bytes'],
                               'baseline_mtime_matches': (RAW/r['path']).stat().st_mtime_ns == r.get('mtime_ns')} for r in inventory['files']]}
    if existing.exists():
        old = read(existing)
        assert old['files'] == files, 'Frozen baseline differs: stop, do not overwrite baseline snapshot'
    else:
        write('baseline_frozen.json', snapshot)
    write('input_provenance.json', {'raw_root_verified': str(RAW), 'raw_identity': inventory['source_version'],
            'review_inputs': [{'path': p.relative_to(REPO).as_posix(), 'sha256': sha(p)} for p in sorted(REVIEW.glob('*')) if p.is_file()],
            'baseline_files_hashed': len(files), 'raw_files_metadata_rechecked': len(snapshot['raw_files']),
            'all_raw_sizes_match_inventory': all(x['size_matches'] for x in snapshot['raw_files']),
            'raw_mtime_differences': [x['path'] for x in snapshot['raw_files'] if not x['baseline_mtime_matches']],
            'raw_hash_policy': 'Reuse original source inventory/checkpoints; hash actual log files and sampled byte ranges only. No whole raw rehash or full extraction.'})
    return snapshot


def verify_frozen():
    before = read(OUT / 'baseline_frozen.json')
    current = {p.relative_to(BASE).as_posix(): {'bytes': p.stat().st_size, 'sha256': sha(p)} for p in sorted(BASE.rglob('*')) if p.is_file()}
    changed = [p for p in sorted(set(before['files']) | set(current)) if before['files'].get(p) != current.get(p)]
    raw_changed = [r['path'] for r in before['raw_files'] if (RAW/r['path']).stat().st_size != r['bytes'] or (RAW/r['path']).stat().st_mtime_ns != r['mtime_ns']]
    result = {'baseline_byte_for_byte_unchanged': not changed, 'changed_baseline_paths': changed,
              'raw_size_mtime_unchanged': not raw_changed, 'raw_changed_paths': raw_changed,
              'raw_hash_limit': 'All original raw hashes reused; sampled raw ranges and logs checked separately. No new claim of an exhaustive raw rehash.'}
    write('preservation_verification.json', result)
    assert not changed and not raw_changed
    return result
