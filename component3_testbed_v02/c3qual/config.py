"""Load the frozen proposed design; only Q01-Q04 can be collected by this version."""
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PURPOSE = 'QUALIFICATION_UNSCORED_NOT_MODEL_DATA'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def design():
    return read_json(ROOT / 'design/collection_design.json')


def planned(run_id):
    if run_id not in ('Q01', 'Q02', 'Q03', 'Q04'):
        raise ValueError('Only Q01-Q04 engineering qualification is enabled; main collection is gated')
    with (ROOT / 'design/PROSPECTIVE_RUN_ROSTER.csv').open(encoding='utf8', newline='') as f:
        row = next(r for r in csv.DictReader(f) if r['planned_run_id'] == run_id)
    if row['purpose'] != 'qualification_unscored':
        raise ValueError('Roster purpose is not qualification')
    row['seed'] = int(row['seed'])
    row['design_sha256'] = sha(ROOT / 'design/collection_design.json')
    row['roster_sha256'] = sha(ROOT / 'design/PROSPECTIVE_RUN_ROSTER.csv')
    row['policy_id'] = design()['policy']['id']
    return row


def object_map(map_id):
    return next(m for m in design()['maps'] if m['id'] == map_id)


def source_hashes():
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(ROOT.rglob('*'))
            if p.is_file() and (p.suffix in ('.py', '.ps1', '.yaml') or p.name == 'Dockerfile'
                                or p.name in ('.dockerignore', '.gitignore')
                                or p.parent.name == 'design') and 'evidence' not in p.parts}
