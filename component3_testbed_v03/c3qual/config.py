"""Engineering-only v0.3 adoption. Main-run loader deliberately unavailable."""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parent.parent
PURPOSE = 'ENGINEERING_V03_UNSCORED_NOT_MODEL_DATA'
RUN_IDS = tuple(f'EQ{i:02d}' for i in range(1,15))


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def design():
    return read_json(ROOT/'design/proposed_main_design.json')


def object_map(map_id):
    return next(m for m in design()['public_detector_configuration']['maps'] if m['id']==map_id)


def planned(run_id):
    if run_id not in RUN_IDS:
        raise ValueError('Only adopted EQ01-EQ14 engineering probes are enabled; main collection disabled')
    adoption = read_json(ROOT/'design/engineering_adoption.json')
    if adoption['status'] != 'USER_ADOPTED_ENGINEERING_PROBES_ONLY':
        raise ValueError('Engineering adoption missing')
    if adoption['source_design_sha256'] != sha(ROOT/'design/proposed_main_design.json') or \
       adoption['source_roster_sha256'] != sha(ROOT/'design/proposed_run_roster.json'):
        raise ValueError('Engineering design/roster changed without versioned adoption')
    roster=read_json(ROOT/'design/proposed_run_roster.json')
    row=dict(next(r for r in roster['engineering_runs'] if r['planned_run_id']==run_id))
    if row['purpose'] != 'ENGINEERING_ONLY_UNSCORED' or row['actual_partition_membership'] is not None:
        raise ValueError('Unscored engineering purpose required')
    row.update(design_sha256=adoption['source_design_sha256'],roster_sha256=adoption['source_roster_sha256'],
               adoption_sha256=sha(ROOT/'design/engineering_adoption.json'),policy_id='lab-policy-v1')
    return row


def source_hashes():
    return {p.relative_to(ROOT).as_posix():sha(p) for p in sorted(ROOT.rglob('*')) if p.is_file()
            and 'evidence' not in p.parts and (p.suffix in ('.py','.ps1','.yaml')
            or p.name in ('Dockerfile','.dockerignore','.gitignore') or p.parent.name=='design')}
