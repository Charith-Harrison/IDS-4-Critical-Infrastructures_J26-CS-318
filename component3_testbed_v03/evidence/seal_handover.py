"""Seal portable evidence after successful collection and independent review."""
from pathlib import Path
import json
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from c3qual.config import read_json,sha,source_hashes
from audit_workspace import check


def main():
    summary=read_json(ROOT/'evidence/engineering_summary.json')
    audit=read_json(ROOT/'evidence/shortcut_audit.json')
    if summary['status']!='FOURTEEN_ENGINEERING_PROBES_PASSED' or audit['status']!='PASSED':
        raise ValueError('Both collection and independent audit must pass before sealing')
    if summary['label_counts']!=audit['label_counts'] or summary['source_sha256']!=source_hashes():
        raise ValueError('Evidence/source identities differ')
    if audit['code_sha256']!=sha(ROOT/'evidence/audit_shortcuts.py'):
        raise ValueError('Independent audit code changed')
    preservation=check()
    if preservation['status']!='PASSED': raise ValueError('Frozen predecessors changed')
    captures={}
    for row in summary['runs']:
        folder=ROOT.parent/row['source']
        for name,digest in row['artifact_sha256'].items():
            if sha(folder/name)!=digest: raise ValueError('Recording artifact changed: '+row['source']+'/'+name)
        captures[row['source']]=row['artifact_sha256']
    archive=ROOT/'evidence/runtime-images-v03.tar'
    if not archive.is_file(): raise ValueError('Exact runtime archive absent')
    archive_sha=sha(archive)
    (ROOT/'evidence/runtime-images-v03.tar.sha256').write_text(archive_sha+'  runtime-images-v03.tar\n',encoding='ascii')
    files=[p for p in ROOT.rglob('*') if p.is_file() and '__pycache__' not in p.parts
           and p.name!='handover_manifest.json']
    manifest=dict(status='SEALED_ENGINEERING_ONLY',scope='EQ01-EQ14; not final model data or main collection',
                  path_policy='Paths below are relative to component3_testbed_v03 or the repository root as indicated',
                  engineering_source_sha256=summary['source_sha256'],
                  package_artifact_sha256={p.relative_to(ROOT).as_posix():sha(p) for p in sorted(files)},
                  recording_artifact_sha256=captures,runtime_archive=dict(file='evidence/runtime-images-v03.tar',
                       bytes=archive.stat().st_size,sha256=archive_sha,
                       tags=['c3-qualification:0.3.0','c3-qualification:0.2.0','kaveesha-c3-pilot:0.1.0']),
                  actual_collection_machines=sorted({r['collector_machine'] for r in summary['runs']}),
                  runtime_image_ids=sorted({r['image_id'] for r in summary['runs']}),
                  preserved_predecessors=preservation,academic_supervisor_approval='NOT_RECORDED',
                  new_main_captures=0,model_preprocessing_or_training=False,
                  reproducible_review_commands=[
                      '.\\.venv\\Scripts\\python.exe -B component3_testbed_v03/summarize_engineering.py',
                      '.\\.venv\\Scripts\\python.exe -B component3_testbed_v03/evidence/audit_shortcuts.py',
                      '.\\.venv\\Scripts\\python.exe -B component3_testbed_v03/evidence/seal_handover.py'])
    (ROOT/'evidence/handover_manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(status=manifest['status'],recordings=len(captures),preserved_files=preservation['protected_files'],
                         runtime_archive_bytes=archive.stat().st_size,runtime_archive_sha256=archive_sha),indent=2))


if __name__=='__main__': main()
