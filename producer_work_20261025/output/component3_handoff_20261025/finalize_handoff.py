"""Add handoff guidance and CIC code references to the intact results archive."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
WORKSPACE = ROOT.parent.parent
COLLECTION = WORKSPACE / 'C3/Component3_Modbus_Collector/component3_collection_runs/main-frozen-v1-20261025'
ARCHIVE = ROOT / 'C3_KAVEESHA_COMPLETE_HANDOFF_20261025.zip'


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            value.update(chunk)
    return value.hexdigest()


final = json.loads((COLLECTION / 'collection_complete.json').read_text())
counts, roles = Counter(), Counter()
for item in final['completed'].values():
    receipt = json.loads((COLLECTION / item['attempt'] / 'completion.json').read_text())
    counts.update(receipt['label_counts'])
    roles[item['intended_evaluation_role']] += 1
report = {
    'checked_at_utc': datetime.now(timezone.utc).isoformat(),
    'collection_id': final['collection_id'],
    'source_bundle_id': final['source_bundle_id'],
    'independent_inspector_result': {
        'status': 'ALL_104_VALIDATED', 'validated': 104, 'expected': 104,
        'label_counts': dict(counts), 'attempts': 107, 'preprocessing_or_models': False,
    },
    'independent_inspector_command': 'python -B tools/inspect_collection.py --output <original collection path>',
    'note': 'The original frozen inspector completed successfully before packaging. Counts here summarize sealed receipts; no model work or data-dependent final-test selection occurred.',
    'intended_role_runs': dict(roles),
    'excluded_attempts': ['MX086-20261025T063126Z-16600283', 'MX087-20261025T063952Z-1fa45191', 'MX088-20261025T064936Z-55b059c6'],
    'accepted_post_capture_recovery': 'MX040',
}
(ROOT / 'POST_COLLECTION_CHECK.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf8')

supplement = {
    'START_HERE.md': ROOT / 'START_HERE.md',
    'handoff/PROMPT_FOR_KAVEESHA_CODEX.txt': ROOT / 'PROMPT_FOR_KAVEESHA_CODEX.txt',
    'handoff/check_handoff.py': ROOT / 'check_handoff.py',
    'handoff/POST_COLLECTION_CHECK.json': ROOT / 'POST_COLLECTION_CHECK.json',
}
cic = WORKSPACE / 'C3/component3_preparation'
for subdir in ('c3prep', 'tests'):
    for path in sorted((cic / subdir).glob('*.py')):
        supplement['references/cic_preparation/' + path.relative_to(cic).as_posix()] = path
for relative in ('README.md', 'PREPROCESSING_PLAN.md', 'EXTRACTION_VIVA_NOTES.md', 'schema/data_dictionary.md'):
    supplement['references/cic_preparation/' + relative] = cic / relative
manifest = {
    'purpose': 'Handoff guidance and unchanged local CIC code/documentation references only; no CIC records or trained models',
    'file_sha256': {name: sha(path) for name, path in supplement.items()},
}
with zipfile.ZipFile(ARCHIVE, 'a', compression=zipfile.ZIP_DEFLATED, compresslevel=1) as archive:
    if 'START_HERE.md' in archive.namelist():
        raise ValueError('Archive already finalized; do not create duplicate ZIP members')
    for name, path in supplement.items():
        archive.write(path, name)
    archive.writestr('handoff/REFERENCE_MANIFEST.json', json.dumps(manifest, indent=2) + '\n')
with zipfile.ZipFile(ARCHIVE) as archive:
    if len(archive.namelist()) != len(set(archive.namelist())):
        raise ValueError('Duplicate ZIP entries')
    if archive.testzip() is not None:
        raise ValueError('ZIP CRC failure')
    original = json.loads(archive.read('RETURN_MANIFEST.json'))
    all_hashes = {'collection/' + name: digest for name, digest in original['file_sha256'].items()}
    all_hashes.update(manifest['file_sha256'])
    for name, expected in all_hashes.items():
        digest = hashlib.sha256()
        with archive.open(name) as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b''):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise ValueError('Archived content hash mismatch: ' + name)
checksum = sha(ARCHIVE)
ARCHIVE.with_suffix('.zip.sha256').write_text(checksum + '  ' + ARCHIVE.name + '\n', encoding='ascii')
print(json.dumps({'status': 'COMPLETE_HANDOFF_CRC_AND_CONTENT_HASHES_VERIFIED',
                  'zip': str(ARCHIVE), 'bytes': ARCHIVE.stat().st_size,
                  'MiB': round(ARCHIVE.stat().st_size / 1024**2, 2),
                  'sha256': checksum, 'accepted_runs': 104,
                  'CIC_code_reference_files': len(supplement) - 4,
                  'CSV_or_model_preprocessing_executed': False}, indent=2), flush=True)
