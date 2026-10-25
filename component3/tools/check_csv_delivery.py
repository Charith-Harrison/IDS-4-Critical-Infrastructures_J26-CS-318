# Check recorded CSV/browser test results and confirm protected files kept their original bytes.
"""Recheck protected evidence and record the CSV adapter delivery checks."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
C3 = ROOT / 'component3'


# Calculate a file hash for an integrity comparison.
def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


if __name__ == '__main__':
    baseline = json.loads((C3 / 'local/frontend_redesign_before/protected_hashes.json').read_text())
    changed = [name for name, expected in baseline.items()
               if not (ROOT / name).is_file() or digest(ROOT / name) != expected]
    log = (C3 / 'local/csv_full_tests.txt').read_text(encoding='utf-8-sig')
    import re
    test_counts = re.findall(r'Ran (\d+) tests?', log)
    browser = {name: json.loads((C3 / f'reports/{name}_frontend_check.json').read_text())
               for name in ('csv', 'pcap')}
    passed = not changed and test_counts == ['38', '18'] and log.count('\nOK') == 2
    passed = passed and all(result['status'] == 'PASSED' for result in browser.values())
    files = ['csv_inference.py', 'observation_inference.py', 'traffic_ui.py',
             'capture_replay.py', 'frontend.py', 'tests/test_csv_inference.py']
    report = {
        'status': 'PASSED' if passed else 'FAILED',
        'protected_manifest': 'component3/local/frontend_redesign_before/protected_hashes.json',
        'protected_manifest_sha256': digest(C3 / 'local/frontend_redesign_before/protected_hashes.json'),
        'protected_files_checked': len(baseline), 'changed_protected_files': changed,
        'test_groups': test_counts, 'tests_passed': sum(map(int, test_counts)),
        'test_command': '.\\.venv\\Scripts\\python.exe -B c3.py test',
        'browser_checks': browser,
        'equivalence_recording': 'MX025 (validation)',
        'equivalence_messages': 2272,
        'equivalence_contract': 'Exact feature rows and B/D class predictions; confidence tolerance 1e-12 for parallel RF floating-point summation.',
        'schema': 'c3-modbus-observations-v1',
        'inference_refits': False, 'labels_in_predictors': False,
        'official_final_evaluation_rerun': False,
        'source_sha256': {name: digest(C3 / name) for name in files},
    }
    (C3 / 'reports/csv_inference_tests.txt').write_text(log, encoding='utf-8')
    (C3 / 'reports/csv_inference_validation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if passed else 1)
