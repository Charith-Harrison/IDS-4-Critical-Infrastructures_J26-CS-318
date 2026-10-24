"""Post-capture reporting adapter; preserve the exact collection source bundle.

Windows PowerShell 5 serialized Docker's one-item array as {value:[...],Count:1}.
Unwrap that metadata in memory; never rewrite host records or raw evidence.
The capture validator and collection source hashes remain unchanged.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import summarize_qualification as frozen_report
from c3qual.config import sha

original_read = frozen_report.read_json


def read_host_metadata(path):
    data = original_read(path)
    if Path(path).name == 'host_execution.json':
        for key in ('image', 'base_image'):
            value = data.get(key)
            if isinstance(value, dict) and 'value' in value:
                data[key] = value['value']
    return data


if __name__ == '__main__':
    frozen_report.read_json = read_host_metadata
    code = frozen_report.main()
    output = ROOT / 'evidence/qualification_summary.json'
    summary = json.loads(output.read_text(encoding='utf8'))
    summary['reporting_adapter'] = dict(path='evidence/build_report.py', sha256=sha(Path(__file__)),
                                       purpose='Read-only unwrapping of Windows PowerShell image metadata')
    output.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf8')
    files = [ROOT / 'QUALIFICATION_REPORT.md', output, ROOT / 'evidence/evidence_examples.json',
             ROOT / 'evidence/coverage_counts.csv', Path(__file__)]
    (ROOT / 'evidence/report_artifact_hashes.json').write_text(json.dumps(
        {p.relative_to(ROOT).as_posix(): sha(p) for p in files}, indent=2) + '\n', encoding='utf8')
    raise SystemExit(code)
