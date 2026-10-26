"""List existing result files; distinguish classification reports from capture validation."""
from collections import Counter
import json
import os
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
OUTPUT=ROOT/'component3/reports/results_accuracy_v1'


def inventory():
    found=[]
    for folder,dirs,names in os.walk(ROOT):
        dirs[:]=[d for d in dirs if d not in {'.git','.venv','.venv-c3','venv','env','node_modules',
                                            '__pycache__','typecheck_tools'}]
        for name in names:
            path=Path(folder)/name
            named=name in {'validation_report.json','final_summary.json','selection.json','validation_predictions.parquet'}
            final=name.startswith('final_test_') and name.endswith(('_report.json','_predictions.parquet'))
            older=path.parent==ROOT/'results/metrics'
            supplemental=path==ROOT/'component3/reports/model_metrics_saved_20261026.csv'
            if not (named or final or older or supplemental):continue
            category='saved_experiment_artifact'
            if older:category='older_application_report'
            elif supplemental:category='derived_reporting_export'
            elif name=='validation_report.json':
                data=json.loads(path.read_text(encoding='utf-8-sig'))
                category='classification_validation_metrics' if 'methods' in data else 'capture_or_other_validation'
            found.append({'path':path.relative_to(ROOT).as_posix(),'bytes':path.stat().st_size,'category':category})
    return sorted(found,key=lambda r:r['path'])


if __name__=='__main__':
    OUTPUT.mkdir(parents=True,exist_ok=True)
    rows=inventory()
    (OUTPUT/'file_inventory.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
    lines=['# Existing metric and prediction file inventory','',
           'Paths below exist on this laptop. Capture validation reports are not ML evaluation reports.',
           'The older application reports are separate from the locked three-class testbed experiment.','']
    categories=('classification_validation_metrics','saved_experiment_artifact','derived_reporting_export',
                'older_application_report','capture_or_other_validation')
    for category in categories:
        lines.extend(['## '+category,''])
        lines.extend('- `'+r['path']+'`' for r in rows if r['category']==category)
        lines.append('')
    (OUTPUT/'FILE_LOCATIONS.md').write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps(dict(Counter(r['category'] for r in rows)),indent=2))
    for row in rows:
        if row['category']!='capture_or_other_validation':print(row['path'])
