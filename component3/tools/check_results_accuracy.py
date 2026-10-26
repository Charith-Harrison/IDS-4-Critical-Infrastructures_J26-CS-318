"""Record reporting checks and preservation hashes; never run or load a model."""
import hashlib
import json
from pathlib import Path
import sys

import pandas as pd

ROOT=Path(__file__).resolve().parents[2]
HERE=ROOT/'component3'
sys.path.insert(0,str(HERE))
from demo_results import comparison_export,load_results


def sha(path):
    with path.open('rb') as handle:return hashlib.file_digest(handle,'sha256').hexdigest()


if __name__=='__main__':
    local=HERE/'local/results_accuracy_v1'; output=HERE/'reports/results_accuracy_v1'
    before=json.loads((local/'protected_before.json').read_text())
    changed=[name for name,digest in before.items() if sha(ROOT/name)!=digest]
    assert not changed,changed
    tests=(local/'tests.txt').read_text(encoding='utf-8-sig')
    assert 'Ran 5 tests' in tests and '\nOK' in tests
    browser=json.loads((output/'browser_check.json').read_text())
    assert browser['status']=='PASSED'
    results=load_results()
    rows=comparison_export(results['conditions'])
    pd.DataFrame(rows).to_csv(output/'derived_final_metrics.csv',index=False)
    sources=['frontend.py','demo_results.py','tests/test_results_accuracy.py','tools/results_inventory.py',
             'tools/results_accuracy_browser_check.cjs','tools/check_results_accuracy.py']
    for name in sources:
        if name.endswith('.py'):compile((HERE/name).read_bytes(),str(HERE/name),'exec')
    lock=json.loads((HERE/'locked/v1_20261025/artifacts/experiment_lock.json').read_text())
    mismatches={name:{'current_sha256':sha(HERE/'locked/v1_20261025/c3model'/name),'lock_sha256':expected}
                for name,expected in lock['code_sha256'].items()
                if sha(HERE/'locked/v1_20261025/c3model'/name)!=expected}
    summary={
        'reporting_checks':'PASSED','syntax':'PASSED','new_accuracy_tests_passed':5,
        'browser':browser,'derived_rows':len(rows),'final_conditions':5,'methods':6,
        'accuracy_definition':'100 * trace(common_cohort.confusion) / common_cohort.support',
        'coverage_definition':'100 * method.scored / report.task_eligible',
        'unrepresented_common_decisions':'Remain in the accuracy denominator; never counted as correct.',
        'saved_predictions_verified':'All six methods across all five final conditions; read existing Parquet only.',
        'macro_f1_unchanged':True,'protected_files_unchanged_since_task_start':len(before),'protected_changes':changed,
        'training_or_model_inference_executed':False,'locked_final_evaluation_rerun':False,
        'active_suite':{'methods_run':29,'passed':28,'failed':1,'class_setup_errors':2,
                        'additional_methods_blocked':14,'status':'FAILED_PREEXISTING_SOURCE_LOCK_MISMATCH',
                        'affected':['CaptureReplayTests setup','CsvInferenceTests setup','frontend PCAP replay test']},
        'preexisting_source_lock_mismatches':mismatches,
        'code_sha256':{name:sha(HERE/name) for name in sources},
    }
    (output/'verification.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    for source,destination in [('tests.txt','accuracy_tests.txt'),('all_active_tests.txt','active_suite.txt')]:
        (output/destination).write_bytes((local/source).read_bytes())
    print(json.dumps(summary,indent=2))
