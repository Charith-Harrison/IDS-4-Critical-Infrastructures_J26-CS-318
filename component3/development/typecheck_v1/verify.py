"""Read-only equivalence checks for a typing proposal; never train or open final payloads."""
import ast
from collections import Counter
import csv
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ORIGINAL = ROOT / 'component3/locked/v1_20261025'
LOCAL = ROOT / 'component3/local/typecheck_v1'
REPORTS = HERE / 'verification'
SOURCE = ROOT / 'component3/data/collection'


def sha(path):
    with path.open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def package(name, folder):
    spec = importlib.util.spec_from_file_location(name, folder / '__init__.py', submodule_search_locations=[str(folder)])
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return __import__(name + '.experiment', fromlist=['experiment'])


def existing_tests(folder, name):
    # Run the same 17 existing non-training checks against each package copy.
    # The omitted 18th test explicitly trains toy models; no fitting is allowed here.
    environment = dict(os.environ, PYTHONPATH=str(folder), PYTHONDONTWRITEBYTECODE='1')
    tests = ['test_records',
             'test_experiment.ExperimentTests.test_explicit_allowlist_never_admits_private_columns',
             'test_experiment.ExperimentTests.test_fpr_reports_unscored_traffic_separately']
    command = [sys.executable, '-B', '-m', 'unittest', '-v', *tests]
    completed = subprocess.run(command, cwd=ORIGINAL / 'tests', env=environment,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    (REPORTS / f'{name}_existing_tests.txt').write_text(completed.stdout, encoding='utf-8')
    assert completed.returncode == 0, completed.stdout
    assert 'Ran 17 tests' in completed.stdout
    return {'command': command, 'tests_passed': 17, 'training_test_omitted': True}


def main():
    REPORTS.mkdir(exist_ok=True)
    lock = read(ORIGINAL / 'artifacts/experiment_lock.json')
    baseline = read(LOCAL / 'protected_before.json')
    file_checks = {}
    patches = []
    for name in ('experiment.py', 'records.py'):
        original, proposed = ORIGINAL / 'c3model' / name, HERE / 'c3model' / name
        # compile() checks syntax without writing bytecode to the frozen directory.
        for path in (original, proposed):
            compile(path.read_bytes(), str(path), 'exec')
            ast.parse(path.read_bytes(), type_comments=True)
        file_checks[name] = {'task_start_sha256': baseline[str(original.relative_to(ROOT))],
                            'current_original_sha256': sha(original),
                            'experiment_lock_sha256': lock['code_sha256'][name],
                            'proposal_sha256': sha(proposed)}
        file_checks[name]['preexisting_lock_mismatch'] = sha(original) != lock['code_sha256'][name]
        patches.extend(difflib.unified_diff(original.read_text().splitlines(True), proposed.read_text().splitlines(True),
                                           fromfile=f'before/c3model/{name}', tofile=f'after/c3model/{name}'))
    (HERE / 'typecheck.patch').write_text(''.join(patches), encoding='utf-8')
    old = package('c3_typing_original', ORIGINAL / 'c3model')
    new = package('c3_typing_proposed', HERE / 'c3model')
    assert (old.CURRENT, old.CONTEXT, old.WIRE) == (new.CURRENT, new.CONTEXT, new.WIRE)
    assert [len(new.CURRENT), len(new.CONTEXT), len(new.WIRE)] == [9, 5, 5]
    assert old.METHODS == new.METHODS and old.CLASSES == new.CLASSES
    assert old.CANDIDATES == new.CANDIDATES and old.FIXED == new.FIXED
    assert old.FINAL_ROLES == new.FINAL_ROLES
    for truth, predicted in [([], []), (['normal'], ['normal']),
                             (old.CLASSES * 3, ['normal'] * 9), (old.CLASSES, old.CLASSES)]:
        assert old.metrics(truth, predicted) == new.metrics(truth, predicted)
    # Hash-check each model before a read-only load. Do not change the production
    # loader or bypass its code-identity checks in the actual frontend/runtime.
    models = {}
    for name in old.METHODS:
        path = ORIGINAL / 'artifacts/models' / f'{name}.joblib'
        assert sha(path) == lock['artifact_sha256'][f'models/{name}.joblib']
        models[name] = joblib.load(path)
        assert list(models[name].feature_names_in_) == new.METHODS[name]
    membership_path = ORIGINAL / 'artifacts/actual_memberships.csv'
    assert sha(membership_path) == lock['artifact_sha256']['actual_memberships.csv']
    with membership_path.open(encoding='utf-8-sig', newline='') as handle:
        members = [row for row in csv.DictReader(handle) if row['evaluation_role'] in ('train', 'validation')]
    index = read(SOURCE / 'collection_complete.json')
    assert sha(SOURCE / 'collection_complete.json') == lock['collection']['canonical_index_sha256']
    protocol = read(SOURCE / '_handover/source/collector/frozen/protocol.json')
    maps = protocol['public_configuration']['maps']
    checks = []
    maximum_probability_difference = 0.0
    with (patch.object(Pipeline, 'fit', side_effect=AssertionError('No fitting allowed')),
          patch.object(Pipeline, 'fit_transform', side_effect=AssertionError('No fitting allowed')),
          patch.object(SimpleImputer, 'fit', side_effect=AssertionError('No fitting allowed')),
          patch.object(SimpleImputer, 'fit_transform', side_effect=AssertionError('No fitting allowed')),
          patch.object(RandomForestClassifier, 'fit', side_effect=AssertionError('No fitting allowed'))):
        for member in members:
            entry = index['completed'][member['planned_run_id']]
            assert entry['attempt'] == member['run_id']
            folder = SOURCE / entry['attempt']
            receipt = read(folder / 'completion.json')
            assert sha(folder / 'completion.json') == entry['completion_sha256']
            for name in ('application_ledger.jsonl', 'verified_labels.jsonl'):
                assert sha(folder / name) == receipt['artifact_sha256'][name]
            before = old.build_run(folder, member, maps)
            after = new.build_run(folder, member, maps)
            pd.testing.assert_frame_equal(before, after, check_exact=True)
            for name, columns in old.METHODS.items():
                pd.testing.assert_frame_equal(old.feature_frame(before, columns), new.feature_frame(after, columns), check_exact=True)
                mask = old.common(before) if name.startswith('D') else before.eligible
                if mask.any():
                    left = models[name].predict_proba(old.feature_frame(before.loc[mask], columns))
                    right = models[name].predict_proba(new.feature_frame(after.loc[mask], columns))
                    np.testing.assert_allclose(left, right, atol=1e-12, rtol=0)
                    maximum_probability_difference = max(maximum_probability_difference, float(np.max(np.abs(left-right))))
            left_report, left_predictions = old.evaluate_frame(before, models)
            right_report, right_predictions = new.evaluate_frame(after, models)
            pd.testing.assert_frame_equal(left_predictions, right_predictions, check_exact=True)
            assert left_report == right_report
            checks.append({'run':member['planned_run_id'], 'role':member['evaluation_role'], 'messages':len(before),
                           'abstentions':left_report['context_abstentions'], 'out_of_scope':left_report['out_of_scope']})
            print(f"MATCH {member['planned_run_id']}: {len(before)} messages", flush=True)
    tests = {name: existing_tests(folder, name) for name, folder in [('original', ORIGINAL), ('proposal', HERE)]}
    protected_changes = [name for name, expected in baseline.items() if sha(ROOT / name) != expected]
    assert not protected_changes, protected_changes
    baseline_types = read(LOCAL / 'baseline_diagnostics.json')
    proposal_types = read(LOCAL / 'proposal_diagnostics.json')
    assert baseline_types['summary']['filesAnalyzed'] == proposal_types['summary']['filesAnalyzed'] == 2
    assert proposal_types['summary']['errorCount'] == 0
    for name in ('baseline', 'proposal'):
        (REPORTS / f'{name}_pyright.json').write_text(json.dumps(read(LOCAL / f'{name}_diagnostics.json'), indent=2), encoding='utf-8')
    report = {'status':'PASSED', 'syntax':'PASSED', 'files':file_checks,
              'pyright_version':proposal_types['version'], 'type_checking_mode':'basic',
              'stub_source':'Installed Pylance 2026.4.1 bundled stubs',
              'baseline_type_errors':baseline_types['summary']['errorCount'],
              'proposal_type_errors':proposal_types['summary']['errorCount'],
              'feature_counts':{'CURRENT':9,'CONTEXT':5,'WIRE':5},
              'feature_names_and_order_unchanged':True, 'candidates_fixed_parameters_and_classes_unchanged':True,
              'runs_checked':len(checks), 'messages_checked':sum(r['messages'] for r in checks),
              'roles_checked':dict(Counter(r['role'] for r in checks)), 'runs':checks,
              'all_decoded_features_predictions_abstentions_and_metrics_equal':True,
              'maximum_probability_difference':maximum_probability_difference,
              'probability_absolute_tolerance':1e-12, 'existing_tests':tests,
              'protected_files_unchanged_since_task_start':len(baseline), 'protected_changes':protected_changes,
              'fitting_executed':False,'final_payloads_parsed':False,'final_evaluation_rerun':False,
              'production_integration':False,
              'limitations':['The frozen source files already differed from their lock hashes at task start.',
                             'This is a development proposal, not a change to the frozen experiment.',
                             'The existing toy-training test is omitted to avoid all fitting.',
                             'VS Code diagnostics on the original files remain until a separately approved workflow uses the development copy.']}
    (REPORTS / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({k:v for k,v in report.items() if k not in ('runs','files','existing_tests')}, indent=2))


if __name__ == '__main__':
    main()
