"""Transparent train/validation selection, evidence locking and separate final evaluations."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import Pipeline

from .records import CURRENT, WIRE, CONTEXT, build_run, verify_collection

CLASSES = ['normal', 'command_injection', 'response_injection']
METHODS = {'B': CURRENT, 'D': CURRENT + CONTEXT,
           'B-wire': CURRENT + WIRE, 'D-wire': CURRENT + CONTEXT + WIRE}
#Hyperparameters 
CANDIDATES = [dict(max_depth=depth, min_samples_leaf=leaf, class_weight=weight)
              for weight in ['balanced', None] for depth, leaf in [(12, 2), (8, 5)]]
FIXED = dict(n_estimators=160, max_features='sqrt', random_state=42, n_jobs=2)
FINAL_ROLES = ['final_test_repeat', 'final_test_values', 'final_test_map', 'final_test_order', 'final_test_timing']


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''): h.update(chunk)
    return h.hexdigest()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + '\n', encoding='utf8')


def code_hashes():
    root = Path(__file__).resolve().parent
    return {p.name: sha(p) for p in sorted(root.glob('*.py'))}


def feature_frame(frame, columns):
    # The explicit list is the only model admission path. Never infer X by dropping y.
    result = frame.loc[:, columns].apply(pd.to_numeric, errors='raise').astype(float)
    if np.isinf(result.to_numpy()).any(): raise ValueError('Infinite predictor')
    return result


def load_roles(source, info, roles):
    rows = [r for r in info['runs'] if r['evaluation_role'] in roles]
    if not rows: raise ValueError('No accepted runs for requested roles')
    frames = []
    started = time.perf_counter()
    for i, member in enumerate(rows, 1):
        frame = build_run(Path(member['folder']), member, info['public_maps'])
        frames.append(frame)
        print(f"Decoded {i}/{len(rows)} {member['planned_run_id']} | {len(frame)} ADUs | {time.perf_counter()-started:.1f}s", flush=True)
    data = pd.concat(frames, ignore_index=True)
    if data.event_id.duplicated().any(): raise ValueError('Repeated event identity')
    return data


def common(frame):
    return frame.eligible.astype(bool) & frame.context_available.astype(bool)


def metrics(y, predictions):
    y, predictions = np.asarray(y, dtype=str), np.asarray(predictions, dtype=str)
    if len(y) == 0: return {'support': 0, 'macro_f1': None, 'confusion': None}
    p, r, f, n = precision_recall_fscore_support(y, predictions, labels=CLASSES, zero_division=0)
    return {'support': len(y), 'labels': CLASSES,
            'confusion': confusion_matrix(y, predictions, labels=CLASSES).tolist(),
            'macro_f1': float(np.mean(f)),
            'per_class': {label: {'support': int(n[i]), 'precision': float(p[i]) if np.sum(predictions == label) else None,
                                  'recall': float(r[i]) if n[i] else None, 'f1': float(f[i]) if n[i] else None}
                          for i, label in enumerate(CLASSES)}}


def _rate(numerator, denominator):
    return {'count': int(numerator), 'denominator': int(denominator),
            'rate': float(numerator / denominator) if denominator else None}


def evaluate_frame(frame, models):
    mask = common(frame)
    report = {'all_adus': len(frame), 'raw_label_counts': dict(Counter(frame.label)),
              'task_eligible': int(frame.eligible.sum()), 'common_supported': int(mask.sum()),
              'context_abstentions': int((frame.eligible & ~frame.context_available.astype(bool)).sum()),
              'out_of_scope': int((~frame.eligible.astype(bool)).sum()), 'methods': {}}
    predictions = pd.DataFrame({'event_id': frame.event_id, 'run_id': frame.run_id,
                                'label': frame.label, 'task': frame.task, 'eligible': frame.eligible,
                                'context_available': frame.context_available})
    for name in ['A', 'C'] + list(METHODS):
        current = np.full(len(frame), 'out_of_scope', dtype=object)
        if name == 'A': current[frame.eligible] = frame.loc[frame.eligible, 'protocol_prediction'].to_numpy()
        elif name == 'C': current = frame.rule_prediction.to_numpy(copy=True)
        else:
            coverage = mask if name.startswith('D') else frame.eligible.astype(bool)
            if coverage.any(): current[coverage] = models[name].predict(feature_frame(frame.loc[coverage], METHODS[name]))
            if name.startswith('D'): current[frame.eligible & ~coverage] = 'abstain'
        predictions[name] = current
        scored = np.isin(current, CLASSES)
        method = {'common_cohort': metrics(frame.loc[mask, 'label'], current[mask]),
                  'all_available_cohort': metrics(frame.loc[scored, 'label'], current[scored]),
                  'scored': int(scored.sum()), 'abstained': int(np.sum(current == 'abstain')),
                  'tasks': {}, 'false_alarms': {}}
        for task, attack in [('command', 'command_injection'), ('response', 'response_injection')]:
            sub = mask & (frame.task == task)
            detail = metrics(frame.loc[sub, 'label'], current[sub])
            # Binary task F1 avoids treating the deliberately absent other attack class as supported.
            y, pred = frame.loc[sub, 'label'].to_numpy(), current[sub]
            tp = np.sum((y == attack) & (pred == attack)); fp = np.sum((y != attack) & (pred == attack)); fn = np.sum((y == attack) & (pred != attack))
            detail['attack_f1'] = float(2 * tp / (2 * tp + fp + fn)) if 2 * tp + fp + fn else None
            method['tasks'][task] = detail
        for mode in ['normal_only', 'mixed']:
            actual = (frame.recording_mode == mode) & (frame.label == 'normal')
            scope = actual & scored
            false = actual & np.isin(current, ['command_injection', 'response_injection'])
            method['false_alarms'][mode] = {'on_scored_normal': _rate(false.sum(), scope.sum()),
                                             'per_all_normal_traffic': _rate(false.sum(), actual.sum()),
                                             'scored_normal_coverage': _rate(scope.sum(), actual.sum())}
        report['methods'][name] = method
    return report, predictions


def paired_uncertainty(frame, predictions):
    results = []
    mask = common(frame)
    for run, indices in frame.groupby('run_id', sort=False).groups.items():
        index = list(indices)
        sub = frame.loc[index]
        keep = mask.loc[index]
        if not keep.any(): continue
        record = {'run_id': run, 'support': int(keep.sum()),
                  'recording_mode': str(sub.recording_mode.iloc[0]),
                  'class_support': dict(Counter(sub.loc[keep, 'label'])), 'confusion': {}}
        for name in ['A', 'C'] + list(METHODS):
            value = metrics(sub.loc[keep, 'label'], predictions.loc[index].loc[keep, name])
            record[name] = value['macro_f1']
            record['confusion'][name] = value['confusion']
        results.append(record)
    rng = np.random.default_rng(42)
    def cm_f1(cm):
        den = cm.sum(axis=-1) + cm.sum(axis=-2)
        return np.mean(np.divide(2 * np.diagonal(cm, axis1=-2, axis2=-1), den,
                                 out=np.zeros_like(den, dtype=float), where=den != 0), axis=-1)
    if results:
        # Preserve mixed/normal-only run counts and paired methods; bootstrap whole runs,
        # then pool confusion counts before computing the primary three-class metric.
        groups = [[i for i, row in enumerate(results) if row['recording_mode'] == mode]
                  for mode in sorted({row['recording_mode'] for row in results})]
        samples = np.concatenate([rng.choice(g, size=(2000, len(g)), replace=True) for g in groups], axis=1)
        b = np.asarray([r['confusion']['B'] for r in results])
        d = np.asarray([r['confusion']['D'] for r in results])
        delta = cm_f1(d[samples].sum(axis=1)) - cm_f1(b[samples].sum(axis=1))
        interval = np.quantile(delta, [0.025, 0.975]).tolist()
        point = float(cm_f1(d.sum(axis=0)) - cm_f1(b.sum(axis=0)))
    else: interval, point = None, None
    return {'run_scores': results, 'pooled_D_minus_B_macro_f1': point,
            'paired_run_bootstrap_95_percent_interval': interval, 'replications': len(results),
            'limitation': 'Whole-run bootstrap stratified by mixed/normal-only, not industrial-campaign confidence. Per-run fixed-three-class macro scores and their actual class support are shown separately.'}


def admission_report(info):
    return {'collection_id': info['collection_id'], 'runs': len(info['runs']),
            'roles': dict(Counter(r['evaluation_role'] for r in info['runs'])),
            'canonical_index_sha256': sha(Path(info['root']) / 'collection_complete.json')}


def prepare(source, artifacts):
    artifacts = Path(artifacts)
    if (artifacts/'development/prepare_report.json').exists(): raise ValueError('Prepared outputs already exist; choose a fresh artifacts folder')
    info = verify_collection(Path(source))
    save(artifacts/'admission.json', admission_report(info))
    # Preserve explicit actual memberships without opening held-out payloads.
    pd.DataFrame([{k: str(v) if isinstance(v, Path) else v for k, v in r.items() if k != 'folder'}
                  for r in info['runs']]).to_csv(artifacts/'actual_memberships.csv', index=False)
    data = load_roles(source, info, ['train', 'validation'])
    target = artifacts/'development'; target.mkdir(exist_ok=True)
    # Full stream is preserved; cohort filtering happens only after causal reconstruction.
    data.to_parquet(target/'all_adus.parquet', index=False)
    data.to_csv(target/'all_adus.csv.gz', index=False, compression='gzip')
    columns = list(dict.fromkeys(CURRENT + WIRE + CONTEXT))
    # Deliberately separate X, y and identities to make leakage inspection straightforward.
    feature_frame(data, columns).to_parquet(target/'candidate_features.parquet', index=False)
    data[['event_id','label']].to_csv(target/'labels.csv', index=False)
    group_cols = [c for c in ['event_id','run_id','related_group','evaluation_role','recording_mode','task','eligible','context_available'] if c in data]
    data[group_cols].to_parquet(target/'routing_and_eligibility.parquet', index=False)
    summary = {'status': 'DEVELOPMENT_PREPARED_FINAL_ROWS_NOT_OPENED', 'adus': len(data),
               'label_counts': dict(Counter(data.label)), 'eligible': int(data.eligible.sum()),
               'common_supported': int(common(data).sum()), 'feature_columns': METHODS,
               'artifacts_bytes': sum(p.stat().st_size for p in target.iterdir() if p.is_file()),
               'source_admission': admission_report(info), 'code_sha256': code_hashes(),
               'development_file_sha256': sha(target/'all_adus.parquet'),
               'memberships_sha256': sha(artifacts/'actual_memberships.csv'),
               'definitions': {'current_features': 'Exact current bytes/public map only; absent response addresses remain missing',
                               'context': 'Wire-derived earlier mode/read, successful FC6 ACK and request identity, max6interveningADUs',
                               'preprocessing': 'Decode, preserve missingness, causal replay, explicit feature separation. RF imputer fitted later on train only.',
                               'excluded': 'No scaling needed for RF; no resampling, row shuffle, oracle predictors or absolute-time features'}}
    save(target/'prepare_report.json', summary)
    return summary


def train(source, artifacts):
    artifacts = Path(artifacts)
    if (artifacts/'selection.json').exists(): raise ValueError('Selection exists; do not silently overwrite an experiment')
    prepared = json.loads((artifacts/'development/prepare_report.json').read_text())
    if (prepared['code_sha256'] != code_hashes()
            or prepared['development_file_sha256'] != sha(artifacts/'development/all_adus.parquet')
            or prepared['memberships_sha256'] != sha(artifacts/'actual_memberships.csv')):
        raise ValueError('Prepared code/data/membership changed; create a fresh preparation')
    info = verify_collection(Path(source))
    if prepared['source_admission'] != admission_report(info): raise ValueError('Prepared source identity differs')
    data = pd.read_parquet(artifacts/'development/all_adus.parquet')
    fit = data.loc[(data.evaluation_role == 'train') & common(data)]
    validation = data.loc[(data.evaluation_role == 'validation') & common(data)]
    if set(fit.label) != set(CLASSES) or set(validation.label) != set(CLASSES): raise ValueError('Class-complete development cohort required')
    if set(fit.related_group) & set(validation.related_group): raise ValueError('Train/validation group leakage')
    models, selection = {}, {}
    for name, columns in METHODS.items():
        trials = []
        for params in CANDIDATES:
            model = Pipeline([('imputer', SimpleImputer(strategy='median', add_indicator=True, keep_empty_features=True)),
                              ('rf', RandomForestClassifier(**FIXED, **params))])
            model.fit(feature_frame(fit, columns), fit.label)
            score = metrics(validation.label, model.predict(feature_frame(validation, columns)))
            trials.append((score['macro_f1'], params, model, score))
            print(f'{name} {params} validation macroF1={score["macro_f1"]:.4f}', flush=True)
        # A fixed candidate order resolves ties; test data cannot influence this choice.
        best = max(range(len(trials)), key=lambda i: trials[i][0])
        _, params, model, score = trials[best]
        models[name] = model
        destination = artifacts/'models'/f'{name}.joblib'; destination.parent.mkdir(exist_ok=True)
        joblib.dump(model, destination)
        restored = joblib.load(destination)
        if not np.array_equal(model.predict(feature_frame(validation, columns)), restored.predict(feature_frame(validation, columns))):
            raise ValueError('Serialized model prediction mismatch')
        selection[name] = {'features': columns, 'parameters': {**FIXED, **params},
                           'candidate_validation_macro_f1': [t[0] for t in trials],
                           'validation': score, 'model_sha256': sha(destination)}
    validation_all = data.loc[data.evaluation_role == 'validation'].reset_index(drop=True)
    report, pred = evaluate_frame(validation_all, models)
    report['paired_run_uncertainty'] = paired_uncertainty(validation_all, pred)
    save(artifacts/'validation_report.json', report)
    pred.to_parquet(artifacts/'validation_predictions.parquet', index=False)
    save(artifacts/'selection.json', {'status': 'TRAIN_FITTED_VALIDATION_SELECTED_FINAL_UNOPENED',
                                     'fit_rows': len(fit), 'validation_common_rows': len(validation),
                                     'methods': selection, 'selection_metric': 'Common-cohort three-class macroF1',
                                     'development_file_sha256': sha(artifacts/'development/all_adus.parquet'),
                                     'prepare_report_sha256': sha(artifacts/'development/prepare_report.json'),
                                     'code_sha256': code_hashes(), 'source_admission': admission_report(info),
                                     'versions': {n: importlib.metadata.version(n) for n in ['numpy','pandas','scikit-learn','joblib','pyarrow']}})
    return {k: v['validation']['macro_f1'] for k, v in selection.items()}


def freeze(source, artifacts):
    artifacts = Path(artifacts)
    lock = artifacts/'experiment_lock.json'
    if lock.exists(): raise ValueError('Experiment already frozen')
    if not (artifacts/'selection.json').exists(): raise ValueError('Train/validation selection required')
    info = verify_collection(Path(source))
    selected = json.loads((artifacts/'selection.json').read_text())
    prepared = json.loads((artifacts/'development/prepare_report.json').read_text())
    if (selected['code_sha256'] != code_hashes() or selected['source_admission'] != admission_report(info)
            or selected['development_file_sha256'] != sha(artifacts/'development/all_adus.parquet')
            or selected['prepare_report_sha256'] != sha(artifacts/'development/prepare_report.json')):
        raise ValueError('Selected experiment provenance changed before freeze')
    if prepared['memberships_sha256'] != sha(artifacts/'actual_memberships.csv'):
        raise ValueError('Prepared memberships changed before freeze')
    if set(selected['methods']) != set(METHODS): raise ValueError('Selected method set differs')
    for name, details in selected['methods'].items():
        if details['features'] != METHODS[name] or sha(artifacts/'models'/f'{name}.joblib') != details['model_sha256']:
            raise ValueError('Selected feature list or model changed before freeze')
    hashes = {p.relative_to(artifacts).as_posix(): sha(p) for p in [artifacts/'selection.json', artifacts/'actual_memberships.csv',
              artifacts/'development/all_adus.parquet', artifacts/'development/prepare_report.json'] + list((artifacts/'models').glob('*.joblib'))}
    value = {'status': 'FROZEN_BEFORE_FINAL_PAYLOAD_ACCESS', 'frozen_at_utc': datetime.now(timezone.utc).isoformat(),
             'collection': admission_report(info), 'code_sha256': code_hashes(), 'artifact_sha256': hashes,
             'final_roles': FINAL_ROLES, 'methods': METHODS, 'classes': CLASSES,
             'metric': 'Primary common-supported task-conditioned three-class macroF1, with full coverage and false alarm denominators',
             'policy': 'No refit/feature changes after final scores. New experiments after final inspection are exploratory.',
             'limitations': ['One deterministic software testbed, two interventions, not industrial campaigns',
                             'Rules express the complete lab policy; no assumed ML superiority',
                             'Numeric/context/timing/map robustness limited to declared held-out conditions',
                             'Wall-clock retry failures and fixed execution-order drift limitations',
                             'Supervisor acceptance of testbed-primary methodology not recorded']}
    save(lock, value)
    return {'status': value['status'], 'lock_sha256': sha(lock)}


def final_evaluation(source, artifacts):
    artifacts = Path(artifacts)
    if (artifacts/'final_evaluation_started.json').exists(): raise ValueError('Final evaluation already started; preserve the first result, no silent rerun')
    lock = json.loads((artifacts/'experiment_lock.json').read_text())
    if lock['code_sha256'] != code_hashes(): raise ValueError('Code changed after freeze')
    for name, expected in lock['artifact_sha256'].items():
        if sha(artifacts/name) != expected: raise ValueError('Frozen artifact changed: '+name)
    info = verify_collection(Path(source))
    if admission_report(info) != lock['collection']: raise ValueError('Collection changed after freeze')
    save(artifacts/'final_evaluation_started.json', {'started_at_utc': datetime.now(timezone.utc).isoformat(),
                                                 'experiment_lock_sha256': sha(artifacts/'experiment_lock.json')})
    models = {name: joblib.load(artifacts/'models'/f'{name}.joblib') for name in METHODS}
    results = {}
    for role in FINAL_ROLES:
        frame = load_roles(source, info, [role])
        report, pred = evaluate_frame(frame, models)
        report['paired_run_uncertainty'] = paired_uncertainty(frame, pred)
        save(artifacts/'final'/f'{role}_report.json', report)
        pred.to_parquet(artifacts/'final'/f'{role}_predictions.parquet', index=False)
        results[role] = {'common_supported': report['common_supported'],
                         'macro_f1': {name: detail['common_cohort']['macro_f1'] for name, detail in report['methods'].items()}}
    save(artifacts/'final_summary.json', {'status': 'LOCKED_FINAL_EVALUATION_COMPLETE',
                                        'lock_sha256': sha(artifacts/'experiment_lock.json'), 'roles': results,
                                        'limitations': lock['limitations']})
    return results
