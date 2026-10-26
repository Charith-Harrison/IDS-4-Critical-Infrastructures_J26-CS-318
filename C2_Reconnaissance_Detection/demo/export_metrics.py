"""Display metrics from ALREADY SAVED held-out scores. Never fits or re-scores a model.

The resulting small JSON ships with the dashboard source, independently of the
immutable model bundle. Counts are request-pooled; H1 scenario-balanced recall is
kept separately and clearly labelled.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DATA = REPO / 'component2_testbed/data/final_v1'
MODELS = ('A', 'B1', 'B2', 'B3', 'L')
COMPARISONS = {
    'revisiting': {'label': 'Revisiting normal work', 'strata': ['revisiting_normal'],
                   'description': 'Reconnaissance versus normal tasks that repeatedly revisit registers. This is the primary research comparison.'},
    'one_pass': {'label': 'Legitimate one-pass work', 'strata': ['one_pass_normal'],
                 'description': 'Reconnaissance versus backups, startup reads and other legitimate one-pass tasks. This exposes the main false-alarm limitation.'},
    'all_normal': {'label': 'All legitimate traffic',
                   'strata': ['revisiting_normal', 'one_pass_normal', 'legitimate_lead_in', 'background'],
                   'description': 'Includes normal work, one-pass tasks, lead-in activity and background HMI polling. Large amounts of background traffic can inflate accuracy.'},
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def divide(n, d):
    return float(n / d) if d else None


def calculate(y, scores, threshold):
    y = np.asarray(y, dtype=bool)
    scores = np.asarray(scores, dtype=float)
    alert = scores > threshold  # exactly the frozen evaluator's comparison, including ties
    tp, fp = int((y & alert).sum()), int((~y & alert).sum())
    tn, fn = int((~y & ~alert).sum()), int((y & ~alert).sum())
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'requests': len(y),
            'positive_requests': tp + fn, 'normal_requests': tn + fp,
            'precision': divide(tp, tp + fp), 'recall': divide(tp, tp + fn),
            'f1': divide(2 * tp, 2 * tp + fp + fn), 'accuracy': divide(tp + tn, len(y)),
            'fpr': divide(fp, fp + tn), 'specificity': divide(tn, tn + fp),
            'roc_auc': float(roc_auc_score(y, scores)) if len(np.unique(y)) == 2 else None,
            'threshold': float(threshold)}


def align(meta, scores):
    if not meta.adu_id.is_unique or not scores.adu_id.is_unique:
        raise ValueError('Duplicate request identities in frozen metadata or scores')
    if set(meta.adu_id) != set(scores.adu_id):
        raise ValueError('Frozen scores and metadata do not contain the same request identities')
    return meta.merge(scores, on='adu_id', how='left', validate='one_to_one')


def build():
    thresholds_path = DATA / 'models/thresholds.json'
    thresholds = json.loads(thresholds_path.read_text())
    bundle_thresholds = json.loads((HERE.parent / 'demo_bundle/models/thresholds.json').read_text())
    if thresholds != bundle_thresholds:
        raise ValueError('Demo and final frozen thresholds differ')
    result = {'schema_version': 1, 'collection': 'final_v1', 'positive_class': 'Reconnaissance request',
              'method': 'Aggregated from existing frozen held-out predictions, joined to labels by unique ADU identity. No model fit or new test scoring.',
              'averaging': 'Request-pooled metrics; scenario-balanced recall and run-bootstrap confidence intervals remain separate.',
              'threshold_rule': 'score > frozen threshold; thresholds selected on validation revisiting-normal requests only',
              'undefined_metrics': 'null when the denominator or class population is undefined',
              'comparisons': COMPARISONS, 'source_files': [], 'populations': {}}
    for part, title in [('test_in_site', 'In-site test · A + B'), ('test_out_of_site', 'Unseen-site test · C')]:
        meta_path = DATA / f'model_inputs/{part}/meta.parquet'
        score_path = DATA / f'models/{part}_scores.parquet'
        report_path = DATA / f'models/{part}_report.json'
        meta, scores = pd.read_parquet(meta_path), pd.read_parquet(score_path)
        df = align(meta, scores)
        report = json.loads(report_path.read_text())
        if thresholds != report['thresholds_frozen']:
            raise ValueError('Report and stored prediction thresholds differ')
        pop = {'label': title, 'runs': int(df.run_id.nunique()), 'requests': len(df), 'contexts': {}}
        for context, full in [('full', True), ('all', False)]:
            d = df[df.full_context] if full else df
            original = report['rates_full_context' if full else 'rates_all_targets']
            views = {}
            for key, spec in COMPARISONS.items():
                selected = d[d.stratum.isin(['recon', *spec['strata']])]
                models = {m: calculate(selected.gt_label_recon, selected[m], thresholds[m]) for m in MODELS}
                views[key] = {'requests': len(selected), 'runs': int(selected.run_id.nunique()),
                              'positive_requests': int(selected.gt_label_recon.sum()),
                              'normal_requests': int(selected.gt_label_recon.eq(0).sum()), 'models': models}
            by_stratum = {}
            for stratum in ['revisiting_normal', 'one_pass_normal', 'legitimate_lead_in', 'background']:
                normal = d[d.stratum.eq(stratum)]
                by_stratum[stratum] = {'requests': len(normal), 'runs': int(normal.run_id.nunique()), 'models': {}}
                for m in MODELS:
                    fp = int((normal[m] > thresholds[m]).sum())
                    rate = divide(fp, len(normal))
                    saved = original[m].get(stratum)
                    if saved and round(rate, 4) != saved['rate']:
                        raise ValueError(f'Saved report rate disagrees: {part}/{context}/{stratum}/{m}')
                    by_stratum[stratum]['models'][m] = {'fp': fp, 'rate': rate, 'ci95': saved.get('ci95') if saved else None}
            for m in MODELS:
                for key, neg in [('revisiting', 'revisiting_normal'), ('one_pass', 'one_pass_normal')]:
                    calc = views[key]['models'][m]
                    if round(calc['recall'], 4) != original[m]['recon']['rate']:
                        raise ValueError('Saved request recall differs')
                    if round(calc['roc_auc'], 4) != original[m][f'auc_recon_vs_{neg}']:
                        raise ValueError('Saved ROC-AUC differs')
            pop['contexts'][context] = {'label': 'Full 20-request histories' if full else 'All requests, including short histories',
                                        'comparisons': views, 'false_alarms': by_stratum,
                                        'scenario_balanced_recall': report['H1_primary_full_context' if full else 'H1_secondary_all_targets']['scenario_balanced_recall']}
        result['populations'][part] = pop
        for path in [meta_path, score_path, report_path]:
            result['source_files'].append({'path': str(path.relative_to(REPO)).replace('\\', '/'), 'sha256': sha(path)})
    result['source_files'].append({'path': str(thresholds_path.relative_to(REPO)).replace('\\', '/'), 'sha256': sha(thresholds_path)})
    target = HERE / 'metrics_report.json'
    target.write_text(json.dumps(result, indent=2, allow_nan=False) + '\n', encoding='utf8')
    print(f'Exported display metrics: {target}')
    print('Reconciled every displayed stratum rate, pooled recall and ROC-AUC with frozen reports.')
    return result


if __name__ == '__main__':
    build()
