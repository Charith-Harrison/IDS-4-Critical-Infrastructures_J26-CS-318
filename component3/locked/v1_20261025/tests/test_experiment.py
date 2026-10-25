import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import joblib
import numpy as np
import pandas as pd

from c3model.experiment import CURRENT, WIRE, CONTEXT, METHODS, CLASSES, feature_frame, train, evaluate_frame, sha, save, code_hashes, admission_report


class ExperimentTests(unittest.TestCase):
    def fixture(self):
        rows = []
        for role in ['train', 'validation']:
            for j in range(12):
                label = CLASSES[j % 3]
                row = {name: 7.0 if role == 'train' else 1e9 for name in set(CURRENT + WIRE + CONTEXT)}
                row.update(event_id=f'{role}-{j}', run_id=f'{role}-run', related_group=f'{role}-group',
                           evaluation_role=role, recording_mode='mixed', label=label,
                           task='command' if label == 'command_injection' else 'response',
                           eligible=True, context_available=True, rule_prediction=label, protocol_prediction='normal')
                rows.append(row)
        return pd.DataFrame(rows)

    def test_explicit_allowlist_never_admits_private_columns(self):
        data = self.fixture()
        data['scenario'] = data['label']
        data['seed'] = 42
        x = feature_frame(data, CURRENT)
        self.assertEqual(list(x), CURRENT)
        self.assertNotIn('scenario', x)
        self.assertNotIn('label', x)
        with self.assertRaises(KeyError): feature_frame(data.drop(columns=CURRENT[0]), CURRENT)

    def test_train_only_imputer_and_serialized_reload(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); (root/'development').mkdir()
            data = self.fixture()
            data.to_parquet(root/'development/all_adus.parquet',index=False)
            (root/'collection_complete.json').write_text('{}')
            (root/'actual_memberships.csv').write_text('synthetic memberships')
            info={'root':str(root),'collection_id':'SYNTHETIC-collection', 'runs':[]}
            save(root/'development/prepare_report.json',{
                'code_sha256':code_hashes(), 'development_file_sha256':sha(root/'development/all_adus.parquet'),
                'memberships_sha256':sha(root/'actual_memberships.csv'),'source_admission':admission_report(info)})
            with patch('c3model.experiment.verify_collection',return_value=info):train(root,root)
            model=joblib.load(root/'models/B.joblib')
            # Validation's one-billion sentinel must never affect the fitted training median.
            self.assertTrue(np.all(model.named_steps['imputer'].statistics_ == 7))
            selected=json.loads((root/'selection.json').read_text())
            self.assertEqual(selected['fit_rows'],12)
            self.assertEqual(selected['validation_common_rows'],12)
            self.assertEqual(set(selected['methods']),set(METHODS))
            with self.assertRaises(ValueError): train(root,root)

    def test_fpr_reports_unscored_traffic_separately(self):
        data=self.fixture().iloc[:3].copy().reset_index(drop=True)
        data.loc[0,['label','eligible','context_available']]=['normal',False,False]
        data.loc[0,'rule_prediction']='out_of_scope'
        class PredictNormal:
            def predict(self,x):return np.full(len(x),'normal')
        report,pred=evaluate_frame(data,{name:PredictNormal() for name in METHODS})
        self.assertEqual(report['out_of_scope'],1)
        self.assertEqual(pred.loc[0,'B'],'out_of_scope')
        self.assertEqual(report['methods']['B']['false_alarms']['mixed']['on_scored_normal']['denominator'],0)
        self.assertEqual(report['methods']['B']['false_alarms']['mixed']['per_all_normal_traffic']['denominator'],1)


if __name__=='__main__':unittest.main()
