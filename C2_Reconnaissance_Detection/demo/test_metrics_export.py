"""Meaningful edge cases for display aggregation; does not fit/re-score models."""
import unittest
import pandas as pd
from export_metrics import align, calculate


class MetricsTests(unittest.TestCase):
    def test_exact_threshold_is_not_an_alert(self):
        m = calculate([1, 1, 0, 0], [.9, .5, .7, .2], .5)
        self.assertEqual([m[k] for k in ['tp', 'fp', 'tn', 'fn']], [1, 1, 1, 1])
        self.assertEqual(m['precision'], .5)
        self.assertEqual(m['recall'], .5)
        self.assertEqual(m['f1'], .5)
        self.assertEqual(m['fpr'], .5)

    def test_undefined_precision_is_not_invented(self):
        m = calculate([1, 0], [.1, .1], .5)
        self.assertIsNone(m['precision'])
        self.assertEqual(m['recall'], 0)
        self.assertEqual(m['f1'], 0)

    def test_auc_requires_both_classes(self):
        m = calculate([0, 0], [.1, .8], .5)
        self.assertIsNone(m['roc_auc'])
        self.assertIsNone(m['recall'])

    def test_scores_are_joined_by_identity_not_row_position(self):
        meta = pd.DataFrame({'adu_id': ['first', 'second'], 'gt_label_recon': [1, 0]})
        scores = pd.DataFrame({'adu_id': ['second', 'first'], 'A': [.1, .9]})
        merged = align(meta, scores)
        self.assertEqual(merged.A.tolist(), [.9, .1])

    def test_duplicate_or_missing_identity_is_rejected(self):
        meta = pd.DataFrame({'adu_id': ['first', 'second']})
        for ids in [['first', 'first'], ['first', 'third']]:
            with self.assertRaises(ValueError):
                align(meta, pd.DataFrame({'adu_id': ids}))


if __name__ == '__main__':
    unittest.main()
