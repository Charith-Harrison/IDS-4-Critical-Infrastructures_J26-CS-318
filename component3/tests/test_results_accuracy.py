"""Check derived accuracy against saved matrices and predictions; never load models."""
import copy
from pathlib import Path
import sys
import unittest

import pandas as pd

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from demo_results import CONDITIONS,comparison_rows,comparison_export,load_results

METHODS=('A','B','C','D','B-wire','D-wire')


class ResultsAccuracyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results=load_results()

    def test_all_method_condition_accuracies_and_coverage_match_saved_reports(self):
        for condition,role in CONDITIONS.items():
            report=self.results['conditions'][role]
            for method,row in zip(METHODS,comparison_rows(report,METHODS,evaluation='Final test · '+condition)):
                saved=report['methods'][method]; detail=saved['common_cohort']
                matrix=detail['confusion']; total=sum(map(sum,matrix))
                correct=sum(matrix[i][i] for i in range(len(matrix)))
                self.assertEqual(total,detail['support'])
                self.assertEqual(row['Accuracy (%)'],100*correct/total)
                self.assertEqual(row['Macro F1'],detail['macro_f1'])
                self.assertEqual(row['Evaluated decisions'],report['common_supported'])
                self.assertEqual(row['Prediction coverage (% eligible)'],100*saved['scored']/report['task_eligible'])
                self.assertEqual(row['Abstentions'],saved['abstained'])
                self.assertEqual(row['Predictions produced']+row['Abstentions'],report['task_eligible'])
                self.assertEqual(row['Evaluation'],'Final test · '+condition)

    def test_saved_prediction_files_independently_confirm_all_confusion_matrices(self):
        for role,report in self.results['conditions'].items():
            frame=pd.read_parquet(HERE/'locked/v1_20261025/artifacts/final'/f'{role}_predictions.parquet')
            mask=frame.eligible.astype(bool)&frame.context_available.astype(bool)
            self.assertEqual(int(mask.sum()),report['common_supported'])
            for method in METHODS:
                detail=report['methods'][method]['common_cohort']
                truth,pred=frame.loc[mask,'label'],frame.loc[mask,method]
                matrix=[[int(((truth==actual)&(pred==guess)).sum()) for guess in detail['labels']]
                        for actual in detail['labels']]
                self.assertEqual(matrix,detail['confusion'])
                expected=100*int((truth==pred).sum())/len(truth)
                self.assertEqual(comparison_rows(report,(method,))[0]['Accuracy (%)'],expected)
                self.assertEqual(int(frame[method].isin(detail['labels']).sum()),report['methods'][method]['scored'])
                self.assertEqual(int(frame[method].eq('abstain').sum()),report['methods'][method]['abstained'])

    def test_unrepresented_common_decisions_do_not_disappear_from_accuracy(self):
        report=copy.deepcopy(self.results['conditions']['final_test_order'])
        detail=report['methods']['D']['common_cohort']
        detail['confusion']=[[1,0,0],[0,0,0],[0,0,0]]; detail['support']=4
        row=comparison_rows(report,('D',))[0]
        self.assertEqual(row['Accuracy (%)'],25)
        self.assertEqual(row['Common cohort unscored'],3)
        detail['confusion']=None; detail['support']=0
        self.assertIsNone(comparison_rows(report,('D',))[0]['Accuracy (%)'])
        detail['confusion']=[[2,0,0],[0,0,0],[0,0,0]]; detail['support']=1
        with self.assertRaisesRegex(ValueError,'exceeds'):comparison_rows(report,('D',))

    def test_export_keeps_method_condition_and_cohort_identity(self):
        rows=comparison_export(self.results['conditions'])
        self.assertEqual(len(rows),30)
        self.assertEqual({r['Method'] for r in rows},set(METHODS))
        self.assertTrue(all(r['Evaluation'].startswith('Final test · ') for r in rows))
        order=next(r for r in rows if r['Method']=='D' and r['Evaluation']=='Final test · Changed ordering')
        self.assertAlmostEqual(order['Accuracy (%)'],100*1399/1400)
        self.assertEqual(order['Accuracy cohort'],'Common supported cohort')

    def test_frontend_displays_two_decimal_accuracy_and_selected_condition(self):
        from streamlit.testing.v1 import AppTest
        page=AppTest.from_file(str(HERE/'frontend.py'),default_timeout=60).run()
        self.assertFalse(page.exception)
        next(s for s in page.selectbox if s.label=='Test condition').set_value('Changed ordering').run()
        self.assertFalse(page.exception)
        tables=[d.value for d in page.dataframe if 'Accuracy (%)' in d.value]
        all_rows=pd.concat(tables,ignore_index=True)
        self.assertEqual(len(all_rows),6)
        row=all_rows.loc[all_rows.Model.eq('Context-aware RF')].iloc[0]
        self.assertEqual(row['Accuracy (%)'],'99.93%')
        self.assertEqual(row['Macro F1'],'0.9987')
        self.assertEqual(row['Evaluated decisions'],1400)
        self.assertEqual(row['Abstentions'],720)
        self.assertEqual(row['Prediction coverage (% eligible)'],'66.04%')
        self.assertTrue(all_rows['Accuracy (%)'].str.fullmatch(r'\d+\.\d{2}%').all())
        captions=' '.join(c.value for c in page.caption)
        self.assertIn('Final test · Changed ordering',captions)
        self.assertIn('scored-only',captions)


if __name__=='__main__':unittest.main()
