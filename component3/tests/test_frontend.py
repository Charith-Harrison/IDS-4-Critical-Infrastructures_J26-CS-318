"""Optional local frontend integration test; development examples only."""
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

HERE=Path(__file__).resolve().parents[1]
READY=(importlib.util.find_spec('streamlit') is not None and
       (HERE/'data/collection/collection_complete.json').is_file() and
       (HERE/'locked/v1_20261025/artifacts/models/D.joblib').is_file())

@unittest.skipUnless(READY,'Frontend needs optional Streamlit and local evidence/models')
class FrontendTests(unittest.TestCase):
    def test_demonstrations_and_saved_results_are_read_only(self):
        from streamlit.testing.v1 import AppTest
        artifacts=HERE/'locked/v1_20261025/artifacts'
        protected=[artifacts/n for n in ('experiment_lock.json','final_evaluation_started.json','final_summary.json')]
        before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in protected}
        page=AppTest.from_file(str(HERE/'frontend.py'),default_timeout=60).run()
        self.assertFalse(page.exception)
        self.assertEqual(page.radio[0].value,'Command injection')
        self.assertEqual([tab.label for tab in page.tabs],['Demo','How it works','Results','Evidence','Dataset & scope'])
        self.assertEqual(page.radio[0].options,['Command injection','Response injection'])
        self.assertFalse(page.toggle[0].value)
        self.assertTrue(any('Can the current message alone' in item.value for item in page.markdown))
        page.toggle[0].set_value(True).run(); self.assertFalse(page.exception)
        def examples():
            return [item.value for item in page.dataframe if list(item.value.columns)==['Model','Prediction','Confidence']]
        command=examples()
        self.assertEqual(command[1].Prediction.tolist(),['Normal','Command injection'])
        self.assertEqual(command[1].Confidence.tolist(),['Not saved','Not saved'])
        page.radio[0].set_value('Response injection').run(); self.assertFalse(page.exception)
        self.assertEqual(examples()[1].Prediction.tolist(),['Normal','Response injection'])
        next(c for c in page.selectbox if c.label=='Test condition').set_value('Changed ordering').run(); self.assertFalse(page.exception)
        tables=[item.value for item in page.dataframe if 'Macro F1' in item.value]
        model=tables[0].set_index('Model')
        self.assertEqual(model.loc['Context-aware RF','Macro F1'],'0.9987')
        self.assertEqual(model.loc['Context-aware RF','Response recall'],'99.31%')
        # Old examples remain selectable with exactly their original byte lineage.
        next(c for c in page.selectbox if c.label=='Example').set_value(4).run(); self.assertFalse(page.exception)
        self.assertTrue(any('MX084-20261025T063001Z-dfeac789:e2388' in item.value for item in page.code))
        next(c for c in page.selectbox if c.label=='Example').set_value(8).run(); self.assertFalse(page.exception)
        visible=' '.join(str(item.value) for collection in (page.markdown,page.caption,page.info,page.warning) for item in collection)
        for phrase in ('supervisor acceptance','what to say in the viva','PP1 talking points','suggested presentation'):
            self.assertNotIn(phrase,visible.lower())
        next(c for c in page.button if c.label=='Recheck evidence and reload').click().run(); self.assertFalse(page.exception)
        self.assertEqual(before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in protected})

    def test_saved_outputs_and_public_features_are_separate(self):
        import pandas as pd
        from demo_data import load_demo,read,LOCKED
        from runtime import Detector,CURRENT,CONTEXT
        seen=[]
        original=Detector.observe
        def observe(detector,row):
            seen.append(set(row)); return original(detector,row)
        with (patch('demo_data.predict_batch',side_effect=AssertionError('Fresh predictions forbidden')),
             patch('demo_data.load_locked_models',side_effect=AssertionError('Model loading not needed')),
             patch.object(Detector,'observe',observe)):
            demo=load_demo(saved_predictions_only=True)
        forbidden={'label','scenario','step','episode_id','seed','private_state','transaction_index'}
        self.assertTrue(all(not keys & forbidden for keys in seen))
        saved=pd.read_parquet(LOCKED/'artifacts/validation_predictions.parquet').set_index('event_id')
        for task,pair in demo['pairs'].items():
            self.assertEqual(pair[0]['observation']['adu_hex'],pair[1]['observation']['adu_hex'])
            for case in pair:
                self.assertEqual(case['evaluation_role'],'validation')
                for method in ('B','D','B-wire','D-wire'):
                    self.assertEqual(case['predictions'][method]['prediction'],saved.loc[case['event_id'],method])
                    self.assertIsNone(case['predictions'][method]['confidence'])
                self.assertFalse(set(CURRENT+CONTEXT) & forbidden)
        original_examples=read(LOCKED/'reports/viva_examples.json')
        self.assertEqual([c['event_id'] for c in demo['reference_cases']],[c['event_id'] for c in original_examples])
        for case in demo['reference_cases']:
            source=HERE.parent/case['source_relative']
            line=(source/'application_ledger.jsonl').read_text().splitlines()[case['ledger_line']-1]
            import json
            self.assertEqual(json.loads(line),case['observation'])
            for ref in case['annotation']['frame_byte_references']:
                raw=(source/'capture.pcap').read_bytes()
                i,n,j=ref['pcap_file_byte_offset'],ref['length'],ref['message_byte_offset']
                self.assertEqual(raw[i:i+n],bytes.fromhex(case['observation']['adu_hex'])[j:j+n])

    def test_results_labels_and_denominators_match_saved_reports(self):
        from demo_results import load_results,comparison_rows
        data=load_results()
        for report in data['conditions'].values():
            rows=comparison_rows(report)
            self.assertEqual([r['Model'] for r in rows],['Packet-only RF','Context-aware RF'])
            for row,method in zip(rows,('B','D')):
                saved=report['methods'][method]['common_cohort']
                self.assertEqual(row['Macro F1'],saved['macro_f1'])
                self.assertEqual(row['Command recall'],saved['per_class']['command_injection']['recall'])
                self.assertEqual(row['Response recall'],saved['per_class']['response_injection']['recall'])
                matrix=saved['confusion']
                self.assertEqual(row['False-alarm rate'],sum(matrix[0][1:])/sum(matrix[0]))

    def test_missing_saved_predictions_do_not_trigger_live_inference(self):
        from demo_data import load_demo
        is_file=Path.is_file
        def present(path):
            return False if path.name=='validation_predictions.parquet' else is_file(path)
        with (patch.object(Path,'is_file',present),
              patch('demo_data.predict_batch',side_effect=AssertionError('No simulated results'))):
            demo=load_demo(saved_predictions_only=True)
        self.assertEqual(demo['prediction_source'],'unavailable')
        for pair in demo['pairs'].values():
            for case in pair:
                self.assertFalse(case['predictions']['B']['available'])
                self.assertIsNone(case['predictions']['B']['prediction'])
                self.assertIsNone(case['predictions']['B']['confidence'])

    def test_pcap_button_runs_detection_and_metrics_include_confusion(self):
        from streamlit.testing.v1 import AppTest
        page=AppTest.from_file(str(HERE/'frontend.py'),default_timeout=60).run()
        self.assertFalse(page.exception)
        next(c for c in page.button if c.label=='Run detection').click().run()
        self.assertFalse(page.exception)
        values={item.label:item.value for item in page.metric}
        self.assertEqual(values['Messages replayed'],'2,272')
        self.assertEqual(values['Injection alerts'],'27')
        outputs=[item.value for item in page.dataframe if 'PCAP frame' in item.value]
        self.assertEqual(len(outputs[0]),27)
        self.assertTrue(outputs[0]['Confidence'].str.endswith('%').all())
        self.assertTrue(any('Confidence is computed now' in item.value for item in page.caption))
        detail=[item.value for item in page.dataframe if 'Support' in item.value and 'Class' in item.value]
        self.assertEqual(detail[0]['Support'].tolist(),[4056,144,288])
        self.assertEqual(detail[0]['Recall'].tolist(),['1.0000','1.0000','1.0000'])

if __name__=='__main__':unittest.main()
