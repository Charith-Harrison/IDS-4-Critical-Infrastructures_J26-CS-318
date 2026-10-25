"""CSV contract, causality, partition and real PCAP-route equivalence checks."""
import csv
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from csv_inference import (parse_csv,analyze_csv,template_csv,observations_csv,
    evaluate_predictions,prediction_csv,manifest_registry,partition_status)
from runtime import load_locked_models,Detector

def table(data): return list(csv.DictReader(io.StringIO(data.decode('utf-8'))))
def encode(rows):
    text=io.StringIO(newline=''); writer=csv.DictWriter(text,fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
    return text.getvalue().encode()

class CsvSchemaTests(unittest.TestCase):
    def test_template_is_exact_complete_wire_observation_schema(self):
        parsed=parse_csv(template_csv())
        self.assertEqual(len(parsed['rows']),4)
        self.assertEqual(parsed['rows'][0]['observed_at_ns'],1000000000)
    def test_missing_column_generic_flow_and_precomputed_features_rejected(self):
        for data in [b'flow_id,label\na,normal\n',b'current_function,earlier_observed_mode\n5,0\n']:
            with self.assertRaisesRegex(ValueError,'required to reconstruct'): parse_csv(data)
    def test_wrong_type_unknown_private_column_and_inconsistent_decoding_rejected(self):
        for column,value in [('observed_at_ns','1.0'),('stream_offset','-1'),('scenario','attack'),
                             ('unit','2'),('role','response'),('adu_hex','00')]:
            rows=table(template_csv())
            for row in rows: row[column]=value
            with self.subTest(column=column),self.assertRaises(ValueError): parse_csv(encode(rows))
    def test_duplicate_ids_partial_endpoints_schema_version_rejected(self):
        for kind in ('ids','endpoints','version'):
            rows=table(template_csv())
            if kind=='ids': rows[1]['event_id']=rows[0]['event_id']
            if kind=='endpoints':
                for row in rows: del row['source_port']
            if kind=='version':
                for row in rows: row['observation_schema']='unknown-v2'
            with self.subTest(kind=kind),self.assertRaises(ValueError): parse_csv(encode(rows))
    def test_one_ground_truth_alias_only(self):
        rows=table(template_csv())
        for row in rows: row.update(label='normal',ground_truth='normal')
        with self.assertRaisesRegex(ValueError,'only one'): parse_csv(encode(rows))

@unittest.skipUnless((HERE/'data/collection/collection_complete.json').is_file(),'Local experiment required')
class CsvInferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.models=load_locked_models(); cls.registry=manifest_registry()

    def analyze(self,data,registry=None):
        return analyze_csv(data,self.models,self.registry if registry is None else registry,trusted_single_writer=True)

    def test_template_predicts_and_missing_context_abstains_before_imputation(self):
        result=self.analyze(template_csv())
        self.assertEqual(result['predictions_produced'],1)
        rows=table(template_csv())[2:]
        for row in rows: row['stream_offset']='0'
        partial=self.analyze(encode(rows))
        self.assertEqual(partial['records'][1]['prediction'],'abstain')
        self.assertFalse(partial['records'][1]['context_available'])
    def test_unique_timestamps_restore_order_without_float_rounding(self):
        rows=table(template_csv()); rows.reverse()
        result=self.analyze(encode(rows))
        self.assertEqual(result['rows_reordered'],4)
        expected=self.analyze(template_csv())
        self.assertEqual([r['prediction'] for r in result['records']],[r['prediction'] for r in expected['records']])
        self.assertEqual([r['observed_at_ns'] for r in result['records']],[1000000000,1001000000,1002000000,1003000000])
    def test_ambiguous_timestamp_stream_and_byte_gaps_are_rejected(self):
        for kind in ('time','gap'):
            rows=table(template_csv())
            if kind=='time':
                rows[1]['observed_at_ns']=rows[0]['observed_at_ns']; rows.reverse()
            else: rows[2]['stream_offset']='999'
            result=self.analyze(encode(rows))
            self.assertEqual(result['rejected_rows'],4)
            self.assertEqual(result['predictions_produced'],0)
            self.assertTrue(all(r['prediction'] is None for r in result['records']))
    def test_runs_and_connections_cannot_share_anchor(self):
        for boundary in ('run_id','connection_id'):
            rows=table(template_csv())
            for row in rows[2:]: row[boundary]='another-generation'; row['stream_offset']='0'
            result=self.analyze(encode(rows))
            reply=next(r for r in result['records'] if r['event_id']=='example-e3')
            self.assertEqual(reply['prediction'],'abstain')
            self.assertFalse(reply['context_available'])
    def test_future_mutation_does_not_change_past_features_or_predictions(self):
        from observation_inference import infer_observations
        from csv_inference import maps
        rows=parse_csv(template_csv())['rows']
        # Keep a genuinely scored earlier reply, then append a future exchange.
        import copy
        future=copy.deepcopy(rows[2:])
        for i,row in enumerate(future):
            row['event_id']='future-'+str(i); row['observed_at_ns']+=2000000
            row['stream_offset']=24 if i==0 else 23
        rows+=future
        before,pred_before=infer_observations(rows,maps()['M0'],self.models)
        rows[5]['adu_hex']='0005000000050103020076'
        after,pred_after=infer_observations(rows,maps()['M0'],self.models)
        import pandas as pd
        pd.testing.assert_frame_equal(pd.DataFrame([r['features'] for r in before[:4]]),pd.DataFrame([r['features'] for r in after[:4]]))
        self.assertEqual([r['prediction'] for r in pred_before['D'][:4]],[r['prediction'] for r in pred_after['D'][:4]])
    def test_no_fit_or_fit_transform_and_labels_never_enter_observe(self):
        from sklearn.pipeline import Pipeline
        from sklearn.impute import SimpleImputer
        rows=table(template_csv())
        for row in rows: row['label']='command_injection'
        seen=[]; observe=Detector.observe
        def spy(detector,row): seen.append(set(row)); return observe(detector,row)
        with (patch.object(Pipeline,'fit',side_effect=AssertionError('fit forbidden')),
              patch.object(Pipeline,'fit_transform',side_effect=AssertionError('fit_transform forbidden')),
              patch.object(SimpleImputer,'fit',side_effect=AssertionError('imputer fit forbidden')),
              patch.object(SimpleImputer,'fit_transform',side_effect=AssertionError('imputer fit_transform forbidden')),
              patch.object(Detector,'observe',spy)):
            result=self.analyze(encode(rows))
        original=self.analyze(template_csv())
        self.assertEqual([r['prediction'] for r in result['records']],[r['prediction'] for r in original['records']])
        self.assertTrue(all(not key & {'label','run_id','class','ground_truth','_ground_truth','map_id'} for key in seen))
        self.assertFalse(result['labels_used_for_prediction'])
        self.assertEqual(evaluate_predictions(result)['support'],1)
    def test_csv_report_is_not_reaccepted_as_input(self):
        result=self.analyze(template_csv())
        with self.assertRaises(ValueError): parse_csv(prediction_csv(result))
    def test_ground_truth_validation_is_after_prediction(self):
        rows=table(template_csv())
        for row in rows: row['label']='0'
        result=self.analyze(encode(rows))
        self.assertEqual(result['predictions_produced'],1)
        with self.assertRaisesRegex(ValueError,'Unsupported ground-truth'): evaluate_predictions(result)
    def test_partition_badges_conservative_and_id_alone_cannot_prove_independence(self):
        rows=parse_csv(template_csv())['rows']
        for planned,expected in [('MX001','TRAINING RUN'),('MX025','VALIDATION RUN'),('MX069','HELD-OUT TEST RUN'),('unmatched','EXTERNAL / UNKNOWN')]:
            status=partition_status(planned,rows,self.registry)
            self.assertEqual(status['badge'],expected)
            self.assertNotEqual(status['match'],'complete_byte_trace')
        self.assertIn('already-observed',partition_status('MX069',rows,self.registry)['note'].lower())
    def test_pcap_csv_equivalence_and_full_trace_provenance(self):
        from capture_replay import replay_capture
        import observation_inference
        import pandas as pd
        original=observation_inference.predict_batch; features=[]
        def spy(rows,models,name):
            features.append(pd.DataFrame([r['features'] for r in rows])); return original(rows,models,name)
        with patch('observation_inference.predict_batch',spy):
            pcap=replay_capture('MX025',models=self.models)
            csv_result=self.analyze(observations_csv(pcap['observations']))
        pd.testing.assert_frame_equal(features[0],features[2])
        self.assertFalse(csv_result['rejected_streams'])
        self.assertEqual(csv_result['messages'],pcap['messages'])
        self.assertEqual([r['prediction'] for r in csv_result['records']],[r['context_aware'] for r in pcap['records']])
        for a,b in zip(csv_result['records'],pcap['records']):
            if a['confidence'] is None: self.assertIsNone(b['confidence'])
            else: self.assertAlmostEqual(a['confidence'],b['confidence'],places=12)
        self.assertEqual([r['packet_only'] for r in csv_result['records']],[r['packet_only'] for r in pcap['records']])
        status=csv_result['partition_status'][0]
        self.assertEqual(status['badge'],'VALIDATION RUN'); self.assertEqual(status['match'],'complete_byte_trace')
        # Renaming the run cannot turn known development bytes into unseen data.
        renamed=self.analyze(observations_csv(pcap['observations'],run_id='renamed-external'))
        self.assertEqual(renamed['partition_status'][0]['role'],'validation')

if __name__=='__main__':unittest.main()
