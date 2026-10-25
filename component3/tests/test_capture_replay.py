# Check capture replay behavior using software fixtures and existing evidence.
"""Real accepted development capture; no final payloads or research fitting."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from capture_replay import SOURCE,replay_capture,development_captures

# Group the related software checks and their shared test helpers.
@unittest.skipUnless((SOURCE/'collection_complete.json').is_file(),'Local accepted collection required')
class CaptureReplayTests(unittest.TestCase):
    # Load shared development evidence or saved models once for this test class.
    @classmethod
    def setUpClass(cls):
        import capture_replay
        from runtime import Detector
        from sklearn.pipeline import Pipeline
        original_read=capture_replay.read; original_observe=Detector.observe
        cls.public_keys=[]
        # Fail the test if replay tries to read application, label, or private simulator files.
        def read(path):
            if Path(path).name in ('application_ledger.jsonl','verified_labels.jsonl','server_audit.jsonl',
                                   'intervention_audit.jsonl','scenario_plan.json'):
                raise AssertionError('Private/label/application evidence must not be an inference input')
            return original_read(path)
        # Record the fields sent to the detector, then call its original observation method.
        def observe(detector,row):
            cls.public_keys.append(set(row)); return original_observe(detector,row)
        with (patch('capture_replay.read',read),patch.object(Detector,'observe',observe),
              patch.object(Pipeline,'fit',side_effect=AssertionError('No fitting in replay'))):
            cls.result=replay_capture('MX025')

    # Check that pcap predictions match the original saved validation outputs.
    def test_pcap_predictions_match_the_original_saved_validation_outputs(self):
        import pandas as pd
        saved=pd.read_parquet(HERE/'locked/v1_20261025/artifacts/validation_predictions.parquet')
        saved=saved.loc[saved.run_id==self.result['run_id']]
        records=self.result['records']
        self.assertEqual(len(records),2272)
        self.assertEqual([r['packet_only'] for r in records],saved.B.tolist())
        self.assertEqual([r['context_aware'] for r in records],saved.D.tolist())
        self.assertEqual(self.result['prediction_counts']['command_injection'],9)
        self.assertEqual(self.result['prediction_counts']['response_injection'],18)
        self.assertEqual(self.result['abstentions'],90)
        forbidden={'label','scenario','step','episode_id','seed','transaction_index','private_state'}
        self.assertTrue(all(not keys & forbidden for keys in self.public_keys))
        self.assertFalse(self.result['labels_used'])

    # Check that identical bytes have separate positions and different decisions.
    def test_identical_bytes_have_separate_positions_and_different_decisions(self):
        records=self.result['records']
        for normal,attack,label in [(36,1060,'command_injection'),(33,2101,'response_injection')]:
            self.assertEqual(records[normal]['adu_hex'],records[attack]['adu_hex'])
            self.assertNotEqual(records[normal]['stream_offset'],records[attack]['stream_offset'])
            self.assertEqual(records[normal]['context_aware'],'normal')
            self.assertEqual(records[attack]['context_aware'],label)
            self.assertTrue(0<=records[attack]['confidence']<=1)
        capture=(HERE.parent/self.result['pcap']).read_bytes()
        for row in records:
            raw=bytes.fromhex(row['adu_hex'])
            for ref in row['frame_byte_references']:
                a,n,b=ref['pcap_file_byte_offset'],ref['length'],ref['message_byte_offset']
                self.assertEqual(capture[a:a+n],raw[b:b+n])
            for key,value in row['context_evidence'].items():
                if key.endswith('_event_id') and value:
                    self.assertLess(int(value.rsplit(':e',1)[1]),row['message_number']-1)

    # Check that final and unindexed attempts are refused.
    def test_final_and_unindexed_attempts_are_refused(self):
        self.assertEqual(len(development_captures()),48)
        with self.assertRaisesRegex(ValueError,'training/validation'):
            replay_capture('MX069')
        with self.assertRaises(ValueError): replay_capture('MX025-unindexed-attempt')

    # Check that changed capture is refused without replacing evidence.
    def test_changed_capture_is_refused_without_replacing_evidence(self):
        import capture_replay
        original=capture_replay.sha
        with patch('capture_replay.sha',lambda path:'changed' if Path(path).name=='capture.pcap' else original(path)):
            with self.assertRaisesRegex(ValueError,'Changed replay input'):
                replay_capture('MX025')

if __name__=='__main__':unittest.main()
