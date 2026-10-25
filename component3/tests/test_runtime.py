import copy
import importlib.util
import math
from pathlib import Path
import unittest
from runtime import Detector,LOCKED,CURRENT,CONTEXT,WIRE,predict_batch

spec=importlib.util.spec_from_file_location('frozen_fixture',LOCKED/'tests/test_records.py')
fixture=importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
MAP={'mode_register':0,'setpoint_register':1,'pump_coil':1}

class RuntimeTests(unittest.TestCase):
    def detector(self): return Detector(MAP,trusted_single_writer=True)
    def replay(self,f):
        d=self.detector(); return [d.observe(r) for r in f.rows]
    def test_requires_explicit_trust_contract(self):
        with self.assertRaises(ValueError): Detector(MAP)
    def test_current_reply_has_no_address_and_zero_is_valid(self):
        f=fixture.WireFixture(); f.exchange(6,1,0); _,i=f.exchange(3,1,1)
        r=self.replay(f)[i]
        self.assertTrue(r['context_available']); self.assertEqual(r['prediction'],'normal')
        self.assertEqual(r['features']['earlier_acknowledged_setpoint'],0)
        self.assertTrue(math.isnan(r['features']['current_wire_address']))
        self.assertIsNone(r['wire_address']); self.assertEqual(r['address_or_register'],1)
        self.assertEqual(r['address_origin'],'earlier_paired_request')
    def test_private_ordinals_and_labels_are_irrelevant(self):
        f=fixture.WireFixture(); f.mode_anchor(0); i,_=f.exchange(5,1,0xff00)
        for r in f.rows:
            r.update(transaction_index='FALSE',label='WRONG',episode_id='WRONG',scenario='WRONG')
        self.assertEqual(self.replay(f)[i]['prediction'],'command_injection')
    def test_reused_tid_and_repeated_bytes_preserve_events(self):
        f=fixture.WireFixture(); f.exchange(6,1,10); _,a=f.exchange(3,1,1,tid=5); _,b=f.exchange(3,1,1,tid=5)
        r=self.replay(f)
        self.assertEqual(len(r),len(f.rows)); self.assertNotEqual(r[a]['evidence']['paired_request_event_id'],r[b]['evidence']['paired_request_event_id'])
    def test_concurrent_requests_fail_closed(self):
        f=fixture.WireFixture(); f.exchange(3,0,1); f.exchange(3,1,1)
        d=self.detector(); d.observe(f.rows[0])
        self.assertEqual(d.observe(f.rows[2])['processing_status'],'ambiguous_pair')
    def test_wrong_tid_echo_and_unit_invalidate(self):
        for mutation,status in [('tid','pair_mismatch'),('echo','pair_mismatch'),('unit','unsupported_input')]:
            f=fixture.WireFixture(); f.exchange(6,1,10)
            raw=bytearray.fromhex(f.rows[1]['adu_hex'])
            if mutation=='tid': raw[1]^=1
            elif mutation=='echo': raw[-1]^=1
            else: raw[6]=2
            f.rows[1]['adu_hex']=raw.hex(); d=self.detector(); d.observe(f.rows[0])
            self.assertEqual(d.observe(f.rows[1])['processing_status'],status)
            self.assertFalse(d.connections)
    def test_missing_anchor_is_eligible_abstention(self):
        f=fixture.WireFixture(); i,_=f.exchange(5,1,0xff00)
        r=self.replay(f)[i]; self.assertTrue(r['eligible']); self.assertFalse(r['context_available'])
        self.assertEqual(r['processing_status'],'insufficient_context')
    def test_mode_write_invalidates_and_no_future_ack_backfill(self):
        f=fixture.WireFixture(); f.mode_anchor(1); f.exchange(6,0,0); i,_=f.exchange(5,1,0xff00)
        self.assertEqual(self.replay(f)[i]['prediction'],'abstain')
        f=fixture.WireFixture(); f.exchange(6,1,10); i,j=f.exchange(6,1,20); _,k=f.exchange(3,1,1)
        r=self.replay(f)
        self.assertEqual(r[i]['features']['earlier_acknowledged_setpoint'],10)
        self.assertTrue(math.isnan(r[j]['features']['earlier_acknowledged_setpoint']))
        self.assertEqual(r[k]['features']['earlier_acknowledged_setpoint'],20)
    def test_gap_and_malformed_input_are_statuses_not_normal(self):
        f=fixture.WireFixture(); f.mode_anchor(1)
        d=self.detector(); d.observe(f.rows[0]); bad=copy.deepcopy(f.rows[1]); bad['stream_offset']=1
        r=d.observe(bad); self.assertEqual(r['processing_status'],'stream_gap'); self.assertIsNone(r['eligible'])
        bad['adu_hex']='00'; self.assertEqual(d.observe(bad)['processing_status'],'invalid_input')
    def test_public_map_change_clears_anchors(self):
        f=fixture.WireFixture(); f.mode_anchor(1)
        d=self.detector(); [d.observe(r) for r in f.rows]; d.set_map(dict(mode_register=10,setpoint_register=11,pump_coil=7))
        self.assertFalse(d.connections)
        with self.assertRaises(ValueError): d.set_map(dict(mode_register=1,setpoint_register=1,pump_coil=7))
    def test_old_anchor_expires_and_episode_does_not_reset(self):
        f=fixture.WireFixture(); f.mode_anchor(1); f.episode='NEW'
        for _ in range(4): f.exchange(1,1,1)
        i,_=f.exchange(5,1,0xff00)
        self.assertEqual(self.replay(f)[i]['prediction'],'abstain')
    def test_new_connection_has_no_old_anchors(self):
        f=fixture.WireFixture(); f.mode_anchor(1); f.new_connection(); i,_=f.exchange(5,1,0xff00)
        self.assertFalse(self.replay(f)[i]['context_available'])
    def test_missing_context_cannot_be_filled_into_prediction(self):
        f=fixture.WireFixture(); f.exchange(5,1,0xff00)
        class MustNotPredict:
            def predict(self,x): raise AssertionError('Must abstain')
        r=predict_batch(self.replay(f),{'D':MustNotPredict()},'D')
        self.assertEqual(r[0]['prediction'],'abstain'); self.assertIsNone(r[0]['confidence'])
    def test_missing_public_identity_or_timestamp_fails_closed(self):
        f=fixture.WireFixture(); f.exchange(3,0,1)
        for key in ('event_id','observed_at_ns'):
            row=dict(f.rows[0]); del row[key]
            self.assertEqual(self.detector().observe(row)['processing_status'],'invalid_input')

if __name__=='__main__': unittest.main()
