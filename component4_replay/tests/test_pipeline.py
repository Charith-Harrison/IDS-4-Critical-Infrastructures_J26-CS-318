import json
from pathlib import Path
import tempfile
import unittest
import numpy as np
import pandas as pd
from component4_replay.src.load_data import load_data
from component4_replay.src.reconstruct_transactions import reconstruct_transactions
from component4_replay.src.features import extract_features, CURRENT, CONTEXT
from component4_replay.src.split import apply_manifest


def row(t=0,tid=1,request=1,port=2000,**kw):
    r=dict(timestamp=t,frame_number=int(t*10+1),src_ip='client' if request else 'server',
           dst_ip='server' if request else 'client',src_port=port if request else 502,
           dst_port=502 if request else port,is_request=request,mbtcp_trans_id=tid,
           mbtcp_unit_id=1,modbus_func_code=3,modbus_ref_num=8,modbus_word_cnt=1,
           modbus_bit_cnt=0,modbus_val=1,is_attack=0)
    r.update(kw); return r


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def load(self,rows,name='source.csv'):
        p=self.root/name; pd.DataFrame(rows).to_csv(p,index=False); return load_data(p)
    def tx(self,rows): return reconstruct_transactions(self.load(rows))[0]

    def test_interleaved_ports_never_pair(self):
        tx,o=reconstruct_transactions(self.load([row(0,port=2000),row(.1,request=0,port=2001)]))
        self.assertEqual(tx.match_status.tolist(),['response_not_observed']); self.assertEqual(len(o),1)
    def test_concurrent_tids_pair_separately(self):
        tx,o=reconstruct_transactions(self.load([row(0,tid=1),row(.1,tid=2),row(.2,tid=2,request=0),row(.3,tid=1,request=0)]))
        self.assertEqual(tx.match_status.tolist(),['matched','matched']); self.assertEqual(len(o),0)
    def test_exception_response_normalizes_function(self):
        tx=self.tx([row(0),row(.1,request=0,modbus_func_code=131)])
        self.assertEqual(tx.match_status.iloc[0],'matched')
    def test_same_tid_collision_remains_ambiguous(self):
        tx,o=reconstruct_transactions(self.load([row(0),row(.1),row(.2,request=0),row(.3,request=0)]))
        self.assertTrue(tx.match_status.eq('ambiguous_unpaired').all()); self.assertEqual(len(o),2)
        self.assertTrue(tx.response_row_id.isna().all())
    def test_late_response_and_capture_end_not_called_timeout(self):
        tx,o=reconstruct_transactions(self.load([row(0),row(2,request=0)]))
        self.assertEqual(tx.match_status.iloc[0],'response_not_observed'); self.assertFalse(tx.right_censored.iloc[0]); self.assertEqual(len(o),1)
        self.assertTrue(self.tx([row(0)]).right_censored.iloc[0])
    def test_duplicate_reply_is_not_a_second_transaction(self):
        tx,o=reconstruct_transactions(self.load([row(0),row(.1,request=0),row(.2,request=0)]))
        self.assertEqual(len(tx),1); self.assertEqual(len(o),1)
    def test_capture_boundary_never_pairs(self):
        tx,o=reconstruct_transactions(self.load([row(0,frame_number=10),row(.1,request=0,frame_number=1)]))
        self.assertEqual(tx.match_status.iloc[0],'response_not_observed'); self.assertEqual(len(o),1)
    def test_observed_rst_closes_session(self):
        tx,o=reconstruct_transactions(self.load([row(0,tcp_flags_rst=1),row(.1,request=0,tcp_flags_rst=0)]))
        self.assertEqual(tx.match_status.iloc[0],'response_not_observed'); self.assertEqual(len(o),1)
    def test_tid_wrap_and_first_history_missing(self):
        f=extract_features(self.tx([row(0,tid=65535),row(.1,tid=0)]))
        self.assertTrue(np.isnan(f.session_tid_diff.iloc[0])); self.assertEqual(f.session_tid_delta_mod65536.iloc[1],1)
        self.assertEqual(f.session_tid_diff.iloc[1],-65535)
    def test_endpoint_and_session_context_are_distinct(self):
        f=extract_features(self.tx([row(0,tid=100,port=2000),row(.1,tid=101,port=2001)]))
        self.assertTrue(f.session_tid_diff.isna().all()); self.assertEqual(f.endpoint_tid_diff.iloc[1],1)
    def test_interleaved_servers_do_not_make_artificial_tid_jumps(self):
        f=extract_features(self.tx([row(0,tid=15044),row(.1,tid=42101,dst_ip='serverB'),
                                   row(.2,tid=15045),row(.3,tid=42106,dst_ip='serverB')]))
        self.assertEqual(f.endpoint_tid_diff.iloc[2:].tolist(),[1,5])
    def test_future_and_labels_cannot_change_request_features(self):
        early=self.tx([row(0),row(.1,tid=2)])
        later=self.tx([row(0,is_attack=1),row(.1,tid=2,is_attack=1),row(.2,tid=1,request=0),row(.3,tid=2,request=0)])
        a=extract_features(early)[CURRENT+CONTEXT]; b=extract_features(later)[CURRENT+CONTEXT]
        pd.testing.assert_frame_equal(a.reset_index(drop=True),b.reset_index(drop=True))
    def test_bounded_history_expires(self):
        f=extract_features(self.tx([row(0),row(2,tid=2)]),window_seconds=1)
        self.assertEqual(f.observed_command_seen_recently.iloc[1],0)
        self.assertTrue(np.isnan(f.endpoint_tid_diff.iloc[1]))
    def test_missing_payload_scalar_is_not_zero_filled(self):
        f=extract_features(self.tx([row(0,modbus_val=np.nan),row(.1,modbus_val=np.nan)]))
        self.assertTrue(f.modbus_val.isna().all()); self.assertEqual(f.observed_command_seen_recently.iloc[1],0)
    def test_unknown_provenance_and_labels_preserved(self):
        d=self.load([row(0)]); self.assertTrue(d.source_pcap.isna().all())
        r=row(0); del r['is_attack']; d=self.load([r]); self.assertEqual(d.is_attack.iloc[0],-1)
    def test_invalid_required_field_rejected(self):
        for kw in [dict(mbtcp_trans_id=65536),dict(src_port=2.5),dict(timestamp=np.nan),dict(is_attack=2)]:
            with self.assertRaises((ValueError,TypeError)): self.load([row(**kw)])
    def test_labels_preserved_on_conflict(self):
        tx=self.tx([row(0,is_attack=1),row(.1,request=0,is_attack=0)])
        self.assertTrue(tx.label_conflict.iloc[0]); self.assertEqual(tx.request_label_target.iloc[0],1)
        self.assertEqual(tx.response_label.iloc[0],0)
    def test_empty_and_response_only(self):
        tx,o=reconstruct_transactions(self.load([row(0,request=0)])); self.assertTrue(tx.empty); self.assertEqual(len(o),1)
    def test_manifest_refuses_shared_groups_and_missing_classes(self):
        tx=pd.DataFrame(dict(transaction_id=['a','b','c'],segment_id=['a','b','c'],
                             request_label_target=[0,1,0],source_pcap=[None]*3))
        m=pd.DataFrame(dict(segment_id=['a','b','c'],independence_group=['same']*3,
                            partition=['train','validation','test'],evidence=['log']*3))
        with self.assertRaisesRegex(ValueError,'Related groups'): apply_manifest(tx,m)
        m['independence_group']=['a','b','c']
        with self.assertRaisesRegex(ValueError,'both verified classes'): apply_manifest(tx,m)
    def test_manifest_prevents_source_crossing_even_if_groups_misnamed(self):
        tx=pd.DataFrame(dict(transaction_id=['a','b','c'],segment_id=['a','b','c'],
                             request_label_target=[0,1,0],source_pcap=['same.pcap']*3))
        m=pd.DataFrame(dict(segment_id=['a','b','c'],independence_group=['a','b','c'],
                            partition=['train','validation','test'],evidence=['log']*3))
        with self.assertRaisesRegex(ValueError,'Source recording'): apply_manifest(tx,m)
    def test_features_reset_across_partitions(self):
        tx=self.tx([row(0),row(.1)]); tx['partition']=['train','test']
        self.assertTrue(extract_features(tx).endpoint_tid_diff.isna().all())

    def test_synthetic_train_infer_roundtrip_and_no_overwrite(self):
        # Artificial fixture, deliberately independent from ALL research datasets.
        # This verifies artifact/feature-order wiring, not predictive quality.
        from component4_replay.src.train import train
        from component4_replay.src.infer import infer
        from component4_replay.src.load_data import digest
        from component4_replay.src.features import SCHEMA_VERSION
        groups=[]
        for i in range(3):
            g=self.tx([row(i*10,tid=1),row(i*10+.1,tid=2,is_attack=1)])
            g['source_pcap']=f'synthetic_run_{i}.pcap'; groups.append(g)
        tx=pd.concat(groups,ignore_index=True)
        prepared=self.root/'prepared'; prepared.mkdir()
        tx.to_csv(prepared/'transactions.csv.gz',index=False)
        config=json.loads((Path(__file__).resolve().parents[1]/'configs/baseline.json').read_text())
        config['model']['n_estimators']=2
        metadata=dict(schema_version=SCHEMA_VERSION,config=config,
                      outputs={'transactions.csv.gz':digest(prepared/'transactions.csv.gz')})
        (prepared/'metadata.json').write_text(json.dumps(metadata))
        manifest=pd.DataFrame(dict(segment_id=[g.segment_id.iloc[0] for g in groups],
                    independence_group=['synthetic_a','synthetic_b','synthetic_c'],
                    partition=['train','validation','test'],evidence=['unit test fixture only']*3))
        path=self.root/'manifest.csv'; manifest.to_csv(path,index=False)
        out=self.root/'model'; result=train(prepared,path,out)
        test=extract_features(apply_manifest(tx,manifest)); test=test[test.partition.eq('test')]
        prediction,timing=infer(test,out)
        self.assertEqual(len(prediction),2); self.assertTrue(prediction.replay_probability.between(0,1).all())
        self.assertEqual(result['comparisons']['C_transaction_context']['test']['support'],2)
        self.assertIsNone(timing['operational_end_to_end_latency_ms'])
        with self.assertRaises(FileExistsError): train(prepared,path,out)

    def test_historical_dashboard_rejects_writes_but_allows_viewing(self):
        from app import create_app
        client=create_app().test_client()
        self.assertEqual(client.post('/api/train_model').status_code,409)
        self.assertEqual(client.post('/api/apply_cleaning').status_code,409)
        self.assertEqual(client.get('/evaluation').status_code,200)

    def test_historical_cli_refuses_unsafe_pipeline(self):
        from run_pipeline import run_pipeline
        with self.assertRaisesRegex(RuntimeError,'Historical pipeline disabled'): run_pipeline({})


if __name__=='__main__': unittest.main()
