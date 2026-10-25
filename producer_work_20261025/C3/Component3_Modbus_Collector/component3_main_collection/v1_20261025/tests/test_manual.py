"""No real Docker, sockets or main collection in this suite. Temp fixtures only."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import tempfile
import threading
import unittest
from unittest.mock import patch,Mock,MagicMock

from runtime import common as C,launcher as L,evidence as E,storage as S
from runtime.docker_host import Docker
from qualified_fixture import fixture


class FakeProcess:
    def __init__(self,code=0): self.returncode=code
    def poll(self): return self.returncode
    def wait(self,timeout=None): return self.returncode


class FakeDocker:
    def __init__(self,root,cancel=False): self.root=root;self.cancel=cancel;self.commands=[];self.launches=0;self.stops=0
    def preflight(self): return dict(image_id='TEST_IMAGE',engine={},docker_guest_free=100*S.GIB)
    def owned_running(self,*_): return False
    def stop(self,*_): self.stops+=1
    def launch(self,*_):
        self.launches+=1;self.commands.append(['TEST_ONLY_NO_DOCKER'])
        if self.cancel:
            C.atomic(self.root/'cancel.request',{'TEST_ONLY':True});return FakeProcess(None)
        return FakeProcess()


class ManualTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='c3-manual-TEST-ONLY-');self.base=Path(self.temp.name);self.root=self.base/'collection'
    def tearDown(self): self.temp.cleanup()

    def test_original_roster_unchanged_conditions_and_qualification_excluded(self):
        main=C.roster();self.assertEqual(len(main),104)
        self.assertEqual(len({x['seed'] for x in main}),104)
        self.assertEqual(sum(x['recording_mode']=='normal_only' for x in main),24)
        for bad in ('EQ01','Q01','MX105','../MX001'):
            with self.assertRaises(ValueError): C.planned(bad)

    def test_default_cli_only_preflights(self):
        with patch.object(L,'Docker',return_value=Mock()) as ctor,patch.object(L,'preflight',return_value=({'TEST_ONLY':True},)),patch.object(L,'run') as start,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(L.main(['--output',str(self.root)]),0)
            start.assert_not_called();ctor.return_value.launch.assert_not_called()
        self.assertFalse(self.root.exists())

    def test_preflight_itself_does_not_create_output_or_collect(self):
        docker=FakeDocker(self.root)
        with patch.object(L,'verify_package',return_value={'bundle_id':'test'}),patch.object(L,'docker_backing_paths',return_value=([self.base],'test')), \
             patch.object(L,'space',return_value={'status':'PASSED'}):
            result,*_=L.preflight(self.root,docker,S.Limits())
        self.assertFalse(result['traffic_generated']);self.assertEqual(docker.launches,0);self.assertFalse(self.root.exists())

    def test_protected_output_and_unrelated_nonempty_path_refused(self):
        for path in (L.REPO,L.REPO/'data/raw/new',C.ROOT/'evidence/new',L.REPO/'component3_collection_runs/engineering-v03/new'):
            with self.assertRaises(ValueError): L.output_path(str(path))
        self.root.mkdir();(self.root/'unrelated.txt').write_text('preserve')
        with self.assertRaises(ValueError): L.output_path(str(self.root))
        self.assertEqual((self.root/'unrelated.txt').read_text(),'preserve')

    def test_missing_output_parents_are_resolved_without_creation(self):
        p=L.output_path(str(self.root/'new/deeper'))
        self.assertEqual(p,self.root/'new/deeper');self.assertFalse(p.exists())

    def test_space_accounts_for_copy_margin_and_shared_docker_drive(self):
        usage=shutil._ntuple_diskusage(100*S.GIB,0,100*S.GIB)
        with patch.object(S.shutil,'disk_usage',return_value=usage):
            x=S.check_space(self.base,[self.base],100*S.GIB,104,104,10<<20,S.Limits())
        self.assertEqual(len(x['host_filesystems']),1)
        self.assertGreater(x['host_filesystems'][0]['required'],x['output_required_bytes'])
        self.assertGreater(S.requirements(104,104,10<<20,S.Limits()),S.requirements(100,104,10<<20,S.Limits()))

    def test_output_disk_and_docker_guest_shortage_each_refused(self):
        with patch.object(S.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(100,90,10)):
            with self.assertRaisesRegex(ValueError,'Insufficient storage'): S.check_space(self.base,[],100*S.GIB,104,104,100,S.Limits())
        with patch.object(S.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(100*S.GIB,0,100*S.GIB)):
            with self.assertRaisesRegex(ValueError,'guest'): S.check_space(self.base,[],10,104,104,100,S.Limits())

    def test_low_space_stops_before_any_attempt_or_docker_launch(self):
        docker=FakeDocker(self.root)
        with patch.object(L,'preflight',side_effect=ValueError('Insufficient storage')):
            with self.assertRaises(ValueError): L.run(self.root,docker,S.Limits())
        self.assertEqual(docker.launches,0);self.assertFalse(self.root.exists())

    def test_changed_source_or_freeze_rejected(self):
        with patch.object(C,'read',return_value={'source_configuration_sha256':{'a':'old'},'bundle_id':'old'}),patch.object(C,'source_inventory',return_value={'a':'new'}):
            with self.assertRaisesRegex(ValueError,'changed'): C.verify_package()

    def test_observed_progress_counts_actual_complete_lines_not_elapsed_time(self):
        self.root.mkdir();C.atomic(self.root/'progress.json',dict(phase='CAPTURING',planned_transactions=9))
        (self.root/'application_ledger.jsonl').write_bytes(b'{}\n{}\n{}\npartial')
        result=E.observed_progress(self.root)
        self.assertEqual(result['observed_complete_pairs'],1);self.assertEqual(result['planned_transactions'],9)

    def test_live_lock_refused_and_dead_own_host_lock_archived(self):
        self.root.mkdir();lock=L.Lock(self.root,'test');lock.acquire()
        with self.assertRaises(ValueError): L.Lock(self.root,'second').acquire()
        lock.release()
        C.atomic(self.root/'collector.lock',dict(machine=L.socket.gethostname(),pid=999999999,token='old'))
        with patch.object(L,'process_alive',return_value=False): lock.acquire()
        self.assertTrue(list(self.root.glob('collector.lock.stale-*')));lock.release()

    def test_successful_generator_exit_without_validation_never_completed(self):
        docker=FakeDocker(self.root);row=C.roster()[0]
        initial=({},docker.preflight(),[self.base],{}, {},None)
        with patch.object(L,'preflight',return_value=initial),patch.object(L,'copy_handover'),patch.object(L,'verify_package',return_value={}), \
             patch.object(L,'space',return_value={}),patch.object(L,'roster',return_value=[row]),patch.object(L,'seal',side_effect=ValueError('capture loss')), \
             contextlib.redirect_stdout(io.StringIO()):
            code=L.run(self.root,docker,S.Limits())
        self.assertEqual(code,2);self.assertEqual(docker.launches,1)
        self.assertEqual(C.read(self.root/'collection_state.json')['validated_completed'],0)
        self.assertFalse(list(self.root.glob('MX*/completion.json')))
        self.assertTrue(list(self.root.glob('MX*/attempt_disposition.json')))

    def test_cancellation_stops_owned_container_and_marks_unaccepted(self):
        docker=FakeDocker(self.root,cancel=True);row=C.roster()[0]
        with patch.object(L,'preflight',return_value=({},docker.preflight(),[self.base],{},{},None)),patch.object(L,'copy_handover'), \
             patch.object(L,'verify_package',return_value={}),patch.object(L,'space',return_value={}),patch.object(L,'roster',return_value=[row]),contextlib.redirect_stdout(io.StringIO()):
            code=L.run(self.root,docker,S.Limits())
        self.assertEqual(code,130);self.assertGreater(docker.stops,0)
        self.assertEqual(C.read(self.root/'collection_state.json')['status'],'INTERRUPTED')
        self.assertFalse((self.root/'collector.lock').exists());self.assertFalse(list(self.root.glob('MX*/completion.json')))

    def test_failed_attempt_requires_explicit_retry_and_three_attempt_cap(self):
        self.root.mkdir();session={'collection_id':'TEST_SESSION'}
        C.atomic(self.root/'collection_manifest.json',session)
        old=[]
        for i in range(3): p=self.root/f'failed{i}';p.mkdir();old.append(p)
        docker=FakeDocker(self.root);row=C.roster()[0]
        for retry in (False,True):
            with patch.object(L,'preflight',return_value=({},docker.preflight(),[self.base],{}, {'MX001':old},session)), \
                 patch.object(L,'roster',return_value=[row]),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(L.run(self.root,docker,S.Limits(),resume=True,retry_failed=retry),2)
        self.assertEqual(docker.launches,0);self.assertTrue(all(p.exists() for p in old))

    def test_sealed_changed_artifact_refuses_resume_before_any_rewrite(self):
        self.root.mkdir();p=self.root/'raw.txt';p.write_text('old');original=C.sha(p);p.write_text('changed')
        C.atomic(self.root/'completion.json',dict(planned_run_id='MX001',collection_id='TEST',source_bundle_id=C.bundle_id(),image_id='IMAGE',artifact_sha256={'raw.txt':original}))
        with patch.object(E,'verify_attempt') as raw_check:
            with self.assertRaisesRegex(ValueError,'artifact changed'): E.verify_seal(self.root,'MX001','TEST','IMAGE')
            raw_check.assert_not_called()
        self.assertEqual(p.read_text(),'changed')

    def test_duplicate_observation_trace_does_not_create_independence(self):
        with self.assertRaisesRegex(ValueError,'Duplicate'): E.assert_unique({'ordered_pdu_trace_sha256':'same'},[{'ordered_pdu_trace_sha256':'same'}])

    def test_quarantine_preserves_failed_annotations_and_raw_bytes(self):
        self.root.mkdir();(self.root/'verified_labels.jsonl').write_text('TEST_ONLY')
        (self.root/'raw.txt').write_text('keep');E.quarantine(self.root,'failed controls','FAILED')
        self.assertFalse((self.root/'verified_labels.jsonl').exists())
        self.assertEqual(next(self.root.glob('verified_labels.unaccepted-*')).read_text(),'TEST_ONLY')
        self.assertEqual((self.root/'raw.txt').read_text(),'keep')

    def test_qualified_decoder_accepts_synthetic_main_envelope_but_not_as_measured(self):
        for run_id in ('MX001','MX081'):
            with self.subTest(run_id=run_id):
                fixture(self.base,run_id=run_id)
                result=C.validator()(self.base,write=False,allow_synthetic=True)
                self.assertEqual(result['status'],'SYNTHETIC_TEST_PASSED',result)
                self.assertFalse(result['accepted_labels']);self.assertFalse((self.base/'verified_labels.jsonl').exists())
                refused=C.validator()(self.base,write=False)
                self.assertEqual(refused['status'],'FAILED')

    def test_container_collect_guard_rejects_host_before_socket_or_capture(self):
        from runtime import collector
        with patch.object(collector,'verify_package',return_value={}),patch.dict(os.environ,{},clear=True),patch.object(collector.socket,'create_connection') as connect,patch.object(collector,'Capture') as cap:
            with self.assertRaises(RuntimeError): collector.collect(self.root,'MX001')
            connect.assert_not_called();cap.assert_not_called()

    def test_cancellation_before_capture_never_opens_a_socket(self):
        from runtime import collector
        self.root.mkdir();C.atomic(self.root/'attempt_request.json',dict(attempt_id='TEST_ONLY',collection_id='TEST'))
        stop=threading.Event();stop.set();handlers={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        try:
            with patch.object(collector,'verify_package',return_value={}),patch.dict(os.environ,{'C3_MAIN_MANUAL_CONTAINER':'1'}),patch.object(collector.platform,'system',return_value='Linux'),patch.object(collector.socket,'if_nameindex',return_value=[(1,'lo')]),patch.object(collector.socket,'create_connection') as connect,patch.object(collector,'Capture') as cap:
                self.assertEqual(collector.collect(self.root,'MX001',stop=stop),130)
                connect.assert_not_called();cap.assert_not_called()
        finally:
            for sig,handler in handlers.items(): signal.signal(sig,handler)
        self.assertEqual(C.read(self.root/'run_manifest.json')['status'],'INTERRUPTED')
        self.assertFalse((self.root/'verified_labels.jsonl').exists())

    def test_stop_refuses_an_unowned_container(self):
        docker=Docker()
        with patch.object(docker,'json',return_value=[{'Config':{'Labels':None},'State':{'Running':True}}]):
            with self.assertRaises(ValueError): docker.stop('unrelated','TEST')

    def test_liveness_query_does_not_send_a_signal_to_current_process(self):
        with patch.object(L.os,'kill',side_effect=AssertionError('Do not signal Windows process for liveness')):
            self.assertTrue(L.process_alive(os.getpid()))

    def test_all_36_main_condition_cells_compose_without_network_using_fresh_engineering_seeds(self):
        from c3qual.scenarios import build
        from c3qual.protocol import Process,adu
        from c3qual.config import object_map
        from c3qual.validation import pair
        conditions={}
        for row in C.roster(): conditions.setdefault(tuple(row[k] for k in ('map','values','ordering','timing','recording_mode')),row)
        self.assertEqual(len(conditions),36)
        for n,(condition,row) in enumerate(conditions.items(),1):
            config=dict(row,seed=880000+n)  # never consume a future main recording/seed for debugging
            with self.subTest(condition=condition):
                mapping=object_map(config['map']);process=Process(mapping);episodes=build(config)
                self.assertEqual(len(episodes),90)
                for ep in episodes:
                    for step in ep['steps']:
                        raw=bytes.fromhex(step['pdu_hex']);reply=process.handle(raw)
                        if step['intervention']=='response_injection': reply=b'\x03\x02'+step['replacement'].to_bytes(2,'big')
                        pair(adu(step['tid'],raw),adu(step['tid'],reply),mapping)

    def test_cancellation_after_observed_pair_closes_capture_and_keeps_unaccepted_evidence(self):
        from runtime import collector
        from c3qual.protocol import Process,parse,adu
        from c3qual.config import object_map
        self.root.mkdir();C.atomic(self.root/'attempt_request.json',dict(attempt_id='TEST_ONLY',collection_id='TEST'))
        stop=threading.Event();device=Process(object_map('M0'))
        client=MagicMock();client.__enter__.return_value=client;client.__exit__.return_value=False
        client.getsockname.return_value=('127.0.0.1',41000)
        def receive(_):
            request=client.sendall.call_args.args[0];tid,pdu=parse(request)
            reply=adu(tid,device.handle(pdu));stop.set();return reply
        cap=Mock();cap.stop.return_value=0
        server=Mock();server.thread.is_alive.return_value=False
        handlers={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        try:
            with patch.object(collector,'verify_package',return_value={}),patch.dict(os.environ,{'C3_MAIN_MANUAL_CONTAINER':'1'}),patch.object(collector.platform,'system',return_value='Linux'),patch.object(collector.socket,'if_nameindex',return_value=[(1,'lo')]),patch.object(collector.socket,'create_connection',return_value=client),patch.object(collector,'Server',return_value=server),patch.object(collector,'Capture',return_value=cap),patch.object(collector,'recv_adu',side_effect=receive):
                self.assertEqual(collector.collect(self.root,'MX001',stop=stop),130)
        finally:
            for sig,handler in handlers.items(): signal.signal(sig,handler)
        cap.stop.assert_called_once()
        self.assertEqual(C.read(self.root/'run_manifest.json')['observed_application_messages'],2)
        self.assertEqual(len((self.root/'application_ledger.jsonl').read_text().splitlines()),2)
        self.assertFalse((self.root/'verified_labels.jsonl').exists())


if __name__=='__main__': unittest.main()
