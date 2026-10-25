"""Manual-only host orchestration. Default command is a traffic-free preflight."""
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from dataclasses import asdict
import argparse
import json
import os
import platform
import signal
import socket
import statistics
import sys
import time
import uuid
import shutil

from .common import ROOT,atomic,read,sha,utc,roster,planned,bundle_id,verify_package
from .docker_host import Docker
from .storage import Limits,GIB,docker_backing_paths,check_space,nearest
from .evidence import verify_seal,seal,quarantine,observed_progress,assert_unique

REPO=ROOT.parent.parent


def output_path(value=None):
    path=Path(os.path.expandvars(value)).expanduser() if value else REPO/'component3_collection_runs/main-frozen-v1-20261025'
    if not path.is_absolute(): path=REPO/path
    path=path.resolve()
    if ',' in str(path) or (os.name=='nt' and str(path).startswith('\\\\')):
        raise ValueError('Choose a local output directory without commas; Docker bind-mount restrictions apply')
    protected=[ROOT.parent,REPO/'data/raw',REPO/'data/processed',REPO/'models',REPO/'component3_preparation',
               REPO/'component3_reassessment',REPO/'component3_testbed_pilot',REPO/'component3_testbed_v02',
               REPO/'component3_testbed_v03',REPO/'component3_main_design',REPO/'component3_collection_design',
               REPO/'component3_collection_runs/design-v1',REPO/'component3_collection_runs/engineering-v03']
    if path==REPO or path==Path(path.anchor) or any(path.is_relative_to(p.resolve()) for p in protected):
        raise ValueError('Output overlaps a protected source/qualification directory or filesystem root')
    nearest(path)
    if path.exists() and any(path.iterdir()) and not (path/'collection_manifest.json').is_file():
        raise ValueError('Nonempty unrecognized output directory; choose a fresh directory, never reuse unrelated files')
    return path


def assert_session(root,image):
    manifest=read(root/'collection_manifest.json')
    if manifest['source_bundle_id']!=bundle_id() or manifest['image_id']!=image:
        raise ValueError('Output collection has incompatible frozen source/config/image; refusing resume')
    return manifest


class Lock:
    def __init__(self,root,token): self.path=root/'collector.lock';self.token=token
    def acquire(self):
        try: fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL)
        except FileExistsError:
            old=read(self.path)
            alive=process_alive(old['pid'])
            if old['machine']!=socket.gethostname() or alive:
                raise ValueError('Collector lock is active or from another host; cancel/review that collector first')
            self.path.rename(self.path.with_name('collector.lock.stale-'+uuid.uuid4().hex))
            return self.acquire()
        with os.fdopen(fd,'w',encoding='utf8') as f:
            json.dump(dict(pid=os.getpid(),machine=socket.gethostname(),token=self.token,created_at_utc=utc()),f)
    def release(self):
        if self.path.exists() and read(self.path).get('token')==self.token: self.path.unlink()


def process_alive(pid):
    if pid==os.getpid(): return True
    if os.name=='nt':
        import ctypes
        from ctypes import wintypes
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        kernel.OpenProcess.restype=wintypes.HANDLE
        kernel.GetExitCodeProcess.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)]
        kernel.GetExitCodeProcess.restype=wintypes.BOOL
        kernel.CloseHandle.argtypes=[wintypes.HANDLE]
        handle=kernel.OpenProcess(0x1000,False,pid)  # query only; never TerminateProcess
        if not handle:
            if ctypes.get_last_error()==87: return False
            return True  # access denied/unknown fails closed
        try:
            code=wintypes.DWORD()
            if not kernel.GetExitCodeProcess(handle,ctypes.byref(code)): return True
            return code.value==259
        finally: kernel.CloseHandle(handle)
    try: os.kill(pid,0);return True
    except ProcessLookupError: return False
    except PermissionError: return True


def scan(root,collection_id,image_id):
    completed={};attempts=defaultdict(list)
    for folder in sorted(root.iterdir()):
        if not folder.is_dir() or not (folder/'attempt_request.json').is_file(): continue
        request=read(folder/'attempt_request.json');qid=request['planned_run_id'];planned(qid)
        if request['collection_id']!=collection_id or request['source_bundle_id']!=bundle_id():
            raise ValueError('Foreign/incompatible attempt in collection output')
        attempts[qid].append(folder)
        if (folder/'completion.json').is_file():
            if qid in completed: raise ValueError('Multiple successful attempts for '+qid+'; preserve and review, never count both')
            receipt=verify_seal(folder,qid,collection_id,image_id)
            assert_unique({k:receipt[k] for k in ('ordered_adu_trace_sha256','ordered_pdu_trace_sha256')},
                          [x['receipt'] for x in completed.values()])
            completed[qid]=dict(folder=folder,receipt=receipt)
    return completed,attempts


def estimate_seconds(rows,completed):
    observed=defaultdict(list)
    for row in rows:
        if row['planned_run_id'] in completed:
            seconds=completed[row['planned_run_id']]['receipt']['wall_seconds']
            if isinstance(seconds,(int,float)) and seconds>0:
                observed[(row['timing'],row['recording_mode'])].append(seconds)
    basis=read(ROOT/'frozen/storage_policy.json')['qualified_wall_seconds_by_timing']
    total=0
    for row in rows:
        if row['planned_run_id'] in completed: continue
        values=observed[(row['timing'],row['recording_mode'])]
        total+=statistics.median(values) if values else statistics.median(basis[row['timing']])
    return total


def space(docker_info,root,backing,remaining,limits):
    policy=read(ROOT/'frozen/storage_policy.json')
    return check_space(root,backing,docker_info['docker_guest_free'],remaining,104,policy['upper_run_artifact_bytes'],limits)


def preflight(root,docker,limits,docker_path=None):
    frozen=verify_package();info=docker.preflight()
    backing,how=docker_backing_paths(info['engine'],docker_path)
    completed={};attempts={};session=None
    if (root/'collection_manifest.json').exists():
        session=assert_session(root,info['image_id'])
        completed,attempts=scan(root,session['collection_id'],info['image_id'])
    capacity=space(info,root,backing,104-len(completed),limits)
    result=dict(status='READY_FOR_MANUAL_START',traffic_generated=False,source_bundle_id=frozen['bundle_id'],
                output=str(root),validated_completed=len(completed),frozen_total=104,
                docker_storage_paths=[str(p) for p in backing],docker_storage_discovery=how,space=capacity,
                expected_remaining_hours=estimate_seconds(roster(),completed)/3600,
                academic_acceptance='NOT_RECORDED',note='ETA uses measured qualified/completed runs; no simulated progress')
    return result,info,backing,completed,attempts,session


def cancel(root,docker):
    if not (root/'collection_manifest.json').is_file(): raise ValueError('No collection at this output path')
    session=read(root/'collection_manifest.json')
    atomic(root/'cancel.request',dict(requested_at_utc=utc(),collection_id=session['collection_id']))
    active=root/'active_attempt.json'
    if active.exists():
        data=read(active)
        docker.stop(data['container_name'],session['collection_id'])
    print('Cancellation requested. Available evidence is preserved; incomplete work cannot count as completed.')


def copy_handover(root):
    source=root/'_handover/source/collector';source.mkdir(parents=True)
    for rel in verify_package()['source_configuration_sha256']:
        target=source/rel;target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/rel,target)
    for rel in ('frozen/freeze_manifest.json','image_identity.json','INSTRUCTIONS.md'):
        shutil.copy2(ROOT/rel,source/rel)
    archive=ROOT/'evidence/manual-runtime.tar'
    if archive.exists(): shutil.copy2(archive,root/'_handover/manual-runtime.tar')


def run(root,docker,limits,resume=False,retry_failed=False,docker_path=None):
    check,info,backing,completed,attempts,session=preflight(root,docker,limits,docker_path)
    if session is not None and not resume: raise ValueError('Collection already exists; use -Resume')
    if session is None and resume: raise ValueError('No existing collection; use -Start')
    root.mkdir(parents=True,exist_ok=True)
    lock=Lock(root,uuid.uuid4().hex);lock.acquire()
    current=None;process=None;interrupted=False
    try:
        if session is None:
            if (root/'collection_manifest.json').exists(): raise ValueError('Another collector initialized this output; use Resume')
            if any(p.name!='collector.lock' for p in root.iterdir()): raise ValueError('Output changed after preflight; choose a fresh directory')
            session=dict(status='CREATED',collection_id=uuid.uuid4().hex,source_bundle_id=bundle_id(),image_id=info['image_id'],
                         protocol_id='c3-main-manual-v1-20261025',frozen_roster_sha256=sha(ROOT/'frozen/main_roster.json'),
                         created_at_utc=utc(),qualification_excluded=True,academic_supervisor_approval='NOT_RECORDED')
            atomic(root/'collection_manifest.json',session)
            copy_handover(root)
        active=root/'active_attempt.json'
        if active.exists():
            old=read(active)
            if docker.owned_running(old['container_name'],session['collection_id']):
                raise ValueError('Previous attempt is still running. Cancel it before resuming.')
        if (root/'cancel.request').exists():
            (root/'cancel.request').rename(root/('cancel.request.history-'+uuid.uuid4().hex+'.json'))
        invocation=dict(started_at_utc=utc(),argv=sys.argv,limits=asdict(limits),machine=socket.gethostname(),
                        host_os=platform.platform(),host_python=sys.version,clock_utc=utc(),
                        local_clock=datetime.now().astimezone().isoformat(),clock_note='Self-reported, no independent clock attestation',
                        docker=info,source_bundle_id=bundle_id())
        atomic(root/('invocation-'+uuid.uuid4().hex+'.json'),invocation)
        for row in roster():
            qid=row['planned_run_id']
            if qid in completed: continue
            if (root/'cancel.request').exists(): raise KeyboardInterrupt
            # A complete captured attempt can finish validation after a controller crash.
            old_attempts=attempts.get(qid,[])
            for old in old_attempts:
                if not (old/'run_manifest.json').is_file(): continue
                if read(old/'run_manifest.json').get('status')=='CAPTURE_COLLECTED':
                    try:
                        receipt=seal(old,qid,session['collection_id'],None,recovered=True,prior=[x['receipt'] for x in completed.values()])
                    except Exception as exc:
                        quarantine(old,str(exc),'UNACCEPTED');continue
                    completed[qid]=dict(folder=old,receipt=receipt);break
            if qid in completed: continue
            if old_attempts and not retry_failed:
                raise ValueError(qid+' has an interrupted/failed attempt. Inspect it; use -Resume -RetryFailed for one preserved fresh retry.')
            if len(old_attempts)>=3: raise ValueError(qid+' reached the limit of three attempts; stop and review rather than retry indefinitely')
            verify_package()
            fresh=docker.preflight()
            capacity=space(fresh,root,backing,104-len(completed),limits)
            if (root/'cancel.request').exists(): raise KeyboardInterrupt
            attempt=qid+'-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+uuid.uuid4().hex[:8]
            current=root/attempt;current.mkdir(exist_ok=False)
            name='c3main-'+session['collection_id'][:8]+'-'+attempt.lower()
            atomic(current/'attempt_request.json',dict(attempt_id=attempt,planned_run_id=qid,collection_id=session['collection_id'],
                                                      source_bundle_id=bundle_id(),related_group=row['prospective_related_group'],
                                                      intended_evaluation_role=row['intended_evaluation_role'],created_at_utc=utc()))
            host=dict(**invocation,collection_id=session['collection_id'],image_id=info['image_id'],planned_run_id=qid,
                      attempt_id=attempt,attempt_started_at_utc=utc(),space_before_run=capacity,container_name=name,docker_exit_code=None)
            atomic(current/'host_execution.json',host)
            atomic(root/'active_attempt.json',dict(container_name=name,attempt=attempt,planned_run_id=qid))
            start=time.monotonic()
            print(f"\n{qid} | {row['recording_mode']} {row['map']}/{row['values']}/{row['ordering']}/{row['timing']} | validated {len(completed)}/104",flush=True)
            try:
                with (current/'docker_output.log').open('xb') as log:
                    process=docker.launch(root,current,qid,name,session['collection_id'],info['image_id'],log)
                    last_display=0
                    while process.poll() is None:
                        if (root/'cancel.request').exists(): raise KeyboardInterrupt
                        # Check all host filesystems during the run; Docker guest is checked before every run.
                        space(fresh,root,backing,104-len(completed),limits)
                        p=observed_progress(current);total=p.get('planned_transactions');n=p['observed_complete_pairs']
                        percent=f'{100*n/total:.1f}%' if total else 'not yet measurable'
                        eta=estimate_seconds(roster(),completed)/3600
                        free=__import__('shutil').disk_usage(nearest(root)).free/GIB
                        if time.monotonic()-last_display>=5:
                            status=f"{qid} {p['phase']} | observed {n}/{total or '?'} ({percent}) | VALIDATED {len(completed)}/104 | ETA~{eta:.2f}h | free {free:.2f} GiB"
                            print(('\r'+status+' '*8) if sys.stdout.isatty() else status,end='' if sys.stdout.isatty() else '\n',flush=True)
                            last_display=time.monotonic()
                        time.sleep(2)
                    code=process.returncode
                    print('\n  HOST VERIFICATION: completion is not counted yet',flush=True)
                host.update(docker_exit_code=code,finished_at_utc=utc(),docker_argv=docker.commands[-1])
                atomic(current/'host_execution.json',host)
                if code==130 or (root/'cancel.request').exists(): raise KeyboardInterrupt
                if code!=0: raise RuntimeError(f'{qid} stopped with exit {code}; inspect run_manifest.json, capture.log and validation_report.json')
                receipt=seal(current,qid,session['collection_id'],time.monotonic()-start,prior=[x['receipt'] for x in completed.values()])
                completed[qid]=dict(folder=current,receipt=receipt)
                print(f'  VALIDATED {len(completed)}/104: {qid}',flush=True)
                atomic(root/'collection_state.json',dict(status='RUNNING',validated_completed=len(completed),
                        completed={k:v['folder'].name for k,v in completed.items()},updated_at_utc=utc()))
            finally:
                docker.stop(name,session['collection_id'])
            current=None;process=None
        if len(completed)!=104: raise ValueError('Cannot declare completion without exactly 104 validated planned IDs')
        index={qid:dict(attempt=v['folder'].name,completion_sha256=sha(v['folder']/'completion.json'),
                       intended_evaluation_role=planned(qid)['intended_evaluation_role'],related_group=planned(qid)['prospective_related_group'])
               for qid,v in completed.items()}
        atomic(root/'collection_complete.json',dict(status='ALL_104_VALIDATED',source_bundle_id=bundle_id(),
                collection_id=session['collection_id'],completed=index,finished_at_utc=utc(),no_model_preprocessing_or_training=True))
        atomic(root/'collection_state.json',dict(status='ALL_104_VALIDATED',validated_completed=104,updated_at_utc=utc()))
        print('SUCCESS: all 104 frozen runs independently validated. Raw evidence only; no model dataset or training.',flush=True)
        return 0
    except BaseException as exc:
        interrupted=isinstance(exc,KeyboardInterrupt)
        previous=signal.signal(signal.SIGINT,signal.SIG_IGN)
        try:
            if current:
                active=read(root/'active_attempt.json');docker.stop(active['container_name'],session['collection_id'])
                if process:
                    try: process.wait(timeout=35)
                    except Exception: pass
                if (current/'completion.json').exists():
                    qid=read(current/'attempt_request.json')['planned_run_id']
                    completed[qid]=dict(folder=current,receipt=verify_seal(current,qid,session['collection_id'],info['image_id']))
                else:
                    quarantine(current,'Operator cancellation' if interrupted else str(exc),'INTERRUPTED' if interrupted else 'FAILED')
            atomic(root/'collection_state.json',dict(status='INTERRUPTED' if interrupted else 'STOPPED',
                    validated_completed=len(completed),error='Operator cancellation' if interrupted else str(exc),updated_at_utc=utc()))
        finally: signal.signal(signal.SIGINT,previous)
        print(('CANCELLED' if interrupted else 'STOPPED')+': '+('Evidence preserved; use Resume.' if interrupted else str(exc)),flush=True)
        return 130 if interrupted else 2
    finally: lock.release()


def main(argv=None):
    p=argparse.ArgumentParser(description='Manual Component 3 main collection; default is traffic-free preflight')
    mode=p.add_mutually_exclusive_group();mode.add_argument('--preflight',action='store_true');mode.add_argument('--start',action='store_true')
    mode.add_argument('--resume',action='store_true');mode.add_argument('--cancel',action='store_true')
    p.add_argument('--output');p.add_argument('--docker-storage-path');p.add_argument('--retry-failed',action='store_true')
    p.add_argument('--safety-factor',type=float,default=2);p.add_argument('--planned-copies',type=int,default=2)
    p.add_argument('--reserve-gib',type=float,default=2);p.add_argument('--docker-reserve-gib',type=float,default=2)
    a=p.parse_args(argv);root=output_path(a.output);docker=Docker()
    limits=Limits(a.safety_factor,a.planned_copies,a.reserve_gib,a.docker_reserve_gib)
    try:
        if a.cancel: cancel(root,docker);return 0
        if a.retry_failed and not a.resume: raise ValueError('RetryFailed is allowed only with Resume')
        if a.start or a.resume: return run(root,docker,limits,a.resume,a.retry_failed,a.docker_storage_path)
        result,*_=preflight(root,docker,limits,a.docker_storage_path);print(json.dumps(result,indent=2));return 0
    except Exception as exc: print('PREFLIGHT/CONTROL FAILED: '+str(exc),file=sys.stderr);return 2


if __name__=='__main__': raise SystemExit(main())
