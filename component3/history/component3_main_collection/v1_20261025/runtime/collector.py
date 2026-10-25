"""Container lifecycle adapter around the unchanged qualified wire engine.

Never invoked by preflight/tests. The operator must explicitly choose Start/Resume.
Cancellation is cooperative; actual transaction progress is read from flushed ledgers.
"""
from pathlib import Path
from collections import Counter
import os
import platform
import signal
import socket
import sys
import threading
import time

from .common import PURPOSE,atomic,artifacts,planned,source_inventory,utc,validator,verify_package
from c3qual.runner import Server,HOST,PORT
from c3qual.protocol import adu,parse,recv_adu
from c3qual.scenarios import build
from c3qual.config import object_map
from c3qual.recorder import Capture,JsonLines


class Interrupted(Exception): pass


def collect(folder,run_id,stop=None):
    verify_package()
    config=planned(run_id)
    if os.environ.get('C3_MAIN_MANUAL_CONTAINER')!='1' or platform.system()!='Linux':
        raise RuntimeError('Collection requires the supplied isolated manual launcher')
    if {name for _,name in socket.if_nameindex()}!={'lo'}:
        raise RuntimeError('Expected network none with only loopback')
    stop=stop or threading.Event()
    for sig in (signal.SIGINT,signal.SIGTERM): signal.signal(sig,lambda *_:stop.set())
    folder=Path(folder)
    # Host exclusively creates and identifies this new attempt; never reuse an existing ledger.
    if (folder/'run_manifest.json').exists(): raise ValueError('Attempt already has a recording; refusing overwrite')
    episodes=build(config)
    request=__import__('json').loads((folder/'attempt_request.json').read_text())
    recording=request['attempt_id'];connection_id=recording+':connection-0'
    manifest=dict(schema_version=3,version='manual-v1/qualified-engine-0.3.0',purpose=PURPOSE,
                  run_id=recording,planned_run=config,connection_id=connection_id,status='STARTED',
                  capture_required=True,python=sys.version,platform=platform.platform(),created_at_utc=utc(),
                  isolation='docker-network-none',server_host=HOST,server_port=PORT,episodes=len(episodes),
                  source_sha256=source_inventory(),source_bundle_id=config['source_bundle_id'],
                  collection_id=request['collection_id'],no_model_preprocessing_or_training=True,
                  academic_supervisor_approval='NOT_RECORDED')
    atomic(folder/'run_manifest.json',manifest)
    atomic(folder/'planned_run.json',config);atomic(folder/'scenario_plan.json',episodes)
    total=sum(len(ep['steps']) for ep in episodes)
    def progress(phase):
        atomic(folder/'progress.json',dict(phase=phase,planned_transactions=total,updated_at_utc=utc(),
                                          note='Completed observed pairs are counted from the flushed application ledger; not capture-validated yet'))
    progress('STARTING_CAPTURE')
    ledger=JsonLines(folder/'application_ledger.jsonl');oracle=JsonLines(folder/'server_audit.jsonl')
    hooks=JsonLines(folder/'intervention_audit.jsonl')
    capture=server=None;rows=[];offsets=dict(client_to_server=0,server_to_client=0);error=None
    try:
        if stop.is_set(): raise Interrupted('Cancelled before capture')
        capture=Capture(folder)
        if stop.is_set(): raise Interrupted('Cancelled during capture startup')
        server=Server(object_map(config['map']),oracle,[s for ep in episodes for s in ep['steps']],connection_id)
        server.thread.start();progress('CAPTURING')
        with socket.create_connection((HOST,PORT),timeout=5) as client:
            client.settimeout(10);client.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
            local_port=client.getsockname()[1];manifest['client_port']=local_port;t=0
            for ep in episodes:
                for step in ep['steps']:
                    if stop.wait(step['sleep_seconds']): raise Interrupted('Operator cancellation requested')
                    tid=step['tid'];outgoing=adu(tid,bytes.fromhex(step['pdu_hex']))
                    hooks.append(dict(transaction_index=t,connection_id=connection_id,request_adu_hex=outgoing.hex(),
                                      kind=step['intervention'],replacement=step['replacement'],recorded_at_ns=time.time_ns(),
                                      use='PRIVATE_ANNOTATION_EVIDENCE_NOT_PREDICTORS'))
                    sent_at=time.time_ns();client.sendall(outgoing);incoming=recv_adu(client);received_at=time.time_ns()
                    if parse(incoming)[0]!=tid: raise ValueError('Response TID differs')
                    for j,(role,direction,raw,stamp) in enumerate((('request','client_to_server',outgoing,sent_at),
                                                                 ('response','server_to_client',incoming,received_at))):
                        label='command_injection' if j==0 and step['intervention']=='command_injection' else \
                              'response_injection' if j==1 and step['intervention']=='response_injection' else 'normal'
                        row=dict(event_id=f'{recording}:e{len(rows)}',run_id=recording,connection_id=connection_id,
                                 transaction_index=t,episode_id=ep['episode_id'],scenario=ep['family'],step=step['step'],
                                 label=label,role=role,direction=direction,tid=tid,unit=1,block=ep['block'],
                                 tid_profile=ep['tid_profile'],anchor_poll_count=ep['anchor_poll_count'],
                                 adu_hex=raw.hex(),pdu_hex=raw[7:].hex(),stream_offset=offsets[direction],observed_at_ns=stamp,
                                 source_ip=HOST,destination_ip=HOST,source_port=local_port if j==0 else PORT,
                                 destination_port=PORT if j==0 else local_port,metadata_use='AUDIT_ONLY_NOT_MODEL_INPUTS')
                        offsets[direction]+=len(raw);rows.append(row);ledger.append(row)
                    t+=1
                    if stop.is_set(): raise Interrupted('Operator cancellation requested')
        server.finish()
        manifest['status']='CAPTURE_COLLECTED'
    except BaseException as exc:
        error=exc
        manifest.update(status='INTERRUPTED' if stop.is_set() or isinstance(exc,(Interrupted,KeyboardInterrupt)) else 'FAILED',
                        error=f'{type(exc).__name__}: {exc}')
    finally:
        if capture:
            manifest['capture_exit_code']=capture.stop()
        if server and server.thread.is_alive(): server.thread.join(timeout=12)
        for stream in (ledger,oracle,hooks): stream.close()
        manifest['observed_application_messages']=len(rows)
        manifest['proposed_label_counts_not_yet_verified']=dict(Counter(r['label'] for r in rows))
        owned=('capture.pcap','capture.log','application_ledger.jsonl','server_audit.jsonl',
               'intervention_audit.jsonl','planned_run.json','scenario_plan.json','attempt_request.json')
        manifest['input_sha256']={k:v for k,v in artifacts(folder).items() if k in owned}
        atomic(folder/'run_manifest.json',manifest)
    if error:
        progress(manifest['status']);return 130 if manifest['status']=='INTERRUPTED' else 2
    if stop.is_set():
        manifest['status']='INTERRUPTED';atomic(folder/'run_manifest.json',manifest);progress('INTERRUPTED');return 130
    progress('VALIDATING')
    report=validator()(folder,write=True)
    if stop.is_set():
        labels=folder/'verified_labels.jsonl'
        if labels.exists(): labels.rename(folder/'verified_labels.interrupted.jsonl')
        progress('INTERRUPTED');return 130
    if report['status']!='PASSED': progress('VALIDATION_FAILED');return 2
    atomic(folder/'runtime_result.json',dict(status='VALIDATED',source_bundle_id=config['source_bundle_id'],
                                           planned_run_id=run_id,finished_at_utc=utc(),validation_sha256=artifacts(folder)['validation_report.json']))
    progress('AWAITING_HOST_VERIFICATION')
    return 0


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--folder',required=True,type=Path);p.add_argument('--run-id',required=True)
    a=p.parse_args();raise SystemExit(collect(a.folder,a.run_id))
