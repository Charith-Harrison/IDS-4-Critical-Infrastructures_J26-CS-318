"""Unscored development-PCAP inference with the original saved RF models.

No application ledger, labels, server state or intervention log is read. The
qualified single-connection TCP reader is reused byte-for-byte from the bundle.
This is an offline replay demonstration, never another final evaluation.
"""
from collections import Counter
import importlib.util
from pathlib import Path
import struct
from demo_data import HERE,LOCKED,checked_child,read,sha
from runtime import Detector,load_locked_models,predict_batch
from observation_inference import infer_observations

SOURCE=HERE/'data/collection'
ATTACKS={'command_injection','response_injection'}
LOCK_SHA='f59f8e8922de62afd28f610a2521d9c45c0ebc46cec35b587210f4da0c6181c9'
PROTOCOL_SHA='7634b3187e53c029db5d4755c6c3cf9df6a7985ab8ad1c67d3ebf00662a43c48'
TRANSPORT_SHA='bd1bdf2acabeb26c5dff7fd3e677f68ce7029d1196b10f4cdd6ef2c839b479d6'

def development_captures(source=SOURCE):
    source=Path(source).resolve()
    lock_path=LOCKED/'artifacts/experiment_lock.json'
    if sha(lock_path)!=LOCK_SHA: raise ValueError('Unexpected experiment lock')
    lock=read(lock_path)
    if sha(source/'collection_complete.json')!=lock['collection']['canonical_index_sha256']:
        raise ValueError('Collection index differs from the locked experiment')
    index=read(source/'collection_complete.json')
    return {name:entry for name,entry in index['completed'].items()
            if entry['intended_evaluation_role'] in ('train','validation')}

def _transport(source):
    path=source/'_handover/source/collector/engine/c3qual/transport.py'
    if sha(path)!=TRANSPORT_SHA: raise ValueError('Qualified PCAP reader changed')
    spec=importlib.util.spec_from_file_location('c3_capture_transport',path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def wire_observations(capture,client_port,transport):
    """Read every ADU at its first complete wire observation, before filtering."""
    streams,lineage,statistics=transport._read_pcap(capture,15020,client_port)
    capture_sha=sha(capture); pending=[]
    for direction,stream in streams.items():
        start=0
        while start<len(stream):
            if len(stream)-start<7: raise ValueError('Incomplete Modbus header')
            _,pid,length,_=struct.unpack_from('!HHHB',stream,start)
            if pid!=0 or not 2<=length<=254 or start+6+length>len(stream):
                raise ValueError('Invalid/incomplete Modbus ADU; replay stopped')
            raw=stream[start:start+6+length]
            refs=transport._message_refs(lineage[direction],start,len(raw))
            first=min(ref['frame_number'] for ref in refs)
            complete=max(min(item['frame_number'] for item,_ in lineage[direction][start+k])
                         for k in range(len(raw)))
            complete_time=next(ref['capture_timestamp_ns'] for ref in refs if ref['frame_number']==complete)
            request=direction=='client_to_server'
            pending.append({'connection_id':'pcap:'+capture_sha[:16],
                'direction':direction,'stream_offset':start,'adu_hex':raw.hex(),
                'observed_at_ns':complete_time,'source_ip':'127.0.0.1','destination_ip':'127.0.0.1',
                'source_port':client_port if request else 15020,
                'destination_port':15020 if request else client_port,
                'wire_first_frame':first,'wire_complete_frame':complete,'frame_byte_references':refs})
            start+=len(raw)
    pending.sort(key=lambda row:row['wire_complete_frame'])
    previous=0
    for ordinal,row in enumerate(pending):
        if row['wire_first_frame']<=previous:
            raise ValueError('Overlapping observations exceed the qualified one-outstanding-request scope')
        previous=row['wire_complete_frame']
        row['event_id']=f'pcap:{capture_sha[:16]}:e{ordinal}'
    return pending,statistics

def replay_capture(planned_id,source=SOURCE,models=None):
    source=Path(source).resolve()
    entries=development_captures(source)
    if planned_id not in entries:
        raise ValueError('Replay is restricted to accepted training/validation captures')
    entry=entries[planned_id]; folder=checked_child(source,entry['attempt'])
    if sha(folder/'completion.json')!=entry['completion_sha256']: raise ValueError('Run receipt changed')
    receipt=read(folder/'completion.json')
    for name in ('capture.pcap','run_manifest.json','planned_run.json'):
        if sha(folder/name)!=receipt['artifact_sha256'][name]: raise ValueError('Changed replay input: '+name)
    protocol_path=source/'_handover/source/collector/frozen/protocol.json'
    if sha(protocol_path)!=PROTOCOL_SHA: raise ValueError('Public map/policy changed')
    protocol=read(protocol_path); plan=read(folder/'planned_run.json'); manifest=read(folder/'run_manifest.json')
    mapping=next(m for m in protocol['public_configuration']['maps'] if m['id']==plan['map'])
    observations,statistics=wire_observations(folder/'capture.pcap',manifest['client_port'],_transport(source))
    decoded,predictions=infer_observations(observations,mapping,models)
    records=[]
    for ordinal,(wire,observed) in enumerate(zip(observations,decoded,strict=True)):
        current=predictions['D'][ordinal]; baseline=predictions['B'][ordinal]
        records.append({'message_number':ordinal+1,'event_id':wire['event_id'],
                        'direction':wire['direction'],'function':observed['function_code'],
                        'eligible':observed['eligible'],'context_available':observed['context_available'],
                        'processing_status':current['processing_status'],'packet_only':baseline['prediction'],
                        'context_aware':current['prediction'],'confidence':current['confidence'],
                        'wire_complete_frame':wire['wire_complete_frame'],'stream_offset':wire['stream_offset'],
                        'adu_hex':wire['adu_hex'],'frame_byte_references':wire['frame_byte_references'],
                        'context_evidence':observed['evidence']})
    counts=Counter(r['context_aware'] for r in records)
    return {'kind':'DEVELOPMENT_PCAP_INFERENCE_NOT_FINAL_EVALUATION','planned_id':planned_id,
            'run_id':entry['attempt'],'role':entry['intended_evaluation_role'],
            'pcap':str((folder/'capture.pcap').relative_to(HERE.parent)),
            'capture_sha256':receipt['artifact_sha256']['capture.pcap'],
            'messages':len(records),'eligible':sum(bool(r['eligible']) for r in records),
            'alerts':sum(counts[name] for name in ATTACKS),'abstentions':counts['abstain'],
            'out_of_scope':counts['out_of_scope'],'prediction_counts':dict(counts),
            'capture_statistics':statistics,'records':records,'labels_used':False,
            'observations':[dict(row,run_id=entry['attempt'],map_id=plan['map']) for row in observations],
            'training_executed':False,'final_evaluation_executed':False}
