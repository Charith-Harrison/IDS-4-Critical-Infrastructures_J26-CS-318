"""Strict ordered-observation CSV adapter. No fitting or feature-CSV ingestion."""
from collections import Counter,defaultdict
import csv
import hashlib
import io
import ipaddress
import re
from pathlib import Path
from demo_data import HERE,LOCKED,read,sha,checked_child
from observation_inference import infer_observations
from runtime import decode,load_locked_models

REQUIRED=('run_id','event_id','connection_id','observed_at_ns','direction','stream_offset','adu_hex','map_id')
ENDPOINTS=('source_ip','destination_ip','source_port','destination_port')
DERIVED=('tid','unit','function_code','pdu_hex','role')
LABEL_COLUMNS=('label','class','ground_truth','target','target_label')
OPTIONAL=ENDPOINTS+DERIVED+('observation_schema',)
SCHEMA='c3-modbus-observations-v1'
CLASSES=('normal','command_injection','response_injection')
MAX_BYTES=20*1024*1024
MAX_ROWS=100000
SOURCE=HERE/'data/collection'

def maps():
    path=HERE/'history/component3_main_collection/v1_20261025/frozen/protocol.json'
    if sha(path)!='7634b3187e53c029db5d4755c6c3cf9df6a7985ab8ad1c67d3ebf00662a43c48':
        raise ValueError('Public configuration changed')
    return {m['id']:m for m in read(path)['public_configuration']['maps']}

def integer(value,name,row):
    if not re.fullmatch(r'[0-9]+',value): raise ValueError(f'Row {row}: {name} must be a nonnegative integer')
    number=int(value)
    if number>2**63-1: raise ValueError(f'Row {row}: {name} exceeds int64')
    return number

def parse_csv(data):
    if isinstance(data,str): data=data.encode('utf-8')
    if len(data)>MAX_BYTES: raise ValueError('CSV exceeds 20 MiB')
    try: text=data.decode('utf-8-sig')
    except UnicodeDecodeError as exc: raise ValueError('CSV must use UTF-8') from exc
    reader=csv.DictReader(io.StringIO(text,newline=''),strict=True)
    headers=reader.fieldnames or []
    if len(headers)!=len(set(headers)): raise ValueError('Duplicate CSV column names')
    missing=set(REQUIRED)-set(headers)
    if missing:
        raise ValueError('This CSV does not contain the fields required to reconstruct Component 3 context. Missing: '+', '.join(sorted(missing)))
    unknown=set(headers)-set(REQUIRED+OPTIONAL+LABEL_COLUMNS)
    if unknown: raise ValueError('Unsupported columns: '+', '.join(sorted(unknown))+'. Use the observation template, not features or prediction reports.')
    labels=[key for key in LABEL_COLUMNS if key in headers]
    if len(labels)>1: raise ValueError('Use only one ground-truth column')
    endpoints=set(headers)&set(ENDPOINTS)
    if endpoints and endpoints!=set(ENDPOINTS): raise ValueError('Supply all four endpoint fields or omit all four')
    public_maps=maps(); rows=[]; seen=set(); group_maps={}
    try:
        for line,row in enumerate(reader,2):
            if len(rows)>=MAX_ROWS: raise ValueError('CSV exceeds 100,000 observations')
            if None in row or any(value is None for value in row.values()): raise ValueError(f'Row {line}: wrong field count')
            row={key:value.strip() for key,value in row.items()}
            for key in REQUIRED:
                if not row[key]: raise ValueError(f'Row {line}: {key} is required')
            if row.get('observation_schema',SCHEMA)!=SCHEMA: raise ValueError('Observation schema/version mismatch')
            if row['map_id'] not in public_maps: raise ValueError(f'Row {line}: unsupported public map')
            identity=(row['run_id'],row['event_id'])
            if identity in seen: raise ValueError(f'Row {line}: duplicate event ID within run')
            seen.add(identity)
            stream=(row['run_id'],row['connection_id'])
            if stream in group_maps and group_maps[stream]!=row['map_id']: raise ValueError('Public map changes within a connection; use a fresh connection generation')
            group_maps[stream]=row['map_id']
            for key in ('observed_at_ns','stream_offset'): row[key]=integer(row[key],key,line)
            if row['direction'] not in ('client_to_server','server_to_client'): raise ValueError(f'Row {line}: invalid direction')
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){8,260}',row['adu_hex']): raise ValueError(f'Row {line}: adu_hex must contain one complete 8–260-byte ADU')
            request=row['direction']=='client_to_server'
            raw=bytes.fromhex(row['adu_hex']); parsed=decode(raw,request)
            row['adu_hex']=raw.hex()
            for key,expected in [('tid',parsed['tid']),('unit',parsed['unit']),('function_code',parsed['function'])]:
                if key in row and integer(row[key],key,line)!=expected: raise ValueError(f'Row {line}: {key} disagrees with wire bytes')
            if 'pdu_hex' in row and row['pdu_hex'].lower()!=raw[7:].hex(): raise ValueError(f'Row {line}: PDU disagrees with ADU')
            if 'role' in row and row['role']!=('request' if request else 'response'): raise ValueError(f'Row {line}: role disagrees with direction')
            if endpoints:
                for key in ENDPOINTS[:2]:
                    try: row[key]=str(ipaddress.ip_address(row[key]))
                    except ValueError as exc: raise ValueError(f'Row {line}: invalid IP address') from exc
                for key in ENDPOINTS[2:]:
                    row[key]=integer(row[key],key,line)
                    if not 1<=row[key]<=65535: raise ValueError(f'Row {line}: invalid port')
            row['source_row']=line
            # Raw ground truth is held separately; never forwarded into state/X.
            row['_ground_truth']=row.get(labels[0],'') if labels else ''
            rows.append(row)
    except csv.Error as exc: raise ValueError('Malformed CSV: '+str(exc)) from exc
    if not rows: raise ValueError('CSV has no observations')
    return {'rows':rows,'ground_truth_column':labels[0] if labels else None,'sha256':hashlib.sha256(data).hexdigest()}

def ordered_streams(rows):
    groups=defaultdict(list)
    for row in rows: groups[(row['run_id'],row['connection_id'])].append(row)
    accepted=[]; rejected=[]; moved=0
    for key,stream in groups.items():
        times=[r['observed_at_ns'] for r in stream]
        if times!=sorted(times):
            if len(times)!=len(set(times)):
                rejected.append({'run_id':key[0],'connection_id':key[1],'rows':len(stream),'reason':'Out-of-order stream has tied timestamps; order is ambiguous'}); continue
            sorted_rows=sorted(stream,key=lambda r:r['observed_at_ns'])
            moved+=sum(a['source_row']!=b['source_row'] for a,b in zip(stream,sorted_rows))
            stream=sorted_rows
        accepted.append((key,stream))
    return accepted,rejected,moved

def manifest_registry(source=SOURCE):
    """Metadata-only matching. Never opens final capture/application payloads."""
    source=Path(source)
    lock=read(LOCKED/'artifacts/experiment_lock.json')
    if sha(LOCKED/'artifacts/experiment_lock.json')!='f59f8e8922de62afd28f610a2521d9c45c0ebc46cec35b587210f4da0c6181c9': raise ValueError('Experiment lock changed')
    if not (source/'collection_complete.json').is_file():
        path=LOCKED/'artifacts/actual_memberships.csv'
        if sha(path)!=lock['artifact_sha256']['actual_memberships.csv']: raise ValueError('Saved membership changed')
        with path.open(encoding='utf-8-sig',newline='') as handle:
            return [{'planned_id':r['planned_run_id'],'run_id':r['run_id'],'role':r['evaluation_role'],
                     'map_id':r['map'],'trace':None} for r in csv.DictReader(handle)]
    if sha(source/'collection_complete.json')!=lock['collection']['canonical_index_sha256']: raise ValueError('Collection index changed')
    roster_path=source/'_handover/source/collector/frozen/main_roster.json'
    if sha(roster_path)!='6d689dcc9c22faf49347082a55890ad76591fde2fa7652a4f5bf5bf61ecf11ad': raise ValueError('Frozen roster changed')
    plans={r['planned_run_id']:r for r in read(roster_path)['runs']}
    entries=[]
    for planned,entry in read(source/'collection_complete.json')['completed'].items():
        receipt=checked_child(source,entry['attempt'])/'completion.json'
        if sha(receipt)!=entry['completion_sha256']: raise ValueError('Run receipt changed')
        item=read(receipt)
        entries.append({'planned_id':planned,'run_id':entry['attempt'],'role':entry['intended_evaluation_role'],
                        'map_id':plans[planned]['map'],'trace':item['ordered_adu_trace_sha256']})
    return entries

def partition_status(run_id,rows,registry):
    trace=hashlib.sha256('\n'.join(r['direction']+':'+r['adu_hex'] for r in rows).encode()).hexdigest()
    exact=[r for r in registry if r['trace']==trace and all(row['map_id']==r['map_id'] for row in rows)]
    claimed=[r for r in registry if run_id in (r['run_id'],r['planned_id'])]
    selected=exact or claimed
    if not selected: return {'run_id':run_id,'role':'unknown','match':'none','badge':'EXTERNAL / UNKNOWN','note':'Not matched to the saved experiment manifest. Independence is not established.'}
    match='complete_byte_trace' if exact else 'run_id_only'
    role=selected[0]['role']
    if role=='train': badge='TRAINING RUN'; note='Training data — do not use this as independent performance evidence.'
    elif role=='validation': badge='VALIDATION RUN'; note='Development data — metrics are not independent test evidence.'
    else: badge='HELD-OUT TEST RUN'; note='Already-observed test data — uploaded metrics are exploratory. Official saved results stay unchanged.'
    if match=='run_id_only': note+=' Run ID matched; uploaded content is unverified or partial.'
    return {'run_id':run_id,'role':role,'match':match,'badge':badge,'note':note,'matched_run_id':selected[0]['run_id']}

def analyze_csv(data,models=None,registry=None,*,trusted_single_writer=False):
    if trusted_single_writer is not True:
        raise ValueError('CSV inference requires the declared single-writer/trusted-anchor testbed policy')
    parsed=parse_csv(data); streams,rejected,moved=ordered_streams(parsed['rows'])
    public_maps=maps(); registry=manifest_registry() if registry is None else registry
    models=load_locked_models() if models is None else models
    records=[]
    for (run,connection),rows in streams:
        try:
            # Each (run, connection generation) owns a fresh state machine.
            if 'source_ip' in rows[0]:
                endpoint=None
                for row in rows:
                    key=(row['source_ip'],row['source_port'],row['destination_ip'],row['destination_port'])
                    if row['direction']=='server_to_client': key=(key[2],key[3],key[0],key[1])
                    if endpoint is None: endpoint=key
                    if key!=endpoint: raise ValueError('Endpoint identity changes within connection')
            decoded,predictions=infer_observations(rows,public_maps[rows[0]['map_id']],models)
        except ValueError as exc:
            rejected.append({'run_id':run,'connection_id':connection,'rows':len(rows),'reason':str(exc)}); continue
        for row,observed,b,d in zip(rows,decoded,predictions['B'],predictions['D'],strict=True):
            truth=row['_ground_truth']
            wire=decode(bytes.fromhex(row['adu_hex']),row['direction']=='client_to_server')
            records.append({'source_row':row['source_row'],'event_id':row['event_id'],'run_id':run,
                'connection_id':connection,'observed_at_ns':row['observed_at_ns'],'map_id':row['map_id'],
                'unit':wire['unit'],'tid':wire['tid'],'wire_word':wire['word'],'quantity':wire['quantity'],
                'function':observed['function_code'],'wire_address':observed['wire_address'],
                'address_or_register':observed['address_or_register'],'direction':row['direction'],
                'adu_hex':row['adu_hex'],'stream_offset':row['stream_offset'],
                'eligible':observed['eligible'],'context_available':observed['context_available'],
                'prediction':d['prediction'],'packet_only':b['prediction'],'confidence':d['confidence'],
                'processing_status':d['processing_status'],'context_evidence':observed['evidence'],
                'ground_truth':truth,'correct':d['prediction']==truth if truth in CLASSES and d['prediction'] in CLASSES else None})
    # Rejected streams stay visible/exportable, with no invented predictions.
    for rejection in rejected:
        for row in parsed['rows']:
            if (row['run_id'],row['connection_id'])!=(rejection['run_id'],rejection['connection_id']): continue
            records.append({'source_row':row['source_row'],'event_id':row['event_id'],'run_id':row['run_id'],
                'connection_id':row['connection_id'],'observed_at_ns':row['observed_at_ns'],'map_id':row['map_id'],
                'direction':row['direction'],'adu_hex':row['adu_hex'],'stream_offset':row['stream_offset'],
                'function':bytes.fromhex(row['adu_hex'])[7]&127,'wire_address':None,'address_or_register':None,
                'eligible':None,'context_available':False,'prediction':None,'packet_only':None,'confidence':None,
                'processing_status':'rejected_stream','context_evidence':{},'ground_truth':row['_ground_truth'],
                'correct':None,'reason':rejection['reason']})
    # Partition claims never affect feature construction or predictions.
    run_rows=defaultdict(list)
    for row in parsed['rows']: run_rows[row['run_id']].append(row)
    statuses=[partition_status(run,sorted(rows,key=lambda r:(r['connection_id'],r['observed_at_ns'],r['source_row'])),registry)
              for run,rows in run_rows.items()]
    counts=Counter(r['prediction'] for r in records if r['prediction'] is not None)
    return {'schema':SCHEMA,'source_sha256':parsed['sha256'],'input_rows':len(parsed['rows']),
        'messages':len(records)-sum(r['rows'] for r in rejected),'runs':len(run_rows),
        'streams':len({(r['run_id'],r['connection_id']) for r in parsed['rows']}),
        'rows_reordered':moved,'rejected_streams':rejected,'rejected_rows':sum(r['rows'] for r in rejected),
        'predictions_produced':sum(counts[c] for c in CLASSES),'prediction_counts':dict(counts),
        'abstentions':counts['abstain'],'out_of_scope':counts['out_of_scope'],'records':records,
        'partition_status':statuses,'ground_truth_column':parsed['ground_truth_column'],
        'labels_used_for_prediction':False,'training_executed':False,'final_evaluation_executed':False}

def evaluate_predictions(result):
    from c3model.experiment import metrics
    labelled=[r for r in result['records'] if r['ground_truth']]
    invalid=sorted({r['ground_truth'] for r in labelled if r['ground_truth'] not in CLASSES})
    if invalid: raise ValueError('Unsupported ground-truth labels: '+', '.join(invalid)+'. Use normal, command_injection or response_injection.')
    scored=[r for r in labelled if r['prediction'] in CLASSES]
    report=metrics([r['ground_truth'] for r in scored],[r['prediction'] for r in scored])
    normal=[r for r in scored if r['ground_truth']=='normal']
    false=sum(r['prediction']!='normal' for r in normal)
    report.update(labelled_rows=len(labelled),labelled_abstentions=sum(r['prediction']=='abstain' for r in labelled),
                  labelled_out_of_scope=sum(r['prediction']=='out_of_scope' for r in labelled),
                  labelled_rejected=sum(r['processing_status']=='rejected_stream' for r in labelled),
                  false_positive_rate=false/len(normal) if normal else None,normal_denominator=len(normal),
                  partition_status=result['partition_status'],scope='UPLOADED_LABELS_EXPLORATORY_NOT_OFFICIAL_EXPERIMENT',
                  missing_classes=[c for c in CLASSES if not any(r['ground_truth']==c for r in scored)])
    return report

def prediction_csv(result):
    columns=('source_row','event_id','observed_at_ns','run_id','connection_id','function','unit','tid','wire_address','wire_word','quantity',
             'address_or_register','prediction','confidence','eligible','context_available','processing_status','ground_truth','correct','reason')
    output=io.StringIO(newline=''); writer=csv.DictWriter(output,fieldnames=columns); writer.writeheader()
    for record in result['records']: writer.writerow({k:record.get(k) for k in columns})
    return output.getvalue().encode('utf-8')

def observations_csv(rows,run_id=None,map_id=None):
    """Lossless public-observation export, distinct from a prediction report."""
    columns=REQUIRED+ENDPOINTS
    output=io.StringIO(newline=''); writer=csv.DictWriter(output,fieldnames=columns); writer.writeheader()
    for row in rows:
        item={key:row.get(key,'') for key in columns}
        if run_id is not None: item['run_id']=run_id
        if map_id is not None: item['map_id']=map_id
        writer.writerow(item)
    return output.getvalue().encode('utf-8')

def template_csv():
    # Synthetic format examples, not recorded research/evaluation data.
    pdus=['060001001e','060001001e','0300010001','0302001e']
    rows=[]; offsets={'client_to_server':0,'server_to_client':0}
    for i,pdu in enumerate(pdus):
        direction='client_to_server' if i%2==0 else 'server_to_client'; request=i%2==0
        raw=(b'\x00\x05\x00\x00'+(len(bytes.fromhex(pdu))+1).to_bytes(2,'big')+b'\x01'+bytes.fromhex(pdu)).hex()
        rows.append({'run_id':'example-run','event_id':f'example-e{i}','connection_id':'connection-0',
                     'observed_at_ns':1000000000+i*1000000,'direction':direction,
                     'stream_offset':offsets[direction],'adu_hex':raw,'map_id':'M0',
                     'source_ip':'127.0.0.1','destination_ip':'127.0.0.1',
                     'source_port':41000 if request else 15020,'destination_port':15020 if request else 41000})
        offsets[direction]+=len(bytes.fromhex(raw))
    return observations_csv(rows)
