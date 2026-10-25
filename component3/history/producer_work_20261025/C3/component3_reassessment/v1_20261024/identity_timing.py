"""Original-byte/source-row lineage and timing, without relabelling."""
from collections import Counter, defaultdict
import csv
import re
from decimal import Decimal, ROUND_HALF_EVEN
from zipfile import ZipFile
import xml.etree.ElementTree as ET

import pyarrow.parquet as pq
from common import BASE, RAW, OUT, read, write, day, stats
from bounded_pilot import raw_record


def workbook_rows(path):
    ns={'m':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
    with ZipFile(path) as z:
        strings=[]
        if 'xl/sharedStrings.xml' in z.namelist():
            strings=[''.join(n.itertext()) for n in ET.fromstring(z.read('xl/sharedStrings.xml')).findall('m:si',ns)]
        wb=ET.fromstring(z.read('xl/workbook.xml'))
        prop=wb.find('m:workbookPr',ns)
        is1904=prop is not None and prop.get('date1904','0').lower() in ('1','true')
        rels={e.get('Id'):e.get('Target') for e in ET.fromstring(z.read('xl/_rels/workbook.xml.rels'))}
        for s in wb.findall('m:sheets/m:sheet',ns):
            rel=rels[s.get('{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id')]
            target=rel.lstrip('/') if rel.startswith('/') else 'xl/'+rel
            with z.open(target) as f:
                headers=None
                for _,r in ET.iterparse(f,events=('end',)):
                    if not r.tag.endswith('}row'):continue
                    cells={}
                    for c in r.findall('m:c',ns):
                        col=''.join(x for x in c.get('r','') if x.isalpha())
                        v=c.find('m:v',ns);text=v.text if v is not None else ''
                        if c.get('t')=='s':text=strings[int(text)]
                        elif c.get('t')=='inlineStr':text=''.join(c.itertext())
                        cells[col]=text
                    if headers is None:headers=cells
                    else:yield s.get('name'),int(r.get('r')),{headers[k]:v for k,v in cells.items()},is1904
                    r.clear()


def run():
    bundle=read(OUT/'event_examples.json')
    accepted=bundle['accepted_attacks']
    examples=bundle['examples']
    # Add representative candidates that disappear/appear, including exact ties.
    ids={uid for t in read(OUT/'cohort_diagnostics.json')['window_transitions'] for uid in t['appearing_examples']+t['disappearing_examples']}
    present={e['event']['event_uid'] for e in examples}
    more=pq.read_table(BASE/'output/extraction/scada_ied1a/events.parquet',filters=[('event_uid','in',sorted(ids-present))]).to_pylist() if ids-present else []
    rawchecks=[]
    checkpoints={view:read(BASE/f'output/extraction/{view}/checkpoint.json') for view in ('scada_ied1a','ied_ied1b')}
    metadata=[]
    for ex in examples:
        metadata.append((ex['event'],ex.get('log_lineage',[]),ex['category']))
    for ev in more:metadata.append((ev,[],'window_transition_example'))
    for ev in accepted:metadata.append((ev,ev['log_signature_lineage'],'frozen_accepted_'+ev['component_label']))
    needed=defaultdict(set)
    for ev,logs,category in metadata:
        for log in logs:needed[log['source_path']].add((log['source_sheet'],log['source_row']))
    original={}
    for path,wanted in needed.items():
        if path.endswith('.csv'):
            with (RAW/path).open(newline='',encoding='utf-8-sig') as f:
                for i,r in enumerate(csv.DictReader(f),2):
                    if (None,i) in wanted:original[(path,None,i)]=r
        else:
            for sheet,row,r,is1904 in workbook_rows(RAW/path):
                if (sheet,row) in wanted:original[(path,sheet,row)]={**r,'_date_system':'1904' if is1904 else '1900'}
    residuals=defaultdict(list);days=defaultdict(list);signs=Counter();actual_clock_checks=[]
    seen=set()
    for ev,logs,category in metadata:
        if (ev['event_uid'],category) in seen:continue
        seen.add((ev['event_uid'],category))
        sources={r['chunk']:r for r in checkpoints[ev['view_id']]['contract']['sources']}
        frames=[raw_record(RAW/sources[s['chunk']]['path'],s['pcap_offset'],s['frame']) for s in ev['segment_refs']]
        complete_matches=[a for f in frames for a in f['decoded'].get('adus',[]) if a['adu_hex']==ev['adu_bytes']]
        # JSON rendered bytes from event_examples are hex strings; Arrow extra
        # events are bytes. Keep comparison lossless for both input mechanisms.
        expected=ev['adu_bytes'].hex() if isinstance(ev['adu_bytes'],bytes) else ev['adu_bytes']
        complete_matches=[a for f in frames for a in f['decoded'].get('adus',[]) if a['adu_hex']==expected]
        entries=[]
        for log in logs:
            key=(log['source_path'],log['source_sheet'],log['source_row'])
            row=original[key]
            direct_tid=int(row['TransactionID'])
            attack=row['Attack'];target=row['TargetIP']
            if key[1]:
                rawserial=row['Timestamp'];origin=Decimal('24107') if row['_date_system']=='1904' else Decimal('25569')
                timestamp=int(((Decimal(rawserial)-origin)*Decimal('86400000000')).to_integral_value(rounding=ROUND_HALF_EVEN))
            else:
                from datetime import datetime
                d=datetime.fromisoformat(row['Timestamp'])-datetime(1970,1,1)
                timestamp=(d.days*86400+d.seconds)*1000000+d.microseconds
            equal=(direct_tid==ev['mbap_trans_id'] and target==(ev['server_ip'] if ev['protocol_role']=='request' else ev['client_ip'])
                   and attack==log['attack_original'] and timestamp==log['timestamp_us_candidate_utc'])
            coil=re.search(r'Address:\s*(\d+)',attack)
            if coil and ev['protocol_role']=='request':equal=equal and int(coil.group(1))==ev['address']
            entries.append({'log_signature_id':log['log_signature_id'],'source_path':key[0],'sheet':key[1],'row':key[2],
                            'original_fields':row,'candidate_utc_us':timestamp,'identity_fields_agree':equal,
                            'original_logged_coil_address':int(coil.group(1)) if coil else None,
                            'event_complete_residual_us':ev['ts_complete_us']-timestamp})
            if category.startswith('frozen_accepted_'):
                residual=ev['ts_complete_us']-timestamp
                label=ev['component_label'];residuals[label].append(residual);days[(label,day(timestamp))].append(residual)
                signs[(label,'negative' if residual<0 else 'zero' if residual==0 else 'positive')]+=1
        rawchecks.append({'event_uid':ev['event_uid'],'category':category,'connection_generation':ev['conn_uid'],
            'endpoint_tuple':[ev['client_ip'],ev['client_port'],ev['server_ip'],ev['server_port']],
            'event_first_us':ev['ts_first_us'],'event_complete_us':ev['ts_complete_us'],'assembly_delay_us':ev['ts_complete_us']-ev['ts_first_us'],
            'tid':ev['mbap_trans_id'],'address':ev['address'],'single_value':ev['single_value'],
            'adu_hex':expected,'pdu_hex':expected[14:],'parse_status':ev['parse_status'],
            'raw_frame_observations':frames,'whole_adu_bytes_verified_in_raw_frame':bool(complete_matches),
            'raw_verification_limit':None if complete_matches else 'Segmented record needs independent stream reconstruction; no fabricated byte agreement.',
            'original_log_rows':entries,'pair_audit':ev.get('pair_audit')})
    acceptedchecks=[r for r in rawchecks if r['category'].startswith('frozen_accepted_')]
    assert len(acceptedchecks)==154 and all(r['whole_adu_bytes_verified_in_raw_frame'] and all(l['identity_fields_agree'] for l in r['original_log_rows']) for r in acceptedchecks)
    # Raw response/exception details remain observations, not process success.
    wanted=defaultdict(set)
    for ev in accepted:
        p=ev['pair_audit']
        counterpart=p['response_uid'] if ev['protocol_role']=='request' else p['request_uid']
        if counterpart:wanted[ev['view_id']].add(counterpart)
    counterparts={}
    for view,ids in wanted.items():
        cols=['event_uid','conn_uid','protocol_role','func_raw','exception_code','address','quantity','single_value','pdu_bytes','parse_status','ts_complete_us','first_chunk','first_frame','segment_refs']
        for r in pq.read_table(BASE/f'output/extraction/{view}/events.parquet',columns=cols,filters=[('event_uid','in',sorted(ids))]).to_pylist():
            counterparts[r['event_uid']]=r
    outcomes=Counter();relations=[]
    for ev in accepted:
        p=ev['pair_audit'];other=p['response_uid'] if ev['protocol_role']=='request' else p['request_uid']
        partner=counterparts.get(other)
        outcomes[(ev['component_label'],p['status'],partner.get('exception_code') if partner else None)]+=1
        relations.append({'accepted_event_uid':ev['event_uid'],'label':ev['component_label'],'pair_state':p['status'],
            'counterpart':partner,'interpretation':'Documented injection attempt; exception/rejection observed, no demonstrated state change' if p['status']=='matched_exception'
            else ('Reply not observed; neither success nor failure established' if p['status'].startswith('pending_')
            else 'Pair/shape evidence only; physical impact and authorization not inferred')})
    write('identity_byte_log_examples.json',{'all_154_accepted_original_byte_and_log_checks_pass':True,'accepted_events_checked':154,'examples':rawchecks})
    write('mechanism_parse_pair_impact.json',{'outcome_counts':[{'class':k[0],'pair_state':k[1],'observed_counterpart_exception_code':k[2],'accepted_adus':n} for k,n in outcomes.items()],
        'relations':relations,'separation_rules':['Attack log records attempted behavior; it is not process outcome instrumentation.',
            'A valid exception can reject a request; no reply is not proof of failure.',
            'A genuine acknowledgement associated with a command stays an acknowledgement, not forged response.',
            'Parser-ok is syntactic only. No units, register meaning, expected values, authorization policy or process impact established.']})
    timing={'accepted_residual_us':{k:stats(v) for k,v in residuals.items()},
            'by_family_day':[{'accepted_class':k[0],'candidate_utc_day':k[1],'residual_us':stats(v)} for k,v in sorted(days.items())],
            'signed_residual_counts':[{'class':k[0],'sign':k[1],'adus':n} for k,n in signs.items()],
            'timestamp_compared':'Reassembled ADU ts_complete_us. First/complete and source-frame times shown separately for every example.',
            'offset_evidence':read(BASE/'output/label_report.json')['clock_calibration'],
            'drift_finding':'Accepted daywise residuals describe a strongly selected cohort. No independent clock synchronization/configuration or attacker source exists locally; offset/jitter/drift cannot be identified globally from these matches. Zero offset has observed family/campaign support, not proof for every log.',
            'precision_limit':'Millisecond text serialization versus microsecond PCAP storage creates quantization uncertainty; neither precision establishes timestamp accuracy or call ordering.'}
    write('identity_and_clock_audit.json',timing)
    print('identity',len(rawchecks),'stratified examples; all154 accepted byte/log checks pass',flush=True)


if __name__=='__main__':
    run()
