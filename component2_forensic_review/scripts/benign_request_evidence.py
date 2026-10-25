"""Read canonical benign SCADA captures, retaining exact request evidence and causal context."""
from pathlib import Path
import sys,importlib.util,csv,json,struct,time
from collections import defaultdict,deque,Counter
import numpy as np

sys.dont_write_bytecode=True
OUT=Path(__file__).resolve().parents[1]; E=OUT/'evidence'
RAW=Path(r'G:\modbus cic 2023\Modbus Dataset')
PARSER=Path(__file__).with_name('pcapio.py')  # preserved SHA256-identical copy of inventoried C3 parser
spec=importlib.util.spec_from_file_location('c2_benign_readonly_pcapio',PARSER)
pc=importlib.util.module_from_spec(spec);sys.modules[spec.name]=pc;spec.loader.exec_module(pc)

def main():
    t0=time.monotonic();hist=defaultdict(lambda:deque(maxlen=20));seen=set();gens=defaultdict(int);stream_counts=Counter()
    report=[];counts=Counter();shapes=Counter();files=sorted((RAW/'benign/scada-hmi/scada-hmi-network-capture').glob('*.pcap'),key=lambda p:int(p.stem.split('-')[-1]))
    target=E/'benign_read_request_evidence.csv';writer=None
    with target.open('w',newline='',encoding='utf8') as out:
        for path in files:
            ct=Counter();mini=None;maxi=None
            with path.open('rb') as fh:
                h=pc.open_pcap(fh)
                for frame,sec,frac,caplen,origlen,data,offset in pc.iter_records(fh,h):
                    ct['frames']+=1
                    if data is None:ct['truncated_records']+=1;continue
                    us=sec*1_000_000+frac*1_000_000//h.ticks_per_second
                    mini=us if mini is None else min(mini,us);maxi=us if maxi is None else max(maxi,us)
                    kind,seg=pc.decode_l2l3l4(data,h.linktype)
                    if seg is None or seg.dst_port!=502:continue
                    stream=(seg.src_ip,seg.src_port,seg.dst_ip,seg.dst_port)
                    if seg.flags&2 and not seg.flags&16:gens[stream]+=1
                    if not seg.payload:continue
                    raw=seg.payload;off=0
                    while off+7<=len(raw):
                        tid,proto,length=struct.unpack_from('!HHH',raw,off)
                        if proto!=0 or length<2 or length>254:ct['unframed_payloads']+=1;break
                        end=off+6+length
                        if end>len(raw):ct['incomplete_single_segment_ADU']+=1;break
                        adu=raw[off:end];fc=adu[7];unit=adu[6]
                        if fc not in (1,2,3,4) or len(adu)<12:off=end;continue
                        addr=int.from_bytes(adu[8:10],'big');qty=int.from_bytes(adu[10:12],'big')
                        key=(stream,gens[stream],seg.seq+off,adu)
                        if key in seen:ct['retransmission_candidate_excluded']+=1;off=end;continue
                        seen.add(key)
                        hh=hist[(seg.src_ip,seg.dst_ip,unit)]
                        if hh and (us<hh[-1][0] or us-hh[-1][0]>60_000_000):hh.clear();ct['logical_context_resets']+=1
                        shape=(fc,addr,qty,length,caplen,unit)
                        stream_counts[(seg.src_ip,seg.dst_ip,unit)]+=1
                        systematic=stream_counts[(seg.src_ip,seg.dst_ip,unit)]%100==0
                        shape_exemplar=shapes[shape]<3
                        shapes[shape]+=1;ct['read_requests']+=1
                        if not systematic and not shape_exemplar:
                            hh.append((us,addr,fc));off=end;continue
                        aa=np.array([x[1] for x in hh],dtype=float);tt=np.array([x[0] for x in hh],dtype=np.int64);dd=np.diff(tt)/1e6
                        rr=dict(source_reference=str(path),source_relative_path=path.relative_to(RAW).as_posix(),capture_run='benign_SCADA_recording',
                            capture_chunk=path.name,frame_identity=frame,pcap_record_offset=offset,adu_offset_in_tcp_payload=off,timestamp_us=us,
                            src_ip=seg.src_ip,dst_ip=seg.dst_ip,src_tcp_port=seg.src_port,dst_tcp_port=seg.dst_port,
                            tcp_connection_generation_observed=gens[stream],unit_id=unit,func_code=fc,wire_function_code=fc,
                            modbus_len=length,address=addr,quantity_value=qty,packet_size=caplen,transaction_id=tid,adu_hex=adu.hex(),
                            previous_context_n=len(hh),previous_request_delta_s=(us-hh[-1][0])/1e6 if hh else None,
                            address_delta=addr-hh[-1][1] if hh else None,absolute_address_delta=abs(addr-hh[-1][1]) if hh else None,
                            unique_addresses_previous20=len(set(aa)),register_span_previous20=float(np.ptp(aa)) if len(aa) else None,
                            monotonic_increasing_fraction_previous20=float(np.mean(np.diff(aa)>0)) if len(aa)>1 else None,
                            function_transitions_previous20=sum(a[2]!=b[2] for a,b in zip(hh,list(hh)[1:])),
                            previous20_interval_mean_s=float(np.mean(dd)) if len(dd) else None,
                            previous20_interval_cv=float(np.std(dd)/np.mean(dd)) if len(dd) and np.mean(dd)>0 else None,
                            previous20_requests_per_s=(len(hh)-1)/((hh[-1][0]-hh[0][0])/1e6) if len(hh)>1 and hh[-1][0]>hh[0][0] else None,
                            causal_context_max_idle_gap_s=60,label_state='source_documented_benign_recording',
                            extraction_status='complete_ADU_within_single_TCP_segment',
                            context_sampling='systematic_every_100_per_logical_stream' if systematic else 'first_three_shape_exemplar',
                            read_request_ordinal_in_logical_stream=stream_counts[(seg.src_ip,seg.dst_ip,unit)])
                        if writer is None:writer=csv.DictWriter(out,fieldnames=list(rr));writer.writeheader()
                        writer.writerow(rr);hh.append((us,addr,fc));ct['context_rows_saved']+=1;off=end
            counts.update(ct);report.append(dict(source=path.relative_to(RAW).as_posix(),min_timestamp_us=mini,max_timestamp_us=maxi,counts=dict(ct)))
            print(json.dumps({'file':path.name,'requests':ct['read_requests'],'elapsed_s':round(time.monotonic()-t0,1)}),flush=True)
    with (E/'benign_request_shapes.csv').open('w',newline='') as fh:
        w=csv.writer(fh);w.writerow(['func_code','address','quantity_value','modbus_len','packet_size','unit_id','count'])
        for k,v in sorted(shapes.items()):w.writerow([*k,v])
    (E/'benign_raw_extraction.json').write_text(json.dumps(dict(counts=dict(counts),files=report,wall_s=time.monotonic()-t0,
        limitations=['one canonical benign HMI NIC view, all its rotation chunks','single-segment complete ADUs; no guessed TCP reassembly',
        '60s gap-aware logical endpoint/unit history crosses TCP connections by design; never asserts independent sessions',
        'documented benign scenario labels, rather than normality inferred from absence of an attack log',
        'all current-message shapes counted; causal temporal contexts saved every100th request per logical stream plus first3 shape exemplars; temporal distributions use systematic rows only']),indent=2))

if __name__=='__main__':main()
