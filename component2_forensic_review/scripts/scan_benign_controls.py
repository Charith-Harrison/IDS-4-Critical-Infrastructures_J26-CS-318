"""Read-only full benign HMI-chain shape census and bounded causal controls."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json,struct,time
from collections import Counter,defaultdict,deque
from datetime import datetime,timezone
import numpy as np
import pandas as pd
from recover_raw_requests import OUT,E,RAW,pcapio,qstats


def main():
    paths=sorted((RAW/'benign/scada-hmi/scada-hmi-network-capture').glob('*.pcap'),key=lambda x:int(x.stem.split('-')[-1]))
    counts=Counter();shapes=Counter();addrs=Counter();hist=defaultdict(lambda:deque(maxlen=20));samples=[];reports=[];t0=time.monotonic();lastseq={}
    for path in paths:
        fcounters=Counter();lo=None;hi=None
        with path.open('rb') as fh:
            h=pcapio.open_pcap(fh)
            for frame,sec,frac,caplen,origlen,data,offset in pcapio.iter_records(fh,h):
                fcounters['frames']+=1
                if data is None:fcounters['truncated_records']+=1;continue
                us=sec*1000000+frac*1000000//h.ticks_per_second
                lo=us if lo is None else min(lo,us);hi=us if hi is None else max(hi,us)
                kind,seg=pcapio.decode_l2l3l4(data,h.linktype)
                if seg is None or seg.dst_port!=502 or not seg.payload:continue
                raw=seg.payload;off=0
                while off+7<=len(raw):
                    tid,proto,length=struct.unpack_from('!HHH',raw,off)
                    if proto or not 2<=length<=254:fcounters['noncanonical_unframed']+=1;break
                    end=off+6+length
                    if end>len(raw):fcounters['incomplete_single_segment_adu']+=1;break
                    adu=raw[off:end];unit=adu[6];fc=adu[7]&127
                    fcounters['complete_request_adus']+=1
                    key=(seg.src_ip,seg.src_port,seg.dst_ip,seg.dst_port)
                    sig=(seg.seq+off,adu)
                    if lastseq.get(key)==sig:
                        fcounters['retransmission_candidates']+=1;off=end;continue
                    lastseq[key]=sig
                    if fc in (1,2,3,4) and len(adu)==12:
                        address=int.from_bytes(adu[8:10],'big');quantity=int.from_bytes(adu[10:12],'big')
                        shape=(fc,quantity,length,caplen,seg.src_ip,seg.dst_ip,unit)
                        shapes[shape]+=1;addrs[(fc,address,quantity)]+=1
                        hk=(seg.src_ip,seg.dst_ip,unit);hh=hist[hk]
                        if hh and not 0<=us-hh[-1][0]<=60_000_000:hh.clear()
                        if shapes[shape]<=40 or shapes[shape]%500==0:
                            a=[x[1] for x in hh];dts=np.diff([x[0] for x in hh])/1e6 if len(hh)>1 else []
                            rr={'source_reference':str(path),'source_relative_path':path.relative_to(RAW).as_posix(),
                                'capture_run':'benign_January_recording','capture_chunk':path.name,'frame_identity':frame,
                                'pcap_record_offset':offset,'adu_offset_in_tcp_payload':off,'timestamp_us':us,
                                'timestamp':datetime.fromtimestamp(us/1e6,timezone.utc).isoformat(timespec='microseconds'),
                                'src_ip':seg.src_ip,'dst_ip':seg.dst_ip,'src_tcp_port':seg.src_port,'dst_tcp_port':seg.dst_port,
                                'unit_id':unit,'func_code':fc,'modbus_len':length,'address':address,
                                'quantity_value':quantity,'packet_size':caplen,'transaction_id':tid,'adu_hex':adu.hex(),
                                'raw_source_verified':True,'benign_ground_truth_verified':True,
                                'benign_evidence':'publisher benign scenario directory; no per-event experiment ledger',
                                'previous_context_n':len(hh),'previous_request_delta_s':(us-hh[-1][0])/1e6 if hh else None,
                                'address_delta':address-hh[-1][1] if hh else None,
                                'absolute_address_delta':abs(address-hh[-1][1]) if hh else None,
                                'unique_addresses_previous20':len(set(a)),
                                'register_span_previous20':max(a)-min(a) if a else None,
                                'monotonic_increasing_fraction_previous20':float(np.mean(np.diff(a)>0)) if len(a)>1 else None,
                                'function_transitions_previous20':sum(x[2]!=y[2] for x,y in zip(hh,list(hh)[1:])),
                                'previous20_interval_mean_s':float(np.mean(dts)) if len(dts) else None,
                                'previous20_interval_cv':float(np.std(dts)/np.mean(dts)) if len(dts) and np.mean(dts)>0 else None,
                                'previous20_requests_per_s':(len(hh)-1)/((hh[-1][0]-hh[0][0])/1e6) if len(hh)>1 and hh[-1][0]>hh[0][0] else None,
                                'causal_context_max_idle_gap_s':60}
                            samples.append(rr)
                        hh.append((us,address,fc))
                    off=end
        counts.update(fcounters);reports.append({'path':path.relative_to(RAW).as_posix(),'counts':dict(fcounters),
            'minimum_timestamp_us':lo,'maximum_timestamp_us':hi})
        print(json.dumps({'file':path.name,'requests':fcounters['complete_request_adus'],'seconds':round(time.monotonic()-t0,1)}),flush=True)
    pd.DataFrame(samples).to_csv(E/'benign_request_context.csv',index=False)
    pd.DataFrame([dict(zip(['func_code','quantity','modbus_len','packet_size','src_ip','dst_ip','unit_id'],k),count=v) for k,v in shapes.items()]).to_csv(E/'benign_current_request_shape_census.csv',index=False)
    pd.DataFrame([dict(zip(['func_code','address','quantity'],k),count=v) for k,v in addrs.items()]).to_csv(E/'benign_address_shape_census.csv',index=False)
    (E/'benign_request_census.json').write_text(json.dumps({'canonical_sources':len(paths),'counts':counts,
        'read_requests':sum(shapes.values()),'controls_saved':len(samples),'file_reports':reports,
        'limitations':['Complete single-segment ADUs only','Publisher benign directory is source scenario evidence; per-event ledger absent',
            'Controls sampled first40 per shape then every500th; distributions of saved controls are not unbiased population estimates'],
        'seconds':time.monotonic()-t0},indent=2)+'\n')


if __name__=='__main__':main()
