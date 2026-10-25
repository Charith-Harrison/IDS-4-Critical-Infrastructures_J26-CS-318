"""Restore/check candidate response hex directly against immutable source frames."""
import sys
sys.dont_write_bytecode=True
import struct,json
from collections import defaultdict
import pandas as pd
from recover_raw_requests import OUT,E,RAW,pcapio


def main():
    path=OUT/'recon_request_candidates.csv'
    c=pd.read_csv(path,dtype={'adu_hex':str,'response_adu_hex':str})
    targets=defaultdict(lambda:defaultdict(list))
    for i,r in c[c.response_frame_identity.notna()].iterrows():
        targets[r.response_source_reference][int(r.response_frame_identity)].append(i)
    records=[]
    for rel,frames in targets.items():
        with (RAW/rel).open('rb') as fh:
            h=pcapio.open_pcap(fh)
            for frame,sec,frac,caplen,origlen,data,offset in pcapio.iter_records(fh,h):
                if frame not in frames:continue
                kind,seg=pcapio.decode_l2l3l4(data,h.linktype)
                if seg is None:raise ValueError((rel,frame,'not TCP'))
                raw=seg.payload;off=0
                while off+8<=len(raw):
                    tid,proto,length=struct.unpack_from('!HHH',raw,off);end=off+6+length
                    if proto or not 2<=length<=254 or end>len(raw):break
                    adu=raw[off:end]
                    for i in frames[frame]:
                        r=c.loc[i]
                        if tid==r.transaction_id and adu[6]==r.unit_id and (adu[7]&127)==r.func_code:
                            old=r.response_adu_hex
                            c.loc[i,'response_adu_hex']=adu.hex()
                            c.loc[i,'response_pcap_record_offset']=offset
                            c.loc[i,'response_adu_offset_in_tcp_payload']=off
                            c.loc[i,'response_bytes_source_verified']=True
                            records.append({'candidate_id':r.candidate_id,'source_relative_path':rel,
                                'frame_identity':frame,'pcap_record_offset':offset,'adu_offset':off,
                                'response_adu_hex':adu.hex(),'previous_text':old,'already_exact':old==adu.hex()})
                    off=end
                if frame>=max(frames):break
        print(rel,len(frames),flush=True)
    if len(records)!=c.response_frame_identity.notna().sum():raise ValueError(('not all responses source-verified',len(records),int(c.response_frame_identity.notna().sum())))
    c.to_csv(path,index=False)
    pd.DataFrame(records).to_csv(E/'response_byte_reconciliation.csv',index=False)
    (E/'response_byte_reconciliation.json').write_text(json.dumps({'response_rows':len(records),
        'all_response_bytes_verified_from_original_frames':True,
        'numeric_text_coercion_repaired_from_immutable_raw_source':sum(not r['already_exact'] for r in records),
        'instruction':'Always read hex-byte CSV columns with explicit string dtype; never infer numbers'},indent=2)+'\n')


if __name__=='__main__':main()
