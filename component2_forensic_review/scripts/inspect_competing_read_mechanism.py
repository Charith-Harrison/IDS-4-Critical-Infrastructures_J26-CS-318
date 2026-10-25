"""Inspect original external log context for old positive quantity-20 reads.

Nearest event is contextual evidence only; supplied binary labels are unchanged.
"""
from pathlib import Path
from datetime import datetime,timezone
import csv,bisect
import pandas as pd

OUT=Path(__file__).resolve().parents[1];E=OUT/'evidence'
SOURCE=Path(r'G:\modbus cic 2023\Modbus Dataset\attack\external\external-attacker\attacker logs\02-01-2023\02-01-2023-1.csv')


def main():
    p=pd.read_csv(OUT/'label_provenance.csv',keep_default_na=False,dtype={'raw_bytes':str,'matching_request_adu_hex':str}).astype(object)
    q=p[p.cohort.eq('nonroutine_read_quantity_shape')&p.quantity.eq(20)&p.label_state.ne('supported_contextual')]
    times=pd.to_datetime(q.timestamp,format='mixed',utc=True).dt.as_unit('us').astype('int64')
    rows=[]
    with SOURCE.open(newline='',encoding='utf-8-sig') as fh:
        for i,r in enumerate(csv.DictReader(fh),2):
            us=int(datetime.fromisoformat(r['Timestamp']).replace(tzinfo=timezone.utc).timestamp()*1e6)
            rows.append((us,i,r['Attack']))
    rows.sort();index=[r[0] for r in rows];output=[]
    for (i,packet),us in zip(q.iterrows(),times):
        at=bisect.bisect_left(index,us)
        possibilities=rows[max(0,at-2):at+2]
        event=min(possibilities,key=lambda x:abs(x[0]-us))
        reference=str(SOURCE)+'#row='+str(event[1])
        output.append({'processed_row_id':packet.original_processed_row_id,'timestamp':packet.timestamp,
            'file':packet.file_source,'quantity':packet.quantity,'nearest_attack_log':event[2],
            'nearest_log_reference':reference,'packet_minus_log_us':int(us-event[0]),
            'context_only_not_exact_attack_label':True})
        p.loc[i,'associated_nonrecon_log_reference']=reference
        p.loc[i,'associated_nonrecon_log_attack']=event[2]
        p.loc[i,'associated_nonrecon_log_delta_us']=int(us-event[0])
        reason=' Original external log closest context is '+event[2]+' ('+str(int(us-event[0]))+'us packet-minus-log), competing with a recon interpretation; proximity alone does not label the full interval.'
        if reason not in p.loc[i,'evidence_reason']:p.loc[i,'evidence_reason']+=reason
    pd.DataFrame(output).to_csv(E/'unsupported_read_nearest_original_events.csv',index=False)
    p.to_csv(OUT/'label_provenance.csv',index=False)
    print(pd.DataFrame(output).groupby('nearest_attack_log').size().to_dict())


if __name__=='__main__':main()
