"""Pair observed ADU rows conservatively; this is not TCP stream reassembly."""
import heapq
import pandas as pd


def reconstruct_transactions(messages, timeout=1.):
    if timeout <= 0: raise ValueError('timeout must be positive')
    transactions, orphans = [], []
    for scope, g in messages.groupby('segment_id',sort=False):
        pending = {}; expiry = []; serial = 0
        # Stable tie ordering uses retained CSV order; equal timestamps are flagged.
        g = g.sort_values(['timestamp','source_row'],kind='stable')
        end = g.timestamp.max()
        for row in g.to_dict('records'):
            now = row['timestamp']
            while expiry and expiry[0][0] < now:
                _,_,key,tx = heapq.heappop(expiry)
                if tx in pending.get(key,[]): pending[key].remove(tx)
            key = (row['session_proxy_id'],int(row['mbtcp_trans_id']),int(row['mbtcp_unit_id']),int(row['modbus_func_code']) & 0x7f)
            if row['is_request']==1:
                tx = dict(row)
                tx.update(transaction_id=row['source_row_id'],request_timestamp=now,
                          request_row_id=row['source_row_id'],request_label=row['is_attack'],
                          response_row_id=None,response_timestamp=None,response_label=None,
                          response_latency=None,label_conflict=False,match_status='response_not_observed',
                          request_label_target=row['is_attack'],ambiguity_observed=False,
                          right_censored=bool(now+timeout>end),timestamp_tie=False)
                transactions.append(tx)
                pending.setdefault(key,[]).append(tx)
                heapq.heappush(expiry,(now+timeout,serial,key,tx)); serial+=1
            else:
                candidates = pending.get(key,[])
                # Once collisions occur, do not greedily assign either reply. Retain
                # ambiguity for every candidate until they expire.
                if len(candidates)==1 and not candidates[0]['ambiguity_observed']:
                    tx = candidates.pop()
                    tx.update(response_row_id=row['source_row_id'],response_timestamp=now,
                              response_label=row['is_attack'],response_latency=now-tx['request_timestamp'],
                              match_status='matched',right_censored=False,
                              label_conflict=bool(tx['request_label']!=row['is_attack']),
                              timestamp_tie=bool(now==tx['request_timestamp']))
                else:
                    for tx in candidates:
                        tx.update(ambiguity_observed=True,match_status='ambiguous_unpaired')
                    reason = 'ambiguous_reply' if candidates else 'orphan_or_duplicate_or_late_reply'
                    orphans.append(dict(row,orphan_reason=reason,candidate_count=len(candidates)))
    tx = pd.DataFrame(transactions)
    if tx.empty:
        tx = pd.DataFrame(columns=list(messages.columns)+['transaction_id','request_label_target','match_status'])
    return tx, pd.DataFrame(orphans)
