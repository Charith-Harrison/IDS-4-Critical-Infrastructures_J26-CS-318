# Inspect saved coverage and feature evidence for the audit; this is not model training.
"""Audit-only coverage, shortcut and saved-model representation inspection."""
from collections import Counter,defaultdict
import csv
import gzip
import json
from pathlib import Path
import sys
HERE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(HERE))
from runtime import load_locked_models

# Read existing audit/model artifacts and write the additional inspection report.
def main():
    source=HERE/'data/collection'; out=HERE/'reports/audit_final_20261025'
    index=json.loads((source/'collection_complete.json').read_text())
    counts=Counter(); controls=Counter(); membership=defaultdict(set); examples=[]
    error='MX069-20261025T060458Z-f13e4f3b:e1851'
    for planned,entry in sorted(index['completed'].items()):
        folder=source/entry['attempt']; labels=[json.loads(l) for l in (folder/'verified_labels.jsonl').read_text().splitlines()]
        normal_pdu={(r['direction'],r['pdu_hex']) for r in labels if r['label']=='normal'}
        normal_adu={(r['direction'],r['adu_hex']) for r in labels if r['label']=='normal'}
        for r in labels:
            day=entry['attempt'].split('-')[1][:8]
            key=(entry['intended_evaluation_role'],r['independent_campaign_group'],day,planned,r['episode_id'],
                 r['destination_ip'] if r['role']=='request' else r['source_ip'],r['function_code'],r['pdu_hex'],r['label'],r['parse_state'],r['pair_state'])
            counts[key]+=1
            membership[(planned,r['episode_id'])].add(entry['intended_evaluation_role'])
            if r['label']!='normal':
                controls[(r['label'],'targets')]+=1
                controls[(r['label'],'same_run_normal_PDU')]+=int((r['direction'],r['pdu_hex']) in normal_pdu)
                controls[(r['label'],'same_run_normal_complete_ADU')]+=int((r['direction'],r['adu_hex']) in normal_adu)
            if r['event_id']==error:
                ordinal=next(i for i,a in enumerate(labels) if a['event_id']==error)
                examples=labels[max(0,ordinal-8):ordinal+1]
    with gzip.open(out/'pattern_coverage.csv.gz','xt',newline='',encoding='utf-8') as stream:
        w=csv.writer(stream);w.writerow(['evaluation_role','campaign','observed_day','planned_run','episode','server','function','pdu_hex','label','parse_state','pair_state','rows'])
        w.writerows([*k,v] for k,v in sorted(counts.items()))
    models=load_locked_models(); importance={}
    for name,model in models.items():
        names=model.named_steps['imputer'].get_feature_names_out()
        importance[name]=sorted([{'feature':str(n),'impurity_importance':float(v)} for n,v in zip(names,model.named_steps['rf'].feature_importances_,strict=True)],key=lambda r:-r['impurity_importance'])
    result={'status':'AUDIT_ONLY_NO_TRAINING','episodes':len(membership),'episodes_crossing_roles':sum(len(v)>1 for v in membership.values()),
            'matched_controls':[{ 'class':k[0],'scope':k[1],'rows':v} for k,v in sorted(controls.items())],
            'importance':importance,'importance_limit':'Impurity importance of saved trees is descriptive, not causal attribution; correlated engineered features share credit.',
            'error_scope':'Known original final D error inspected retrospectively; no retuning, new predictions or revised labels.'}
    (out/'representation.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'original_order_error_lineage.json').write_text(json.dumps(examples,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='importance'},indent=2))

if __name__=='__main__':main()
