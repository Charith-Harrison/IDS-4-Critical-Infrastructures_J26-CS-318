"""Portable read-only inspection/revalidation; never starts traffic or a model."""
from pathlib import Path
import argparse
import json
import sys
from collections import Counter
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from runtime.common import read,verify_package
from runtime.launcher import scan


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    verify_package();session=read(a.output/'collection_manifest.json')
    completed,attempts=scan(a.output.resolve(),session['collection_id'],session['image_id'])
    counts=Counter()
    for row in completed.values(): counts.update(row['receipt']['label_counts'])
    print(json.dumps(dict(status='ALL_104_VALIDATED' if len(completed)==104 else 'PARTIAL',
                         validated=len(completed),expected=104,label_counts=dict(counts),
                         accepted_planned_ids=sorted(completed),attempts=sum(map(len,attempts.values())),
                         preprocessing_or_models=False),indent=2))
