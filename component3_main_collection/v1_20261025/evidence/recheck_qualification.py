"""Container check of preserved qualification only. Never captures or writes input."""
import sys
import json
from pathlib import Path
sys.path.insert(0,'/qualification03')
from c3qual.validation import validate

results=[]
for folder in sorted(Path('/qualified').glob('EQ*-*')):
    report=validate(folder,write=False)
    results.append(dict(recording=folder.name,status=report['status'],errors=report['errors']))
if len(results)!=14 or any(r['status']!='PASSED' for r in results):
    print(json.dumps(results,indent=2));raise SystemExit(2)
print(json.dumps(dict(status='PASSED',preserved_recordings_revalidated=14,new_captures=0,input_read_only=True,results=results),indent=2))
