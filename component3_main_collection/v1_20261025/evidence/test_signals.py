"""Host signal-forwarding check only. Child opens no sockets/capture/collector."""
import json
from pathlib import Path
import subprocess
import time
import uuid

root=Path(__file__).resolve().parent.parent
name='c3manual-signal-test-'+uuid.uuid4().hex[:8]
collection='TEST_ONLY_NO_TRAFFIC'
image=json.loads((root/'image_identity.json').read_text(encoding='utf-8-sig'))['image_id']
command=['docker','run','--rm','--pull','never','--init','--name',name,'--network','none','--read-only','--cap-drop','ALL',
         '--label','component3.collection='+collection,image,'python','-B','-m','tools.lifecycle_probe']
flags=(subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP) if __import__('os').name=='nt' else 0
p=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,creationflags=flags)
try:
    ready=json.loads(p.stdout.readline())
    if ready['status']!='TEST_ONLY_READY': raise ValueError('Signal probe never became ready')
    stopped=subprocess.run(['docker','stop','--signal','SIGINT','--timeout','10',name],capture_output=True,text=True,creationflags=flags)
    if stopped.returncode: raise ValueError(stopped.stderr)
    out,err=p.communicate(timeout=15)
    result=json.loads(out.strip())
    if p.returncode!=0 or result['status']!='TEST_ONLY_INTERRUPTED': raise ValueError('Signal forwarding/cleanup failed: '+err)
    record=dict(status='PASSED',test='Protocol-free Docker SIGINT forwarding',traffic_generated=False,
                captures_created=0,background_service_left=False,commands=[command,['docker','stop','--signal','SIGINT','--timeout','10',name]])
    (root/'evidence/signal_check.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))
finally:
    if p.poll() is None:
        subprocess.run(['docker','stop','--signal','SIGINT','--timeout','10',name],capture_output=True,creationflags=flags)
        p.wait(timeout=15)
