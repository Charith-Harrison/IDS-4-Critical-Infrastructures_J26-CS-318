"""Traffic-free frozen source identity and Docker guest disk probe."""
import json
import shutil
import sys
from .common import verify_package

if __name__=='__main__':
    data=verify_package()
    result={k:data[k] for k in ('bundle_id','source_configuration_sha256')}
    result['source_bundle_id']=result.pop('bundle_id')
    if '--disk' in sys.argv: result['disk_free']=shutil.disk_usage('/').free
    print(json.dumps(result))
