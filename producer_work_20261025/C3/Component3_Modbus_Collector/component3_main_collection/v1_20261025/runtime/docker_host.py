import json
import os
import subprocess
from .common import ROOT,read,verify_package


def hidden_flags():
    return (subprocess.CREATE_NO_WINDOW|subprocess.CREATE_NEW_PROCESS_GROUP) if os.name=='nt' else 0


class Docker:
    def __init__(self): self.commands=[]

    def call(self,args,timeout=60):
        command=['docker',*map(str,args)];self.commands.append(command)
        p=subprocess.run(command,capture_output=True,text=True,timeout=timeout,creationflags=hidden_flags())
        if p.returncode: raise RuntimeError('Docker failed: '+' '.join(command)+'\n'+p.stderr.strip())
        return p.stdout.strip()

    def json(self,args): return json.loads(self.call(args))

    def preflight(self):
        frozen=verify_package();receipt=read(ROOT/'image_identity.json')
        if receipt['source_bundle_id']!=frozen['bundle_id']: raise ValueError('Image receipt belongs to another freeze')
        info=self.json(['info','--format','{{json .}}'])
        if info['OSType']!='linux': raise ValueError('Docker Linux containers are required')
        context=self.json(['context','inspect'])[0]
        endpoint=context['Endpoints']['docker']['Host']
        if not endpoint.startswith(('npipe:','unix:')):
            raise ValueError('Only a local Docker engine is supported for safe host-path/storage checks')
        image=self.json(['image','inspect','--format','{{json .}}',receipt['image_id']])
        if image['Id']!=receipt['image_id']: raise ValueError('Frozen image identity differs')
        # This short-lived read-only process opens no sockets and captures no traffic.
        identity=self.json(['run','--rm','--pull','never','--network','none','--read-only','--cap-drop','ALL',
                            '--memory','128m','--pids-limit','32',image['Id'],'python','-B','-m','runtime.identity','--disk'])
        if identity['source_bundle_id']!=frozen['bundle_id'] or identity['source_configuration_sha256']!=frozen['source_configuration_sha256']:
            raise ValueError('Local/image frozen source/configuration mismatch')
        return dict(image_id=image['Id'],source_bundle_id=frozen['bundle_id'],docker_guest_free=identity['disk_free'],
                    engine={k:info.get(k) for k in ('ID','Name','ServerVersion','OSType','OperatingSystem','DockerRootDir','Architecture','KernelVersion')},
                    context_endpoint=endpoint,docker_version=self.json(['version','--format','{{json .}}']),
                    compose_version=self.call(['compose','version','--short']))

    def owned_running(self,name,collection_id):
        try: obj=self.json(['inspect',name])[0]
        except RuntimeError as exc:
            if 'no such' in str(exc).lower(): return False
            raise
        if (obj['Config'].get('Labels') or {}).get('component3.collection')!=collection_id:
            raise ValueError('Refusing to signal a container not owned by this collection')
        return obj['State']['Running']

    def stop(self,name,collection_id):
        if self.owned_running(name,collection_id):
            try: self.call(['stop','--signal','SIGINT','--timeout','30',name],timeout=45)
            except RuntimeError as exc:
                if 'no such' not in str(exc).lower(): raise

    def launch(self,root,folder,run_id,name,collection_id,image_id,log):
        args=['run','--rm','--pull','never','--init','--name',name,'--network','none','--read-only',
              '--cap-drop','ALL','--cap-add','NET_RAW','--cap-add','SETGID','--security-opt','no-new-privileges:true',
              '--tmpfs','/tmp:size=32m','--memory','256m','--cpus','1','--pids-limit','64',
              '--label','component3.collection='+collection_id,'--label','component3.planned_run='+run_id,
              '--mount',f'type=bind,source={root},target=/output','--env','C3_MAIN_MANUAL_CONTAINER=1',
              image_id,'python','-B','-m','runtime.collector','--folder','/output/'+folder.name,'--run-id',run_id]
        command=['docker',*args];self.commands.append(command)
        return subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,creationflags=hidden_flags())
