"""Headroom checks: no cleanup, no assumptions about another host's drive letters."""
from pathlib import Path
from dataclasses import dataclass,asdict
import json
import os
import shutil
import sys

GIB=1<<30


@dataclass
class Limits:
    safety_factor:float=2.0
    planned_copies:int=2
    reserve_gib:float=2.0
    docker_reserve_gib:float=2.0

    def check(self):
        if not 1<=self.safety_factor<=10 or not 1<=self.planned_copies<=4:
            raise ValueError('SafetyFactor must be 1..10 and PlannedCopies 1..4')
        if self.reserve_gib<.25 or self.docker_reserve_gib<.25:
            raise ValueError('ReserveGiB and DockerReserveGiB must each be at least 0.25')


def nearest(path):
    path=Path(path).resolve()
    while not path.exists():
        parent=path.parent
        if parent==path: raise ValueError('Output drive/filesystem is unavailable')
        path=parent
    if not path.is_dir(): raise ValueError('Output path has a file as an ancestor')
    return path


def docker_backing_paths(info,override=None):
    if override:
        path=Path(os.path.expandvars(override)).expanduser().resolve()
        if not path.is_dir(): raise ValueError('DockerStoragePath must be an existing directory on the Docker data drive')
        return [path], 'operator-supplied Docker backing path'
    if sys.platform!='win32':
        path=Path(info['DockerRootDir'])
        if path.is_dir(): return [path.resolve()],'local engine DockerRootDir'
        raise ValueError('Cannot inspect DockerRootDir on this host; supply --docker-storage-path')
    candidates=[]
    settings=Path(os.environ.get('APPDATA',''))/'Docker/settings-store.json'
    if settings.is_file():
        data=json.loads(settings.read_text(encoding='utf-8-sig'))
        def walk(value):
            if not isinstance(value,dict): return
            for key,item in value.items():
                if isinstance(item,dict): walk(item)
                elif isinstance(item,str) and key.lower() in ('datafolder','diskimagelocation','wsldataroot'):
                    if item: candidates.append(Path(os.path.expandvars(item)))
        walk(data)
    candidates.append(Path(os.environ.get('LOCALAPPDATA',''))/'Docker/wsl')
    disks=[]
    for base in candidates:
        if not base.is_dir(): continue
        for pattern in ('*.vhdx','*/*.vhdx','*/*/*.vhdx'):
            disks.extend(p.resolve().parent for p in base.glob(pattern))
    if not disks:
        raise ValueError('Docker Desktop data disk not discovered. Supply --docker-storage-path with its actual backing directory.')
    return sorted(set(disks)), 'discovered existing Docker Desktop VHDX files'


def requirements(remaining,total,upper_per_run,limits):
    limits.check()
    # Reserve space for originals still to collect, an entire future handover copy,
    # one partial/retried run and temporary validation output. No automatic copy/delete.
    payload=(remaining+total*(limits.planned_copies-1)+2)*upper_per_run
    return int(limits.reserve_gib*GIB+limits.safety_factor*payload)


def check_space(output,backing,vm_free,remaining,total,upper_per_run,limits):
    need=requirements(remaining,total,upper_per_run,limits)
    groups={}
    def add(path,required,role):
        path=nearest(path)
        key=str(path.anchor).casefold() if sys.platform=='win32' else str(path.stat().st_dev)
        usage=shutil.disk_usage(path)
        item=groups.setdefault(key,dict(paths=[],roles=[],free=usage.free,required=0,total=usage.total))
        item['paths'].append(str(path));item['roles'].append(role);item['required']+=required
    add(output,need,'output originals, planned copies, temporary/retry allowance and reserve')
    seen=set()
    for path in backing:
        p=nearest(path);key=str(p.anchor).casefold() if sys.platform=='win32' else str(p.stat().st_dev)
        if key in seen: continue
        seen.add(key);add(p,int(limits.docker_reserve_gib*GIB),'Docker backing storage reserve')
    failures=[f"{x['paths']}: {x['free']/GIB:.2f} GiB free, {x['required']/GIB:.2f} GiB required"
              for x in groups.values() if x['free']<x['required']]
    if vm_free<int(limits.docker_reserve_gib*GIB):
        failures.append(f'Docker guest storage: {vm_free/GIB:.2f} GiB free below reserve')
    result=dict(status='FAILED' if failures else 'PASSED',limits=asdict(limits),host_filesystems=list(groups.values()),
                docker_guest_free=vm_free,output_required_bytes=need,upper_per_run_bytes=upper_per_run,
                copy_note='Headroom reserved; backup copies are not automatically created',failures=failures)
    if failures: raise ValueError('Insufficient storage; no deletion performed. '+'; '.join(failures))
    return result
