from pathlib import Path
import uuid
import os
import shutil
import tempfile
import hashlib
from .common import ROOT,PURPOSE,read,sha,atomic,planned,validator,artifacts,bundle_id,utc


def verify_attempt(folder,expected_run,collection_id):
    folder=Path(folder)
    request=read(folder/'attempt_request.json')
    if (request['planned_run_id'],request['collection_id'],request['source_bundle_id'])!=(expected_run,collection_id,bundle_id()):
        raise ValueError('Attempt identity/configuration belongs to another frozen collection')
    manifest=read(folder/'run_manifest.json');host=read(folder/'host_execution.json')
    if manifest['purpose']!=PURPOSE or manifest['planned_run']!=planned(expected_run):
        raise ValueError('Attempt purpose or frozen planned configuration differs')
    if host['source_bundle_id']!=bundle_id() or host['collection_id']!=collection_id:
        raise ValueError('Host execution identity differs')
    # The qualified validator compares an existing annotation file byte-for-byte
    # with its independent reconstruction only in write mode. Run it on a private
    # temporary view so disagreement cannot rewrite the original reports/labels.
    temp_root=folder.parent/'verification_tmp';temp_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='verify-',dir=temp_root) as name:
        temp=Path(name)
        if not temp.resolve().is_relative_to(temp_root.resolve()): raise ValueError('Unsafe verification temp path')
        for p in folder.iterdir():
            if not p.is_file(): continue
            target=temp/p.name
            if p.name in ('verified_labels.jsonl','validation_report.json'):
                shutil.copy2(p,target)
            else:
                try: os.link(p,target)
                except OSError: shutil.copy2(p,target)
        report=validator()(temp,write=True)
        if report['status']!='PASSED': raise ValueError('Host validation failed: '+'; '.join(report['errors']))
        if not (folder/'verified_labels.jsonl').is_file():
            shutil.copy2(temp/'verified_labels.jsonl',folder/'verified_labels.jsonl')
    stored=read(folder/'validation_report.json')
    for key in ('label_counts','message_count','transaction_count','capture_sha256','control_matches','causal_dependencies'):
        if stored[key]!=report[key]: raise ValueError('Runtime/host validation disagreement: '+key)
    return report


def quarantine(folder,reason,status):
    folder=Path(folder);labels=folder/'verified_labels.jsonl'
    if labels.exists(): labels.rename(folder/('verified_labels.unaccepted-'+uuid.uuid4().hex+'.jsonl'))
    atomic(folder/'attempt_disposition.json',dict(status=status,reason=reason,at_utc=utc(),accepted=False))


def fingerprints(folder):
    rows=[__import__('json').loads(s) for s in (Path(folder)/'application_ledger.jsonl').read_text(encoding='utf8').splitlines() if s]
    return {name:hashlib.sha256('\n'.join(r['direction']+':'+r[field] for r in rows).encode()).hexdigest()
            for name,field in (('ordered_adu_trace_sha256','adu_hex'),('ordered_pdu_trace_sha256','pdu_hex'))}


def assert_unique(fingerprints,prior):
    for receipt in prior:
        if any(fingerprints[k]==receipt.get(k) for k in fingerprints):
            raise ValueError('Duplicate ordered stream across planned groups; preserve and review, never fabricate independence')


def seal(folder,run_id,collection_id,elapsed,recovered=False,prior=()):
    report=verify_attempt(folder,run_id,collection_id)
    prints=fingerprints(folder);assert_unique(prints,prior)
    host=read(Path(folder)/'host_execution.json')
    result=dict(status='VALIDATED',planned_run_id=run_id,collection_id=collection_id,source_bundle_id=bundle_id(),
                image_id=host['image_id'],validated_at_utc=utc(),wall_seconds=elapsed,recovered_after_interrupt=recovered,
                label_counts=report['label_counts'],**prints,artifact_sha256=artifacts(folder,exclude=('completion.json',)))
    atomic(Path(folder)/'completion.json',result)
    return result


def verify_seal(folder,run_id,collection_id,image_id):
    folder=Path(folder);completion=read(folder/'completion.json')
    if (completion['planned_run_id'],completion['collection_id'],completion['source_bundle_id'],completion['image_id'])!=(run_id,collection_id,bundle_id(),image_id):
        raise ValueError('Sealed attempt frozen identity differs')
    for name,value in completion['artifact_sha256'].items():
        if Path(name).name!=name or sha(folder/name)!=value: raise ValueError('Completed artifact changed: '+name)
    report=verify_attempt(folder,run_id,collection_id)
    if completion['label_counts']!=report['label_counts'] or any(completion.get(k)!=v for k,v in fingerprints(folder).items()):
        raise ValueError('Sealed annotation counts/trace identity changed')
    return completion


def observed_progress(folder):
    folder=Path(folder)
    progress=read(folder/'progress.json') if (folder/'progress.json').exists() else dict(phase='STARTING',planned_transactions=None)
    path=folder/'application_ledger.jsonl';line_count=0
    if path.is_file():
        with path.open('rb') as f:
            for b in iter(lambda:f.read(1<<20),b''): line_count+=b.count(b'\n')
    progress['observed_complete_pairs']=line_count//2
    return progress
