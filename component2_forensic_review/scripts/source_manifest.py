"""Read-only SHA256 inventory. Outputs only inside the forensic review directory."""
from pathlib import Path
import hashlib, json, sys, datetime

REVIEW = Path(__file__).resolve().parents[1]
REPO = REVIEW.parent
RAW = Path(r'G:\modbus cic 2023\Modbus Dataset')
ATTACHED = [Path(r'D:\VSCode\GitHub\4th Year Cyber\C2') / n for n in (
    'attack_events_mapped.xlsx','recon_labeled_packets_ALL.csv.xlsx',
    'recon_sequences_ALL.csv.xlsx','IT23269002_Charith H. (1).pdf')]
ATTACHED += [Path(r'D:\VSCode\GitHub\4th Year Cyber\References\IT4010-TAF-2026 J26-CS-318.pdf')]
ANCILLARY = [Path(r'D:\VSCode\GitHub\4th Year Cyber\C3\component3_preparation') / n for n in (
    'c3prep/pcapio.py','output/inventory.json','output/log_summary.json')]

def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''): h.update(b)
    return h.hexdigest()

def sources():
    for p in REPO.rglob('*'):
        if p.is_file() and '.git' not in p.parts and REVIEW not in p.parents:
            yield p, 'repository_existing', 'derived'
    for p in ATTACHED:
        if p.exists(): yield p, 'attached_research_or_processed_data', 'derived'
    for p in ANCILLARY:
        if p.exists(): yield p, 'existing_C3_readonly_parser_or_historical_cross_reference', 'derived'
    if RAW.exists():
        for p in RAW.rglob('*'):
            if p.is_file(): yield p, 'original_cic_distribution', ('raw' if p.suffix.lower() in ('.pcap','.csv') else 'source_documentation_or_upstream_derived')

def main():
    target=REVIEW/'source_manifest.json'
    if '--extend-dependencies' in sys.argv:
        result=json.loads(target.read_text('utf8'))
        found={r['path'] for r in result['files']}
        for p in ANCILLARY:
            if p.exists() and str(p) not in found:
                st=p.stat()
                result['files'].append(dict(path=str(p),size=st.st_size,sha256=digest(p),file_type=p.suffix,
                    role='existing_C3_readonly_parser_or_historical_cross_reference',raw_or_derived='derived',
                    modified_during_task=False,mtime_ns=st.st_mtime_ns,
                    baseline_note='Added upon identifying this ancillary read-only dependency'))
        target.write_text(json.dumps(result,indent=2),encoding='utf8')
        print('Extended baseline entries:',len(result['files']))
        return
    verify='--verify' in sys.argv
    old=json.loads(target.read_text('utf8')) if verify else None
    entries=[]
    for i,(p,role,kind) in enumerate(sources()):
        st=p.stat()
        entries.append(dict(path=str(p), size=st.st_size, sha256=digest(p), file_type=p.suffix.lower() or 'extensionless',
            role=role, raw_or_derived=kind, modified_during_task=False, mtime_ns=st.st_mtime_ns))
        if i%30==0: print(f'Hashed {i+1} files',flush=True)
    if verify:
        prior={x['path']:x for x in old['files']}
        for e in entries:
            b=prior.get(e['path'])
            e['sha256_before']=b['sha256'] if b else None
            e['modified_during_task']=None if b is None else e['sha256'] != b['sha256'] or e['size'] != b['size']
        result=dict(old)
        result.update(files=entries, verification_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            modified_source_count=sum(x['modified_during_task'] is True for x in entries),
            missing_since_baseline=sorted(set(prior)-{x['path'] for x in entries}),
            note='Source content hashes rechecked against baseline; review outputs and isolated dependencies excluded.')
    else:
        result=dict(created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            scope='All pre-existing non-Git repository files, five supplied attachments, and all files in user-identified original CIC distribution. Review outputs excluded.',
            raw_root=str(RAW), files=entries, verification_utc=None,
            modified_source_count=None, note='Before/after content verification pending until --verify is run.')
    target.write_text(json.dumps(result,indent=2),encoding='utf8')
    print(f"Inventory: {len(entries)} files; {sum(x['size'] for x in entries)} bytes; {target}",flush=True)

if __name__=='__main__': main()
