"""Reproduce bounded CIC reassessment, preserving the complete frozen baseline."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from common import HERE, OUT, REPO, CONFIG, BASE, REVIEW, freeze, verify_frozen, read, write, sha

STAGES={
 'cohort.py':['cohort_diagnostics.json','review_reproduction.json','diagnostic_candidates.json','event_examples.json','accepted_class_campaign_day_endpoint_function_pdu_parse_pair.csv'],
 'logs_audit.py':['original_log_timing_and_coverage.json'],
 'bounded_pilot.py':['bounded_pilot_summary.json','bounded_raw_evidence.json'],
 'identity_timing.py':['identity_byte_log_examples.json','identity_and_clock_audit.json','mechanism_parse_pair_impact.json'],
 'overlap_plan.py':['view_overlap_samples.json','expanded_scope_plan.json'],
 'temporal_feasibility.py':['temporal_feasibility.json'],
 'report.py':['shortcut_risks.json','proposed_policy_v2_not_adopted.json','decision.json'],
}


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--refresh',action='store_true');args=ap.parse_args()
    t0=time.monotonic();freeze()
    manifest_path=OUT/'execution_manifest.json'
    old=read(manifest_path) if manifest_path.exists() else {}
    code={p.name:sha(p) for p in sorted(HERE.glob('*.py'))}
    contract={'code_sha256':code,'config_sha256':sha(HERE/'config.json'),
              'frozen_baseline_manifest_sha256':sha(OUT/'baseline_frozen.json'),
              'review_sha256':{p.name:sha(p) for p in sorted(REVIEW.glob('*')) if p.is_file()}}
    stages={}
    windows_flags=getattr(subprocess,'CREATE_NO_WINDOW',0) if os.name=='nt' else 0
    def stage(name):
        outputs=STAGES[name];oldstage=old.get('stages',{}).get(name,{})
        if not args.refresh and old.get('contract')==contract and oldstage.get('exit_code')==0 and all((OUT/o).is_file() and sha(OUT/o)==oldstage.get('output_sha256',{}).get(o) for o in outputs):
            result={**oldstage,'this_invocation':'verified_cache_reused'}
            print(name+': verified cached diagnostics reused',flush=True)
            return name,result
        command=[sys.executable,'-B',str(HERE/name)]
        begin=time.monotonic()
        r=subprocess.run(command,cwd=REPO,capture_output=True,text=True,creationflags=windows_flags)
        result={'exact_command_arguments':command,'code_sha256':code[name],
                'config_sha256':contract['config_sha256'],'exit_code':r.returncode,
                'elapsed_s':round(time.monotonic()-begin,3),'stdout':r.stdout,'stderr':r.stderr,
                'output_sha256':{o:sha(OUT/o) for o in outputs if (OUT/o).exists()},'this_invocation':'executed'}
        print(name+': '+r.stdout.strip(),flush=True)
        if r.returncode:raise RuntimeError(name+': '+r.stderr)
        return name,result
    # These readers have disjoint output files and depend only on frozen inputs.
    with ThreadPoolExecutor(max_workers=3) as pool:
        for name,result in pool.map(stage,('cohort.py','logs_audit.py','bounded_pilot.py')):stages[name]=result
    with ThreadPoolExecutor(max_workers=3) as pool:
        for name,result in pool.map(stage,('identity_timing.py','overlap_plan.py','temporal_feasibility.py')):stages[name]=result
    name,result=stage('report.py');stages[name]=result
    testcmd=[sys.executable,'-B',str(HERE/'test_reassessment.py')]
    test=subprocess.run(testcmd,cwd=REPO,capture_output=True,text=True,creationflags=windows_flags)
    preservation=verify_frozen()
    manifest={'version':CONFIG['version'],'client_date':'2026-10-24','timezone':'Asia/Colombo',
              'repository_root':str(REPO),'raw_root':str(REPO/CONFIG['raw_root']),'baseline_root':str(BASE),
              'contract':contract,'stages':stages,'tests':{'exact_command_arguments':testcmd,'exit_code':test.returncode,'stdout':test.stdout,'stderr':test.stderr},
              'preservation':preservation,'total_elapsed_s':round(time.monotonic()-t0,3),
              'guardrails':{'new_accepted_labels':0,'full_expanded_extraction':False,'replacement_split':False,'model_preprocessing':False,'model_training_or_evaluation':False},
              'scope_limits':'Existing extraction tables are diagnostic inputs only. Original raw source hashes reused except actual logs/sampled byte checks; no exhaustive raw rehash claimed.'}
    write('execution_manifest.json',manifest)
    if test.returncode:raise RuntimeError(test.stderr)
    print('COMPLETE: baseline unchanged; diagnostics only; tests passed',flush=True)


if __name__=='__main__':
    main()
