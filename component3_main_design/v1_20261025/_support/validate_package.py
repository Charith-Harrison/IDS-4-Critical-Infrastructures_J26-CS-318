"""Check proposal consistency and frozen-file preservation; no experiment run."""
from collections import Counter
from pathlib import Path
import importlib.util
import json

HERE = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('review_local', HERE/'_support/review_evidence.py')
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


def main():
    d = review.read(HERE/'proposed_main_design.json')
    r = review.read(HERE/'proposed_run_roster.json')
    e = review.read(HERE/'evidence_checks.json')
    require = review.require
    require(d['status']=='PROPOSED_NOT_ADOPTED_NOT_FROZEN', 'Design adopted/frozen accidentally')
    require(d['engineering_decision']=='CONDITIONAL_GO', 'Unexpected engineering decision')
    require(r['proposed_design_sha256']==review.sha(HERE/'proposed_main_design.json'), 'Roster/design hash mismatch')
    require(d['provenance']['evidence_checks_sha256']==review.sha(HERE/'evidence_checks.json'), 'Design/evidence hash mismatch')
    require(d['provenance']['code_sha256']==review.sha(HERE/'_support/build_design.py'), 'Builder hash mismatch')
    require(e['provenance']['reviewer_code_sha256']==review.sha(HERE/'_support/review_evidence.py'), 'Review code hash mismatch')
    require(len(d['scenarios'])==8 and sum(s['label']=='normal' for s in d['scenarios'])==6, 'Family/mechanism count mismatch')
    needed = {'intervention','label','control','current_message','earlier_observations','decision','indistinguishable'}
    require(all(needed<=s.keys() for s in d['scenarios']), 'Incomplete scenario observation rules')
    require(d['public_detector_configuration']['policy']['id']=='lab-policy-v1', 'Changed original lab policy')
    rows = r['prospective_main_runs']
    quals = r['engineering_runs']
    require(len(rows)==104 and len(quals)==14, 'Roster size differs')
    require(Counter(x['proposed_role'] for x in rows)==r['counts']['main_by_role'], 'Role totals differ')
    require(sum(x['recording_mode']=='normal_only' for x in rows)==24, 'Normal-only coverage differs')
    require(len({x['seed'] for x in rows+quals})==118, 'Seed collision')
    require(len({x['planned_run_id'] for x in rows+quals})==118, 'Planned ID collision')
    require(all(x['actual_recording_id'] is None and x['actual_partition_membership'] is None for x in rows+quals),
            'Actual membership was created')
    require(all(x['status']=='PROPOSED_NOT_COLLECTED' for x in rows+quals), 'Collection claim found')
    require(all(x['proposed_role']=='excluded_from_all_model_work' for x in quals), 'Engineering included in model roles')
    for x in rows:
        if x['proposed_role'] in ('train','validation'):
            require(x['map'] in ('M0','M1') and x['values']=='V0' and x['ordering'] in ('O0','O1')
                    and x['timing'] in ('T0','T1'), 'Held-out condition in development')
    for role,key,value in [('final_test_map','map','M2'),('final_test_values','values','V1'),
                           ('final_test_order','ordering','O2'),('final_test_timing','timing','T2')]:
        require(all(x[key]==value for x in rows if x['proposed_role']==role), 'Stress-test axis differs')
    require(e['total_counts']['adus']==1846 and e['label_counts']==dict(normal=1822,command_injection=8,response_injection=16),
            'Qualification totals differ')
    require(e['existing_evidence_examples_checked']==24 and len(e['representative_direct_checks'])==8, 'Example check totals differ')
    require(e['preserved_failed_attempt']['included_in_accepted_totals'] is False, 'Failed attempt counted')
    require(e['academic_acceptance']['status']=='NOT_RECORDED_IN_REVIEWED_MATERIAL', 'Invented academic approval')
    old = review.read(HERE/'_support/protected_sources.json')
    current = review.protected_snapshot()
    require(old==current, 'Protected files changed')
    files = ['DECISION.md','proposed_main_design.json','proposed_run_roster.json','evidence_checks.json',
             '_support/review_evidence.py','_support/build_design.py','_support/validate_package.py','_support/protected_sources.json']
    result = dict(status='PASSED', protected_files_compared=len(old), protected_files_changed=[],
                  proposal_status='PROPOSED_NOT_ADOPTED', actual_new_recordings=0, actual_partition_assignments=0,
                  model_preprocessing_or_training=False,
                  proposal_consistency='All scenario rules, run totals, held-out axes, null memberships, fresh seeds and input hashes checked',
                  repository_instructions=dict(agents_md='None found in repository discovery, root or immediate parent',
                                               root_readme_read=True, root_readme_sha256=review.sha(review.REPO/'README.md'),
                                               precedence='Current pasted user request controls scope; old binary-model README commands not run'),
                  commands=[
                      '.\\.venv\\Scripts\\python.exe -X utf8 -B component3_main_design/v1_20261025/_support/review_evidence.py',
                      '.\\.venv\\Scripts\\python.exe -X utf8 -B component3_main_design/v1_20261025/_support/build_design.py',
                      '.\\.venv\\Scripts\\python.exe -X utf8 -B component3_main_design/v1_20261025/_support/validate_package.py'],
                  artifact_sha256={name:review.sha(HERE/name) for name in files})
    review.save(HERE/'_support/package_validation.json',result)
    print(json.dumps({k:v for k,v in result.items() if k not in ('artifact_sha256','commands','repository_instructions')},indent=2))


if __name__=='__main__':
    main()
